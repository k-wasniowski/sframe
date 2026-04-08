#include <doctest/doctest.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <sframe/sframe.h>

#include "common.h"

#include <iostream>
#include <map>       // for map
#include <stdexcept> // for invalid_argument
#include <string>    // for basic_string, operator==

using namespace SFRAME_NAMESPACE;

TEST_CASE("SFrame Round-Trip")
{
  const auto rounds = 1 << 9;
  const auto kid = KeyID(0x42);
  const auto plaintext = from_hex("00010203");
  const std::map<CipherSuite, bytes> keys{
    { CipherSuite::AES_128_CTR_HMAC_SHA256_80,
      from_hex("000102030405060708090a0b0c0d0e0f") },
    { CipherSuite::AES_128_CTR_HMAC_SHA256_80,
      from_hex("101112131415161718191a1b1c1d1e1f") },
    { CipherSuite::AES_128_CTR_HMAC_SHA256_80,
      from_hex("202122232425262728292a2b2c2d2e2f") },
    { CipherSuite::AES_GCM_128_SHA256,
      from_hex("303132333435363738393a3b3c3d3e3f") },
    { CipherSuite::AES_GCM_256_SHA512,
      from_hex("404142434445464748494a4b4c4d4e4f"
               "505152535455565758595a5b5c5d5e5f") },
  };

  auto pt_out = bytes(plaintext.size());
  auto ct_out = bytes(plaintext.size() + Context::max_overhead);

  for (auto& pair : keys) {
    auto& suite = pair.first;
    auto& key = pair.second;

    auto send = Context(suite);
    send.add_key(kid, KeyUsage::protect, key).unwrap();

    auto recv = Context(suite);
    recv.add_key(kid, KeyUsage::unprotect, key).unwrap();

    for (int i = 0; i < rounds; i++) {
      auto encrypted =
        to_bytes(send.protect(kid, ct_out, plaintext, {}).unwrap());
      auto decrypted = to_bytes(recv.unprotect(pt_out, encrypted, {}).unwrap());
      CHECK(decrypted == plaintext);
    }
  }
}

// The MLS-based key derivation isn't covered by the RFC test vectors.  So we
// only have round-trip tests, not known-answer tests.
TEST_CASE("MLS Round-Trip")
{
  const auto epoch_bits = 2;
  const auto test_epochs = 1 << (epoch_bits + 1);
  const auto epoch_rounds = 10;
  const auto metadata = from_hex("00010203");
  const auto plaintext = from_hex("04050607");
  const auto sender_id_a = MLSContext::SenderID(0xA0A0A0A0);
  const auto sender_id_b = MLSContext::SenderID(0xA1A1A1A1);
  const std::vector<CipherSuite> suites{
    CipherSuite::AES_128_CTR_HMAC_SHA256_80,
    CipherSuite::AES_128_CTR_HMAC_SHA256_64,
    CipherSuite::AES_128_CTR_HMAC_SHA256_32,
    CipherSuite::AES_GCM_128_SHA256,
    CipherSuite::AES_GCM_256_SHA512,
  };

  auto pt_out = bytes(plaintext.size());
  auto ct_out = bytes(plaintext.size() + Context::max_overhead);

  for (auto& suite : suites) {
    auto member_a = MLSContext(suite, epoch_bits);
    auto member_b = MLSContext(suite, epoch_bits);

    for (MLSContext::EpochID epoch_id = 0; epoch_id < test_epochs; epoch_id++) {
      const auto sframe_epoch_secret = bytes(8, uint8_t(epoch_id));

      member_a.add_epoch(epoch_id, sframe_epoch_secret).unwrap();
      member_b.add_epoch(epoch_id, sframe_epoch_secret).unwrap();

      for (int i = 0; i < epoch_rounds; i++) {
        auto encrypted_ab =
          member_a.protect(epoch_id, sender_id_a, ct_out, plaintext, metadata)
            .unwrap();
        auto decrypted_ab =
          member_b.unprotect(pt_out, encrypted_ab, metadata).unwrap();
        CHECK(plaintext == to_bytes(decrypted_ab));

        auto encrypted_ba =
          member_b.protect(epoch_id, sender_id_b, ct_out, plaintext, metadata)
            .unwrap();
        auto decrypted_ba =
          member_a.unprotect(pt_out, encrypted_ba, metadata).unwrap();
        CHECK(plaintext == to_bytes(decrypted_ba));
      }
    }
  }
}

TEST_CASE("MLS Round-Trip with context")
{
  const auto epoch_bits = 4;
  const auto test_epochs = 1 << (epoch_bits + 1);
  const auto epoch_rounds = 10;
  const auto metadata = from_hex("00010203");
  const auto plaintext = from_hex("04050607");
  const auto sender_id_a = MLSContext::SenderID(0xA0A0A0A0);
  const auto sender_id_b = MLSContext::SenderID(0xA1A1A1A1);
  const auto sender_id_bits = size_t(32);
  const auto context_id_0 = 0xB0B0;
  const auto context_id_1 = 0xB1B1;

  const std::vector<CipherSuite> suites{
    CipherSuite::AES_128_CTR_HMAC_SHA256_80,
    CipherSuite::AES_128_CTR_HMAC_SHA256_64,
    CipherSuite::AES_128_CTR_HMAC_SHA256_32,
    CipherSuite::AES_GCM_128_SHA256,
    CipherSuite::AES_GCM_256_SHA512,
  };

  auto pt_out = bytes(plaintext.size());
  auto ct_out_1 = bytes(plaintext.size() + Context::max_overhead);
  auto ct_out_0 = bytes(plaintext.size() + Context::max_overhead);

  for (auto& suite : suites) {
    auto member_a_0 = MLSContext(suite, epoch_bits);
    auto member_a_1 = MLSContext(suite, epoch_bits);
    auto member_b = MLSContext(suite, epoch_bits);

    for (MLSContext::EpochID epoch_id = 0; epoch_id < test_epochs; epoch_id++) {
      const auto sframe_epoch_secret = bytes(8, uint8_t(epoch_id));

      member_a_0.add_epoch(epoch_id, sframe_epoch_secret, sender_id_bits)
        .unwrap();
      member_a_1.add_epoch(epoch_id, sframe_epoch_secret, sender_id_bits)
        .unwrap();
      member_b.add_epoch(epoch_id, sframe_epoch_secret).unwrap();

      for (int i = 0; i < epoch_rounds; i++) {
        auto encrypted_ab_0 = member_a_0
                                .protect(epoch_id,
                                         sender_id_a,
                                         context_id_0,
                                         ct_out_0,
                                         plaintext,
                                         metadata)
                                .unwrap();
        auto decrypted_ab_0 = to_bytes(
          member_b.unprotect(pt_out, encrypted_ab_0, metadata).unwrap());
        CHECK(plaintext == decrypted_ab_0);

        auto encrypted_ab_1 = member_a_1
                                .protect(epoch_id,
                                         sender_id_a,
                                         context_id_1,
                                         ct_out_1,
                                         plaintext,
                                         metadata)
                                .unwrap();
        auto decrypted_ab_1 = to_bytes(
          member_b.unprotect(pt_out, encrypted_ab_1, metadata).unwrap());
        CHECK(plaintext == decrypted_ab_1);

        CHECK(to_bytes(encrypted_ab_0) != to_bytes(encrypted_ab_1));

        auto encrypted_ba =
          member_b.protect(epoch_id, sender_id_b, ct_out_0, plaintext, metadata)
            .unwrap();
        auto decrypted_ba_0 = to_bytes(
          member_a_0.unprotect(pt_out, encrypted_ba, metadata).unwrap());
        auto decrypted_ba_1 = to_bytes(
          member_a_1.unprotect(pt_out, encrypted_ba, metadata).unwrap());
        CHECK(plaintext == decrypted_ba_0);
        CHECK(plaintext == decrypted_ba_1);
      }
    }
  }
}

TEST_CASE("MLS Failure after Purge")
{
  const auto suite = CipherSuite::AES_GCM_128_SHA256;
  const auto epoch_bits = 2;
  const auto metadata = from_hex("00010203");
  const auto plaintext = from_hex("04050607");
  const auto sender_id_a = MLSContext::SenderID(0xA0A0A0A0);
  const auto sframe_epoch_secret_1 = bytes(32, 1);
  const auto sframe_epoch_secret_2 = bytes(32, 2);

  auto pt_out = bytes(plaintext.size());
  auto ct_out = bytes(plaintext.size() + Context::max_overhead);

  auto member_a = MLSContext(suite, epoch_bits);
  auto member_b = MLSContext(suite, epoch_bits);

  // Install epoch 1 and create a cipihertext
  const auto epoch_id_1 = MLSContext::EpochID(1);
  member_a.add_epoch(epoch_id_1, sframe_epoch_secret_1).unwrap();
  member_b.add_epoch(epoch_id_1, sframe_epoch_secret_1).unwrap();

  const auto enc_ab_1 =
    member_a.protect(epoch_id_1, sender_id_a, ct_out, plaintext, metadata)
      .unwrap();
  const auto enc_ab_1_data = to_bytes(enc_ab_1);

  // Install epoch 2
  const auto epoch_id_2 = MLSContext::EpochID(2);
  member_a.add_epoch(epoch_id_2, sframe_epoch_secret_2).unwrap();
  member_b.add_epoch(epoch_id_2, sframe_epoch_secret_2).unwrap();

  // Purge epoch 1 and verify failure
  member_a.purge_before(epoch_id_2);
  member_b.purge_before(epoch_id_2);

  CHECK(member_a.protect(epoch_id_1, sender_id_a, ct_out, plaintext, metadata)
          .error()
          .type() == SFrameErrorType::invalid_parameter_error);
  CHECK(member_b.unprotect(pt_out, enc_ab_1_data, metadata).error().type() ==
        SFrameErrorType::invalid_parameter_error);

  const auto enc_ab_2 =
    member_a.protect(epoch_id_2, sender_id_a, ct_out, plaintext, metadata)
      .unwrap();
  const auto dec_ab_2 = member_b.unprotect(pt_out, enc_ab_2, metadata).unwrap();
  CHECK(plaintext == to_bytes(dec_ab_2));
}

TEST_CASE("SFrame Context Remove Key")
{
  const auto suite = CipherSuite::AES_GCM_128_SHA256;
  const auto kid = KeyID(0x07);
  const auto key = from_hex("000102030405060708090a0b0c0d0e0f");
  const auto plaintext = from_hex("00010203");
  const auto metadata = bytes{};

  auto pt_out = bytes(plaintext.size());
  auto ct_out = bytes(plaintext.size() + Context::max_overhead);

  auto sender = Context(suite);
  auto receiver = Context(suite);
  sender.add_key(kid, KeyUsage::protect, key).unwrap();
  receiver.add_key(kid, KeyUsage::unprotect, key).unwrap();

  // Protect and unprotect succeed before removal
  auto encrypted =
    to_bytes(sender.protect(kid, ct_out, plaintext, metadata).unwrap());
  auto decrypted =
    to_bytes(receiver.unprotect(pt_out, encrypted, metadata).unwrap());
  CHECK(decrypted == plaintext);

  // Remove sender key and verify protect fails
  sender.remove_key(kid);
  CHECK(sender.protect(kid, ct_out, plaintext, metadata).error().type() ==
        SFrameErrorType::invalid_parameter_error);

  // Remove receiver key and verify unprotect fails
  receiver.remove_key(kid);
  CHECK(receiver.unprotect(pt_out, encrypted, metadata).error().type() ==
        SFrameErrorType::invalid_parameter_error);

  // Re-add keys and verify round-trip works again
  sender.add_key(kid, KeyUsage::protect, key).unwrap();
  receiver.add_key(kid, KeyUsage::unprotect, key).unwrap();

  encrypted =
    to_bytes(sender.protect(kid, ct_out, plaintext, metadata).unwrap());
  decrypted =
    to_bytes(receiver.unprotect(pt_out, encrypted, metadata).unwrap());
  CHECK(decrypted == plaintext);
}

TEST_CASE("SFrame Context Remove Key - Nonexistent Key")
{
  const auto suite = CipherSuite::AES_GCM_128_SHA256;

  auto ctx = Context(suite);

  // Removing a key that was never added should not throw
  CHECK_NOTHROW(ctx.remove_key(KeyID(0x99)));
}

TEST_CASE("MLS Remove Epoch")
{
  const auto suite = CipherSuite::AES_GCM_128_SHA256;
  const auto epoch_bits = 2;
  const auto metadata = from_hex("00010203");
  const auto plaintext = from_hex("04050607");
  const auto sender_id = MLSContext::SenderID(0xA0A0A0A0);
  const auto sframe_epoch_secret_1 = bytes(32, 1);
  const auto sframe_epoch_secret_2 = bytes(32, 2);

  auto pt_out = bytes(plaintext.size());
  auto ct_out = bytes(plaintext.size() + Context::max_overhead);

  auto member_a = MLSContext(suite, epoch_bits);
  auto member_b = MLSContext(suite, epoch_bits);

  // Install epoch 1 and verify round-trip
  const auto epoch_id_1 = MLSContext::EpochID(1);
  member_a.add_epoch(epoch_id_1, sframe_epoch_secret_1);
  member_b.add_epoch(epoch_id_1, sframe_epoch_secret_1);

  auto enc =
    member_a.protect(epoch_id_1, sender_id, ct_out, plaintext, metadata)
      .unwrap();
  auto enc_data = to_bytes(enc);
  auto dec = to_bytes(member_b.unprotect(pt_out, enc_data, metadata).unwrap());
  CHECK(plaintext == dec);

  // Install epoch 2
  const auto epoch_id_2 = MLSContext::EpochID(2);
  member_a.add_epoch(epoch_id_2, sframe_epoch_secret_2);
  member_b.add_epoch(epoch_id_2, sframe_epoch_secret_2);

  // Remove only epoch 1 (not purge_before) and verify it fails
  member_a.remove_epoch(epoch_id_1);
  member_b.remove_epoch(epoch_id_1);

  CHECK(member_a.protect(epoch_id_1, sender_id, ct_out, plaintext, metadata)
          .error()
          .type() == SFrameErrorType::invalid_parameter_error);
  CHECK(member_b.unprotect(pt_out, enc_data, metadata).error().type() ==
        SFrameErrorType::invalid_parameter_error);

  // Epoch 2 should still work
  enc = member_a.protect(epoch_id_2, sender_id, ct_out, plaintext, metadata)
          .unwrap();
  dec = to_bytes(member_b.unprotect(pt_out, enc, metadata).unwrap());
  CHECK(plaintext == dec);

  // Re-add epoch 1 with the same secret and verify it works again
  member_a.add_epoch(epoch_id_1, sframe_epoch_secret_1);
  member_b.add_epoch(epoch_id_1, sframe_epoch_secret_1);

  enc = member_a.protect(epoch_id_1, sender_id, ct_out, plaintext, metadata)
          .unwrap();
  dec = to_bytes(member_b.unprotect(pt_out, enc, metadata).unwrap());
  CHECK(plaintext == dec);
}

TEST_CASE("RTP Per-SSRC Key Derivation Round-Trip")
{
  const auto rounds = 1 << 5;
  const auto plaintext = from_hex("00010203");
  const auto base_key = from_hex("000102030405060708090a0b0c0d0e0f");
  const auto ssrc_a = RTPContext::SSRC(0xDEADBEEF);
  const auto ssrc_b = RTPContext::SSRC(0xCAFEBABE);
  const auto kid = KeyID(0x01);

  const std::vector<CipherSuite> suites{
    CipherSuite::AES_128_CTR_HMAC_SHA256_80,
    CipherSuite::AES_128_CTR_HMAC_SHA256_64,
    CipherSuite::AES_128_CTR_HMAC_SHA256_32,
    CipherSuite::AES_GCM_128_SHA256,
    CipherSuite::AES_GCM_256_SHA512,
  };

  auto pt_out = bytes(plaintext.size());
  auto ct_out = bytes(plaintext.size() + RTPContext::max_overhead);

  for (auto& suite : suites) {
    // Same base_key + same SSRC => same derived key => round-trip works
    auto sender = RTPContext(suite);
    sender.add_key(kid, base_key).unwrap();
    sender.add_ssrc(ssrc_a, KeyUsage::protect).unwrap();

    auto receiver = RTPContext(suite);
    receiver.add_key(kid, base_key).unwrap();
    receiver.add_ssrc(ssrc_a, KeyUsage::unprotect).unwrap();

    for (int i = 0; i < rounds; i++) {
      auto encrypted =
        to_bytes(sender.protect(ssrc_a, ct_out, plaintext, {}).unwrap());
      auto decrypted =
        to_bytes(receiver.unprotect(ssrc_a, pt_out, encrypted, {}).unwrap());
      CHECK(decrypted == plaintext);
    }

    // Different SSRCs with same base_key => different keys => decrypt fails
    auto wrong_receiver = RTPContext(suite);
    wrong_receiver.add_key(kid, base_key).unwrap();
    wrong_receiver.add_ssrc(ssrc_b, KeyUsage::unprotect).unwrap();

    auto encrypted =
      to_bytes(sender.protect(ssrc_a, ct_out, plaintext, {}).unwrap());
    CHECK(wrong_receiver.unprotect(ssrc_b, pt_out, encrypted, {}).is_err());
  }
}

TEST_CASE("RTP Ratcheting Round-Trip")
{
  const auto suite = CipherSuite::AES_GCM_128_SHA256;
  const auto plaintext = from_hex("04050607");
  const auto metadata = from_hex("00010203");
  const auto base_key = from_hex("000102030405060708090a0b0c0d0e0f");
  const auto ssrc = RTPContext::SSRC(0x12345678);
  const auto kid_0 = KeyID(0x00);
  const auto kid_1 = KeyID(0x01);
  const auto kid_2 = KeyID(0x02);

  auto pt_out = bytes(plaintext.size());
  auto ct_out = bytes(plaintext.size() + RTPContext::max_overhead);

  auto sender = RTPContext(suite);
  auto receiver = RTPContext(suite);

  // Initial key
  sender.add_key(kid_0, base_key).unwrap();
  sender.add_ssrc(ssrc, KeyUsage::protect).unwrap();
  receiver.add_key(kid_0, base_key).unwrap();
  receiver.add_ssrc(ssrc, KeyUsage::unprotect).unwrap();

  auto encrypted =
    to_bytes(sender.protect(ssrc, ct_out, plaintext, metadata).unwrap());
  auto decrypted =
    to_bytes(receiver.unprotect(ssrc, pt_out, encrypted, metadata).unwrap());
  CHECK(decrypted == plaintext);

  // Ratchet sender only — receiver should auto-ratchet on unprotect
  sender.ratchet(kid_1).unwrap();

  // New key_id should work — receiver auto-ratchets
  encrypted =
    to_bytes(sender.protect(ssrc, ct_out, plaintext, metadata).unwrap());
  decrypted =
    to_bytes(receiver.unprotect(ssrc, pt_out, encrypted, metadata).unwrap());
  CHECK(decrypted == plaintext);

  // Ratchet sender again — receiver catches up automatically
  sender.ratchet(kid_2).unwrap();

  encrypted =
    to_bytes(sender.protect(ssrc, ct_out, plaintext, metadata).unwrap());
  decrypted =
    to_bytes(receiver.unprotect(ssrc, pt_out, encrypted, metadata).unwrap());
  CHECK(decrypted == plaintext);
}

TEST_CASE("RTP Ratcheting Produces Different Keys")
{
  const auto suite = CipherSuite::AES_GCM_128_SHA256;
  const auto plaintext = from_hex("04050607");
  const auto base_key = from_hex("000102030405060708090a0b0c0d0e0f");
  const auto ssrc = RTPContext::SSRC(0xAABBCCDD);
  const auto kid_0 = KeyID(0x00);
  const auto kid_1 = KeyID(0x01);

  auto ct_out = bytes(plaintext.size() + RTPContext::max_overhead);

  auto sender = RTPContext(suite);
  sender.add_key(kid_0, base_key).unwrap();
  sender.add_ssrc(ssrc, KeyUsage::protect).unwrap();

  auto ct_before =
    to_bytes(sender.protect(ssrc, ct_out, plaintext, {}).unwrap());

  // Ratchet and encrypt again with new key
  sender.ratchet(kid_1).unwrap();
  auto ct_after =
    to_bytes(sender.protect(ssrc, ct_out, plaintext, {}).unwrap());

  // Ciphertexts must differ (different keys)
  CHECK(ct_before != ct_after);
}

TEST_CASE("RTP Auto-Ratchet Multi-Step Catch-Up")
{
  const auto suite = CipherSuite::AES_GCM_128_SHA256;
  const auto plaintext = from_hex("aabbccdd");
  const auto metadata = from_hex("ee");
  const auto base_key = from_hex("000102030405060708090a0b0c0d0e0f");
  const auto ssrc = RTPContext::SSRC(0x12345678);

  auto ct_out = bytes(plaintext.size() + RTPContext::max_overhead);
  auto pt_out = bytes(plaintext.size());

  auto sender = RTPContext(suite);
  auto receiver = RTPContext(suite);
  sender.add_key(KeyID(0), base_key).unwrap();
  sender.add_ssrc(ssrc, KeyUsage::protect).unwrap();
  receiver.add_key(KeyID(0), base_key).unwrap();
  receiver.add_ssrc(ssrc, KeyUsage::unprotect).unwrap();

  // Sender ratchets 5 times without receiver knowing
  for (KeyID kid = 1; kid <= 5; kid++) {
    sender.ratchet(kid).unwrap();
  }

  // Receiver should catch up automatically in one unprotect call
  auto encrypted =
    to_bytes(sender.protect(ssrc, ct_out, plaintext, metadata).unwrap());
  auto decrypted =
    to_bytes(receiver.unprotect(ssrc, pt_out, encrypted, metadata).unwrap());
  CHECK(decrypted == plaintext);
}

TEST_CASE("RTP New Key After Ratchet Limit Exceeded")
{
  const auto suite = CipherSuite::AES_GCM_128_SHA256;
  const auto plaintext = from_hex("aabbccdd");
  const auto metadata = from_hex("ee");
  const auto base_key = from_hex("000102030405060708090a0b0c0d0e0f");
  const auto new_base_key = from_hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
  const auto ssrc = RTPContext::SSRC(0xAABBCCDD);

  auto ct_out = bytes(plaintext.size() + RTPContext::max_overhead);
  auto pt_out = bytes(plaintext.size());

  auto sender = RTPContext(suite);
  auto receiver = RTPContext(suite);
  sender.add_key(KeyID(0), base_key).unwrap();
  sender.add_ssrc(ssrc, KeyUsage::protect).unwrap();
  receiver.add_key(KeyID(0), base_key).unwrap();
  receiver.add_ssrc(ssrc, KeyUsage::unprotect).unwrap();

  // Sender ratchets 300 times (exceeds the 256 auto-ratchet limit)
  for (KeyID kid = 1; kid <= 300; kid++) {
    sender.ratchet(kid).unwrap();
  }

  // Receiver auto-ratchet should fail (gap=300 > 256)
  auto encrypted =
    to_bytes(sender.protect(ssrc, ct_out, plaintext, metadata).unwrap());
  CHECK(receiver.unprotect(ssrc, pt_out, encrypted, metadata).is_err());

  // Install a fresh key on both sides — should recover
  sender.add_key(KeyID(0), new_base_key).unwrap();
  receiver.add_key(KeyID(0), new_base_key).unwrap();

  encrypted =
    to_bytes(sender.protect(ssrc, ct_out, plaintext, metadata).unwrap());
  auto decrypted =
    to_bytes(receiver.unprotect(ssrc, pt_out, encrypted, metadata).unwrap());
  CHECK(decrypted == plaintext);
}

TEST_CASE("RTP Remove SSRC")
{
  const auto suite = CipherSuite::AES_GCM_128_SHA256;
  const auto plaintext = from_hex("00010203");
  const auto base_key = from_hex("000102030405060708090a0b0c0d0e0f");
  const auto ssrc = RTPContext::SSRC(0x11223344);
  const auto kid = KeyID(0x42);

  auto ct_out = bytes(plaintext.size() + RTPContext::max_overhead);

  auto ctx = RTPContext(suite);
  ctx.add_key(kid, base_key).unwrap();
  ctx.add_ssrc(ssrc, KeyUsage::protect).unwrap();

  // Protect should work
  CHECK(ctx.protect(ssrc, ct_out, plaintext, {}).is_ok());

  // Remove and verify protect fails
  ctx.remove_ssrc(ssrc);
  CHECK(ctx.protect(ssrc, ct_out, plaintext, {}).is_err());
}

TEST_CASE("RTP Multiple SSRCs On Same Context")
{
  const auto suite = CipherSuite::AES_GCM_128_SHA256;
  const auto plaintext_a = from_hex("aabbccdd");
  const auto plaintext_v = from_hex("11223344");
  const auto base_key = from_hex("000102030405060708090a0b0c0d0e0f");
  const auto ssrc_audio = RTPContext::SSRC(0x00000001);
  const auto ssrc_video = RTPContext::SSRC(0x00000002);
  const auto kid = KeyID(0x00);

  auto ct_out = bytes(128);
  auto pt_out = bytes(128);

  auto sender = RTPContext(suite);
  auto receiver = RTPContext(suite);

  // Same KID for all SSRCs (spec-compliant)
  sender.add_key(kid, base_key).unwrap();
  sender.add_ssrc(ssrc_audio, KeyUsage::protect).unwrap();
  sender.add_ssrc(ssrc_video, KeyUsage::protect).unwrap();

  receiver.add_key(kid, base_key).unwrap();
  receiver.add_ssrc(ssrc_audio, KeyUsage::unprotect).unwrap();
  receiver.add_ssrc(ssrc_video, KeyUsage::unprotect).unwrap();

  // Audio round-trip
  auto ct_a =
    to_bytes(sender.protect(ssrc_audio, ct_out, plaintext_a, {}).unwrap());
  auto pt_a =
    to_bytes(receiver.unprotect(ssrc_audio, pt_out, ct_a, {}).unwrap());
  CHECK(pt_a == plaintext_a);

  // Video round-trip
  auto ct_v =
    to_bytes(sender.protect(ssrc_video, ct_out, plaintext_v, {}).unwrap());
  auto pt_v =
    to_bytes(receiver.unprotect(ssrc_video, pt_out, ct_v, {}).unwrap());
  CHECK(pt_v == plaintext_v);

  // Cross-SSRC: audio ciphertext cannot be decrypted with video SSRC
  // (different derived keys due to different SSRCs)
  auto ct_a2 =
    to_bytes(sender.protect(ssrc_audio, ct_out, plaintext_a, {}).unwrap());
  CHECK(receiver.unprotect(ssrc_video, pt_out, ct_a2, {}).is_err());
}

TEST_CASE("RTP Ratchet Advances All SSRCs Together")
{
  const auto suite = CipherSuite::AES_GCM_128_SHA256;
  const auto plaintext = from_hex("deadbeef");
  const auto base_key = from_hex("000102030405060708090a0b0c0d0e0f");
  const auto ssrc_a = RTPContext::SSRC(0xAAAAAAAA);
  const auto ssrc_b = RTPContext::SSRC(0xBBBBBBBB);
  const auto kid_0 = KeyID(0x00);

  auto ct_out = bytes(plaintext.size() + RTPContext::max_overhead);
  auto pt_out = bytes(plaintext.size());

  auto sender = RTPContext(suite);
  auto receiver = RTPContext(suite);

  sender.add_key(kid_0, base_key).unwrap();
  sender.add_ssrc(ssrc_a, KeyUsage::protect).unwrap();
  sender.add_ssrc(ssrc_b, KeyUsage::protect).unwrap();
  receiver.add_key(kid_0, base_key).unwrap();
  receiver.add_ssrc(ssrc_a, KeyUsage::unprotect).unwrap();
  receiver.add_ssrc(ssrc_b, KeyUsage::unprotect).unwrap();

  // Ratchet all SSRCs twice (KIDs 0x01, 0x02)
  sender.ratchet(KeyID(0x01)).unwrap();
  sender.ratchet(KeyID(0x02)).unwrap();

  // Both SSRCs should work with auto-ratchet on receiver
  auto ct_a = to_bytes(sender.protect(ssrc_a, ct_out, plaintext, {}).unwrap());
  auto pt_a = to_bytes(receiver.unprotect(ssrc_a, pt_out, ct_a, {}).unwrap());
  CHECK(pt_a == plaintext);

  auto ct_b = to_bytes(sender.protect(ssrc_b, ct_out, plaintext, {}).unwrap());
  auto pt_b = to_bytes(receiver.unprotect(ssrc_b, pt_out, ct_b, {}).unwrap());
  CHECK(pt_b == plaintext);

  // Cross-SSRC decrypt should still fail (different derived keys)
  auto ct_a2 = to_bytes(sender.protect(ssrc_a, ct_out, plaintext, {}).unwrap());
  CHECK(receiver.unprotect(ssrc_b, pt_out, ct_a2, {}).is_err());
}

TEST_CASE("RTP Old KID Fails After Auto-Ratchet")
{
  const auto suite = CipherSuite::AES_GCM_128_SHA256;
  const auto plaintext = from_hex("cafebabe");
  const auto metadata = from_hex("ff");
  const auto base_key = from_hex("000102030405060708090a0b0c0d0e0f");
  const auto ssrc = RTPContext::SSRC(0x12345678);

  auto ct_out = bytes(plaintext.size() + RTPContext::max_overhead);
  auto pt_out = bytes(plaintext.size());

  auto sender = RTPContext(suite);
  auto receiver = RTPContext(suite);
  sender.add_key(KeyID(0), base_key).unwrap();
  sender.add_ssrc(ssrc, KeyUsage::protect).unwrap();
  receiver.add_key(KeyID(0), base_key).unwrap();
  receiver.add_ssrc(ssrc, KeyUsage::unprotect).unwrap();

  // Encrypt with KID=0
  auto ct_kid0 =
    to_bytes(sender.protect(ssrc, ct_out, plaintext, metadata).unwrap());

  // Sender ratchets to KID=2, receiver auto-ratchets
  sender.ratchet(KeyID(1)).unwrap();
  sender.ratchet(KeyID(2)).unwrap();

  auto ct_kid2 =
    to_bytes(sender.protect(ssrc, ct_out, plaintext, metadata).unwrap());
  auto decrypted =
    to_bytes(receiver.unprotect(ssrc, pt_out, ct_kid2, metadata).unwrap());
  CHECK(decrypted == plaintext);

  // Now try to decrypt the old KID=0 packet — should fail
  // (forward secrecy: old key was deleted during ratchet)
  CHECK(receiver.unprotect(ssrc, pt_out, ct_kid0, metadata).is_err());
}

TEST_CASE("RTP Backward KID Rejected")
{
  const auto suite = CipherSuite::AES_GCM_128_SHA256;
  const auto plaintext = from_hex("01020304");
  const auto base_key = from_hex("000102030405060708090a0b0c0d0e0f");
  const auto ssrc = RTPContext::SSRC(0xDEADFACE);

  auto ct_out = bytes(plaintext.size() + RTPContext::max_overhead);
  auto pt_out = bytes(plaintext.size());

  auto sender = RTPContext(suite);
  auto receiver = RTPContext(suite);
  sender.add_key(KeyID(0), base_key).unwrap();
  sender.add_ssrc(ssrc, KeyUsage::protect).unwrap();
  receiver.add_key(KeyID(0), base_key).unwrap();
  receiver.add_ssrc(ssrc, KeyUsage::unprotect).unwrap();

  // Both sides ratchet to KID=5
  for (KeyID kid = 1; kid <= 5; kid++) {
    sender.ratchet(kid).unwrap();
    receiver.ratchet(kid).unwrap();
  }

  // Encrypt with current KID=5
  auto ct_kid5 = to_bytes(sender.protect(ssrc, ct_out, plaintext, {}).unwrap());
  auto decrypted =
    to_bytes(receiver.unprotect(ssrc, pt_out, ct_kid5, {}).unwrap());
  CHECK(decrypted == plaintext);

  // Craft a scenario: a second sender at KID=3 (behind receiver's KID=5)
  // Receiver should reject it — backward KID
  auto old_sender = RTPContext(suite);
  old_sender.add_key(KeyID(0), base_key).unwrap();
  old_sender.add_ssrc(ssrc, KeyUsage::protect).unwrap();
  for (KeyID kid = 1; kid <= 3; kid++) {
    old_sender.ratchet(kid).unwrap();
  }
  auto ct_kid3 =
    to_bytes(old_sender.protect(ssrc, ct_out, plaintext, {}).unwrap());

  // Receiver at KID=5 should reject KID=3
  CHECK(receiver.unprotect(ssrc, pt_out, ct_kid3, {}).is_err());
}
