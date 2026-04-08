#include <sframe/sframe.h>

#include "crypto.h"
#include "header.h"

namespace SFRAME_NAMESPACE {

///
/// KeyRecord
///

static auto
from_ascii(const char* str, size_t len)
{
  const auto ptr = reinterpret_cast<const uint8_t*>(str);
  return input_bytes(ptr, len);
}

static const auto base_label = from_ascii("SFrame 1.0 Secret ", 18);
static const auto key_label = from_ascii("key ", 4);
static const auto salt_label = from_ascii("salt ", 5);

static owned_bytes<32>
sframe_key_label(CipherSuite suite, KeyID key_id)
{
  auto label = owned_bytes<32>(base_label);
  label.append(key_label);
  label.resize(32);

  auto label_data = output_bytes(label);
  encode_uint(key_id, label_data.subspan(22).first(8));
  encode_uint(static_cast<uint64_t>(suite), label_data.subspan(30));

  return label;
}

static owned_bytes<33>
sframe_salt_label(CipherSuite suite, KeyID key_id)
{
  auto label = owned_bytes<33>(base_label);
  label.append(salt_label);
  label.resize(33);

  auto label_data = output_bytes(label);
  encode_uint(key_id, label_data.last(10).first(8));
  encode_uint(static_cast<uint64_t>(suite), label_data.last(2));

  return label;
}

Result<KeyRecord>
KeyRecord::from_base_key(CipherSuite suite,
                         KeyID key_id,
                         KeyUsage usage,
                         input_bytes base_key)
{
  SFRAME_VALUE_OR_RETURN(key_size, cipher_key_size(suite));
  SFRAME_VALUE_OR_RETURN(nonce_size, cipher_nonce_size(suite));

  const auto empty_byte_string = owned_bytes<1>();
  const auto key_label = sframe_key_label(suite, key_id);
  const auto salt_label = sframe_salt_label(suite, key_id);

  SFRAME_VALUE_OR_RETURN(secret,
                         hkdf_extract(suite, empty_byte_string, base_key));
  SFRAME_VALUE_OR_RETURN(key, hkdf_expand(suite, secret, key_label, key_size));
  SFRAME_VALUE_OR_RETURN(salt,
                         hkdf_expand(suite, secret, salt_label, nonce_size));

  return KeyRecord{ key, salt, usage, 0 };
}

///
/// Context
///

Context::Context(CipherSuite suite_in)
  : suite(suite_in)
{
}

Context::~Context() = default;

void
Context::remove_key(KeyID key_id)
{
  keys.erase(key_id);
}

Result<void>
Context::add_key(KeyID key_id, KeyUsage usage, input_bytes base_key)
{
  SFRAME_VALUE_OR_RETURN(
    record, KeyRecord::from_base_key(suite, key_id, usage, base_key));
  keys.erase(key_id);
  keys.emplace(key_id, record);
  return Result<void>::ok();
}

static owned_bytes<KeyRecord::max_salt_size>
form_nonce(Counter ctr, input_bytes salt)
{
  auto nonce = owned_bytes<KeyRecord::max_salt_size>(salt);
  for (size_t i = 0; i < sizeof(ctr); i++) {
    nonce[nonce.size() - i - 1] ^= uint8_t(ctr >> (8 * i));
  }

  return nonce;
}

static constexpr auto max_aad_size =
  Header::max_size + Context::max_metadata_size;

static Result<owned_bytes<max_aad_size>>
form_aad(const Header& header, input_bytes metadata)
{
  if (metadata.size() > Context::max_metadata_size) {
    return SFrameError(SFrameErrorType::buffer_too_small_error,
                       "Metadata too large");
  }

  auto aad = owned_bytes<max_aad_size>(0);
  aad.append(header.encoded());
  aad.append(metadata);
  return aad;
}

Result<void>
Context::require_key(KeyID key_id) const
{
  if (!keys.contains(key_id)) {
    return SFrameError(SFrameErrorType::invalid_parameter_error,
                       "Unknown key ID");
  }
  return Result<void>::ok();
}

Result<output_bytes>
Context::protect(KeyID key_id,
                 output_bytes ciphertext,
                 input_bytes plaintext,
                 input_bytes metadata)
{
  SFRAME_VOID_OR_RETURN(require_key(key_id));
  auto& key_record = keys.at(key_id);
  const auto counter = key_record.counter;
  key_record.counter += 1;

  const auto header = Header{ key_id, counter };
  const auto header_data = header.encoded();
  if (ciphertext.size() < header_data.size()) {
    return SFrameError(SFrameErrorType::buffer_too_small_error,
                       "Ciphertext too small for SFrame header");
  }

  std::copy(header_data.begin(), header_data.end(), ciphertext.begin());
  auto inner_ciphertext = ciphertext.subspan(header_data.size());
  SFRAME_VALUE_OR_RETURN(
    final_ciphertext,
    Context::protect_inner(header, inner_ciphertext, plaintext, metadata));
  return ciphertext.first(header_data.size() + final_ciphertext.size());
}

Result<output_bytes>
Context::unprotect(output_bytes plaintext,
                   input_bytes ciphertext,
                   input_bytes metadata)
{
  SFRAME_VALUE_OR_RETURN(header, Header::parse(ciphertext));
  const auto inner_ciphertext = ciphertext.subspan(header.size());
  return Context::unprotect_inner(
    header, plaintext, inner_ciphertext, metadata);
}

Result<output_bytes>
Context::protect_inner(const Header& header,
                       output_bytes ciphertext,
                       input_bytes plaintext,
                       input_bytes metadata)
{
  SFRAME_VALUE_OR_RETURN(overhead, cipher_overhead(suite));
  if (ciphertext.size() < plaintext.size() + overhead) {
    return SFrameError(SFrameErrorType::buffer_too_small_error,
                       "Ciphertext too small for cipher overhead");
  }

  SFRAME_VOID_OR_RETURN(require_key(header.key_id));
  const auto& key_and_salt = keys.at(header.key_id);

  SFRAME_VALUE_OR_RETURN(aad, form_aad(header, metadata));
  const auto nonce = form_nonce(header.counter, key_and_salt.salt);
  return seal(suite, key_and_salt.key, nonce, ciphertext, aad, plaintext);
}

Result<output_bytes>
Context::unprotect_inner(const Header& header,
                         output_bytes plaintext,
                         input_bytes ciphertext,
                         input_bytes metadata)
{
  SFRAME_VALUE_OR_RETURN(overhead, cipher_overhead(suite));
  if (ciphertext.size() < overhead) {
    return SFrameError(SFrameErrorType::buffer_too_small_error,
                       "Ciphertext too small for cipher overhead");
  }

  if (plaintext.size() < ciphertext.size() - overhead) {
    return SFrameError(SFrameErrorType::buffer_too_small_error,
                       "Plaintext too small for decrypted value");
  }

  SFRAME_VOID_OR_RETURN(require_key(header.key_id));
  const auto& key_and_salt = keys.at(header.key_id);

  SFRAME_VALUE_OR_RETURN(aad, form_aad(header, metadata));
  const auto nonce = form_nonce(header.counter, key_and_salt.salt);
  return open(suite, key_and_salt.key, nonce, plaintext, aad, ciphertext);
}

///
/// RTP per-SSRC key derivation and ratcheting
///

static const auto rtp_stream_label = from_ascii("SFrame 1.0 RTP Stream", 21);
static const auto ratchet_label = from_ascii("SFrame 1.0 Ratchet", 18);
static const auto empty_info = owned_bytes<1>();

static Result<owned_bytes<64>>
derive_ssrc_key(CipherSuite suite, uint32_t ssrc, input_bytes base_key)
{
  SFRAME_VALUE_OR_RETURN(hash_size, cipher_digest_size(suite));

  // Encode SSRC as 4-byte big-endian salt
  auto ssrc_salt = owned_bytes<4>();
  ssrc_salt.resize(4);
  ssrc_salt[0] = uint8_t(ssrc >> 24);
  ssrc_salt[1] = uint8_t(ssrc >> 16);
  ssrc_salt[2] = uint8_t(ssrc >> 8);
  ssrc_salt[3] = uint8_t(ssrc);

  SFRAME_VALUE_OR_RETURN(prk, hkdf_extract(suite, ssrc_salt, base_key));
  return hkdf_expand(suite, prk, rtp_stream_label, hash_size);
}

static Result<owned_bytes<64>>
ratchet_key(CipherSuite suite, input_bytes current_key)
{
  SFRAME_VALUE_OR_RETURN(hash_size, cipher_digest_size(suite));
  SFRAME_VALUE_OR_RETURN(prk, hkdf_extract(suite, ratchet_label, current_key));
  return hkdf_expand(suite, prk, empty_info, hash_size);
}

///
/// RTPContext
///

RTPContext::RTPContext(CipherSuite suite_in)
  : suite(suite_in)
  , current_key_id(0)
  , ratchet_count(0)
{
}

Result<RTPContext::SSRCRecord>
RTPContext::derive_ssrc_record(SSRC ssrc, KeyUsage usage) const
{
  // Derive per-SSRC key from the base key
  SFRAME_VALUE_OR_RETURN(ssrc_key, derive_ssrc_key(suite, ssrc, base_key));

  // Apply ratchet steps to match the current ratchet count
  auto current = ssrc_key;
  for (uint64_t i = 0; i < ratchet_count; i++) {
    SFRAME_VALUE_OR_RETURN(next, ratchet_key(suite, current));
    current = next;
  }

  // Create a KeyRecord from the derived ssrc key
  SFRAME_VALUE_OR_RETURN(
    key_record,
    KeyRecord::from_base_key(suite, current_key_id, usage, current));

  return SSRCRecord{ current, key_record, usage };
}

Result<void>
RTPContext::add_key(KeyID key_id, input_bytes new_base_key)
{
  base_key = owned_bytes<max_base_key_size>(new_base_key);
  current_key_id = key_id;
  ratchet_count = 0;

  // Re-derive keys for all existing SSRCs
  for (auto& maybe_pair : ssrc_records) {
#ifdef NO_ALLOC
    if (!maybe_pair) {
      continue;
    }
    auto& [ssrc, record] = maybe_pair.value();
#else
    auto& [ssrc, record] = maybe_pair;
#endif

    SFRAME_VALUE_OR_RETURN(new_record, derive_ssrc_record(ssrc, record.usage));
    record = std::move(new_record);
  }

  return Result<void>::ok();
}

Result<void>
RTPContext::add_ssrc(SSRC ssrc, KeyUsage usage)
{
  if (base_key.empty()) {
    return SFrameError(SFrameErrorType::invalid_parameter_error,
                       "No base key set");
  }

  SFRAME_VALUE_OR_RETURN(record, derive_ssrc_record(ssrc, usage));

  ssrc_records.erase(ssrc);
  ssrc_records.emplace(ssrc, std::move(record));
  return Result<void>::ok();
}

Result<void>
RTPContext::ratchet(KeyID new_key_id)
{
  if (base_key.empty()) {
    return SFrameError(SFrameErrorType::invalid_parameter_error,
                       "No base key set");
  }

  ratchet_count += 1;
  current_key_id = new_key_id;

  // Ratchet every SSRC
  for (auto& maybe_pair : ssrc_records) {
#ifdef NO_ALLOC
    if (!maybe_pair) {
      continue;
    }
    auto& [ssrc, record] = maybe_pair.value();
#else
    auto& [ssrc, record] = maybe_pair;
#endif

    SFRAME_VALUE_OR_RETURN(new_ssrc_key,
                           ratchet_key(suite, record.current_ssrc_key));
    SFRAME_VALUE_OR_RETURN(
      new_key_record,
      KeyRecord::from_base_key(suite, new_key_id, record.usage, new_ssrc_key));

    record.current_ssrc_key = new_ssrc_key;
    record.key_record = new_key_record;
  }

  return Result<void>::ok();
}

Result<output_bytes>
RTPContext::protect(SSRC ssrc,
                    output_bytes ciphertext,
                    input_bytes plaintext,
                    input_bytes metadata)
{
  if (!ssrc_records.contains(ssrc)) {
    return SFrameError(SFrameErrorType::invalid_parameter_error,
                       "Unknown SSRC");
  }

  auto& record = ssrc_records.at(ssrc);
  const auto counter = record.key_record.counter;
  record.key_record.counter += 1;

  const auto header = Header{ current_key_id, counter };
  const auto header_data = header.encoded();
  if (ciphertext.size() < header_data.size()) {
    return SFrameError(SFrameErrorType::buffer_too_small_error,
                       "Ciphertext too small for SFrame header");
  }

  std::copy(header_data.begin(), header_data.end(), ciphertext.begin());
  auto inner_ciphertext = ciphertext.subspan(header_data.size());

  SFRAME_VALUE_OR_RETURN(overhead, cipher_overhead(suite));
  if (inner_ciphertext.size() < plaintext.size() + overhead) {
    return SFrameError(SFrameErrorType::buffer_too_small_error,
                       "Ciphertext too small for cipher overhead");
  }

  SFRAME_VALUE_OR_RETURN(aad, form_aad(header, metadata));
  const auto nonce = form_nonce(counter, record.key_record.salt);
  SFRAME_VALUE_OR_RETURN(
    sealed,
    seal(
      suite, record.key_record.key, nonce, inner_ciphertext, aad, plaintext));
  return ciphertext.first(header_data.size() + sealed.size());
}

Result<output_bytes>
RTPContext::unprotect(SSRC ssrc,
                      output_bytes plaintext,
                      input_bytes ciphertext,
                      input_bytes metadata)
{
  SFRAME_VALUE_OR_RETURN(header, Header::parse(ciphertext));

  if (!ssrc_records.contains(ssrc)) {
    return SFrameError(SFrameErrorType::invalid_parameter_error,
                       "Unknown SSRC");
  }

  // Auto-ratchet if needed
  if (header.key_id != current_key_id) {
    if (header.key_id <= current_key_id) {
      return SFrameError(SFrameErrorType::invalid_parameter_error,
                         "Unknown key ID");
    }

    static constexpr uint64_t max_ratchet_steps = 256;
    const auto steps = header.key_id - current_key_id;
    if (steps > max_ratchet_steps) {
      return SFrameError(SFrameErrorType::invalid_parameter_error,
                         "Ratchet step count exceeds limit");
    }

    for (uint64_t i = 0; i < steps; i++) {
      SFRAME_VOID_OR_RETURN(ratchet(current_key_id + 1));
    }
  }

  auto& record = ssrc_records.at(ssrc);
  const auto inner_ciphertext = ciphertext.subspan(header.size());

  SFRAME_VALUE_OR_RETURN(overhead, cipher_overhead(suite));
  if (inner_ciphertext.size() < overhead) {
    return SFrameError(SFrameErrorType::buffer_too_small_error,
                       "Ciphertext too small for cipher overhead");
  }
  if (plaintext.size() < inner_ciphertext.size() - overhead) {
    return SFrameError(SFrameErrorType::buffer_too_small_error,
                       "Plaintext too small for decrypted value");
  }

  SFRAME_VALUE_OR_RETURN(aad, form_aad(header, metadata));
  const auto nonce = form_nonce(header.counter, record.key_record.salt);
  return open(
    suite, record.key_record.key, nonce, plaintext, aad, inner_ciphertext);
}

void
RTPContext::remove_ssrc(SSRC ssrc)
{
  ssrc_records.erase(ssrc);
}

///
/// MLSContext
///

MLSContext::MLSContext(CipherSuite suite_in, size_t epoch_bits_in)
  : Context(suite_in)
  , epoch_bits(epoch_bits_in)
  , epoch_mask((size_t(1) << epoch_bits_in) - 1)
{
  epoch_cache.resize(1 << epoch_bits_in);
}

Result<void>
MLSContext::add_epoch(EpochID epoch_id, input_bytes sframe_epoch_secret)
{
  return add_epoch(epoch_id, sframe_epoch_secret, 0);
}

Result<void>
MLSContext::add_epoch(EpochID epoch_id,
                      input_bytes sframe_epoch_secret,
                      size_t sender_bits)
{
  auto epoch_index = epoch_id & epoch_mask;
  auto& epoch = epoch_cache[epoch_index];

  if (epoch) {
    purge_epoch(epoch->full_epoch);
  }

  SFRAME_VALUE_OR_RETURN(
    new_epoch,
    EpochKeys::create(epoch_id, sframe_epoch_secret, epoch_bits, sender_bits));
  epoch.emplace(std::move(new_epoch));
  return Result<void>::ok();
}

void
MLSContext::purge_before(EpochID keeper)
{
  for (auto& ptr : epoch_cache) {
    if (ptr && ptr->full_epoch < keeper) {
      purge_epoch(ptr->full_epoch);
      ptr.reset();
    }
  }
}

Result<output_bytes>
MLSContext::protect(EpochID epoch_id,
                    SenderID sender_id,
                    output_bytes ciphertext,
                    input_bytes plaintext,
                    input_bytes metadata)
{
  return protect(epoch_id, sender_id, 0, ciphertext, plaintext, metadata);
}

Result<output_bytes>
MLSContext::protect(EpochID epoch_id,
                    SenderID sender_id,
                    ContextID context_id,
                    output_bytes ciphertext,
                    input_bytes plaintext,
                    input_bytes metadata)
{
  SFRAME_VALUE_OR_RETURN(key_id, form_key_id(epoch_id, sender_id, context_id));
  SFRAME_VOID_OR_RETURN(ensure_key(key_id, KeyUsage::protect));
  return Context::protect(key_id, ciphertext, plaintext, metadata);
}

Result<output_bytes>
MLSContext::unprotect(output_bytes plaintext,
                      input_bytes ciphertext,
                      input_bytes metadata)
{
  SFRAME_VALUE_OR_RETURN(header, Header::parse(ciphertext));
  const auto inner_ciphertext = ciphertext.subspan(header.size());

  SFRAME_VOID_OR_RETURN(ensure_key(header.key_id, KeyUsage::unprotect));
  return Context::unprotect_inner(
    header, plaintext, inner_ciphertext, metadata);
}

Result<MLSContext::EpochKeys>
MLSContext::EpochKeys::create(MLSContext::EpochID full_epoch_in,
                              input_bytes sframe_epoch_secret_in,
                              size_t epoch_bits,
                              size_t sender_bits_in)
{
  static constexpr uint64_t one = 1;
  static constexpr size_t key_id_bits = 64;

  EpochKeys epoch_keys;
  epoch_keys.full_epoch = full_epoch_in;
  epoch_keys.sframe_epoch_secret = sframe_epoch_secret_in;
  epoch_keys.sender_bits = sender_bits_in;

  if (epoch_keys.sender_bits > key_id_bits - epoch_bits) {
    return SFrameError(SFrameErrorType::invalid_parameter_error,
                       "Sender ID field too large");
  }

  // XXX(RLB) We use 0 as a signifier that the sender takes the rest of the key
  // ID, and context IDs are not allowed.  This would be more explicit if we
  // used std::optional, but would require more modern C++.
  if (epoch_keys.sender_bits == 0) {
    epoch_keys.sender_bits = key_id_bits - epoch_bits;
  }

  epoch_keys.context_bits = key_id_bits - epoch_keys.sender_bits - epoch_bits;
  epoch_keys.max_sender_id = (one << epoch_keys.sender_bits) - 1;
  epoch_keys.max_context_id = (one << epoch_keys.context_bits) - 1;

  return epoch_keys;
}

Result<owned_bytes<MLSContext::EpochKeys::max_secret_size>>
MLSContext::EpochKeys::base_key(CipherSuite ciphersuite,
                                SenderID sender_id) const
{
  SFRAME_VALUE_OR_RETURN(hash_size, cipher_digest_size(ciphersuite));
  auto enc_sender_id = owned_bytes<8>();
  encode_uint(sender_id, enc_sender_id);

  return hkdf_expand(
    ciphersuite, sframe_epoch_secret, enc_sender_id, hash_size);
}

void
MLSContext::remove_epoch(EpochID epoch_id)
{
  purge_epoch(epoch_id);

  const auto idx = epoch_id & epoch_mask;
  if (idx < epoch_cache.size()) {
    epoch_cache[idx].reset();
  }
}

void
MLSContext::purge_epoch(EpochID epoch_id)
{
  const auto drop_bits = epoch_id & epoch_bits;

  keys.erase_if_key(
    [&](const auto& epoch) { return (epoch & epoch_bits) == drop_bits; });
}

Result<KeyID>
MLSContext::form_key_id(EpochID epoch_id,
                        SenderID sender_id,
                        ContextID context_id) const
{
  auto epoch_index = epoch_id & epoch_mask;
  auto& epoch = epoch_cache[epoch_index];
  if (!epoch) {
    return SFrameError(SFrameErrorType::invalid_parameter_error,
                       "Unknown epoch");
  }

  if (sender_id > epoch->max_sender_id) {
    return SFrameError(SFrameErrorType::invalid_parameter_error,
                       "Sender ID overflow");
  }

  if (context_id > epoch->max_context_id) {
    return SFrameError(SFrameErrorType::invalid_parameter_error,
                       "Context ID overflow");
  }

  auto sender_part = uint64_t(sender_id) << epoch_bits;
  auto context_part = uint64_t(0);
  if (epoch->context_bits > 0) {
    context_part = uint64_t(context_id) << (epoch_bits + epoch->sender_bits);
  }

  return KeyID(context_part | sender_part | epoch_index);
}

Result<void>
MLSContext::ensure_key(KeyID key_id, KeyUsage usage)
{
  // If the required key already exists, we are done
  const auto epoch_index = key_id & epoch_mask;
  auto& epoch = epoch_cache[epoch_index];
  if (!epoch) {
    return SFrameError(SFrameErrorType::invalid_parameter_error,
                       "Unknown epoch");
  }

  if (keys.contains(key_id)) {
    return Result<void>::ok();
  }

  // Otherwise, derive a key and implant it
  const auto sender_id = key_id >> epoch_bits;
  SFRAME_VALUE_OR_RETURN(base, epoch->base_key(suite, sender_id));
  return Context::add_key(key_id, usage, base);
}

} // namespace SFRAME_NAMESPACE
