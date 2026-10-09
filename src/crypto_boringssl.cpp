#if defined(BORINGSSL)

#include "crypto.h"
#include "header.h"

#include <sframe/result.h>

#include <algorithm>
#include <cstring>
#include <memory>
#include <utility>

#include <openssl/aead.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/hmac.h>
#include <openssl/mem.h>

namespace SFRAME_NAMESPACE {

///
/// Convert between native identifiers / errors and OpenSSL ones
///

#ifdef __cpp_exceptions
crypto_error::crypto_error()
  : std::runtime_error(ERR_error_string(ERR_get_error(), nullptr))
{}
#endif

static Result<const EVP_MD*>
openssl_digest_type(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::AES_128_CTR_HMAC_SHA256_80:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_64:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_32:
    case CipherSuite::AES_GCM_128_SHA256:
      return EVP_sha256();

    case CipherSuite::AES_GCM_256_SHA512:
    case CipherSuite::AES_256_CTR_HMAC_SHA512_80:
    case CipherSuite::AES_256_CTR_HMAC_SHA512_64:
    case CipherSuite::AES_256_CTR_HMAC_SHA512_32:
      return EVP_sha512();

    default:
      return SFrameErrorType::unsupported_ciphersuite_error;
  }
}

///
/// HKDF
///

Result<owned_bytes<max_hkdf_extract_size>>
hkdf_extract(CipherSuite suite, input_bytes salt, input_bytes ikm)
{
  clear_openssl_errors();
  SFRAME_VALUE_OR_RETURN(md, openssl_digest_type(suite));
  auto out = owned_bytes<max_hkdf_extract_size>(EVP_MD_size(md));
  auto out_len = size_t(out.size());
  if (1 != HKDF_extract(out.data(),
                        &out_len,
                        md,
                        ikm.data(),
                        ikm.size(),
                        salt.data(),
                        salt.size())) {
    return SFrameErrorType::crypto_error;
  }

  return out;
}

Result<owned_bytes<max_hkdf_expand_size>>
hkdf_expand(CipherSuite suite, input_bytes prk, input_bytes info, size_t size)
{
  clear_openssl_errors();
  SFRAME_VALUE_OR_RETURN(md, openssl_digest_type(suite));
  auto out = owned_bytes<max_hkdf_expand_size>(size);
  if (1 != HKDF_expand(out.data(),
                       out.size(),
                       md,
                       prk.data(),
                       prk.size(),
                       info.data(),
                       info.size())) {
    return SFrameErrorType::crypto_error;
  }

  return out;
}

///
/// Prepared keys
///
/// Key-dependent state (AES key schedule, AEAD context, HMAC with the ipad /
/// opad blocks already absorbed) is computed once per key instead of once per
/// frame.  All of it is read-only after construction, so a single CryptoKey can
/// be shared between threads.
///

struct CryptoKey
{
  CryptoKey()
  {
    EVP_AEAD_CTX_zero(&aead);
    HMAC_CTX_init(&hmac);
  }

  ~CryptoKey()
  {
    EVP_AEAD_CTX_cleanup(&aead);
    HMAC_CTX_cleanup(&hmac);
  }

  CryptoKey(const CryptoKey&) = delete;
  CryptoKey& operator=(const CryptoKey&) = delete;

  EVP_AEAD_CTX aead; // GCM suites
  AES_KEY aes;       // CTR suites
  HMAC_CTX hmac;     // CTR suites
};

static bool
is_ctr_suite(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::AES_128_CTR_HMAC_SHA256_80:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_64:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_32:
    case CipherSuite::AES_256_CTR_HMAC_SHA512_80:
    case CipherSuite::AES_256_CTR_HMAC_SHA512_64:
    case CipherSuite::AES_256_CTR_HMAC_SHA512_32:
      return true;

    default:
      return false;
  }
}

static Result<std::shared_ptr<CryptoKey>>
build_key(CipherSuite suite, input_bytes key)
{
  clear_openssl_errors();
  auto prepared = std::make_shared<CryptoKey>();

  if (is_ctr_suite(suite)) {
    SFRAME_VALUE_OR_RETURN(md, openssl_digest_type(suite));
    SFRAME_VALUE_OR_RETURN(enc_key_size, cipher_enc_key_size(suite));
    if (key.size() < enc_key_size) {
      return SFrameError(SFrameErrorType::invalid_parameter_error,
                         "Key too short");
    }

    const auto enc_key = key.first(enc_key_size);
    const auto auth_key = key.subspan(enc_key_size);
    if (0 != AES_set_encrypt_key(
               enc_key.data(), unsigned(enc_key_size * 8), &prepared->aes)) {
      return SFrameErrorType::crypto_error;
    }

    // Guard against sending nullptr to HMAC_Init_ex
    const auto* auth_data = auth_key.data();
    SFRAME_VALUE_OR_RETURN(auth_size, checked_int(auth_key.size()));
    const auto non_null_zero_length_key = uint8_t(0);
    if (auth_data == nullptr) {
      auth_data = &non_null_zero_length_key;
    }

    if (1 != HMAC_Init_ex(&prepared->hmac, auth_data, auth_size, md, nullptr)) {
      return SFrameErrorType::crypto_error;
    }

    return prepared;
  }

  const EVP_AEAD* aead = nullptr;
  switch (suite) {
    case CipherSuite::AES_GCM_128_SHA256:
      aead = EVP_aead_aes_128_gcm();
      break;

    case CipherSuite::AES_GCM_256_SHA512:
      aead = EVP_aead_aes_256_gcm();
      break;

    default:
      return SFrameErrorType::unsupported_ciphersuite_error;
  }

  SFRAME_VALUE_OR_RETURN(tag_size, cipher_overhead(suite));
  if (1 !=
      EVP_AEAD_CTX_init(
        &prepared->aead, aead, key.data(), key.size(), tag_size, nullptr)) {
    return SFrameErrorType::crypto_error;
  }

  return prepared;
}

Result<std::shared_ptr<const CryptoKey>>
prepare_key(CipherSuite suite, input_bytes key)
{
  SFRAME_VALUE_OR_RETURN(prepared, build_key(suite, key));
  return std::shared_ptr<const CryptoKey>(std::move(prepared));
}

///
/// AEAD Algorithms
///

// HMAC_CTX on the stack, copied from the prepared (already keyed) context
class ScopedHmacCtx
{
public:
  ScopedHmacCtx() { HMAC_CTX_init(&ctx); }
  ~ScopedHmacCtx() { HMAC_CTX_cleanup(&ctx); }
  ScopedHmacCtx(const ScopedHmacCtx&) = delete;
  ScopedHmacCtx& operator=(const ScopedHmacCtx&) = delete;

  HMAC_CTX ctx;
};

static Result<owned_bytes<64>>
compute_tag(const CryptoKey& key,
            input_bytes nonce,
            input_bytes aad,
            input_bytes ct,
            size_t tag_size)
{
  ScopedHmacCtx scoped;
  auto* ctx = &scoped.ctx;
  if (1 != HMAC_CTX_copy_ex(ctx, &key.hmac)) {
    return SFrameErrorType::crypto_error;
  }

  auto len_block = owned_bytes<24>();
  auto len_view = output_bytes(len_block);
  encode_uint(aad.size(), len_view.first(8));
  encode_uint(ct.size(), len_view.first(16).last(8));
  encode_uint(tag_size, len_view.last(8));
  if (1 != HMAC_Update(ctx, len_block.data(), len_block.size())) {
    return SFrameErrorType::crypto_error;
  }

  if (1 != HMAC_Update(ctx, nonce.data(), nonce.size())) {
    return SFrameErrorType::crypto_error;
  }

  if (1 != HMAC_Update(ctx, aad.data(), aad.size())) {
    return SFrameErrorType::crypto_error;
  }

  if (1 != HMAC_Update(ctx, ct.data(), ct.size())) {
    return SFrameErrorType::crypto_error;
  }

  auto tag = owned_bytes<64>();
  auto size = static_cast<unsigned int>(0);
  if (1 != HMAC_Final(ctx, tag.data(), &size)) {
    return SFrameErrorType::crypto_error;
  }

  tag.resize(tag_size);
  return tag;
}

static Result<void>
ctr_crypt(const CryptoKey& key,
          input_bytes nonce,
          output_bytes out,
          input_bytes in)
{
  if (out.size() != in.size()) {
    return SFrameError(SFrameErrorType::buffer_too_small_error,
                       "CTR size mismatch");
  }

  if (nonce.size() > AES_BLOCK_SIZE) {
    return SFrameError(SFrameErrorType::invalid_parameter_error,
                       "Nonce too large");
  }

  // The nonce is left-aligned in the counter block, with a zero counter
  uint8_t ivec[AES_BLOCK_SIZE] = { 0 };
  uint8_t ecount[AES_BLOCK_SIZE] = { 0 };
  unsigned int num = 0;
  if (!nonce.empty()) {
    std::memcpy(ivec, nonce.data(), nonce.size());
  }

  AES_ctr128_encrypt(
    in.data(), out.data(), in.size(), &key.aes, ivec, ecount, &num);
  return Result<void>::ok();
}

static Result<output_bytes>
seal_ctr(CipherSuite suite,
         const CryptoKey& key,
         input_bytes nonce,
         output_bytes ct,
         input_bytes aad,
         input_bytes pt)
{
  SFRAME_VALUE_OR_RETURN(tag_size, cipher_overhead(suite));
  SFRAME_VOID_OR_RETURN(validate_ctr_size(pt.size()));
  if (ct.size() < pt.size() + tag_size) {
    return SFrameError(SFrameErrorType::buffer_too_small_error,
                       "Ciphertext buffer too small");
  }

  // Encrypt with AES-CM
  auto inner_ct = ct.subspan(0, pt.size());
  SFRAME_VOID_OR_RETURN(ctr_crypt(key, nonce, inner_ct, pt));

  // Authenticate with truncated HMAC
  SFRAME_VALUE_OR_RETURN(mac, compute_tag(key, nonce, aad, inner_ct, tag_size));
  auto tag = ct.subspan(pt.size(), tag_size);
  std::copy(mac.begin(), mac.begin() + tag_size, tag.begin());

  return ct.subspan(0, pt.size() + tag_size);
}

static Result<output_bytes>
seal_aead(CipherSuite suite,
          const CryptoKey& key,
          input_bytes nonce,
          output_bytes ct,
          input_bytes aad,
          input_bytes pt)
{
  SFRAME_VALUE_OR_RETURN(tag_size, cipher_overhead(suite));
  if (ct.size() < pt.size() + tag_size) {
    return SFrameError(SFrameErrorType::buffer_too_small_error,
                       "Ciphertext buffer too small");
  }

  auto tag = ct.subspan(pt.size(), tag_size);
  size_t tag_len = 0;
  if (1 != EVP_AEAD_CTX_seal_scatter(&key.aead,
                                     ct.data(),
                                     tag.data(),
                                     &tag_len,
                                     tag.size(),
                                     nonce.data(),
                                     nonce.size(),
                                     pt.data(),
                                     pt.size(),
                                     nullptr,
                                     0,
                                     aad.data(),
                                     aad.size()) ||
      tag_len != tag_size) {
    return SFrameErrorType::crypto_error;
  }

  return ct.subspan(0, pt.size() + tag_size);
}

static Result<output_bytes>
seal_with(CipherSuite suite,
          const CryptoKey& key,
          input_bytes nonce,
          output_bytes ct,
          input_bytes aad,
          input_bytes pt)
{
  clear_openssl_errors();
  if (is_ctr_suite(suite)) {
    return seal_ctr(suite, key, nonce, ct, aad, pt);
  }

  return seal_aead(suite, key, nonce, ct, aad, pt);
}

Result<output_bytes>
seal(CipherSuite suite,
     const std::shared_ptr<const CryptoKey>& prepared,
     input_bytes key,
     input_bytes nonce,
     output_bytes ct,
     input_bytes aad,
     input_bytes pt)
{
  if (prepared) {
    return seal_with(suite, *prepared, nonce, ct, aad, pt);
  }

  return seal(suite, key, nonce, ct, aad, pt);
}

Result<output_bytes>
seal(CipherSuite suite,
     input_bytes key,
     input_bytes nonce,
     output_bytes ct,
     input_bytes aad,
     input_bytes pt)
{
  SFRAME_VALUE_OR_RETURN(prepared, build_key(suite, key));
  return seal_with(suite, *prepared, nonce, ct, aad, pt);
}

static Result<output_bytes>
open_ctr(CipherSuite suite,
         const CryptoKey& key,
         input_bytes nonce,
         output_bytes pt,
         input_bytes aad,
         input_bytes ct)
{
  SFRAME_VALUE_OR_RETURN(tag_size, cipher_overhead(suite));
  if (ct.size() < tag_size) {
    return SFrameError(SFrameErrorType::buffer_too_small_error,
                       "Ciphertext buffer too small");
  }

  auto inner_ct_size = ct.size() - tag_size;
  SFRAME_VOID_OR_RETURN(validate_ctr_size(inner_ct_size));
  auto inner_ct = ct.subspan(0, inner_ct_size);
  auto tag = ct.subspan(inner_ct_size, tag_size);

  // Authenticate with truncated HMAC
  SFRAME_VALUE_OR_RETURN(mac, compute_tag(key, nonce, aad, inner_ct, tag_size));
  if (CRYPTO_memcmp(mac.data(), tag.data(), tag.size()) != 0) {
    return SFrameErrorType::authentication_error;
  }

  // Decrypt with AES-CTR
  if (pt.size() < inner_ct_size) {
    return SFrameError(SFrameErrorType::buffer_too_small_error,
                       "Plaintext buffer too small");
  }

  const auto pt_out = pt.first(inner_ct_size);
  SFRAME_VOID_OR_RETURN(ctr_crypt(key, nonce, pt_out, inner_ct));

  return pt_out;
}

static Result<output_bytes>
open_aead(CipherSuite suite,
          const CryptoKey& key,
          input_bytes nonce,
          output_bytes pt,
          input_bytes aad,
          input_bytes ct)
{
  SFRAME_VALUE_OR_RETURN(tag_size, cipher_overhead(suite));
  if (ct.size() < tag_size) {
    return SFrameError(SFrameErrorType::buffer_too_small_error,
                       "Ciphertext buffer too small");
  }

  auto inner_ct_size = ct.size() - tag_size;
  if (pt.size() < inner_ct_size) {
    return SFrameError(SFrameErrorType::buffer_too_small_error,
                       "Plaintext buffer too small");
  }

  auto tag = ct.subspan(inner_ct_size, tag_size);
  if (1 != EVP_AEAD_CTX_open_gather(&key.aead,
                                    pt.data(),
                                    nonce.data(),
                                    nonce.size(),
                                    ct.data(),
                                    inner_ct_size,
                                    tag.data(),
                                    tag.size(),
                                    aad.data(),
                                    aad.size())) {
    return SFrameErrorType::authentication_error;
  }

  return pt.subspan(0, inner_ct_size);
}

static Result<output_bytes>
open_with(CipherSuite suite,
          const CryptoKey& key,
          input_bytes nonce,
          output_bytes pt,
          input_bytes aad,
          input_bytes ct)
{
  clear_openssl_errors();
  if (is_ctr_suite(suite)) {
    return open_ctr(suite, key, nonce, pt, aad, ct);
  }

  return open_aead(suite, key, nonce, pt, aad, ct);
}

Result<output_bytes>
open(CipherSuite suite,
     const std::shared_ptr<const CryptoKey>& prepared,
     input_bytes key,
     input_bytes nonce,
     output_bytes pt,
     input_bytes aad,
     input_bytes ct)
{
  if (prepared) {
    return open_with(suite, *prepared, nonce, pt, aad, ct);
  }

  return open(suite, key, nonce, pt, aad, ct);
}

Result<output_bytes>
open(CipherSuite suite,
     input_bytes key,
     input_bytes nonce,
     output_bytes pt,
     input_bytes aad,
     input_bytes ct)
{
  SFRAME_VALUE_OR_RETURN(prepared, build_key(suite, key));
  return open_with(suite, *prepared, nonce, pt, aad, ct);
}

} // namespace SFRAME_NAMESPACE

#endif // defined(BORINGSSL)
