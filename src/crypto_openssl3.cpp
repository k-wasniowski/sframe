#if defined(OPENSSL_3)

#include "crypto.h"
#include "header.h"

#include <sframe/result.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <string>

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

namespace SFRAME_NAMESPACE {

///
/// Convert between native identifiers / errors and OpenSSL ones
///

#ifdef __cpp_exceptions
crypto_error::crypto_error()
  : std::runtime_error(ERR_error_string(ERR_get_error(), nullptr))
{}
#endif

static Result<const char*>
openssl_cipher_name(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::AES_128_CTR_HMAC_SHA256_80:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_64:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_32:
      return "AES-128-CTR";

    case CipherSuite::AES_256_CTR_HMAC_SHA512_80:
    case CipherSuite::AES_256_CTR_HMAC_SHA512_64:
    case CipherSuite::AES_256_CTR_HMAC_SHA512_32:
      return "AES-256-CTR";

    case CipherSuite::AES_GCM_128_SHA256:
      return "AES-128-GCM";

    case CipherSuite::AES_GCM_256_SHA512:
      return "AES-256-GCM";

    default:
      return SFrameErrorType::unsupported_ciphersuite_error;
  }
}

static Result<std::string>
openssl_digest_name(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::AES_128_CTR_HMAC_SHA256_80:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_64:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_32:
    case CipherSuite::AES_GCM_128_SHA256:
      return std::string(OSSL_DIGEST_NAME_SHA2_256);

    case CipherSuite::AES_GCM_256_SHA512:
    case CipherSuite::AES_256_CTR_HMAC_SHA512_80:
    case CipherSuite::AES_256_CTR_HMAC_SHA512_64:
    case CipherSuite::AES_256_CTR_HMAC_SHA512_32:
      return std::string(OSSL_DIGEST_NAME_SHA2_512);

    default:
      return SFrameErrorType::unsupported_ciphersuite_error;
  }
}

///
/// HKDF
///

using scoped_evp_kdf = std::unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)>;
using scoped_evp_kdf_ctx =
  std::unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)>;

Result<owned_bytes<max_hkdf_extract_size>>
hkdf_extract(CipherSuite suite, input_bytes salt, input_bytes ikm)
{
  clear_openssl_errors();
  auto mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
  SFRAME_VALUE_OR_RETURN(digest_name, openssl_digest_name(suite));
  auto* salt_ptr =
    const_cast<void*>(reinterpret_cast<const void*>(salt.data()));
  auto* ikm_ptr = const_cast<void*>(reinterpret_cast<const void*>(ikm.data()));

  const auto params = std::array<OSSL_PARAM, 5>{
    OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
    OSSL_PARAM_construct_utf8_string(
      OSSL_KDF_PARAM_DIGEST, digest_name.data(), digest_name.size()),
    OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, ikm_ptr, ikm.size()),
    OSSL_PARAM_construct_octet_string(
      OSSL_KDF_PARAM_SALT, salt_ptr, salt.size()),
    OSSL_PARAM_construct_end(),
  };

  const auto kdf =
    scoped_evp_kdf(EVP_KDF_fetch(NULL, "HKDF", NULL), EVP_KDF_free);
  const auto ctx =
    scoped_evp_kdf_ctx(EVP_KDF_CTX_new(kdf.get()), EVP_KDF_CTX_free);
  if (1 != EVP_KDF_CTX_set_params(ctx.get(), params.data())) {
    return SFrameErrorType::crypto_error;
  }

  const auto digest_size = EVP_KDF_CTX_get_kdf_size(ctx.get());
  auto out = owned_bytes<max_hkdf_extract_size>(digest_size);
  if (1 != EVP_KDF_derive(ctx.get(), out.data(), out.size(), nullptr)) {
    return SFrameErrorType::crypto_error;
  }

  return out;
}

Result<owned_bytes<max_hkdf_expand_size>>
hkdf_expand(CipherSuite suite, input_bytes prk, input_bytes info, size_t size)
{
  clear_openssl_errors();
  auto mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
  SFRAME_VALUE_OR_RETURN(digest_name, openssl_digest_name(suite));
  auto* prk_ptr = const_cast<void*>(reinterpret_cast<const void*>(prk.data()));
  auto* info_ptr =
    const_cast<void*>(reinterpret_cast<const void*>(info.data()));

  const auto params = std::array<OSSL_PARAM, 5>{
    OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
    OSSL_PARAM_construct_utf8_string(
      OSSL_KDF_PARAM_DIGEST, digest_name.data(), digest_name.size()),
    OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, prk_ptr, prk.size()),
    OSSL_PARAM_construct_octet_string(
      OSSL_KDF_PARAM_INFO, info_ptr, info.size()),
    OSSL_PARAM_construct_end(),
  };

  const auto kdf =
    scoped_evp_kdf(EVP_KDF_fetch(NULL, "HKDF", NULL), EVP_KDF_free);
  const auto ctx =
    scoped_evp_kdf_ctx(EVP_KDF_CTX_new(kdf.get()), EVP_KDF_CTX_free);

  auto out = owned_bytes<max_hkdf_expand_size>(size);
  if (1 != EVP_KDF_derive(ctx.get(), out.data(), out.size(), params.data())) {
    return SFrameErrorType::crypto_error;
  }

  return out;
}

///
/// Prepared keys
///
/// Algorithms are fetched once (instead of on every call), and keyed template
/// contexts are built once per key.  Per frame we only duplicate a template,
/// which skips the algorithm fetch, the AES key schedule and the HMAC key
/// setup.  The templates are never modified after construction, so a CryptoKey
/// can be shared between threads.
///

using scoped_evp_cipher =
  std::unique_ptr<EVP_CIPHER, decltype(&EVP_CIPHER_free)>;
using scoped_evp_cipher_ctx =
  std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
using scoped_evp_mac = std::unique_ptr<EVP_MAC, decltype(&EVP_MAC_free)>;
using scoped_evp_mac_ctx =
  std::unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)>;

struct CryptoKey
{
  CryptoKey()
    : cipher(nullptr, EVP_CIPHER_free)
    , enc(nullptr, EVP_CIPHER_CTX_free)
    , dec(nullptr, EVP_CIPHER_CTX_free)
    , mac(nullptr, EVP_MAC_free)
    , hmac(nullptr, EVP_MAC_CTX_free)
  {}

  scoped_evp_cipher cipher;
  scoped_evp_cipher_ctx enc; // keyed, no IV; used for CTR and GCM seal
  scoped_evp_cipher_ctx dec; // keyed, no IV; GCM open only
  scoped_evp_mac mac;
  scoped_evp_mac_ctx hmac; // keyed; CTR suites only
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
  SFRAME_VALUE_OR_RETURN(cipher_name, openssl_cipher_name(suite));

  auto prepared = std::make_shared<CryptoKey>();
  prepared->cipher.reset(EVP_CIPHER_fetch(nullptr, cipher_name, nullptr));
  if (!prepared->cipher) {
    return SFrameErrorType::crypto_error;
  }

  const auto is_ctr = is_ctr_suite(suite);
  auto enc_key = key;
  auto auth_key = key.first(0);
  if (is_ctr) {
    SFRAME_VALUE_OR_RETURN(enc_key_size, cipher_enc_key_size(suite));
    if (key.size() < enc_key_size) {
      return SFrameError(SFrameErrorType::invalid_parameter_error,
                         "Key too short");
    }

    enc_key = key.first(enc_key_size);
    auth_key = key.subspan(enc_key_size);
  }

  const auto aes_key_size = EVP_CIPHER_get_key_length(prepared->cipher.get());
  if (aes_key_size < 0 || enc_key.size() != static_cast<size_t>(aes_key_size)) {
    return SFrameError(SFrameErrorType::invalid_parameter_error,
                       "Invalid key size");
  }

  prepared->enc.reset(EVP_CIPHER_CTX_new());
  if (!prepared->enc || 1 != EVP_EncryptInit_ex(prepared->enc.get(),
                                                prepared->cipher.get(),
                                                nullptr,
                                                enc_key.data(),
                                                nullptr)) {
    return SFrameErrorType::crypto_error;
  }

  if (!is_ctr) {
    prepared->dec.reset(EVP_CIPHER_CTX_new());
    if (!prepared->dec || 1 != EVP_DecryptInit_ex(prepared->dec.get(),
                                                  prepared->cipher.get(),
                                                  nullptr,
                                                  enc_key.data(),
                                                  nullptr)) {
      return SFrameErrorType::crypto_error;
    }

    return prepared;
  }

  SFRAME_VALUE_OR_RETURN(digest_name, openssl_digest_name(suite));
  std::array<OSSL_PARAM, 2> params = {
    OSSL_PARAM_construct_utf8_string(
      OSSL_ALG_PARAM_DIGEST, digest_name.data(), 0),
    OSSL_PARAM_construct_end()
  };

  prepared->mac.reset(EVP_MAC_fetch(nullptr, OSSL_MAC_NAME_HMAC, nullptr));
  if (!prepared->mac) {
    return SFrameErrorType::crypto_error;
  }

  prepared->hmac.reset(EVP_MAC_CTX_new(prepared->mac.get()));
  if (!prepared->hmac || 1 != EVP_MAC_init(prepared->hmac.get(),
                                           auth_key.data(),
                                           auth_key.size(),
                                           params.data())) {
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

static Result<owned_bytes<64>>
compute_tag(const CryptoKey& key,
            input_bytes nonce,
            input_bytes aad,
            input_bytes ct,
            size_t tag_size)
{
  auto len_block = owned_bytes<24>();
  auto len_view = output_bytes(len_block);
  encode_uint(aad.size(), len_view.first(8));
  encode_uint(ct.size(), len_view.first(16).last(8));
  encode_uint(tag_size, len_view.last(8));

  const auto ctx =
    scoped_evp_mac_ctx(EVP_MAC_CTX_dup(key.hmac.get()), EVP_MAC_CTX_free);
  if (!ctx) {
    return SFrameErrorType::crypto_error;
  }

  if (1 != EVP_MAC_update(ctx.get(), len_block.data(), len_block.size())) {
    return SFrameErrorType::crypto_error;
  }

  if (1 != EVP_MAC_update(ctx.get(), nonce.data(), nonce.size())) {
    return SFrameErrorType::crypto_error;
  }

  if (1 != EVP_MAC_update(ctx.get(), aad.data(), aad.size())) {
    return SFrameErrorType::crypto_error;
  }

  if (1 != EVP_MAC_update(ctx.get(), ct.data(), ct.size())) {
    return SFrameErrorType::crypto_error;
  }

  size_t size = 0;
  auto tag = owned_bytes<64>();
  if (1 != EVP_MAC_final(ctx.get(), tag.data(), &size, tag.size())) {
    return SFrameErrorType::crypto_error;
  }

  tag.resize(tag_size);
  return tag;
}

// Duplicate a keyed template and set the IV on the copy
static Result<scoped_evp_cipher_ctx>
cipher_ctx_with_iv(const EVP_CIPHER_CTX* tmpl, bool encrypt, const uint8_t* iv)
{
  auto ctx = scoped_evp_cipher_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (!ctx || 1 != EVP_CIPHER_CTX_copy(ctx.get(), tmpl)) {
    return SFrameErrorType::crypto_error;
  }

  const auto ok =
    encrypt ? EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, nullptr, iv)
            : EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, nullptr, iv);
  if (1 != ok) {
    return SFrameErrorType::crypto_error;
  }

  return ctx;
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

  auto padded_nonce = owned_bytes<16>(0);
  padded_nonce.append(nonce);
  padded_nonce.resize(16);

  SFRAME_VALUE_OR_RETURN(
    ctx, cipher_ctx_with_iv(key.enc.get(), true, padded_nonce.data()));

  int outlen = 0;
  SFRAME_VALUE_OR_RETURN(in_size_int, checked_int(in.size()));
  if (1 != EVP_EncryptUpdate(
             ctx.get(), out.data(), &outlen, in.data(), in_size_int)) {
    return SFrameErrorType::crypto_error;
  }

  // CTR is a streaming mode, so finalization does not emit more bytes and a
  // null output pointer is fine here.
  if (1 != EVP_EncryptFinal(ctx.get(), nullptr, &outlen)) {
    return SFrameErrorType::crypto_error;
  }

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

  SFRAME_VALUE_OR_RETURN(ctx,
                         cipher_ctx_with_iv(key.enc.get(), true, nonce.data()));

  int outlen = 0;
  SFRAME_VALUE_OR_RETURN(aad_size_int, checked_int(aad.size()));
  if (aad.size() > 0) {
    if (1 != EVP_EncryptUpdate(
               ctx.get(), nullptr, &outlen, aad.data(), aad_size_int)) {
      return SFrameErrorType::crypto_error;
    }
  }

  SFRAME_VALUE_OR_RETURN(pt_size_int, checked_int(pt.size()));
  if (1 != EVP_EncryptUpdate(
             ctx.get(), ct.data(), &outlen, pt.data(), pt_size_int)) {
    return SFrameErrorType::crypto_error;
  }

  // Providing nullptr as an argument is safe here because this
  // function never writes with GCM; it only computes the tag
  if (1 != EVP_EncryptFinal(ctx.get(), nullptr, &outlen)) {
    return SFrameErrorType::crypto_error;
  }

  auto tag = ct.subspan(pt.size(), tag_size);
  auto tag_ptr = const_cast<void*>(static_cast<const void*>(tag.data()));
  SFRAME_VALUE_OR_RETURN(tag_size_downcast, checked_int(tag.size()));
  if (1 != EVP_CIPHER_CTX_ctrl(
             ctx.get(), EVP_CTRL_GCM_GET_TAG, tag_size_downcast, tag_ptr)) {
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

  SFRAME_VALUE_OR_RETURN(
    ctx, cipher_ctx_with_iv(key.dec.get(), false, nonce.data()));

  auto tag = ct.subspan(inner_ct_size, tag_size);
  auto tag_ptr = const_cast<void*>(static_cast<const void*>(tag.data()));
  SFRAME_VALUE_OR_RETURN(tag_size_downcast, checked_int(tag.size()));
  if (1 != EVP_CIPHER_CTX_ctrl(
             ctx.get(), EVP_CTRL_GCM_SET_TAG, tag_size_downcast, tag_ptr)) {
    return SFrameErrorType::crypto_error;
  }

  int out_size;
  SFRAME_VALUE_OR_RETURN(aad_size_int, checked_int(aad.size()));
  if (aad.size() > 0) {
    if (1 != EVP_DecryptUpdate(
               ctx.get(), nullptr, &out_size, aad.data(), aad_size_int)) {
      return SFrameErrorType::crypto_error;
    }
  }

  SFRAME_VALUE_OR_RETURN(inner_ct_size_int, checked_int(inner_ct_size));
  if (1 != EVP_DecryptUpdate(
             ctx.get(), pt.data(), &out_size, ct.data(), inner_ct_size_int)) {
    return SFrameErrorType::crypto_error;
  }

  // Providing nullptr as an argument is safe here because this
  // function never writes with GCM; it only verifies the tag
  if (1 != EVP_DecryptFinal(ctx.get(), nullptr, &out_size)) {
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

#endif // defined(OPENSSL_3)
