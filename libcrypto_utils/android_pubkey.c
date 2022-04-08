/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <crypto_utils/android_pubkey.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>

// Better safe than sorry.
#if (ANDROID_PUBKEY_MODULUS_SIZE % 4) != 0
#error RSA modulus size must be multiple of the word size!
#endif

// Size of the RSA modulus in words.
#define ANDROID_PUBKEY_MODULUS_SIZE_WORDS (ANDROID_PUBKEY_MODULUS_SIZE / 4)

// This file implements encoding and decoding logic for Android's custom RSA
// public key binary format. Public keys are stored as a sequence of
// little-endian 32 bit words. Note that Android only supports little-endian
// processors, so we don't do any byte order conversions when parsing the binary
// struct.
typedef struct RSAPublicKey {
    // Modulus length. This must be ANDROID_PUBKEY_MODULUS_SIZE.
    uint32_t modulus_size_words;

    // Precomputed montgomery parameter: -1 / n[0] mod 2^32
    uint32_t n0inv;

    // RSA modulus as a little-endian array.
    uint8_t modulus[ANDROID_PUBKEY_MODULUS_SIZE];

    // Montgomery parameter R^2 as a little-endian array of little-endian words.
    uint8_t rr[ANDROID_PUBKEY_MODULUS_SIZE];

    // RSA modulus: 3 or 65537
    uint32_t exponent;
} RSAPublicKey;

// Reverses byte order in |buffer|.
static void reverse_bytes(uint8_t* buffer, size_t size) {
  for (size_t i = 0; i < (size + 1) / 2; ++i) {
    uint8_t tmp = buffer[i];
    buffer[i] = buffer[size - i - 1];
    buffer[size - i - 1] = tmp;
  }
}

bool android_pubkey_decode(const uint8_t* key_buffer, size_t size, RSA** key) {
  const RSAPublicKey* key_struct = (RSAPublicKey*)key_buffer;
  bool ret = false;
  uint8_t modulus_buffer[ANDROID_PUBKEY_MODULUS_SIZE];
  RSA* new_key = RSA_new();
  if (!new_key) {
    goto cleanup;
  }

  // Check |size| is large enough and the modulus size is correct.
  if (size < sizeof(RSAPublicKey)) {
    goto cleanup;
  }
  if (key_struct->modulus_size_words != ANDROID_PUBKEY_MODULUS_SIZE_WORDS) {
    goto cleanup;
  }

  // Convert the modulus to big-endian byte order as expected by BN_bin2bn.
  memcpy(modulus_buffer, key_struct->modulus, sizeof(modulus_buffer));
  reverse_bytes(modulus_buffer, sizeof(modulus_buffer));
  new_key->n = BN_bin2bn(modulus_buffer, sizeof(modulus_buffer), NULL);
  if (!new_key->n) {
    goto cleanup;
  }

  // Read the exponent.
  new_key->e = BN_new();
  if (!new_key->e || !BN_set_word(new_key->e, key_struct->exponent)) {
    goto cleanup;
  }

  // Note that we don't extract the montgomery parameters n0inv and rr from
  // the RSAPublicKey structure. They assume a word size of 32 bits, but
  // BoringSSL may use a word size of 64 bits internally, so we're lacking the
  // top 32 bits of n0inv in general. For now, we just ignore the parameters
  // and have BoringSSL recompute them internally. More sophisticated logic can
  // be added here if/when we want the additional speedup from using the
  // pre-computed montgomery parameters.

  *key = new_key;
  ret = true;

cleanup:
  if (!ret && new_key) {
    RSA_free(new_key);
  }
  return ret;
}

static bool android_pubkey_encode_bignum(const BIGNUM* num, uint8_t* buffer) {
  if (!BN_bn2bin_padded(buffer, ANDROID_PUBKEY_MODULUS_SIZE, num)) {
    return false;
  }

  reverse_bytes(buffer, ANDROID_PUBKEY_MODULUS_SIZE);
  return true;
}

bool android_pubkey_encode(const RSA* key, uint8_t* key_buffer, size_t size) {
  RSAPublicKey* key_struct = (RSAPublicKey*)key_buffer;
  bool ret = false;
  BN_CTX* ctx = BN_CTX_new();
  BIGNUM* r32 = BN_new();
  BIGNUM* n0inv = BN_new();
  BIGNUM* rr = BN_new();

  if (sizeof(RSAPublicKey) > size ||
      RSA_size(key) != ANDROID_PUBKEY_MODULUS_SIZE) {
    goto cleanup;
  }

  // Store the modulus size.
  key_struct->modulus_size_words = ANDROID_PUBKEY_MODULUS_SIZE_WORDS;

  // Compute and store n0inv = -1 / N[0] mod 2^32.
  if (!ctx || !r32 || !n0inv || !BN_set_bit(r32, 32) ||
      !BN_mod(n0inv, key->n, r32, ctx) ||
      !BN_mod_inverse(n0inv, n0inv, r32, ctx) || !BN_sub(n0inv, r32, n0inv)) {
    goto cleanup;
  }
  key_struct->n0inv = (uint32_t)BN_get_word(n0inv);

  // Store the modulus.
  if (!android_pubkey_encode_bignum(key->n, key_struct->modulus)) {
    goto cleanup;
  }

  // Compute and store rr = (2^(rsa_size)) ^ 2 mod N.
  if (!ctx || !rr || !BN_set_bit(rr, ANDROID_PUBKEY_MODULUS_SIZE * 8) ||
      !BN_mod_sqr(rr, rr, key->n, ctx) ||
      !android_pubkey_encode_bignum(rr, key_struct->rr)) {
    goto cleanup;
  }

  // Store the exponent.
  key_struct->exponent = (uint32_t)BN_get_word(key->e);

  ret = true;

cleanup:
  BN_free(rr);
  BN_free(n0inv);
  BN_free(r32);
  BN_CTX_free(ctx);
  return ret;
}
