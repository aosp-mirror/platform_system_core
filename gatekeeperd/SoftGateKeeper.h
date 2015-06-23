/*
 * Copyright 2015 The Android Open Source Project
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
 *
 */

#ifndef SOFT_GATEKEEPER_H_
#define SOFT_GATEKEEPER_H_

extern "C" {
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <crypto_scrypt.h>
}

#include <UniquePtr.h>
#include <gatekeeper/gatekeeper.h>
#include <iostream>
#include <unordered_map>

namespace gatekeeper {

struct fast_hash_t {
    uint64_t salt;
    uint8_t digest[SHA256_DIGEST_LENGTH];
};

class SoftGateKeeper : public GateKeeper {
public:
    static const uint32_t SIGNATURE_LENGTH_BYTES = 32;

    // scrypt params
    static const uint64_t N = 16384;
    static const uint32_t r = 8;
    static const uint32_t p = 1;

    static const int MAX_UINT_32_CHARS = 11;

    SoftGateKeeper() {
        key_.reset(new uint8_t[SIGNATURE_LENGTH_BYTES]);
        memset(key_.get(), 0, SIGNATURE_LENGTH_BYTES);
    }

    virtual ~SoftGateKeeper() {
    }

    virtual bool GetAuthTokenKey(const uint8_t **auth_token_key,
            uint32_t *length) const {
        if (auth_token_key == NULL || length == NULL) return false;
        uint8_t *auth_token_key_copy = new uint8_t[SIGNATURE_LENGTH_BYTES];
        memcpy(auth_token_key_copy, key_.get(), SIGNATURE_LENGTH_BYTES);

        *auth_token_key = auth_token_key_copy;
        *length = SIGNATURE_LENGTH_BYTES;
        return true;
    }

    virtual void GetPasswordKey(const uint8_t **password_key, uint32_t *length) {
        if (password_key == NULL || length == NULL) return;
        uint8_t *password_key_copy = new uint8_t[SIGNATURE_LENGTH_BYTES];
        memcpy(password_key_copy, key_.get(), SIGNATURE_LENGTH_BYTES);

        *password_key = password_key_copy;
        *length = SIGNATURE_LENGTH_BYTES;
    }

    virtual void ComputePasswordSignature(uint8_t *signature, uint32_t signature_length,
            const uint8_t *, uint32_t, const uint8_t *password,
            uint32_t password_length, salt_t salt) const {
        if (signature == NULL) return;
        crypto_scrypt(password, password_length, reinterpret_cast<uint8_t *>(&salt),
                sizeof(salt), N, r, p, signature, signature_length);
    }

    virtual void GetRandom(void *random, uint32_t requested_length) const {
        if (random == NULL) return;
        RAND_pseudo_bytes((uint8_t *) random, requested_length);
    }

    virtual void ComputeSignature(uint8_t *signature, uint32_t signature_length,
            const uint8_t *, uint32_t, const uint8_t *, const uint32_t) const {
        if (signature == NULL) return;
        memset(signature, 0, signature_length);
    }

    virtual uint64_t GetMillisecondsSinceBoot() const {
        struct timespec time;
        int res = clock_gettime(CLOCK_BOOTTIME, &time);
        if (res < 0) return 0;
        return (time.tv_sec * 1000) + (time.tv_nsec / 1000 / 1000);
    }

    virtual bool IsHardwareBacked() const {
        return false;
    }

    virtual bool GetFailureRecord(uint32_t uid, secure_id_t user_id, failure_record_t *record,
            bool /* secure */) {
        failure_record_t *stored = &failure_map_[uid];
        if (user_id != stored->secure_user_id) {
            stored->secure_user_id = user_id;
            stored->last_checked_timestamp = 0;
            stored->failure_counter = 0;
        }
        memcpy(record, stored, sizeof(*record));
        return true;
    }

    virtual bool ClearFailureRecord(uint32_t uid, secure_id_t user_id, bool /* secure */) {
        failure_record_t *stored = &failure_map_[uid];
        stored->secure_user_id = user_id;
        stored->last_checked_timestamp = 0;
        stored->failure_counter = 0;
        return true;
    }

    virtual bool WriteFailureRecord(uint32_t uid, failure_record_t *record, bool /* secure */) {
        failure_map_[uid] = *record;
        return true;
    }

    fast_hash_t ComputeFastHash(const SizedBuffer &password, uint64_t salt) {
        fast_hash_t fast_hash;
        size_t digest_size = password.length + sizeof(salt);
        std::unique_ptr<uint8_t[]> digest(new uint8_t[digest_size]);
        memcpy(digest.get(), &salt, sizeof(salt));
        memcpy(digest.get() + sizeof(salt), password.buffer.get(), password.length);

        SHA256(digest.get(), digest_size, (uint8_t *) &fast_hash.digest);

        fast_hash.salt = salt;
        return fast_hash;
    }

    bool VerifyFast(const fast_hash_t &fast_hash, const SizedBuffer &password) {
        fast_hash_t computed = ComputeFastHash(password, fast_hash.salt);
        return memcmp(computed.digest, fast_hash.digest, SHA256_DIGEST_LENGTH) == 0;
    }

    bool DoVerify(const password_handle_t *expected_handle, const SizedBuffer &password) {
        FastHashMap::const_iterator it = fast_hash_map_.find(expected_handle->user_id);
        if (it != fast_hash_map_.end() && VerifyFast(it->second, password)) {
            return true;
        } else {
            if (GateKeeper::DoVerify(expected_handle, password)) {
                uint64_t salt;
                GetRandom(&salt, sizeof(salt));
                fast_hash_map_[expected_handle->user_id] = ComputeFastHash(password, salt);
                return true;
            }
        }

        return false;
    }

private:

    typedef std::unordered_map<uint32_t, failure_record_t> FailureRecordMap;
    typedef std::unordered_map<uint64_t, fast_hash_t> FastHashMap;

    UniquePtr<uint8_t[]> key_;
    FailureRecordMap failure_map_;
    FastHashMap fast_hash_map_;
};
}

#endif // SOFT_GATEKEEPER_H_

