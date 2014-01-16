/*
 * Copyright (c) 2009-2013, Google Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name of Google, Inc. nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


#include <openssl/pem.h>
#include <openssl/engine.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "secure.h"
#include "debug.h"
#include "utils.h"


void cert_init_crypto() {
    CRYPTO_malloc_init();
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    ENGINE_load_builtin_engines();
}

X509_STORE *cert_store_from_path(const char *path) {

    X509_STORE *store;
    struct stat st;
    X509_LOOKUP *lookup;

    if (stat(path, &st)) {
        D(ERR, "Unable to stat cert path");
        goto error;
    }

    if (!(store = X509_STORE_new())) {
        goto error;
    }

    if (S_ISDIR(st.st_mode)) {
        lookup = X509_STORE_add_lookup(store,X509_LOOKUP_hash_dir());
        if (lookup == NULL)
            goto error;
        if (!X509_LOOKUP_add_dir(lookup, path, X509_FILETYPE_PEM)) {
            D(ERR, "Error loading cert directory %s", path);
            goto error;
        }
    }
    else if(S_ISREG(st.st_mode)) {
        lookup = X509_STORE_add_lookup(store,X509_LOOKUP_file());
        if (lookup == NULL)
            goto error;
        if (!X509_LOOKUP_load_file(lookup, path, X509_FILETYPE_PEM)) {
            D(ERR, "Error loading cert directory %s", path);
            goto error;
        }
    }
    else {
        D(ERR, "cert path is not directory or regular file");
        goto error;
    }

    return store;

error:
    return NULL;
}


int cert_read(int fd, CMS_ContentInfo **content, BIO **output) {
    BIO *input;
    *output = NULL;


    input = BIO_new_fd(fd, BIO_NOCLOSE);
    if (input == NULL) {
        D(ERR, "Unable to open input");
        goto error;
    }

    //TODO:
    // read with d2i_CMS_bio to support DER
    // with java or just encode data with base64
    *content = SMIME_read_CMS(input, output);
    if (*content == NULL) {
        unsigned long err = ERR_peek_last_error();
        D(ERR, "Unable to parse input file: %s", ERR_lib_error_string(err));
        goto error_read;
    }

    BIO_free(input);

    return 0;

error_read:
    BIO_free(input);
error:
    return 1;
}

int cert_verify(BIO *content, CMS_ContentInfo *content_info, X509_STORE *store, int *out_fd) {
    BIO *output_temp;
    int ret;

    *out_fd = create_temp_file();
    if (*out_fd < 0) {
        D(ERR, "unable to create temporary file");
        return -1;
    }

    output_temp = BIO_new_fd(*out_fd, BIO_NOCLOSE);
    if (output_temp == NULL) {
        D(ERR, "unable to create temporary bio");
        close(*out_fd);
        return -1;
    }

    ret = CMS_verify(content_info, NULL ,store, content, output_temp, 0);

    if (ret == 0) {
        char buf[256];
        unsigned long err = ERR_peek_last_error();
        D(ERR, "Verification failed with reason: %s, %s", ERR_lib_error_string(err),  ERR_error_string(err, buf));
        D(ERR, "Data used: content %p", content);
    }

    ERR_clear_error();
    ERR_remove_state(0);

    BIO_free(output_temp);

    return ret;
}

void cert_release(BIO *content, CMS_ContentInfo *info) {
    BIO_free(content);
    CMS_ContentInfo_free(info);
}

