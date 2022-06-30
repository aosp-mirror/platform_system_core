/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <errno.h>
#include <getopt.h>
#include <libxml/xmlreader.h>
#include <openssl/pem.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>
#include <string>

using std::string;

#include <trusty_keymaster/ipc/trusty_keymaster_ipc.h>

static const char* _sopts = "h";
static const struct option _lopts[] = {
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0},
};

static const char* usage =
        "Usage: %s [options] xml-file\n"
        "\n"
        "options:\n"
        "  -h, --help            prints this message and exit\n"
        "\n";

static void print_usage_and_exit(const char* prog, int code) {
    fprintf(stderr, usage, prog);
    exit(code);
}

static void parse_options(int argc, char** argv) {
    int c;
    int oidx = 0;

    while (1) {
        c = getopt_long(argc, argv, _sopts, _lopts, &oidx);
        if (c == -1) {
            break; /* done */
        }

        switch (c) {
            case 'h':
                print_usage_and_exit(argv[0], EXIT_SUCCESS);
                break;

            default:
                print_usage_and_exit(argv[0], EXIT_FAILURE);
        }
    }
}

struct SetAttestationKeyRequest : public keymaster::KeymasterMessage {
    explicit SetAttestationKeyRequest(int32_t ver = keymaster::kDefaultMessageVersion)
        : KeymasterMessage(ver) {}

    size_t SerializedSize() const override { return sizeof(uint32_t) + key_data.SerializedSize(); }
    uint8_t* Serialize(uint8_t* buf, const uint8_t* end) const override {
        buf = keymaster::append_uint32_to_buf(buf, end, algorithm);
        return key_data.Serialize(buf, end);
    }
    bool Deserialize(const uint8_t** buf_ptr, const uint8_t* end) override {
        return keymaster::copy_uint32_from_buf(buf_ptr, end, &algorithm) &&
               key_data.Deserialize(buf_ptr, end);
    }

    keymaster_algorithm_t algorithm;
    keymaster::Buffer key_data;
};

struct KeymasterNoResponse : public keymaster::KeymasterResponse {
    explicit KeymasterNoResponse(int32_t ver = keymaster::kDefaultMessageVersion)
        : keymaster::KeymasterResponse(ver) {}

    size_t NonErrorSerializedSize() const override { return 0; }
    uint8_t* NonErrorSerialize(uint8_t* buf, const uint8_t*) const override { return buf; }
    bool NonErrorDeserialize(const uint8_t**, const uint8_t*) override { return true; }
};

struct SetAttestationKeyResponse : public KeymasterNoResponse {};

struct ClearAttestationCertChainRequest : public keymaster::KeymasterMessage {
    explicit ClearAttestationCertChainRequest(int32_t ver = keymaster::kDefaultMessageVersion)
        : KeymasterMessage(ver) {}

    size_t SerializedSize() const override { return sizeof(uint32_t); }
    uint8_t* Serialize(uint8_t* buf, const uint8_t* end) const override {
        return keymaster::append_uint32_to_buf(buf, end, algorithm);
    }
    bool Deserialize(const uint8_t** buf_ptr, const uint8_t* end) override {
        return keymaster::copy_uint32_from_buf(buf_ptr, end, &algorithm);
    }

    keymaster_algorithm_t algorithm;
};

struct ClearAttestationCertChainResponse : public KeymasterNoResponse {};

static int set_attestation_key_or_cert_bin(uint32_t cmd, keymaster_algorithm_t algorithm,
                                           const void* key_data, size_t key_data_size) {
    int ret;

    SetAttestationKeyRequest req;
    req.algorithm = algorithm;
    req.key_data.Reinitialize(key_data, key_data_size);
    SetAttestationKeyResponse rsp;

    ret = trusty_keymaster_send(cmd, req, &rsp);
    if (ret) {
        fprintf(stderr, "trusty_keymaster_send cmd 0x%x failed %d\n", cmd, ret);
        return ret;
    }

    return 0;
}

static int set_attestation_key_or_cert_pem(uint32_t cmd, keymaster_algorithm_t algorithm,
                                           const xmlChar* pemkey) {
    int ret;
    int sslret;

    /* Convert from pem to binary */
    BIO* bio = BIO_new_mem_buf(pemkey, xmlStrlen(pemkey));
    if (!bio) {
        fprintf(stderr, "BIO_new_mem_buf failed\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    char* key_name;
    char* key_header;
    uint8_t* key;
    long keylen;
    sslret = PEM_read_bio(bio, &key_name, &key_header, &key, &keylen);
    BIO_free(bio);

    if (!sslret) {
        fprintf(stderr, "PEM_read_bio failed\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    /* Send key in binary format to trusty */
    ret = set_attestation_key_or_cert_bin(cmd, algorithm, key, keylen);

    OPENSSL_free(key_name);
    OPENSSL_free(key_header);
    OPENSSL_free(key);

    return ret;
}

static int set_attestation_key_or_cert_iecs(uint32_t cmd, keymaster_algorithm_t algorithm,
                                            const xmlChar* key_base64) {
    int ret;
    int sslret;

    /* Remove all whitespace. EVP_DecodeBase64 does not support whitespace. */
    string key_base64_str((const char*)key_base64);
    key_base64_str.erase(remove_if(key_base64_str.begin(), key_base64_str.end(), isspace),
                         key_base64_str.end());

    /* Convert from base64 to binary */
    uint8_t* key;
    size_t keylen;
    size_t key_base64_len = key_base64_str.length();

    sslret = EVP_DecodedLength(&keylen, key_base64_len);
    if (!sslret) {
        fprintf(stderr, "invalid input length, %zu\n", key_base64_len);
        return -1;
    }
    key = (uint8_t*)malloc(keylen);
    if (!key) {
        fprintf(stderr, "failed to allocate key, size %zu\n", key_base64_len);
        return -1;
    }
    sslret = EVP_DecodeBase64(key, &keylen, keylen, (const uint8_t*)key_base64_str.data(),
                              key_base64_len);
    if (!sslret) {
        fprintf(stderr, "EVP_DecodeBase64 failed\n");
        ERR_print_errors_fp(stderr);
        free(key);
        return -1;
    }

    /* Send key in binary format to trusty */
    ret = set_attestation_key_or_cert_bin(cmd, algorithm, key, keylen);

    free(key);

    return ret;
}

static int str_to_algorithm(keymaster_algorithm_t* algorithm, const xmlChar* algorithm_str) {
    if (xmlStrEqual(algorithm_str, BAD_CAST "rsa")) {
        *algorithm = KM_ALGORITHM_RSA;
    } else if (xmlStrEqual(algorithm_str, BAD_CAST "ecdsa")) {
        *algorithm = KM_ALGORITHM_EC;
    } else {
        printf("unsupported algorithm: %s\n", algorithm_str);
        return -1;
    }
    return 0;
}

static int set_attestation_key_or_cert(uint32_t cmd, const xmlChar* algorithm_str,
                                       const xmlChar* format, const xmlChar* str) {
    int ret;
    keymaster_algorithm_t algorithm;

    ret = str_to_algorithm(&algorithm, algorithm_str);
    if (ret) {
        return ret;
    }

    if (xmlStrEqual(format, BAD_CAST "pem")) {
        ret = set_attestation_key_or_cert_pem(cmd, algorithm, str);
    } else if (xmlStrEqual(format, BAD_CAST "iecs")) {
        ret = set_attestation_key_or_cert_iecs(cmd, algorithm, str);
    } else {
        printf("unsupported key/cert format: %s\n", format);
        return -1;
    }
    return ret;
}

static int clear_cert_chain(const xmlChar* algorithm_str) {
    int ret;
    ClearAttestationCertChainRequest req;
    ClearAttestationCertChainResponse rsp;

    ret = str_to_algorithm(&req.algorithm, algorithm_str);
    if (ret) {
        return ret;
    }

    ret = trusty_keymaster_send(KM_CLEAR_ATTESTATION_CERT_CHAIN, req, &rsp);
    if (ret) {
        fprintf(stderr, "%s: trusty_keymaster_send failed %d\n", __func__, ret);
        return ret;
    }
    return 0;
}

static int process_xml(xmlTextReaderPtr xml) {
    int ret;
    const xmlChar* algorithm = NULL;
    const xmlChar* element = NULL;
    const xmlChar* element_format = NULL;

    while ((ret = xmlTextReaderRead(xml)) == 1) {
        int nodetype = xmlTextReaderNodeType(xml);
        const xmlChar *name, *value;
        name = xmlTextReaderConstName(xml);
        switch (nodetype) {
            case XML_READER_TYPE_ELEMENT:
                element = name;
                element_format = xmlTextReaderGetAttribute(xml, BAD_CAST "format");
                if (xmlStrEqual(name, BAD_CAST "Key")) {
                    algorithm = xmlTextReaderGetAttribute(xml, BAD_CAST "algorithm");
                } else if (xmlStrEqual(name, BAD_CAST "CertificateChain")) {
                    ret = clear_cert_chain(algorithm);
                    if (ret) {
                        fprintf(stderr, "%s, algorithm %s: Clear cert chain cmd failed, %d\n",
                                element, algorithm, ret);
                        return ret;
                    }
                    printf("%s, algorithm %s: Clear cert chain cmd done\n", element, algorithm);
                }
                break;
            case XML_READER_TYPE_TEXT:
                value = xmlTextReaderConstValue(xml);
                uint32_t cmd;
                if (xmlStrEqual(element, BAD_CAST "PrivateKey")) {
                    if (xmlStrEqual(element_format, BAD_CAST "pem")) {
                        cmd = KM_SET_ATTESTATION_KEY;
                    } else if (xmlStrEqual(element_format, BAD_CAST "iecs")) {
                        cmd = KM_SET_WRAPPED_ATTESTATION_KEY;
                    } else {
                        printf("unsupported key format: %s\n", element_format);
                        return -1;
                    }
                } else if (xmlStrEqual(element, BAD_CAST "Certificate")) {
                    cmd = KM_APPEND_ATTESTATION_CERT_CHAIN;
                } else {
                    break;
                }

                ret = set_attestation_key_or_cert(cmd, algorithm, element_format, value);
                if (ret) {
                    fprintf(stderr, "%s, algorithm %s, format %s: Cmd 0x%x failed, %d\n", element,
                            algorithm, element_format, cmd, ret);
                    return ret;
                }
                printf("%s, algorithm %s, format %s: Cmd 0x%x done\n", element, algorithm,
                       element_format, cmd);
                break;
            case XML_READER_TYPE_END_ELEMENT:
                element = NULL;
                break;
        }
    }
    return ret;
}

static int parse_xml_file(const char* filename) {
    int ret;
    xmlTextReaderPtr xml = xmlReaderForFile(filename, NULL, 0);
    if (!xml) {
        fprintf(stderr, "failed to open %s\n", filename);
        return -1;
    }

    ret = process_xml(xml);

    xmlFreeTextReader(xml);
    if (ret != 0) {
        fprintf(stderr, "Failed to parse or process %s\n", filename);
        return -1;
    }

    return 0;
}

static int provision_ids(void) {
    keymaster::SetAttestationIdsRequest req(4 /* ver */);
    keymaster::EmptyKeymasterResponse rsp(4 /* ver */);

    req.brand.Reinitialize("trusty", 6);
    req.device.Reinitialize("trusty", 6);
    req.product.Reinitialize("trusty", 6);
    req.manufacturer.Reinitialize("trusty", 6);
    req.model.Reinitialize("trusty", 6);

    return trusty_keymaster_send(KM_SET_ATTESTATION_IDS, req, &rsp);
}

int main(int argc, char** argv) {
    int ret = 0;

    parse_options(argc, argv);
    if (optind + 1 != argc) {
        print_usage_and_exit(argv[0], EXIT_FAILURE);
    }

    ret = trusty_keymaster_connect();
    if (ret) {
        fprintf(stderr, "trusty_keymaster_connect failed %d\n", ret);
        return EXIT_FAILURE;
    }

    ret = parse_xml_file(argv[optind]);
    if (ret) {
        fprintf(stderr, "parse_xml_file failed %d\n", ret);
        trusty_keymaster_disconnect();
        return EXIT_FAILURE;
    }

    ret = provision_ids();
    if (ret) {
        fprintf(stderr, "provision_ids failed %d\n", ret);
        trusty_keymaster_disconnect();
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
