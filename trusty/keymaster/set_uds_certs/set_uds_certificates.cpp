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

struct AppendUdsCertificateRequest : public keymaster::KeymasterMessage {
    explicit AppendUdsCertificateRequest(int32_t ver = keymaster::kDefaultMessageVersion)
        : KeymasterMessage(ver) {}

    size_t SerializedSize() const override { return cert_data.SerializedSize(); }
    uint8_t* Serialize(uint8_t* buf, const uint8_t* end) const override {
        return cert_data.Serialize(buf, end);
    }
    bool Deserialize(const uint8_t** buf_ptr, const uint8_t* end) override {
        return cert_data.Deserialize(buf_ptr, end);
    }

    keymaster::Buffer cert_data;
};

struct ClearUdsCertificateRequest : public keymaster::KeymasterMessage {
    explicit ClearUdsCertificateRequest(int32_t ver = keymaster::kDefaultMessageVersion)
        : KeymasterMessage(ver) {}

    size_t SerializedSize() const override { return 0; }
    uint8_t* Serialize(uint8_t* buf, const uint8_t*) const override { return buf; }
    bool Deserialize(const uint8_t**, const uint8_t*) override { return true; };
};

struct KeymasterNoResponse : public keymaster::KeymasterResponse{
    explicit KeymasterNoResponse(int32_t ver = keymaster::kDefaultMessageVersion)
        : keymaster::KeymasterResponse(ver) {}

    size_t NonErrorSerializedSize() const override { return 0; }
    uint8_t* NonErrorSerialize(uint8_t* buf, const uint8_t*) const override { return buf; }
    bool NonErrorDeserialize(const uint8_t**, const uint8_t*) override { return true; }
};

struct AppendUdsCertificateResponse : public KeymasterNoResponse {};
struct ClearUdsCertificateResponse : public KeymasterNoResponse {};

static int set_uds_cert_bin(uint32_t cmd, const void* cert_data, size_t cert_data_size) {
    int ret;

    AppendUdsCertificateRequest req;
    req.cert_data.Reinitialize(cert_data, cert_data_size);
    AppendUdsCertificateResponse rsp;

    ret = trusty_keymaster_send(cmd, req, &rsp);
    if (ret) {
        fprintf(stderr, "trusty_keymaster_send cmd 0x%x failed %d\n", cmd, ret);
        return ret;
    }

    return 0;
}

static int set_uds_cert_pem(uint32_t cmd, const xmlChar* pemkey) {
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
    ret = set_uds_cert_bin(cmd, key, keylen);

    OPENSSL_free(key_name);
    OPENSSL_free(key_header);
    OPENSSL_free(key);

    return ret;
}

static int set_uds_cert(uint32_t cmd, const xmlChar* format, const xmlChar* str) {
    int ret;

    if (xmlStrEqual(format, BAD_CAST "pem")) {
        ret = set_uds_cert_pem(cmd, str);
    } else {
        printf("unsupported key/cert format: %s\n", format);
        return -1;
    }
    return ret;
}

// TODO: Guard by Production Mode
static int clear_cert_chain() {
    int ret;
    ClearUdsCertificateRequest req;
    ClearUdsCertificateResponse rsp;

    ret = trusty_keymaster_send(KM_CLEAR_UDS_CERT_CHAIN, req, &rsp);
    if (ret) {
        fprintf(stderr, "%s: trusty_keymaster_send failed %d\n", __func__, ret);
        return ret;
    }
    return 0;
}

static int process_xml(xmlTextReaderPtr xml) {
    int ret;
    const xmlChar* element = NULL;
    const xmlChar* element_format = NULL;
    bool isPixelUdsCert = false;

    while ((ret = xmlTextReaderRead(xml)) == 1) {
        int nodetype = xmlTextReaderNodeType(xml);
        const xmlChar *name, *value;
        name = xmlTextReaderConstName(xml);
        switch (nodetype) {
            case XML_READER_TYPE_ELEMENT:
                element = name;
                element_format = xmlTextReaderGetAttribute(xml, BAD_CAST "format");
                if (isPixelUdsCert || xmlStrEqual(name, BAD_CAST "PixelUdsCertificates")) {
                    // The first element name must be "PixelUdsCertificates"
                    isPixelUdsCert = true;
                } else {
                    fprintf(stderr, "Not a PixelUdsCertificates: \"%s\"\n", name);
                    return -1;
                }
                if (xmlStrEqual(name, BAD_CAST "CertificateChain")) {
                    ret = clear_cert_chain();
                    if (ret) {
                        fprintf(stderr, "%s: Clear cert chain cmd failed, %d\n", element, ret);
                        return ret;
                    }
                    printf("%s: Clear cert chain cmd done\n", element);
                }
                break;
            case XML_READER_TYPE_TEXT:
                value = xmlTextReaderConstValue(xml);
                uint32_t cmd;
                if (xmlStrEqual(element, BAD_CAST "Certificate")) {
                    cmd = KM_APPEND_UDS_CERT_CHAIN;
                } else {
                    break;
                }

                ret = set_uds_cert(cmd, element_format, value);
                if (ret) {
                    fprintf(stderr, "%s, format %s: Cmd 0x%x failed, %d\n", element, element_format,
                            cmd, ret);
                    return ret;
                }
                printf("%s, format %s: Cmd 0x%x done\n", element, element_format, cmd);
                break;
            case XML_READER_TYPE_END_ELEMENT:
                element = NULL;
                break;
        }
    }
    return ret;
}

static int parse_and_provision_xml_file(const char* filename) {
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

    ret = parse_and_provision_xml_file(argv[optind]);
    if (ret) {
        fprintf(stderr, "parse_and_provision_xml_file failed %d\n", ret);
        trusty_keymaster_disconnect();
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
