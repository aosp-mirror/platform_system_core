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

#include <getopt.h>

#include <string>

#include <android-base/properties.h>
#include <trusty_keymaster/ipc/trusty_keymaster_ipc.h>

namespace {

const char* sopts = "hb:d:p:s:M:m:i:c:";
const struct option lopts[] = {
        {"help", no_argument, nullptr, 'h'},
        {"brand", required_argument, nullptr, 'b'},
        {"device", required_argument, nullptr, 'd'},
        {"product", required_argument, nullptr, 'p'},
        {"serial", required_argument, nullptr, 's'},
        {"manufacturer", required_argument, nullptr, 'M'},
        {"model", required_argument, nullptr, 'm'},
        {"imei", required_argument, nullptr, 'i'},
        {"meid", required_argument, nullptr, 'c'},
        {0, 0, 0, 0},
};

std::string buf2string(const keymaster::Buffer& buf) {
    return std::string(reinterpret_cast<const char*>(buf.peek_read()), buf.available_read());
}

void print_usage(const char* prog, const keymaster::SetAttestationIdsRequest& req) {
    fprintf(stderr,
            "Usage: %s [options]\n"
            "\n"
            "options:\n"
            "  -h, --help                 prints this message and exit\n"
            "  -b, --brand <val>          set brand (default '%s')\n"
            "  -d, --device <val>         set device (default '%s')\n"
            "  -p, --product <val>        set product (default '%s')\n"
            "  -s, --serial <val>         set serial (default '%s')\n"
            "  -M, --manufacturer <val>   set manufacturer (default '%s')\n"
            "  -m, --model <val>          set model (default '%s')\n"
            "  -i, --imei <val>           set IMEI (default '%s')\n"
            "  -c, --meid <val>           set MEID (default '%s')\n"
            "\n",
            prog, buf2string(req.brand).c_str(), buf2string(req.device).c_str(),
            buf2string(req.product).c_str(), buf2string(req.serial).c_str(),
            buf2string(req.manufacturer).c_str(), buf2string(req.model).c_str(),
            buf2string(req.imei).c_str(), buf2string(req.meid).c_str());
}

void set_from_prop(keymaster::Buffer* buf, const std::string& prop) {
    std::string prop_value = ::android::base::GetProperty(prop, /* default_value = */ "");
    if (!prop_value.empty()) {
        buf->Reinitialize(prop_value.data(), prop_value.size());
    }
}

void populate_ids(keymaster::SetAttestationIdsRequest* req) {
    set_from_prop(&req->brand, "ro.product.brand");
    set_from_prop(&req->device, "ro.product.device");
    set_from_prop(&req->product, "ro.product.name");
    set_from_prop(&req->serial, "ro.serialno");
    set_from_prop(&req->manufacturer, "ro.product.manufacturer");
    set_from_prop(&req->model, "ro.product.model");
}

}  // namespace

int main(int argc, char** argv) {
    // By default, set attestation IDs to the values in userspace properties.
    keymaster::SetAttestationIdsRequest req(/* ver = */ 4);
    populate_ids(&req);

    while (true) {
        int oidx = 0;
        int c = getopt_long(argc, argv, sopts, lopts, &oidx);
        if (c == -1) {
            break; /* done */
        }

        switch (c) {
            case 'b':
                req.brand.Reinitialize(optarg, strlen(optarg));
                break;
            case 'd':
                req.device.Reinitialize(optarg, strlen(optarg));
                break;
            case 'p':
                req.product.Reinitialize(optarg, strlen(optarg));
                break;
            case 's':
                req.serial.Reinitialize(optarg, strlen(optarg));
                break;
            case 'M':
                req.manufacturer.Reinitialize(optarg, strlen(optarg));
                break;
            case 'm':
                req.model.Reinitialize(optarg, strlen(optarg));
                break;
            case 'i':
                req.imei.Reinitialize(optarg, strlen(optarg));
                break;
            case 'c':
                req.meid.Reinitialize(optarg, strlen(optarg));
                break;
            case 'h':
                print_usage(argv[0], req);
                exit(EXIT_SUCCESS);
            default:
                print_usage(argv[0], req);
                exit(EXIT_FAILURE);
        }
    }
    if (optind != argc) {
        print_usage(argv[0], req);
        exit(EXIT_FAILURE);
    }

    int ret = trusty_keymaster_connect();
    if (ret) {
        fprintf(stderr, "trusty_keymaster_connect failed: %d\n", ret);
        return EXIT_FAILURE;
    }

    printf("Setting:\n"
           "  brand:        %s\n"
           "  device:       %s\n"
           "  product:      %s\n"
           "  serial:       %s\n"
           "  manufacturer: %s\n"
           "  model:        %s\n"
           "  IMEI:         %s\n"
           "  MEID:         %s\n",
           buf2string(req.brand).c_str(), buf2string(req.device).c_str(),
           buf2string(req.product).c_str(), buf2string(req.serial).c_str(),
           buf2string(req.manufacturer).c_str(), buf2string(req.model).c_str(),
           buf2string(req.imei).c_str(), buf2string(req.meid).c_str());

    keymaster::EmptyKeymasterResponse rsp(/* ver = */ 4);
    ret = trusty_keymaster_send(KM_SET_ATTESTATION_IDS, req, &rsp);
    if (ret) {
        fprintf(stderr, "SET_ATTESTATION_IDS failed: %d\n", ret);
        trusty_keymaster_disconnect();
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
