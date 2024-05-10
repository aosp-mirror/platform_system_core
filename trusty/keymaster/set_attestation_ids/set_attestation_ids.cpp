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
#include <vector>

#include <android-base/properties.h>
#include <android-base/strings.h>
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
        {"imei2", required_argument, nullptr, '2'},
        {0, 0, 0, 0},
};

std::string TELEPHONY_CMD_GET_IMEI = "cmd phone get-imei ";

// Run a shell command and collect the output of it. If any error, set an empty string as the
// output.
std::string exec_command(const std::string& command) {
    char buffer[128];
    std::string result = "";

    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        fprintf(stderr, "popen('%s') failed\n", command.c_str());
        return result;
    }

    while (!feof(pipe)) {
        if (fgets(buffer, 128, pipe) != NULL) {
            result += buffer;
        }
    }

    pclose(pipe);
    return result;
}

// Get IMEI using Telephony service shell command. If any error while executing the command
// then empty string will be returned as output.
std::string get_imei(int slot) {
    std::string cmd = TELEPHONY_CMD_GET_IMEI + std::to_string(slot);
    std::string output = exec_command(cmd);

    if (output.empty()) {
        fprintf(stderr, "Retrieve IMEI command ('%s') failed\n", cmd.c_str());
        return "";
    }

    std::vector<std::string> out =
            ::android::base::Tokenize(::android::base::Trim(output), "Device IMEI:");

    if (out.size() != 1) {
        fprintf(stderr, "Error parsing command ('%s') output '%s'\n", cmd.c_str(), output.c_str());
        return "";
    }

    std::string imei = ::android::base::Trim(out[0]);
    if (imei.compare("null") == 0) {
        fprintf(stderr, "IMEI value from command ('%s') is null, skipping", cmd.c_str());
        return "";
    }
    return imei;
}

std::string buf2string(const keymaster::Buffer& buf) {
    return std::string(reinterpret_cast<const char*>(buf.peek_read()), buf.available_read());
}

void print_usage(const char* prog, const keymaster::SetAttestationIdsKM3Request& req) {
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
            "  -2, --imei2 <val>          set second IMEI (default '%s')\n"
            "\n",
            prog, buf2string(req.base.brand).c_str(), buf2string(req.base.device).c_str(),
            buf2string(req.base.product).c_str(), buf2string(req.base.serial).c_str(),
            buf2string(req.base.manufacturer).c_str(), buf2string(req.base.model).c_str(),
            buf2string(req.base.imei).c_str(), buf2string(req.base.meid).c_str(),
            buf2string(req.second_imei).c_str());
}

void set_to(keymaster::Buffer* buf, const std::string& value) {
    if (!value.empty()) {
        buf->Reinitialize(value.data(), value.size());
    }
}

void set_from_prop(keymaster::Buffer* buf, const std::string& prop) {
    std::string prop_value = ::android::base::GetProperty(prop, /* default_value = */ "");
    set_to(buf, prop_value);
}

void populate_base_ids(keymaster::SetAttestationIdsRequest* req) {
    set_from_prop(&req->brand, "ro.product.brand");
    set_from_prop(&req->device, "ro.product.device");
    set_from_prop(&req->product, "ro.product.name");
    set_from_prop(&req->serial, "ro.serialno");
    set_from_prop(&req->manufacturer, "ro.product.manufacturer");
    set_from_prop(&req->model, "ro.product.model");
    std::string imei = get_imei(0);
    set_to(&req->imei, imei);
}

void populate_ids(keymaster::SetAttestationIdsKM3Request* req) {
    populate_base_ids(&req->base);

    // - "What about IMEI?"
    // - "You've already had it."
    // - "We've had one, yes. What about second IMEI?"
    // - "I don't think he knows about second IMEI, Pip."
    std::string imei2 = get_imei(1);
    set_to(&req->second_imei, imei2);
}

}  // namespace

int main(int argc, char** argv) {
    // By default, set attestation IDs to the values in userspace properties.
    keymaster::SetAttestationIdsKM3Request req(/* ver = */ 4);
    populate_ids(&req);

    while (true) {
        int oidx = 0;
        int c = getopt_long(argc, argv, sopts, lopts, &oidx);
        if (c == -1) {
            break; /* done */
        }

        switch (c) {
            case 'b':
                req.base.brand.Reinitialize(optarg, strlen(optarg));
                break;
            case 'd':
                req.base.device.Reinitialize(optarg, strlen(optarg));
                break;
            case 'p':
                req.base.product.Reinitialize(optarg, strlen(optarg));
                break;
            case 's':
                req.base.serial.Reinitialize(optarg, strlen(optarg));
                break;
            case 'M':
                req.base.manufacturer.Reinitialize(optarg, strlen(optarg));
                break;
            case 'm':
                req.base.model.Reinitialize(optarg, strlen(optarg));
                break;
            case 'i':
                req.base.imei.Reinitialize(optarg, strlen(optarg));
                break;
            case 'c':
                req.base.meid.Reinitialize(optarg, strlen(optarg));
                break;
            case '2':
                req.second_imei.Reinitialize(optarg, strlen(optarg));
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
           "  MEID:         %s\n"
           "  SECOND_IMEI:  %s\n\n",
           buf2string(req.base.brand).c_str(), buf2string(req.base.device).c_str(),
           buf2string(req.base.product).c_str(), buf2string(req.base.serial).c_str(),
           buf2string(req.base.manufacturer).c_str(), buf2string(req.base.model).c_str(),
           buf2string(req.base.imei).c_str(), buf2string(req.base.meid).c_str(),
           buf2string(req.second_imei).c_str());
    fflush(stdout);

    keymaster::EmptyKeymasterResponse rsp(/* ver = */ 4);
    const char* msg;
    if (req.second_imei.available_read() == 0) {
        // No SECOND_IMEI set, use base command.
        ret = trusty_keymaster_send(KM_SET_ATTESTATION_IDS, req.base, &rsp);
        msg = "SET_ATTESTATION_IDS";
    } else {
        // SECOND_IMEI is set, use updated command.
        ret = trusty_keymaster_send(KM_SET_ATTESTATION_IDS_KM3, req, &rsp);
        msg = "SET_ATTESTATION_IDS_KM3";
    }
    trusty_keymaster_disconnect();

    if (ret) {
        fprintf(stderr, "%s failed: %d\n", msg, ret);
        return EXIT_FAILURE;
    } else {
        printf("done\n");
        printf("\nNOTE: device reboot may be required before changes take effect.\n");
        return EXIT_SUCCESS;
    }
}
