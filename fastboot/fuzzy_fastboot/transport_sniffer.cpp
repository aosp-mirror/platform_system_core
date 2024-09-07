#include "transport_sniffer.h"
#include <android-base/stringprintf.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <iomanip>
#include <sstream>

namespace fastboot {

TransportSniffer::TransportSniffer(std::unique_ptr<Transport> transport,
                                         const int serial_fd)
    : transport_(std::move(transport)), serial_fd_(serial_fd) {}

TransportSniffer::~TransportSniffer() {
    Close();
}

ssize_t TransportSniffer::Read(void* data, size_t len) {
    ProcessSerial();

    ssize_t ret = transport_->Read(data, len);
    if (ret < 0) {
        const char* err = strerror(errno);
        std::vector<char> buf(err, err + strlen(err));
        Event e(READ_ERROR, std::move(buf));
        transfers_.push_back(e);
        return ret;
    }

    char* cdata = static_cast<char*>(data);
    std::vector<char> buf(cdata, cdata + ret);
    Event e(READ, std::move(buf));
    transfers_.push_back(e);

    ProcessSerial();
    return ret;
}

ssize_t TransportSniffer::Write(const void* data, size_t len) {
    ProcessSerial();

    size_t ret = transport_->Write(data, len);
    if (ret != len) {
        const char* err = strerror(errno);
        std::vector<char> buf(err, err + strlen(err));
        Event e(WRITE_ERROR, std::move(buf));
        transfers_.push_back(e);
        return ret;
    }

    const char* cdata = static_cast<const char*>(data);
    std::vector<char> buf(cdata, cdata + len);
    Event e(WRITE, std::move(buf));
    transfers_.push_back(e);

    ProcessSerial();
    return ret;
}

int TransportSniffer::Close() {
    return transport_->Close();
}

int TransportSniffer::Reset() {
    ProcessSerial();
    int ret = transport_->Reset();
    std::vector<char> buf;
    Event e(RESET, std::move(buf));
    transfers_.push_back(e);
    ProcessSerial();
    return ret;
}

const std::vector<TransportSniffer::Event> TransportSniffer::Transfers() {
    return transfers_;
}

/*
 * When a test fails, we want a human readable log of everything going on up until
 * the failure. This method will look through its log of captured events, and
 * create a clean printable string of everything that happened.
 */
std::string TransportSniffer::CreateTrace() {
    std::string ret;

    const auto no_print = [](char c) -> bool { return !isprint(c); };
    // This lambda creates a humand readable representation of a byte buffer
    // It first attempts to figure out whether it should be interpreted as an ASCII buffer,
    // and be printed as a string, or just a raw byte-buffer
    const auto msg = [&ret, no_print](const std::vector<char>& buf) {
        ret += android::base::StringPrintf("(%lu bytes): ", buf.size());
        std::vector<const char>::iterator iter = buf.end();
        const unsigned max_chars = 50;
        if (buf.size() > max_chars) {
            iter = buf.begin() + max_chars;
        }
        ret += '"';
        if (std::count_if(buf.begin(), iter, no_print) == 0) {  // print as ascii
            ret.insert(ret.end(), buf.begin(), iter);
        } else {  // print as hex
            std::stringstream ss;
            for (auto c = buf.begin(); c < iter; c++) {
                ss << std::hex << std::setw(2) << std::setfill('0')
                   << static_cast<uint16_t>(static_cast<uint8_t>(*c));
                ss << ',';
            }
            ret += ss.str();
        }
        if (buf.size() > max_chars) {
            ret += android::base::StringPrintf("...\"(+%lu bytes)\n", buf.size() - max_chars);
        } else {
            ret += "\"\n";
        }
    };

    // Now we just scan through the log of everything that happened and create a
    // printable string for each one
    for (const auto& event : transfers_) {
        const std::vector<char>& cbuf = event.buf;
        const std::string tmp(cbuf.begin(), cbuf.end());
        auto start = transfers_.front().start;
        auto durr = event.start - start;
        auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(durr).count();

        switch (event.type) {
            case READ:
                ret += android::base::StringPrintf("[READ %lldms]", millis);
                msg(cbuf);
                break;

            case WRITE:
                ret += android::base::StringPrintf("[WRITE %lldms]", millis);
                msg(cbuf);
                break;

            case RESET:
                ret += android::base::StringPrintf("[RESET %lldms]\n", millis);
                break;

            case READ_ERROR:
                ret += android::base::StringPrintf("[READ_ERROR %lldms] %s\n", millis, tmp.c_str());
                break;

            case WRITE_ERROR:
                ret += android::base::StringPrintf("[WRITE_ERROR %lldms] %s\n", millis,
                                                   tmp.c_str());
                break;

            case SERIAL:
                ret += android::base::StringPrintf("[SERIAL %lldms] %s", millis, tmp.c_str());
                if (ret.back() != '\n') ret += '\n';
                break;
        }
    }
    return ret;
}

// This is a quick call to flush any UART logs the device might have sent
// to our internal event log. It will wait up to 10ms for data to appear
void TransportSniffer::ProcessSerial() {
    if (serial_fd_ <= 0) return;

    fd_set set;
    struct timeval timeout;

    FD_ZERO(&set);
    FD_SET(serial_fd_, &set);
    timeout.tv_sec = 0;
    timeout.tv_usec = 10000;  // 10ms

    int count = 0;
    int n = 0;
    std::vector<char> buf;
    buf.resize(1000);
    while (select(serial_fd_ + 1, &set, NULL, NULL, &timeout) > 0) {
        n = read(serial_fd_, buf.data() + count, buf.size() - count);
        if (n > 0) {
            count += n;
        } else {
            break;
        }
    }

    buf.resize(count);

    if (count > 0) {
        Event e(SERIAL, std::move(buf));
        transfers_.push_back(e);
    }
}

}  // namespace fastboot
