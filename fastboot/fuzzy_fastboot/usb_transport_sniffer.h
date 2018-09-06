/*
 * Copyright (C) 2018 The Android Open Source Project
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
#pragma once

#include <sys/types.h>
#include <unistd.h>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

#include "usb.h"

namespace fastboot {

/* A special class for sniffing reads and writes
 *
 * A useful debugging tool is to see the raw fastboot transactions going between
 * the host and device. This class wraps the UsbTransport class, and snoops and saves
 * all the transactions going on. Additionally, if there is a console serial port
 * from the device, this class can monitor it as well and capture the interleaving of
 * transport transactions and UART log messages.
 */
class UsbTransportSniffer : public UsbTransport {
  public:
    enum EventType {
        READ,
        WRITE,
        RESET,
        SERIAL,  // Serial log message from device
        READ_ERROR,
        WRITE_ERROR,
    };

    struct Event {
        Event(EventType t, const std::vector<char> cbuf) : type(t), buf(cbuf) {
            start = std::chrono::high_resolution_clock::now();
        };
        EventType type;
        std::chrono::high_resolution_clock::time_point start;
        const std::vector<char> buf;
    };

    UsbTransportSniffer(std::unique_ptr<UsbTransport> transport, const int serial_fd = 0);
    ~UsbTransportSniffer() override;

    virtual ssize_t Read(void* data, size_t len) override;
    virtual ssize_t Write(const void* data, size_t len) override;
    virtual int Close() override;
    virtual int Reset() override;

    const std::vector<Event> Transfers();
    std::string CreateTrace();
    void ProcessSerial();

  private:
    std::vector<Event> transfers_;
    std::unique_ptr<UsbTransport> transport_;
    const int serial_fd_;
};

}  // End namespace fastboot
