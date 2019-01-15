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
#include "test_utils.h"
#include <fcntl.h>
#include <termios.h>
#include <sstream>

namespace fastboot {

namespace {
constexpr int rand_seed = 0;
std::default_random_engine rnd(rand_seed);
}  // namespace

char rand_legal() {
    return rnd() % 128;
}

char rand_illegal() {
    return rand_legal() + 128;
}

char rand_char() {
    return rnd() % 256;
}

int random_int(int start, int end) {
    std::uniform_int_distribution<int> uni(start, end);
    return uni(rnd);
}

std::string RandomString(size_t length, std::function<char(void)> provider) {
    std::string str(length, 0);
    std::generate_n(str.begin(), length, provider);
    return str;
}

std::vector<char> RandomBuf(size_t length, std::function<char(void)> provider) {
    std::vector<char> ret;
    ret.resize(length);
    std::generate_n(ret.begin(), length, provider);
    return ret;
}

std::vector<std::string> SplitBySpace(const std::string& s) {
    std::istringstream iss(s);
    return std::vector<std::string>{std::istream_iterator<std::string>{iss},
                                    std::istream_iterator<std::string>{}};
}

std::vector<std::string> GeneratePartitionNames(const std::string& base, int num_slots) {
    if (!num_slots) {
        return std::vector<std::string>{base};
    }
    std::vector<std::string> ret;
    for (char c = 'a'; c < 'a' + num_slots; c++) {
        ret.push_back(base + '_' + c);
    }

    return ret;
}

std::unordered_map<std::string, std::string> ParseArgs(int argc, char** argv,
                                                       std::string* err_msg) {
    // We ignore any gtest stuff
    std::unordered_map<std::string, std::string> ret;

    for (int i = 1; i < argc - 1; i++) {
        std::string arg(argv[i]);

        const std::string gtest_start("--gtest");
        // We found a non gtest argument
        if (!arg.find("-h") ||
            (!arg.find("--") && arg.find("--gtest") && arg.find("=") != arg.npos)) {
            const std::string start(arg.begin() + 2, arg.begin() + arg.find("="));
            const std::string end(arg.begin() + arg.find("=") + 1, arg.end());
            ret[start] = end;
        } else if (arg.find("--gtest") != 0) {
            *err_msg = android::base::StringPrintf("Illegal argument '%s'\n", arg.c_str());
            return ret;
        }
    }

    return ret;
}

int ConfigureSerial(const std::string& port) {
    int fd = open(port.c_str(), O_RDONLY | O_NOCTTY | O_NONBLOCK);

    if (fd <= 0) {
        return fd;
    }

    struct termios tty;
    tcgetattr(fd, &tty);

    cfsetospeed(&tty, (speed_t)B115200);
    cfsetispeed(&tty, (speed_t)B115200);

    tty.c_cflag &= ~PARENB;
    tty.c_cflag &= ~CSTOPB;
    tty.c_cflag &= ~CSIZE;
    tty.c_cflag |= CS8;

    tty.c_cflag &= ~CRTSCTS;
    tty.c_cc[VMIN] = 0;
    tty.c_cc[VTIME] = 2;
    tty.c_cflag &= ~(ICANON | ECHO | ECHOE | ISIG);

    cfmakeraw(&tty);

    tcflush(fd, TCIFLUSH);
    if (tcsetattr(fd, TCSANOW, &tty) != 0) {
        return -1;
    }

    return fd;
}

int StartProgram(const std::string program, const std::vector<std::string> args, int* rpipe) {
    int link[2];
    if (pipe(link) < 0) {
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {  // error
        return -1;
    }

    if (pid) {  // parent
        close(link[1]);
        *rpipe = link[0];
        fcntl(*rpipe, F_SETFL, O_NONBLOCK);  // Non-blocking
    } else {                                 // child
        std::vector<const char*> argv(args.size() + 2, nullptr);
        argv[0] = program.c_str();

        for (int i = 0; i < args.size(); i++) {
            argv[i + 1] = args[i].c_str();
        }

        // We pipe any stderr writes to the parent test process
        dup2(link[1], STDERR_FILENO);  // close stdout and have it now be link[1]
        // Close duplicates
        close(link[0]);
        close(link[1]);

        execvp(program.c_str(), const_cast<char* const*>(argv.data()));
        fprintf(stderr, "Launching validator process '%s' failed with: %s\n", program.c_str(),
                strerror(errno));
        exit(-1);
    }

    return pid;
}

int WaitProgram(const int pid, const int pipe, std::string* error_msg) {
    int status;
    if (waitpid(pid, &status, 0) != pid) {
        close(pipe);
        return -1;
    }
    // Read from pipe
    char buf[1024];
    int n;
    while ((n = read(pipe, buf, sizeof(buf))) > 0) {
        buf[n] = 0; /* terminate the string */
        error_msg->append(buf, n);
    }
    close(pipe);

    if (WIFEXITED(status)) {
        // This WEXITSTATUS macro masks off lower bytes, with no sign extension
        // casting it as a signed char fixes the sign extension issue
        int retmask = WEXITSTATUS(status);
        return reinterpret_cast<int8_t*>(&retmask)[0];
    }

    return -1;
}

}  // namespace fastboot
