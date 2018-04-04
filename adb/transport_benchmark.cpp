/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <stdio.h>

#include <android-base/logging.h>
#include <benchmark/benchmark.h>

#include "adb_trace.h"
#include "sysdeps.h"
#include "transport.h"

#define ADB_CONNECTION_BENCHMARK(benchmark_name, ...)               \
    BENCHMARK_TEMPLATE(benchmark_name, FdConnection, ##__VA_ARGS__) \
        ->Arg(1)                                                    \
        ->Arg(16384)                                                \
        ->Arg(MAX_PAYLOAD)                                          \
        ->UseRealTime()

template <typename ConnectionType>
std::unique_ptr<Connection> MakeConnection(unique_fd fd);

template <>
std::unique_ptr<Connection> MakeConnection<FdConnection>(unique_fd fd) {
    auto fd_connection = std::make_unique<FdConnection>(std::move(fd));
    return std::make_unique<BlockingConnectionAdapter>(std::move(fd_connection));
}

template <typename ConnectionType>
void BM_Connection_Unidirectional(benchmark::State& state) {
    int fds[2];
    if (adb_socketpair(fds) != 0) {
        LOG(FATAL) << "failed to create socketpair";
    }

    auto client = MakeConnection<ConnectionType>(unique_fd(fds[0]));
    auto server = MakeConnection<ConnectionType>(unique_fd(fds[1]));

    std::atomic<size_t> received_bytes;

    client->SetReadCallback([](Connection*, std::unique_ptr<apacket>) -> bool { return true; });
    server->SetReadCallback([&received_bytes](Connection*, std::unique_ptr<apacket> packet) -> bool {
        received_bytes += packet->payload.size();
        return true;
    });

    client->SetErrorCallback(
        [](Connection*, const std::string& error) { LOG(INFO) << "client closed: " << error; });
    server->SetErrorCallback(
        [](Connection*, const std::string& error) { LOG(INFO) << "server closed: " << error; });

    client->Start();
    server->Start();

    for (auto _ : state) {
        size_t data_size = state.range(0);
        std::unique_ptr<apacket> packet = std::make_unique<apacket>();
        memset(&packet->msg, 0, sizeof(packet->msg));
        packet->msg.command = A_WRTE;
        packet->msg.data_length = data_size;
        packet->payload.resize(data_size);

        memset(&packet->payload[0], 0xff, data_size);

        received_bytes = 0;
        client->Write(std::move(packet));
        while (received_bytes < data_size) {
            continue;
        }
    }
    state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) * state.range(0));

    client->Stop();
    server->Stop();
}

ADB_CONNECTION_BENCHMARK(BM_Connection_Unidirectional);

enum class ThreadPolicy {
    MainThread,
    SameThread,
};

template <typename ConnectionType, enum ThreadPolicy Policy>
void BM_Connection_Echo(benchmark::State& state) {
    int fds[2];
    if (adb_socketpair(fds) != 0) {
        LOG(FATAL) << "failed to create socketpair";
    }

    auto client = MakeConnection<ConnectionType>(unique_fd(fds[0]));
    auto server = MakeConnection<ConnectionType>(unique_fd(fds[1]));

    std::atomic<size_t> received_bytes;

    fdevent_reset();
    std::thread fdevent_thread([]() { fdevent_loop(); });

    client->SetReadCallback([&received_bytes](Connection*, std::unique_ptr<apacket> packet) -> bool {
        received_bytes += packet->payload.size();
        return true;
    });

    static const auto handle_packet = [](Connection* connection, std::unique_ptr<apacket> packet) {
        connection->Write(std::move(packet));
    };

    server->SetReadCallback([](Connection* connection, std::unique_ptr<apacket> packet) -> bool {
        if (Policy == ThreadPolicy::MainThread) {
            auto raw_packet = packet.release();
            fdevent_run_on_main_thread([connection, raw_packet]() {
                std::unique_ptr<apacket> packet(raw_packet);
                handle_packet(connection, std::move(packet));
            });
        } else {
            handle_packet(connection, std::move(packet));
        }
        return true;
    });

    client->SetErrorCallback(
        [](Connection*, const std::string& error) { LOG(INFO) << "client closed: " << error; });
    server->SetErrorCallback(
        [](Connection*, const std::string& error) { LOG(INFO) << "server closed: " << error; });

    client->Start();
    server->Start();

    for (auto _ : state) {
        size_t data_size = state.range(0);
        std::unique_ptr<apacket> packet = std::make_unique<apacket>();
        memset(&packet->msg, 0, sizeof(packet->msg));
        packet->msg.command = A_WRTE;
        packet->msg.data_length = data_size;
        packet->payload.resize(data_size);

        memset(&packet->payload[0], 0xff, data_size);

        received_bytes = 0;
        client->Write(std::move(packet));
        while (received_bytes < data_size) {
            continue;
        }
    }
    state.SetBytesProcessed(static_cast<int64_t>(state.iterations()) * state.range(0));

    client->Stop();
    server->Stop();

    // TODO: Make it so that you don't need to poke the fdevent loop to make it terminate?
    fdevent_terminate_loop();
    fdevent_run_on_main_thread([]() {});

    fdevent_thread.join();
}

ADB_CONNECTION_BENCHMARK(BM_Connection_Echo, ThreadPolicy::SameThread);
ADB_CONNECTION_BENCHMARK(BM_Connection_Echo, ThreadPolicy::MainThread);

int main(int argc, char** argv) {
    android::base::SetMinimumLogSeverity(android::base::WARNING);
    adb_trace_init(argv);
    ::benchmark::Initialize(&argc, argv);
    if (::benchmark::ReportUnrecognizedArguments(argc, argv)) return 1;
    ::benchmark::RunSpecifiedBenchmarks();
}
