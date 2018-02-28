/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <signal.h>
#include <sys/types.h>
#include <unistd.h>

#include <binder/Binder.h>
#include <binder/IBinder.h>
#include <binder/IServiceManager.h>
#include <binder/Parcel.h>
#include <binder/ProcessState.h>

#include <gtest/gtest.h>

#include "Allocator.h"
#include "Binder.h"

namespace android {

static const String16 service_name("test.libmemunreachable_binder");

// Provides a service that will hold a strong reference to any remote binder
// object, so that the test can verify that a remote strong reference is
// visible to libmemunreachable.
class BinderService : public BBinder {
 public:
  BinderService() = default;
  virtual ~BinderService() = default;

  virtual status_t onTransact(uint32_t /*code*/, const Parcel& data, Parcel* reply,
                              uint32_t /*flags*/ = 0) {
    reply->writeStrongBinder(ref);
    ref = data.readStrongBinder();
    return 0;
  }

 private:
  sp<IBinder> ref;
};

class BinderObject : public BBinder {
 public:
  BinderObject() = default;
  ~BinderObject() = default;
};

// Forks a subprocess that registers a BinderService with the global binder
// servicemanager.  Requires root permissions.
class ServiceProcess {
 public:
  ServiceProcess() : child_(0) {}
  ~ServiceProcess() { Stop(); }

  bool Run() {
    pid_t ret = fork();
    if (ret < 0) {
      return false;
    } else if (ret == 0) {
      // child
      _exit(Service());
    } else {
      // parent
      child_ = ret;
      return true;
    }
  }

  bool Stop() {
    if (child_ > 0) {
      if (kill(child_, SIGTERM)) {
        return false;
      }
      int status = 0;
      if (TEMP_FAILURE_RETRY(waitpid(child_, &status, 0)) != child_) {
        return false;
      }
      child_ = 0;
      return WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }

    return true;
  }

  int Service() {
    sp<ProcessState> proc{ProcessState::self()};
    sp<IServiceManager> sm = defaultServiceManager();
    if (sm == nullptr) {
      fprintf(stderr, "Failed to get service manager\n");
      return 1;
    }
    // This step requires root permissions
    if (sm->addService(service_name, new BinderService()) != OK) {
      fprintf(stderr, "Failed to add test service\n");
      return 1;
    }
    proc->startThreadPool();
    pause();
    return 0;
  }

 private:
  pid_t child_;
};

class MemunreachableBinderTest : public ::testing::Test {
 protected:
  ServiceProcess service_process_;
};

// Tests that a local binder object with a remote strong reference is visible
// through the libmemunreachable BinderReferences interface, which uses the
// getBinderKernelReferences method in libbinder.  Starts a BinderService
// through ServiceProcess as a remote service to hold the strong reference.
TEST_F(MemunreachableBinderTest, binder) {
  ASSERT_EQ(static_cast<uid_t>(0), getuid()) << "This test must be run as root.";

  ServiceProcess service_process;
  ASSERT_TRUE(service_process.Run());

  sp<IServiceManager> sm = defaultServiceManager();
  ASSERT_TRUE(sm != nullptr);

  // A small sleep allows the service to start, which
  // prevents a longer sleep in getService.
  usleep(100000);

  sp<IBinder> service = sm->getService(service_name);
  ASSERT_TRUE(service != nullptr);

  sp<IBinder> binder{new BinderObject()};

  Parcel send;
  Parcel reply;

  send.writeStrongBinder(binder);
  status_t rv = service->transact(0, send, &reply);
  ASSERT_EQ(static_cast<status_t>(OK), rv);

  Heap heap;
  allocator::vector<uintptr_t> refs{heap};

  ASSERT_TRUE(BinderReferences(refs));

  bool found_ref = false;
  for (auto ref : refs) {
    if (ref == reinterpret_cast<uintptr_t>(binder.get())) {
      found_ref = true;
    }
  }

  ASSERT_TRUE(found_ref);
}

}  // namespace android
