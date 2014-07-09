// Copyright 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRASH_REPORTER_CRASH_SENDER_SERVICE_H_
#define CRASH_REPORTER_CRASH_SENDER_SERVICE_H_

#include <map>
#include <string>
#include <vector>

#include <base/callback_helpers.h>
#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/memory/ref_counted.h>
#include <base/timer/timer.h>

#include "crash-reporter/proxy_resolver.h"
#include "metrics/metrics_library.h"

namespace dbus {
class Bus;
}  // namespace dbus

namespace crash_reporter {

// The configuration for the crash sender. See |crash_sender.conf| for details.
struct CrashSenderConfiguration {
  bool force_official;
  int max_crash_rate;
  bool mock_developer_mode;
  bool override_pause_sending;
  std::string report_upload_prod_url;
  int seconds_send_spread;
};

// The information about a crash report, which is obtained from the associated
// meta file.
struct MetaFile {
  base::Time modification_time;
  base::FilePath path;
  std::map<std::string, std::string> meta_information;
};

class CrashSenderService {
 public:
  explicit CrashSenderService(const CrashSenderConfiguration& config);
  virtual ~CrashSenderService();

  bool Start(ProxyResolver* proxy_resolver);

  void Restart(const CrashSenderConfiguration& config);

  static CrashSenderConfiguration ParseConfiguration(
      const base::FilePath& config_file);

 private:
  enum FileStatus {
    CAN_UPLOAD,
    WAIT,
    DELETE,
  };

  bool ReapplyConfig(const CrashSenderConfiguration& config);
  bool IsCrashTestInProgress() const;
  bool IsTestImage() const;
  bool IsMock() const;
  bool IsMockSuccessful() const;
  bool IsOfficialImage() const;
  bool IsDeveloperMode() const;
  bool IsDeveloperImage() const;
  std::string GetHardwareClass() const;
  std::string GetConsentId() const;
  void CollectCrashes(const base::FilePath& dir);
  void CollectAllCrashes();
  FileStatus FilterCrashes(const MetaFile& file);
  bool MustThrottle() const;
  void PrepareToSendNextCrash();
  bool CanSendNextCrash();
  void SendNextCrash();
  void ScheduleNext();

  ProxyResolver* proxy_resolver_ = nullptr;
  CrashSenderConfiguration config_;
  MetricsLibrary metrics_lib_;
  base::OneShotTimer<CrashSenderService> timer_;
  base::ScopedClosureRunner run_file_deleter_;
  scoped_ptr<base::File> lock_file_;
  std::string channel_;
  std::string board_;
  std::string default_product_;
  std::string default_version_;
  bool official_ = false;
  std::vector<MetaFile> current_crashes_;

  DISALLOW_COPY_AND_ASSIGN(CrashSenderService);
};

class DbusCrashSenderServiceImpl : public CrashSenderService {
 public:
  explicit DbusCrashSenderServiceImpl(const CrashSenderConfiguration& config);
  virtual ~DbusCrashSenderServiceImpl();

  bool Start(dbus::Bus* bus);

 private:
  dbus::Bus* bus_ = nullptr;
  scoped_ptr<DBusProxyResolver> proxy_resolver_;

  DISALLOW_COPY_AND_ASSIGN(DbusCrashSenderServiceImpl);
};
}  // namespace crash_reporter

#endif  // CRASH_REPORTER_CRASH_SENDER_SERVICE_H_
