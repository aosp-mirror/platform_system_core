// Copyright 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/crash_sender_service.h"

#include <curl/curl.h>

#include <algorithm>
#include <utility>

#include <base/bind.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/format_macros.h>
#include <base/logging.h>
#include <base/message_loop/message_loop.h>
#include <base/rand_util.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/time/time.h>
#include <dbus/bus.h>

#include "vboot/crossystem.h"

namespace {

// Default product ID in crash report (used if GOOGLE_CRASH_* is undefined).
const char kDefaultProduct[] = "ChromeOS";

// File whose existence implies crash reports may be sent, and whose
// contents includes our machine's anonymized guid.
const char kConsentIdPath[] = "/home/chronos/Consent To Send Stats";

// Crash sender lock in case the sender is already running.
const char kCrashSenderLockPath[] = "/var/lock/crash_sender";

// Crash sender lock in case the sender is already running for tests.
const char kCrashSenderLockForTestsPath[] = "/var/lock/crash_sender_test";

// Path to file that indicates a crash test is currently running.
const char kCrashTestInProgressPath[] = "/tmp/crash-test-in-progress";

// Path to hardware class description.
const char kHWClassPath[] = "/sys/devices/platform/chromeos_acpi/HWID";

// Path to file that indicates this is a developer image.
const char kLeaveCorePath[] = "/root/.leave_core";

// File whose existence causes crash sending to be delayed (for testing).
// Must be stateful to enable testing kernel crashes.
const char kPauseCrashSendingPath[] = "/var/lib/crash_sender_paused";

// Path to a directory of restricted certificates which includes
// a certificate for ${REPORT_UPLOAD_PROD_URL}.
const char kRestrictedCertificatesPath[] =
    "/usr/share/chromeos-ca-certificates";

// File whose existence implies we're running and not to start again.
const char kRunFilePath[] = "/var/run/crash_sender.pid";

// Directory to store timestamp files indicating the uploads in the past 24
// hours.
const char kTimestampsDirPath[] = "/var/lib/crash_sender";

// Chrome's crash report log file.
const char kChromeCrashLogPath[] = "/var/log/chrome/Crash Reports/uploads.log";

// File whose existence mocks crash sending. If empty we pretend the crash
// sending was successful, otherwise unsuccessful.
const char kMockCrashSendingPath[] = "/tmp/mock-crash-sending";

// Configuration keys.
const char kForceOfficial[] = "FORCE_OFFICIAL";
const char kMaxCrashRate[] = "MAX_CRASH_RATE";
const char kMockDeveloperMode[] = "MOCK_DEVELOPER_MODE";
const char kOverridePauseSending[] = "OVERRIDE_PAUSE_SENDING";
const char kReportUploadProdUrl[] = "REPORT_UPLOAD_PROD_URL";
const char kSecondsSendSpread[] = "SECONDS_SEND_SPREAD";

// Owns a curl handle.
class ScopedCurl {
 public:
  explicit ScopedCurl(bool mock) : mock_(mock) {
    if (!mock)
      curl_ = curl_easy_init();
  }

  ~ScopedCurl() {
    if (mock_)
      return;

    if (post_)
      curl_formfree(post_);

    curl_easy_cleanup(curl_);
  }

  CURL* curl() const { return curl_; }

  void AddMultipartContent(std::string key, std::string value) {
    LOG(INFO) << key << ": " << value;
    if (mock_)
      return;
    curl_formadd(&post_, &last_,
                 CURLFORM_COPYNAME, key.c_str(),
                 CURLFORM_COPYCONTENTS, value.c_str(),
                 CURLFORM_END);
  }

  void AddFile(std::string key, base::FilePath file) {
    LOG(INFO) << key << ": " << file.value();
    if (mock_)
      return;
    curl_formadd(&post_, &last_,
                 CURLFORM_COPYNAME, key.c_str(),
                 CURLFORM_FILE, file.value().c_str(),
                 CURLFORM_END);
  }

  CURLcode perform() {
    CHECK(!mock_);
    curl_easy_setopt(curl_, CURLOPT_HTTPPOST, post_);
    return curl_easy_perform(curl_);
  }

 private:
  bool mock_;
  CURL* curl_ = nullptr;
  struct curl_httppost* post_ = nullptr;
  struct curl_httppost* last_ = nullptr;

  DISALLOW_COPY_AND_ASSIGN(ScopedCurl);
};

// Comparison function.
bool order_meta_files(const crash_reporter::MetaFile& f1,
                      const crash_reporter::MetaFile& f2) {
  return std::make_tuple(f1.modification_time, f1.path.value()) <
         std::make_tuple(f2.modification_time, f2.path.value());
}

// Return the list of directories containing crashes.
std::vector<base::FilePath> GetCrashDirectories() {
  std::vector<base::FilePath> result;
  base::FilePath system_wide("/var/spool/crash");
  if (base::DirectoryExists(system_wide))
    result.push_back(system_wide);

  base::FilePath main_user("/home/chronos/crash");
  if (base::DirectoryExists(main_user))
    result.push_back(main_user);

  base::FileEnumerator enumCrashDirectories(
      base::FilePath("/home/chronos"), false, base::FileEnumerator::DIRECTORIES,
      FILE_PATH_LITERAL("u-*"));
  for (base::FilePath dir = enumCrashDirectories.Next(); !dir.empty();
       dir = enumCrashDirectories.Next()) {
    base::FilePath crash_dir = dir.Append("crash");
    if (base::DirectoryExists(crash_dir))
      result.push_back(crash_dir);
  }
  return result;
}

// Returns all the files in a given directory with the time of last
// modification.
std::vector<std::pair<base::Time, base::FilePath>> GetOrderedFiles(
    const base::FilePath& dir) {
  std::vector<std::pair<base::Time, base::FilePath>> files;
  base::FileEnumerator enumFiles(dir, false, base::FileEnumerator::FILES);
  for (base::FilePath file = enumFiles.Next(); !file.empty();
       file = enumFiles.Next()) {
    files.push_back(
        std::make_pair(enumFiles.GetInfo().GetLastModifiedTime(), file));
  }
  return files;
}

// Parse a file containing key value of the form:
// KEY=VALUE
std::map<std::string, std::string> ParseKeyValueFile(
    const base::FilePath& file) {
  std::map<std::string, std::string> result;
  std::string content;
  if (!base::ReadFileToString(file, &content)) {
    LOG(WARNING) << "Unable to read key values from: " << file.value();
    return result;
  }
  base::StringPairs pairs;
  base::SplitStringIntoKeyValuePairs(content, '=', '\n', &pairs);
  for (base::StringPairs::const_iterator pair = pairs.begin();
       pair != pairs.end(); ++pair) {
    if (!pair->first.empty() && pair->first[0] != '#')
      result[pair->first] = pair->second;
  }

  return result;
}

// Returns the value associated to |key| in |map|, or |default_value| if |map|
// doesn't contain |key|.
std::string GetValue(const std::map<std::string, std::string>& map,
                     const std::string& key, const std::string& default_value) {
  std::map<std::string, std::string>::const_iterator it = map.find(key);
  if (it != map.end())
    return it->second;

  return default_value;
}

// As |GetValue| for values of type |base::FilePath|.
base::FilePath GetPathValue(const std::map<std::string, std::string>& map,
                            const std::string& key,
                            const base::FilePath& default_value) {
  std::map<std::string, std::string>::const_iterator it = map.find(key);
  if (it != map.end())
    return base::FilePath(it->second);

  return default_value;
}

// As |GetValue| for values of type |int|.
int GetIntValue(const std::map<std::string, std::string>& map,
                const std::string& key, int default_value) {
  std::map<std::string, std::string>::const_iterator it = map.find(key);
  if (it != map.end()) {
    int result;
    if (base::StringToInt(it->second, &result)) {
      return result;
    }
  }
  return default_value;
}

// Remove the report for the given |meta_file|.
void RemoveReport(const base::FilePath& meta_file) {
  LOG(INFO) << "Removing report: " << meta_file.value();
  base::FilePath directory = meta_file.DirName();
  base::FilePath template_value = meta_file.ReplaceExtension(".*").BaseName();

  base::FileEnumerator filesToDelete(
      directory, false, base::FileEnumerator::FILES, template_value.value());
  for (base::FilePath file = filesToDelete.Next(); !file.empty();
       file = filesToDelete.Next()) {
    if (!base::DeleteFile(file, false))
      LOG(WARNING) << "Unable to delete " << file.value();
  }
}

// Returns the extenstion of the given file, stripping .gz if the file is
// compressed.
std::string GetExtension(const base::FilePath& file) {
  std::string extension = file.FinalExtension();
  if (extension == ".gz")
    extension = file.RemoveFinalExtension().FinalExtension();

  if (!extension.empty()) {
    DCHECK_EQ(extension[0], '.');
    extension = extension.substr(1);
  }
  return extension;
}

// Returns the report kind.
std::string GetKind(const crash_reporter::MetaFile& meta_file) {
  base::FilePath payload =
      GetPathValue(meta_file.meta_information, "payload", base::FilePath());
  if (payload.value().empty() || !base::PathExists(payload)) {
    LOG(WARNING) << "Missing payload on file: " << meta_file.path.value();
    return "";
  }
  std::string kind = GetExtension(payload);
  if (kind == "dmp") {
    return "minidump";
  }
  return kind;
}

// Callback function for curl. It delegates to a callback passed as additional
// data.
size_t CurlWriteData(void* buffer, size_t size, size_t nmemb, void* data) {
  base::Callback<size_t(void*, size_t)>* callback =
      static_cast<base::Callback<size_t(void*, size_t)>*>(data);
  return callback->Run(buffer, size * nmemb);
}

size_t AppendDataToString(std::string* data, const void* buffer, size_t size) {
  data->append(reinterpret_cast<const char*>(buffer), size);
  return size;
}


}  // namespace

namespace crash_reporter {

CrashSenderService::CrashSenderService(const CrashSenderConfiguration& config)
    : config_(config) {
  metrics_lib_.Init();
}

CrashSenderService::~CrashSenderService() {}

bool CrashSenderService::Start(ProxyResolver* proxy_resolver) {
  proxy_resolver_ = proxy_resolver;
  std::map<std::string, std::string> lsb_release_values =
      ParseKeyValueFile(base::FilePath("/etc/lsb-release"));

  board_ = lsb_release_values["CHROMEOS_RELEASE_BOARD"];
  if (board_.empty()) {
    LOG(ERROR) << "Unable to retrieve board information.";
    return false;
  }

  channel_ = lsb_release_values["CHROMEOS_RELEASE_TRACK"];
  const char kChannelSuffix[] = "-channel";
  if (EndsWith(channel_, kChannelSuffix, true))
    channel_ =
        channel_.substr(0, channel_.size() - arraysize(kChannelSuffix) + 1);

  if (channel_.empty()) {
    LOG(ERROR) << "Unable to retrieve channel information.";
    return false;
  }

  official_ =
      (lsb_release_values["CHROMEOS_RELEASE_DESCRIPTION"].find("Official") !=
       std::string::npos);

  std::map<std::string, std::string> os_release_values =
      ParseKeyValueFile(base::FilePath("/etc/os-release"));

  default_product_ = GetValue(os_release_values, "GOOGLE_CRASH_ID", "");
  if (default_product_.empty())
    default_product_ = GetValue(os_release_values, "ID", "");

  default_version_ = GetValue(os_release_values, "GOOGLE_CRASH_VERSION_ID", "");
  if (default_version_.empty())
    default_version_ = GetValue(os_release_values, "VERSION_ID", "");

  return ReapplyConfig(config_);
}

void CrashSenderService::Restart(const CrashSenderConfiguration& config) {
  CrashSenderConfiguration old_config = config_;
  config_ = config;
  if (!ReapplyConfig(config_)) {
    LOG(ERROR) << "Restarting failed. Reapplying old configuration.";
    config_ = old_config;
    CHECK(ReapplyConfig(config_));
  }
}

CrashSenderConfiguration CrashSenderService::ParseConfiguration(
    const base::FilePath& config_file) {
  CrashSenderConfiguration result;
  std::map<std::string, std::string> key_values =
      ParseKeyValueFile(config_file);

  result.force_official = GetIntValue(key_values, kForceOfficial, false);
  result.max_crash_rate = GetIntValue(key_values, kMaxCrashRate, 32);
  result.mock_developer_mode =
      GetIntValue(key_values, kMockDeveloperMode, false);
  result.override_pause_sending =
      GetIntValue(key_values, kOverridePauseSending, false);
  result.report_upload_prod_url =
      GetValue(key_values, kReportUploadProdUrl,
               "https://clients2.google.com/cr/report");
  result.seconds_send_spread = GetIntValue(key_values, kSecondsSendSpread, 600);

  return result;
}

bool CrashSenderService::ReapplyConfig(const CrashSenderConfiguration& config) {
  bool test_run = IsMock();
  const char* lock_path =
      test_run ? kCrashSenderLockForTestsPath : kCrashSenderLockPath;
  lock_file_.reset(
      new base::File(base::FilePath(lock_path), base::File::FLAG_OPEN_ALWAYS |
                                                    base::File::FLAG_READ |
                                                    base::File::FLAG_WRITE));
  if (lock_file_->Lock() != base::File::FILE_OK) {
    LOG(ERROR) << "Already running; quitting.";
    return false;
  }
  base::FilePath run_file(kRunFilePath);
  run_file_deleter_.Reset(
      base::Bind(base::IgnoreResult(&base::DeleteFile), run_file, false));
  std::string pid = base::IntToString(getpid()) + "\n";
  base::WriteFile(run_file, pid.data(), pid.length());

  CollectAllCrashes();
  if (test_run) {
    base::MessageLoop::current()->PostTask(FROM_HERE,
                                           base::MessageLoop::QuitClosure());
    LOG(INFO) << "crash_sender done.";
  }
  return true;
}

bool CrashSenderService::IsCrashTestInProgress() const {
  return base::PathExists(base::FilePath(kCrashTestInProgressPath));
}

bool CrashSenderService::IsTestImage() const {
  if (IsCrashTestInProgress())
    return false;

  return StartsWithASCII(channel_, "test", true);
}

bool CrashSenderService::IsMock() const {
  return base::PathExists(base::FilePath(kMockCrashSendingPath));
}

bool CrashSenderService::IsMockSuccessful() const {
  std::string content;
  if (base::ReadFileToString(base::FilePath(kMockCrashSendingPath), &content))
    return content.empty();

  return false;
}

bool CrashSenderService::IsOfficialImage() const {
  return config_.force_official || official_;
}

bool CrashSenderService::IsDeveloperMode() const {
  if (config_.mock_developer_mode)
    return true;

  if (IsCrashTestInProgress())
    return false;

  return VbGetSystemPropertyInt("devsw_boot");
}

bool CrashSenderService::IsDeveloperImage() const {
  // Mirrors crash_collector.cc:CrashCollector::IsDeveloperImage().
  if (IsCrashTestInProgress())
    return false;

  return base::PathExists(base::FilePath(kLeaveCorePath));
}

std::string CrashSenderService::GetHardwareClass() const {
  std::string content;
  if (base::ReadFileToString(base::FilePath(kHWClassPath), &content))
    return content;

  char buffer[VB_MAX_STRING_PROPERTY];
  const char* hwid =
      VbGetSystemPropertyString("hwid", buffer, VB_MAX_STRING_PROPERTY);
  if (hwid)
    return hwid;

  return "undefined";
}

std::string CrashSenderService::GetConsentId() const {
  std::string content;
  if (base::ReadFileToString(base::FilePath(kConsentIdPath), &content)) {
    content.erase(std::remove(content.begin(), content.end(), '-'),
                  content.end());
    return content;
  }

  return "undefined";
}

void CrashSenderService::CollectCrashes(const base::FilePath& dir) {
  std::vector<std::pair<base::Time, base::FilePath>> files =
      GetOrderedFiles(dir);
  base::Time now = base::Time::Now();
  for (const std::pair<base::Time, base::FilePath>& file : files) {
    if (file.second.FinalExtension() == ".meta") {
      MetaFile info;
      info.modification_time = file.first;
      info.path = file.second;
      info.meta_information = ParseKeyValueFile(info.path);
      switch (FilterCrashes(info)) {
        case CAN_UPLOAD:
          current_crashes_.push_back(info);
          break;
        case DELETE:
          RemoveReport(info.path);
          break;
        case WAIT:
          // Nothing
          break;
      }
    } else if ((now - file.first >= base::TimeDelta::FromDays(1)) &&
               !base::PathExists(file.second.ReplaceExtension(".meta"))) {
      if (base::DeleteFile(file.second, false)) {
        LOG(INFO) << "Removing old orphaned file: " << file.second.value();
      } else {
        LOG(WARNING) << "Unable to delete: " << file.second.value();
      }
    }
  }
}

void CrashSenderService::CollectAllCrashes() {
  current_crashes_.clear();

  std::vector<base::FilePath> crash_directories = GetCrashDirectories();
  for (const base::FilePath& path : crash_directories) {
    CrashSenderService::CollectCrashes(path);
  }
  std::sort(current_crashes_.begin(), current_crashes_.end(),
            &order_meta_files);

  if (current_crashes_.empty()) {
    // If no crash is present, wait for an hour.
    ScheduleNext();
    return;
  }

  PrepareToSendNextCrash();
}

CrashSenderService::FileStatus CrashSenderService::FilterCrashes(
    const MetaFile& file) {
  if (!metrics_lib_.AreMetricsEnabled()) {
    LOG(INFO) << "Crash reporting is disabled.  Removing crash.";
    return DELETE;
  }

  if (!IsMock() && !IsOfficialImage()) {
    LOG(INFO) << "Not an official OS version.  Removing crash.";
    return DELETE;
  }

  if (GetValue(file.meta_information, "done", "") != "1") {
    // This report is incomplete, so if it's old, just remove it
    if (base::Time::Now() - file.modification_time >=
        base::TimeDelta::FromDays(1)) {
      LOG(INFO) << "Removing old incomplete metadata.";
      return DELETE;
    } else {
      LOG(INFO) << "Ignoring recent incomplete metadata.";
      return WAIT;
    }
  }

  std::string report_kind = GetKind(file);
  if (report_kind != "minidump" && report_kind != "kcrash" &&
      report_kind != "log") {
    LOG(INFO) << "Unknown report kind " << report_kind << ".  Removing report.";
    return DELETE;
  }

  return CAN_UPLOAD;
}

bool CrashSenderService::MustThrottle() const {
  base::FilePath timestamps_dir(kTimestampsDirPath);
  if (!base::CreateDirectoryAndGetError(timestamps_dir, nullptr)) {
    LOG(WARNING) << "Unable to create directory: " << timestamps_dir.value();
    return true;
  }

  base::Time now = base::Time::Now();
  base::FileEnumerator timestamps(timestamps_dir, false,
                                  base::FileEnumerator::FILES);
  int sends_in_24hrs = 0;
  for (base::FilePath file = timestamps.Next(); !file.empty();
       file = timestamps.Next()) {
    if (now - timestamps.GetInfo().GetLastModifiedTime() >=
        base::TimeDelta::FromDays(1)) {
      base::DeleteFile(file, false);
    } else {
      ++sends_in_24hrs;
    }
  }
  LOG(INFO) << "Current send rate: " << sends_in_24hrs << "sends/24hrs";
  if (sends_in_24hrs >= config_.max_crash_rate) {
    LOG(INFO) << "Cannot send more crashes: current " << sends_in_24hrs
              << "send/24hrs >= max " << config_.max_crash_rate << "send/24hrs";
    return true;
  }
  base::FilePath tmp_file;
  if (!base::CreateTemporaryFileInDir(timestamps_dir, &tmp_file)) {
    LOG(WARNING) << "Unable to create a file in " << timestamps_dir.value();
    return true;
  }
  return false;
}

void CrashSenderService::PrepareToSendNextCrash() {
  // If we cannot send any crashes, wait one hour.
  if (!CanSendNextCrash()) {
    ScheduleNext();
    return;
  }

  // If there is no crash to send, collect crashes and return.
  if (current_crashes_.empty()) {
    CollectAllCrashes();
    return;
  }

  const MetaFile& file = current_crashes_.front();
  base::TimeDelta time_to_wait =
      std::max(file.modification_time + base::TimeDelta::FromSeconds(30) -
                   base::Time::Now(),
               base::TimeDelta::FromSeconds(
                   base::RandInt(1, config_.seconds_send_spread)));
  LOG(INFO) << "Scheduled to send " << file.path.value() << " in "
            << time_to_wait.InSeconds() << "s.";

  if (IsMock()) {
    SendNextCrash();
  } else {
    timer_.Start(FROM_HERE, time_to_wait, this,
                 &CrashSenderService::SendNextCrash);
  }
}

bool CrashSenderService::CanSendNextCrash() {
  // Handle pause crash sending
  base::FilePath pause_crash_sending(kPauseCrashSendingPath);
  if (base::PathExists(pause_crash_sending) &&
      !config_.override_pause_sending) {
    LOG(INFO) << "Not sending crashes due to " << pause_crash_sending.value();
    return false;
  }

  // Handle is test image
  if (IsTestImage()) {
    LOG(INFO) << "Not sending crashes due to test image.";
    return false;
  }

  // Handle certificate path
  base::FilePath restricted_certificates_path(kRestrictedCertificatesPath);
  if (!base::DirectoryExists(restricted_certificates_path)) {
    LOG(INFO) << "Not sending crashes due to "
              << restricted_certificates_path.value() << " missing.";
    return false;
  }

  // Guest mode.
  if (metrics_lib_.IsGuestMode()) {
    LOG(INFO)
        << "Guest mode has been entered. Delaying crash sending until exited.";
    return false;
  }

  return true;
}

void CrashSenderService::SendNextCrash() {
  // Ensure the timer will be called again if this is exited early due to
  // exceptional conditions.
  ScheduleNext();

  if (!CanSendNextCrash())
    return;

  // Check uploads rate
  if (MustThrottle()) {
    LOG(INFO) << "Sending a report would exceed rate. Leaving for later.";
    return;
  }

  const MetaFile file = current_crashes_[0];
  current_crashes_.erase(current_crashes_.begin());

  // Trying to send a crash. Preparing next crash.
  base::ScopedClosureRunner send_next_crash(base::Bind(
      &CrashSenderService::PrepareToSendNextCrash, base::Unretained(this)));
  // Delete the report whatever the result.
  base::ScopedClosureRunner report_delete(base::Bind(&RemoveReport, file.path));

  ScopedCurl curl(IsMock());

  LOG(INFO) << "Sending crash:";
  std::string product = GetValue(file.meta_information, "upload_var_prod", "");
  if (product.empty())
    product = default_product_;

  if (product.empty())
    product = kDefaultProduct;

  curl.AddMultipartContent("prod", product);
  if (product != kDefaultProduct)
    LOG(INFO) << "Sending crash report on behalf of " << product;

  LOG(INFO) << "Metadata: " << file.path.value() << " (" << GetKind(file)
            << ")";

  std::string version = GetValue(file.meta_information, "upload_var_ver", "");
  if (version.empty())
    version = default_version_;
  if (version.empty())
    version = GetValue(file.meta_information, "ver", "");

  curl.AddMultipartContent("ver", version);
  curl.AddMultipartContent("board", board_);
  curl.AddMultipartContent("hwclass", GetHardwareClass());
  curl.AddMultipartContent(
      "exec_name", GetValue(file.meta_information, "exec_name", "undefined"));

  std::string image_type;
  if (IsTestImage()) {
    image_type = "test";
  } else if (IsDeveloperImage()) {
    image_type = "dev";
  } else if (config_.force_official) {
    image_type = "force-official";
  } else if (IsMock() && !IsMockSuccessful()) {
    image_type = "mock-fail";
  }
  if (!image_type.empty())
    curl.AddMultipartContent("image_type", image_type);

  if (VbGetSystemPropertyInt("cros_debug") && IsDeveloperMode())
    curl.AddMultipartContent("boot_mode", "dev");

  std::string error_type = GetValue(file.meta_information, "error_type", "");
  if (!error_type.empty())
    curl.AddMultipartContent("error_type", error_type);

  curl.AddMultipartContent("guid", GetConsentId());
  curl.AddMultipartContent(
      "write_payload_size",
      GetValue(file.meta_information, "payload_size", "undefined"));

  base::FilePath payload =
      GetPathValue(file.meta_information, "payload", base::FilePath());
  if (!payload.value().empty()) {
    int64 file_size;
    if (base::GetFileSize(payload, &file_size)) {
      curl.AddMultipartContent("send_payload_size",
                               base::Int64ToString(file_size));
      curl.AddFile("upload_file_" + GetKind(file), payload);
    }
  }

  std::string signature = GetValue(file.meta_information, "sig", "");
  if (!signature.empty()) {
    curl.AddMultipartContent("sig", signature);
    curl.AddMultipartContent("sig2", signature);
  }

  base::FilePath log =
      GetPathValue(file.meta_information, "log", base::FilePath());
  if (base::PathExists(log))
    curl.AddFile("log", log);

  std::string upload_prefix =
      GetValue(file.meta_information, "upload_prefix", "");

  const char kUploadVarPrefix[] = "upload_var_";
  const char kUploadFilePrefix[] = "upload_file_";
  for (const auto& pair : file.meta_information) {
    if (StartsWithASCII(pair.first, kUploadVarPrefix, true)) {
      curl.AddMultipartContent(
          upload_prefix + pair.first.substr(arraysize(kUploadVarPrefix) - 1),
          pair.second);
    }
    if (StartsWithASCII(pair.first, kUploadFilePrefix, true)) {
      curl.AddFile(
          upload_prefix + pair.first.substr(arraysize(kUploadFilePrefix) - 1),
          base::FilePath(pair.second));
    }
  }

  if (IsMock()) {
    if (IsMockSuccessful()) {
      LOG(INFO) << "Mocking successful send";
    } else {
      LOG(INFO) << "Mocking unsuccessful send";
    }
    return;
  }

  curl_easy_setopt(curl.curl(), CURLOPT_URL,
                   config_.report_upload_prod_url.c_str());
  curl_easy_setopt(curl.curl(), CURLOPT_POST, 1L);
  std::vector<std::string> proxies = proxy_resolver_->GetProxiesForUrl(
      config_.report_upload_prod_url, base::TimeDelta::FromSeconds(5));
  if (proxies.size() && proxies[0] != "direct://")
    curl_easy_setopt(curl.curl(), CURLOPT_PROXY, proxies[0].c_str());

  // TODO(qsr) Remove
  curl_easy_setopt(curl.curl(), CURLOPT_PROXY, "http://192.168.45.1:8888");

  std::string received_data = "";
  base::Callback<size_t(const void*, size_t)> callback =
      base::Bind(&AppendDataToString, &received_data);
  curl_easy_setopt(curl.curl(), CURLOPT_WRITEFUNCTION, &CurlWriteData);
  curl_easy_setopt(curl.curl(), CURLOPT_WRITEDATA, &callback);

  CURLcode success = curl.perform();

  if (success != 0 || received_data.size() > 20) {
    LOG(ERROR) << "Unable to upload crash report. Error code: " << success;
    return;
  }

  std::string product_name;
  if (product == "Chrome_ChromeOS") {
    if (IsOfficialImage()) {
      product_name = "Chrome";
    } else {
      product_name = "Chromium";
    }
  } else {
    if (IsOfficialImage()) {
      product_name = "ChromeOS";
    } else {
      product_name = "ChromiumOS";
    }
  }
  std::string log_string = base::StringPrintf(
      "%" PRIu64 ",%s,%s\n", static_cast<uint64_t>(base::Time::Now().ToTimeT()),
      received_data.c_str(), product_name.c_str());
  if (base::AppendToFile(base::FilePath(kChromeCrashLogPath), log_string.data(),
                         log_string.size()) == -1) {
    LOG(ERROR) << "Unable to update crash log.";
  }
}

void CrashSenderService::ScheduleNext() {
  timer_.Start(FROM_HERE, base::TimeDelta::FromHours(1), this,
               &CrashSenderService::PrepareToSendNextCrash);
}

DbusCrashSenderServiceImpl::DbusCrashSenderServiceImpl(
    const CrashSenderConfiguration& config)
    : CrashSenderService(config) {}

DbusCrashSenderServiceImpl::~DbusCrashSenderServiceImpl() {}

bool DbusCrashSenderServiceImpl::Start(dbus::Bus* bus) {
  if (!bus || !bus->Connect()) {
    LOG(ERROR) << "Failed to connect to DBus";
    return false;
  }

  bus_ = bus;
  proxy_resolver_.reset(new DBusProxyResolver(bus_));
  proxy_resolver_->Init();
  return CrashSenderService::Start(proxy_resolver_.get());
}

}  // namespace crash_reporter
