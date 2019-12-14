/*
 * Copyright (C) 2017 The Android Open Source Project
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
#include <fcntl.h>
#include <fnmatch.h>
#include <getopt.h>
#include <inttypes.h>
#include <libgen.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <set>
#include <string>

#include <android-base/file.h>
#include <android-base/strings.h>
#include <ziparchive/zip_archive.h>

using android::base::EndsWith;
using android::base::StartsWith;

enum OverwriteMode {
  kAlways,
  kNever,
  kPrompt,
};

enum Role {
  kUnzip,
  kZipinfo,
};

static Role role;
static OverwriteMode overwrite_mode = kPrompt;
static bool flag_1 = false;
static std::string flag_d;
static bool flag_l = false;
static bool flag_p = false;
static bool flag_q = false;
static bool flag_v = false;
static bool flag_x = false;
static const char* archive_name = nullptr;
static std::set<std::string> includes;
static std::set<std::string> excludes;
static uint64_t total_uncompressed_length = 0;
static uint64_t total_compressed_length = 0;
static size_t file_count = 0;

static const char* g_progname;

static void die(int error, const char* fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  fprintf(stderr, "%s: ", g_progname);
  vfprintf(stderr, fmt, ap);
  if (error != 0) fprintf(stderr, ": %s", strerror(error));
  fprintf(stderr, "\n");
  va_end(ap);
  exit(1);
}

static bool ShouldInclude(const std::string& name) {
  // Explicitly excluded?
  if (!excludes.empty()) {
    for (const auto& exclude : excludes) {
      if (!fnmatch(exclude.c_str(), name.c_str(), 0)) return false;
    }
  }

  // Implicitly included?
  if (includes.empty()) return true;

  // Explicitly included?
  for (const auto& include : includes) {
    if (!fnmatch(include.c_str(), name.c_str(), 0)) return true;
  }
  return false;
}

static bool MakeDirectoryHierarchy(const std::string& path) {
  // stat rather than lstat because a symbolic link to a directory is fine too.
  struct stat sb;
  if (stat(path.c_str(), &sb) != -1 && S_ISDIR(sb.st_mode)) return true;

  // Ensure the parent directories exist first.
  if (!MakeDirectoryHierarchy(android::base::Dirname(path))) return false;

  // Then try to create this directory.
  return (mkdir(path.c_str(), 0777) != -1);
}

static float CompressionRatio(int64_t uncompressed, int64_t compressed) {
  if (uncompressed == 0) return 0;
  return static_cast<float>(100LL * (uncompressed - compressed)) /
         static_cast<float>(uncompressed);
}

static void MaybeShowHeader(ZipArchiveHandle zah) {
  if (role == kUnzip) {
    // unzip has three formats.
    if (!flag_q) printf("Archive:  %s\n", archive_name);
    if (flag_v) {
      printf(
          " Length   Method    Size  Cmpr    Date    Time   CRC-32   Name\n"
          "--------  ------  ------- ---- ---------- ----- --------  ----\n");
    } else if (flag_l) {
      printf(
          "  Length      Date    Time    Name\n"
          "---------  ---------- -----   ----\n");
    }
  } else {
    // zipinfo.
    if (!flag_1 && includes.empty() && excludes.empty()) {
      ZipArchiveInfo info{GetArchiveInfo(zah)};
      printf("Archive:  %s\n", archive_name);
      printf("Zip file size: %" PRId64 " bytes, number of entries: %zu\n", info.archive_size,
             info.entry_count);
    }
  }
}

static void MaybeShowFooter() {
  if (role == kUnzip) {
    if (flag_v) {
      printf(
          "--------          -------  ---                            -------\n"
          "%8" PRId64 "         %8" PRId64 " %3.0f%%                            %zu file%s\n",
          total_uncompressed_length, total_compressed_length,
          CompressionRatio(total_uncompressed_length, total_compressed_length), file_count,
          (file_count == 1) ? "" : "s");
    } else if (flag_l) {
      printf(
          "---------                     -------\n"
          "%9" PRId64 "                     %zu file%s\n",
          total_uncompressed_length, file_count, (file_count == 1) ? "" : "s");
    }
  } else {
    if (!flag_1 && includes.empty() && excludes.empty()) {
      printf("%zu files, %" PRId64 " bytes uncompressed, %" PRId64 " bytes compressed:  %.1f%%\n",
             file_count, total_uncompressed_length, total_compressed_length,
             CompressionRatio(total_uncompressed_length, total_compressed_length));
    }
  }
}

static bool PromptOverwrite(const std::string& dst) {
  // TODO: [r]ename not implemented because it doesn't seem useful.
  printf("replace %s? [y]es, [n]o, [A]ll, [N]one: ", dst.c_str());
  fflush(stdout);
  while (true) {
    char* line = nullptr;
    size_t n;
    if (getline(&line, &n, stdin) == -1) {
      die(0, "(EOF/read error; assuming [N]one...)");
      overwrite_mode = kNever;
      return false;
    }
    if (n == 0) continue;
    char cmd = line[0];
    free(line);
    switch (cmd) {
      case 'y':
        return true;
      case 'n':
        return false;
      case 'A':
        overwrite_mode = kAlways;
        return true;
      case 'N':
        overwrite_mode = kNever;
        return false;
    }
  }
}

static void ExtractToPipe(ZipArchiveHandle zah, ZipEntry& entry, const std::string& name) {
  // We need to extract to memory because ExtractEntryToFile insists on
  // being able to seek and truncate, and you can't do that with stdout.
  uint8_t* buffer = new uint8_t[entry.uncompressed_length];
  int err = ExtractToMemory(zah, &entry, buffer, entry.uncompressed_length);
  if (err < 0) {
    die(0, "failed to extract %s: %s", name.c_str(), ErrorCodeString(err));
  }
  if (!android::base::WriteFully(1, buffer, entry.uncompressed_length)) {
    die(errno, "failed to write %s to stdout", name.c_str());
  }
  delete[] buffer;
}

static void ExtractOne(ZipArchiveHandle zah, ZipEntry& entry, const std::string& name) {
  // Bad filename?
  if (StartsWith(name, "/") || StartsWith(name, "../") || name.find("/../") != std::string::npos) {
    die(0, "bad filename %s", name.c_str());
  }

  // Where are we actually extracting to (for human-readable output)?
  // flag_d is the empty string if -d wasn't used, or has a trailing '/'
  // otherwise.
  std::string dst = flag_d + name;

  // Ensure the directory hierarchy exists.
  if (!MakeDirectoryHierarchy(android::base::Dirname(name))) {
    die(errno, "couldn't create directory hierarchy for %s", dst.c_str());
  }

  // An entry in a zip file can just be a directory itself.
  if (EndsWith(name, "/")) {
    if (mkdir(name.c_str(), entry.unix_mode) == -1) {
      // If the directory already exists, that's fine.
      if (errno == EEXIST) {
        struct stat sb;
        if (stat(name.c_str(), &sb) != -1 && S_ISDIR(sb.st_mode)) return;
      }
      die(errno, "couldn't extract directory %s", dst.c_str());
    }
    return;
  }

  // Create the file.
  int fd = open(name.c_str(), O_CREAT | O_WRONLY | O_CLOEXEC | O_EXCL, entry.unix_mode);
  if (fd == -1 && errno == EEXIST) {
    if (overwrite_mode == kNever) return;
    if (overwrite_mode == kPrompt && !PromptOverwrite(dst)) return;
    // Either overwrite_mode is kAlways or the user consented to this specific case.
    fd = open(name.c_str(), O_WRONLY | O_CREAT | O_CLOEXEC | O_TRUNC, entry.unix_mode);
  }
  if (fd == -1) die(errno, "couldn't create file %s", dst.c_str());

  // Actually extract into the file.
  if (!flag_q) printf("  inflating: %s\n", dst.c_str());
  int err = ExtractEntryToFile(zah, &entry, fd);
  if (err < 0) die(0, "failed to extract %s: %s", dst.c_str(), ErrorCodeString(err));
  close(fd);
}

static void ListOne(const ZipEntry& entry, const std::string& name) {
  tm t = entry.GetModificationTime();
  char time[32];
  snprintf(time, sizeof(time), "%04d-%02d-%02d %02d:%02d", t.tm_year + 1900, t.tm_mon + 1,
           t.tm_mday, t.tm_hour, t.tm_min);
  if (flag_v) {
    printf("%8d  %s  %7d %3.0f%% %s %08x  %s\n", entry.uncompressed_length,
           (entry.method == kCompressStored) ? "Stored" : "Defl:N", entry.compressed_length,
           CompressionRatio(entry.uncompressed_length, entry.compressed_length), time, entry.crc32,
           name.c_str());
  } else {
    printf("%9d  %s   %s\n", entry.uncompressed_length, time, name.c_str());
  }
}

static void InfoOne(const ZipEntry& entry, const std::string& name) {
  if (flag_1) {
    // "android-ndk-r19b/sources/android/NOTICE"
    printf("%s\n", name.c_str());
    return;
  }

  int version = entry.version_made_by & 0xff;
  int os = (entry.version_made_by >> 8) & 0xff;

  // TODO: Support suid/sgid? Non-Unix/non-FAT host file system attributes?
  const char* src_fs = "???";
  char mode[] = "???       ";
  if (os == 0) {
    src_fs = "fat";
    // https://docs.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants
    int attrs = entry.external_file_attributes & 0xff;
    mode[0] = (attrs & 0x10) ? 'd' : '-';
    mode[1] = 'r';
    mode[2] = (attrs & 0x01) ? '-' : 'w';
    // The man page also mentions ".btm", but that seems to be obsolete?
    mode[3] = EndsWith(name, ".exe") || EndsWith(name, ".com") || EndsWith(name, ".bat") ||
                      EndsWith(name, ".cmd")
                  ? 'x'
                  : '-';
    mode[4] = (attrs & 0x20) ? 'a' : '-';
    mode[5] = (attrs & 0x02) ? 'h' : '-';
    mode[6] = (attrs & 0x04) ? 's' : '-';
  } else if (os == 3) {
    src_fs = "unx";
    mode[0] = S_ISDIR(entry.unix_mode) ? 'd' : (S_ISREG(entry.unix_mode) ? '-' : '?');
    mode[1] = entry.unix_mode & S_IRUSR ? 'r' : '-';
    mode[2] = entry.unix_mode & S_IWUSR ? 'w' : '-';
    mode[3] = entry.unix_mode & S_IXUSR ? 'x' : '-';
    mode[4] = entry.unix_mode & S_IRGRP ? 'r' : '-';
    mode[5] = entry.unix_mode & S_IWGRP ? 'w' : '-';
    mode[6] = entry.unix_mode & S_IXGRP ? 'x' : '-';
    mode[7] = entry.unix_mode & S_IROTH ? 'r' : '-';
    mode[8] = entry.unix_mode & S_IWOTH ? 'w' : '-';
    mode[9] = entry.unix_mode & S_IXOTH ? 'x' : '-';
  }

  char method[5] = "stor";
  if (entry.method == kCompressDeflated) {
    snprintf(method, sizeof(method), "def%c", "NXFS"[(entry.gpbf >> 1) & 0x3]);
  }

  // TODO: zipinfo (unlike unzip) sometimes uses time zone?
  // TODO: this uses 4-digit years because we're not barbarians unless interoperability forces it.
  tm t = entry.GetModificationTime();
  char time[32];
  snprintf(time, sizeof(time), "%04d-%02d-%02d %02d:%02d", t.tm_year + 1900, t.tm_mon + 1,
           t.tm_mday, t.tm_hour, t.tm_min);

  // "-rw-r--r--  3.0 unx      577 t- defX 19-Feb-12 16:09 android-ndk-r19b/sources/android/NOTICE"
  printf("%s %2d.%d %s %8d %c%c %s %s %s\n", mode, version / 10, version % 10, src_fs,
         entry.uncompressed_length, entry.is_text ? 't' : 'b',
         entry.has_data_descriptor ? 'X' : 'x', method, time, name.c_str());
}

static void ProcessOne(ZipArchiveHandle zah, ZipEntry& entry, const std::string& name) {
  if (role == kUnzip) {
    if (flag_l || flag_v) {
      // -l or -lv or -lq or -v.
      ListOne(entry, name);
    } else {
      // Actually extract.
      if (flag_p) {
        ExtractToPipe(zah, entry, name);
      } else {
        ExtractOne(zah, entry, name);
      }
    }
  } else {
    // zipinfo or zipinfo -1.
    InfoOne(entry, name);
  }
  total_uncompressed_length += entry.uncompressed_length;
  total_compressed_length += entry.compressed_length;
  ++file_count;
}

static void ProcessAll(ZipArchiveHandle zah) {
  MaybeShowHeader(zah);

  // libziparchive iteration order doesn't match the central directory.
  // We could sort, but that would cost extra and wouldn't match either.
  void* cookie;
  int err = StartIteration(zah, &cookie);
  if (err != 0) {
    die(0, "couldn't iterate %s: %s", archive_name, ErrorCodeString(err));
  }

  ZipEntry entry;
  std::string name;
  while ((err = Next(cookie, &entry, &name)) >= 0) {
    if (ShouldInclude(name)) ProcessOne(zah, entry, name);
  }

  if (err < -1) die(0, "failed iterating %s: %s", archive_name, ErrorCodeString(err));
  EndIteration(cookie);

  MaybeShowFooter();
}

static void ShowHelp(bool full) {
  if (role == kUnzip) {
    fprintf(full ? stdout : stderr, "usage: unzip [-d DIR] [-lnopqv] ZIP [FILE...] [-x FILE...]\n");
    if (!full) exit(EXIT_FAILURE);

    printf(
        "\n"
        "Extract FILEs from ZIP archive. Default is all files. Both the include and\n"
        "exclude (-x) lists use shell glob patterns.\n"
        "\n"
        "-d DIR	Extract into DIR\n"
        "-l	List contents (-lq excludes archive name, -lv is verbose)\n"
        "-n	Never overwrite files (default: prompt)\n"
        "-o	Always overwrite files\n"
        "-p	Pipe to stdout\n"
        "-q	Quiet\n"
        "-v	List contents verbosely\n"
        "-x FILE	Exclude files\n");
  } else {
    fprintf(full ? stdout : stderr, "usage: zipinfo [-1] ZIP [FILE...] [-x FILE...]\n");
    if (!full) exit(EXIT_FAILURE);

    printf(
        "\n"
        "Show information about FILEs from ZIP archive. Default is all files.\n"
        "Both the include and exclude (-x) lists use shell glob patterns.\n"
        "\n"
        "-1	Show filenames only, one per line\n"
        "-x FILE	Exclude files\n");
  }
  exit(EXIT_SUCCESS);
}

static void HandleCommonOption(int opt) {
  switch (opt) {
    case 'h':
      ShowHelp(true);
      break;
    case 'x':
      flag_x = true;
      break;
    case 1:
      // -x swallows all following arguments, so we use '-' in the getopt
      // string and collect files here.
      if (!archive_name) {
        archive_name = optarg;
      } else if (flag_x) {
        excludes.insert(optarg);
      } else {
        includes.insert(optarg);
      }
      break;
    default:
      ShowHelp(false);
      break;
  }
}

int main(int argc, char* argv[]) {
  // Who am I, and what am I doing?
  g_progname = basename(argv[0]);
  if (!strcmp(g_progname, "ziptool") && argc > 1) return main(argc - 1, argv + 1);
  if (!strcmp(g_progname, "unzip")) {
    role = kUnzip;
  } else if (!strcmp(g_progname, "zipinfo")) {
    role = kZipinfo;
  } else {
    die(0, "run as ziptool with unzip or zipinfo as the first argument, or symlink");
  }

  static const struct option opts[] = {
      {"help", no_argument, 0, 'h'},
      {},
  };

  if (role == kUnzip) {
    // `unzip -Z` is "zipinfo mode", so in that case just restart...
    if (argc > 1 && !strcmp(argv[1], "-Z")) {
      argv[1] = const_cast<char*>("zipinfo");
      return main(argc - 1, argv + 1);
    }

    int opt;
    while ((opt = getopt_long(argc, argv, "-d:hlnopqvx", opts, nullptr)) != -1) {
      switch (opt) {
        case 'd':
          flag_d = optarg;
          if (!EndsWith(flag_d, "/")) flag_d += '/';
          break;
        case 'l':
          flag_l = true;
          break;
        case 'n':
          overwrite_mode = kNever;
          break;
        case 'o':
          overwrite_mode = kAlways;
          break;
        case 'p':
          flag_p = flag_q = true;
          break;
        case 'q':
          flag_q = true;
          break;
        case 'v':
          flag_v = true;
          break;
        default:
          HandleCommonOption(opt);
          break;
      }
    }
  } else {
    int opt;
    while ((opt = getopt_long(argc, argv, "-1hx", opts, nullptr)) != -1) {
      switch (opt) {
        case '1':
          flag_1 = true;
          break;
        default:
          HandleCommonOption(opt);
          break;
      }
    }
  }

  if (!archive_name) die(0, "missing archive filename");

  // We can't support "-" to unzip from stdin because libziparchive relies on mmap.
  ZipArchiveHandle zah;
  int32_t err;
  if ((err = OpenArchive(archive_name, &zah)) != 0) {
    die(0, "couldn't open %s: %s", archive_name, ErrorCodeString(err));
  }

  // Implement -d by changing into that directory.
  // We'll create implicit directories based on paths in the zip file, and we'll create
  // the -d directory itself, but we require that *parents* of the -d directory already exists.
  // This is pretty arbitrary, but it's the behavior of the original unzip.
  if (!flag_d.empty()) {
    if (mkdir(flag_d.c_str(), 0777) == -1 && errno != EEXIST) {
      die(errno, "couldn't created %s", flag_d.c_str());
    }
    if (chdir(flag_d.c_str()) == -1) {
      die(errno, "couldn't chdir to %s", flag_d.c_str());
    }
  }

  ProcessAll(zah);

  CloseArchive(zah);
  return 0;
}
