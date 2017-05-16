/*
 * Copyright (C) 2007-2016 The Android Open Source Project
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

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include <experimental/string_view>
#include <functional>
#include <string>
#include <unordered_map>

#include <log/event_tag_map.h>
#include <log/log_properties.h>
#include <private/android_logger.h>
#include <utils/FastStrcmp.h>
#include <utils/RWLock.h>

#include "log_portability.h"
#include "logd_reader.h"

#define OUT_TAG "EventTagMap"

class MapString {
 private:
  const std::string* alloc;                  // HAS-AN
  const std::experimental::string_view str;  // HAS-A

 public:
  operator const std::experimental::string_view() const {
    return str;
  }

  const char* data() const {
    return str.data();
  }
  size_t length() const {
    return str.length();
  }

  bool operator==(const MapString& rval) const {
    if (length() != rval.length()) return false;
    if (length() == 0) return true;
    return fastcmp<strncmp>(data(), rval.data(), length()) == 0;
  }
  bool operator!=(const MapString& rval) const {
    return !(*this == rval);
  }

  MapString(const char* str, size_t len) : alloc(NULL), str(str, len) {
  }
  explicit MapString(const std::string& str)
      : alloc(new std::string(str)), str(alloc->data(), alloc->length()) {
  }
  MapString(MapString&& rval)
      : alloc(rval.alloc), str(rval.data(), rval.length()) {
    rval.alloc = NULL;
  }
  explicit MapString(const MapString& rval)
      : alloc(rval.alloc ? new std::string(*rval.alloc) : NULL),
        str(alloc ? alloc->data() : rval.data(), rval.length()) {
  }

  ~MapString() {
    if (alloc) delete alloc;
  }
};

// Hash for MapString
template <>
struct std::hash<MapString>
    : public std::unary_function<const MapString&, size_t> {
  size_t operator()(const MapString& __t) const noexcept {
    if (!__t.length()) return 0;
    return std::hash<std::experimental::string_view>()(
        std::experimental::string_view(__t));
  }
};

typedef std::pair<MapString, MapString> TagFmt;

template <>
struct std::hash<TagFmt> : public std::unary_function<const TagFmt&, size_t> {
  size_t operator()(const TagFmt& __t) const noexcept {
    // Tag is typically unique.  Will cost us an extra 100ns for the
    // unordered_map lookup if we instead did a hash that combined
    // both of tag and fmt members, e.g.:
    //
    // return std::hash<MapString>()(__t.first) ^
    //        std::hash<MapString>()(__t.second);
    return std::hash<MapString>()(__t.first);
  }
};

// Map
struct EventTagMap {
#define NUM_MAPS 2
  // memory-mapped source file; we get strings from here
  void* mapAddr[NUM_MAPS];
  size_t mapLen[NUM_MAPS];

 private:
  std::unordered_map<uint32_t, TagFmt> Idx2TagFmt;
  std::unordered_map<TagFmt, uint32_t> TagFmt2Idx;
  std::unordered_map<MapString, uint32_t> Tag2Idx;
  // protect unordered sets
  android::RWLock rwlock;

 public:
  EventTagMap() {
    memset(mapAddr, 0, sizeof(mapAddr));
    memset(mapLen, 0, sizeof(mapLen));
  }

  ~EventTagMap() {
    Idx2TagFmt.clear();
    TagFmt2Idx.clear();
    Tag2Idx.clear();
    for (size_t which = 0; which < NUM_MAPS; ++which) {
      if (mapAddr[which]) {
        munmap(mapAddr[which], mapLen[which]);
        mapAddr[which] = 0;
      }
    }
  }

  bool emplaceUnique(uint32_t tag, const TagFmt& tagfmt, bool verbose = false);
  const TagFmt* find(uint32_t tag) const;
  int find(TagFmt&& tagfmt) const;
  int find(MapString&& tag) const;
};

bool EventTagMap::emplaceUnique(uint32_t tag, const TagFmt& tagfmt,
                                bool verbose) {
  bool ret = true;
  static const char errorFormat[] =
      OUT_TAG ": duplicate tag entries %" PRIu32 ":%.*s:%.*s and %" PRIu32
              ":%.*s:%.*s)\n";
  android::RWLock::AutoWLock writeLock(rwlock);
  {
    std::unordered_map<uint32_t, TagFmt>::const_iterator it;
    it = Idx2TagFmt.find(tag);
    if (it != Idx2TagFmt.end()) {
      if (verbose) {
        fprintf(stderr, errorFormat, it->first, (int)it->second.first.length(),
                it->second.first.data(), (int)it->second.second.length(),
                it->second.second.data(), tag, (int)tagfmt.first.length(),
                tagfmt.first.data(), (int)tagfmt.second.length(),
                tagfmt.second.data());
      }
      ret = false;
    } else {
      Idx2TagFmt.emplace(std::make_pair(tag, tagfmt));
    }
  }

  {
    std::unordered_map<TagFmt, uint32_t>::const_iterator it;
    it = TagFmt2Idx.find(tagfmt);
    if (it != TagFmt2Idx.end()) {
      if (verbose) {
        fprintf(stderr, errorFormat, it->second, (int)it->first.first.length(),
                it->first.first.data(), (int)it->first.second.length(),
                it->first.second.data(), tag, (int)tagfmt.first.length(),
                tagfmt.first.data(), (int)tagfmt.second.length(),
                tagfmt.second.data());
      }
      ret = false;
    } else {
      TagFmt2Idx.emplace(std::make_pair(tagfmt, tag));
    }
  }

  {
    std::unordered_map<MapString, uint32_t>::const_iterator it;
    it = Tag2Idx.find(tagfmt.first);
    if (!tagfmt.second.length() && (it != Tag2Idx.end())) {
      Tag2Idx.erase(it);
      it = Tag2Idx.end();
    }
    if (it == Tag2Idx.end()) {
      Tag2Idx.emplace(std::make_pair(tagfmt.first, tag));
    }
  }

  return ret;
}

const TagFmt* EventTagMap::find(uint32_t tag) const {
  std::unordered_map<uint32_t, TagFmt>::const_iterator it;
  android::RWLock::AutoRLock readLock(const_cast<android::RWLock&>(rwlock));
  it = Idx2TagFmt.find(tag);
  if (it == Idx2TagFmt.end()) return NULL;
  return &(it->second);
}

int EventTagMap::find(TagFmt&& tagfmt) const {
  std::unordered_map<TagFmt, uint32_t>::const_iterator it;
  android::RWLock::AutoRLock readLock(const_cast<android::RWLock&>(rwlock));
  it = TagFmt2Idx.find(std::move(tagfmt));
  if (it == TagFmt2Idx.end()) return -1;
  return it->second;
}

int EventTagMap::find(MapString&& tag) const {
  std::unordered_map<MapString, uint32_t>::const_iterator it;
  android::RWLock::AutoRLock readLock(const_cast<android::RWLock&>(rwlock));
  it = Tag2Idx.find(std::move(tag));
  if (it == Tag2Idx.end()) return -1;
  return it->second;
}

// The position after the end of a valid section of the tag string,
// caller makes sure delimited appropriately.
static const char* endOfTag(const char* cp) {
  while (*cp && (isalnum(*cp) || strchr("_.-@,", *cp))) ++cp;
  return cp;
}

// Scan one tag line.
//
// "pData" should be pointing to the first digit in the tag number.  On
// successful return, it will be pointing to the last character in the
// tag line (i.e. the character before the start of the next line).
//
// lineNum = 0 removes verbose comments and requires us to cache the
// content rather than make direct raw references since the content
// will disappear after the call. A non-zero lineNum means we own the
// data and it will outlive the call.
//
// Returns 0 on success, nonzero on failure.
static int scanTagLine(EventTagMap* map, const char*& pData, int lineNum) {
  char* ep;
  unsigned long val = strtoul(pData, &ep, 10);
  const char* cp = ep;
  if (cp == pData) {
    if (lineNum) {
      fprintf(stderr, OUT_TAG ": malformed tag number on line %d\n", lineNum);
    }
    errno = EINVAL;
    return -1;
  }

  uint32_t tagIndex = val;
  if (tagIndex != val) {
    if (lineNum) {
      fprintf(stderr, OUT_TAG ": tag number too large on line %d\n", lineNum);
    }
    errno = ERANGE;
    return -1;
  }

  while ((*++cp != '\n') && isspace(*cp)) {
  }

  if (*cp == '\n') {
    if (lineNum) {
      fprintf(stderr, OUT_TAG ": missing tag string on line %d\n", lineNum);
    }
    errno = EINVAL;
    return -1;
  }

  const char* tag = cp;
  cp = endOfTag(cp);
  size_t tagLen = cp - tag;

  if (!isspace(*cp)) {
    if (lineNum) {
      fprintf(stderr, OUT_TAG ": invalid tag char %c on line %d\n", *cp,
              lineNum);
    }
    errno = EINVAL;
    return -1;
  }

  while (isspace(*cp) && (*cp != '\n')) ++cp;
  const char* fmt = NULL;
  size_t fmtLen = 0;
  if (*cp && (*cp != '#')) {
    fmt = cp;
    while (*cp && (*cp != '\n') && (*cp != '#')) ++cp;
    while ((cp > fmt) && isspace(*(cp - 1))) --cp;
    fmtLen = cp - fmt;
  }

  // KISS Only report identicals if they are global
  // Ideally we want to check if there are identicals
  // recorded for the same uid, but recording that
  // unused detail in our database is too burdensome.
  bool verbose = true;
  while (*cp && (*cp != '#') && (*cp != '\n')) ++cp;
  if (*cp == '#') {
    do {
      ++cp;
    } while (isspace(*cp) && (*cp != '\n'));
    verbose = !!fastcmp<strncmp>(cp, "uid=", strlen("uid="));
  }

  while (*cp && (*cp != '\n')) ++cp;
#ifdef DEBUG
  fprintf(stderr, "%d: %p: %.*s\n", lineNum, tag, (int)(cp - pData), pData);
#endif
  pData = cp;

  if (lineNum) {
    if (map->emplaceUnique(tagIndex,
                           TagFmt(std::make_pair(MapString(tag, tagLen),
                                                 MapString(fmt, fmtLen))),
                           verbose)) {
      return 0;
    }
  } else {
    // cache
    if (map->emplaceUnique(
            tagIndex,
            TagFmt(std::make_pair(MapString(std::string(tag, tagLen)),
                                  MapString(std::string(fmt, fmtLen)))))) {
      return 0;
    }
  }
  errno = EMLINK;
  return -1;
}

static const char* eventTagFiles[NUM_MAPS] = {
  EVENT_TAG_MAP_FILE, "/dev/event-log-tags",
};

// Parse the tags out of the file.
static int parseMapLines(EventTagMap* map, size_t which) {
  const char* cp = static_cast<char*>(map->mapAddr[which]);
  size_t len = map->mapLen[which];
  const char* endp = cp + len;

  // insist on EOL at EOF; simplifies parsing and null-termination
  if (!len || (*(endp - 1) != '\n')) {
#ifdef DEBUG
    fprintf(stderr, OUT_TAG ": map file %zu[%zu] missing EOL on last line\n",
            which, len);
#endif
    if (which) {  // do not propagate errors for other files
      return 0;
    }
    errno = EINVAL;
    return -1;
  }

  bool lineStart = true;
  int lineNum = 1;
  while (cp < endp) {
    if (*cp == '\n') {
      lineStart = true;
      lineNum++;
    } else if (lineStart) {
      if (*cp == '#') {
        // comment; just scan to end
        lineStart = false;
      } else if (isdigit(*cp)) {
        // looks like a tag; scan it out
        if (scanTagLine(map, cp, lineNum) != 0) {
          if (!which || (errno != EMLINK)) {
            return -1;
          }
        }
        lineNum++;  // we eat the '\n'
                    // leave lineStart==true
      } else if (isspace(*cp)) {
        // looks like leading whitespace; keep scanning
      } else {
        fprintf(stderr,
                OUT_TAG
                ": unexpected chars (0x%02x) in tag number on line %d\n",
                *cp, lineNum);
        errno = EINVAL;
        return -1;
      }
    } else {
      // this is a blank or comment line
    }
    cp++;
  }

  return 0;
}

// Open the map file and allocate a structure to manage it.
//
// We create a private mapping because we want to terminate the log tag
// strings with '\0'.
LIBLOG_ABI_PUBLIC EventTagMap* android_openEventTagMap(const char* fileName) {
  EventTagMap* newTagMap;
  off_t end[NUM_MAPS];
  int save_errno, fd[NUM_MAPS];
  size_t which;

  memset(fd, -1, sizeof(fd));
  memset(end, 0, sizeof(end));

  for (which = 0; which < NUM_MAPS; ++which) {
    const char* tagfile = fileName ? fileName : eventTagFiles[which];

    fd[which] = open(tagfile, O_RDONLY | O_CLOEXEC);
    if (fd[which] < 0) {
      if (!which) {
        save_errno = errno;
        fprintf(stderr, OUT_TAG ": unable to open map '%s': %s\n", tagfile,
                strerror(save_errno));
        goto fail_errno;
      }
      continue;
    }
    end[which] = lseek(fd[which], 0L, SEEK_END);
    save_errno = errno;
    (void)lseek(fd[which], 0L, SEEK_SET);
    if (!which && (end[0] < 0)) {
      fprintf(stderr, OUT_TAG ": unable to seek map '%s' %s\n", tagfile,
              strerror(save_errno));
      goto fail_close;
    }
    if (fileName) break;  // Only allow one as specified
  }

  newTagMap = new EventTagMap;
  if (newTagMap == NULL) {
    save_errno = errno;
    goto fail_close;
  }

  for (which = 0; which < NUM_MAPS; ++which) {
    if (fd[which] >= 0) {
      newTagMap->mapAddr[which] =
          mmap(NULL, end[which], which ? PROT_READ : PROT_READ | PROT_WRITE,
               which ? MAP_SHARED : MAP_PRIVATE, fd[which], 0);
      save_errno = errno;
      close(fd[which]); /* fd DONE */
      fd[which] = -1;
      if ((newTagMap->mapAddr[which] != MAP_FAILED) &&
          (newTagMap->mapAddr[which] != NULL)) {
        newTagMap->mapLen[which] = end[which];
      } else if (!which) {
        const char* tagfile = fileName ? fileName : eventTagFiles[which];

        fprintf(stderr, OUT_TAG ": mmap(%s) failed: %s\n", tagfile,
                strerror(save_errno));
        goto fail_unmap;
      }
    }
  }

  for (which = 0; which < NUM_MAPS; ++which) {
    if (parseMapLines(newTagMap, which) != 0) {
      delete newTagMap;
      return NULL;
    }
    /* See 'fd DONE' comments above and below, no need to clean up here */
  }

  return newTagMap;

fail_unmap:
  save_errno = EINVAL;
  delete newTagMap;
fail_close:
  for (which = 0; which < NUM_MAPS; ++which) close(fd[which]); /* fd DONE */
fail_errno:
  errno = save_errno;
  return NULL;
}

// Close the map.
LIBLOG_ABI_PUBLIC void android_closeEventTagMap(EventTagMap* map) {
  if (map) delete map;
}

// Cache miss, go to logd to acquire a public reference.
// Because we lack access to a SHARED PUBLIC /dev/event-log-tags file map?
static const TagFmt* __getEventTag(EventTagMap* map, unsigned int tag) {
  // call event tag service to arrange for a new tag
  char* buf = NULL;
  // Can not use android::base::StringPrintf, asprintf + free instead.
  static const char command_template[] = "getEventTag id=%u";
  int ret = asprintf(&buf, command_template, tag);
  if (ret > 0) {
    // Add some buffer margin for an estimate of the full return content.
    size_t size =
        ret - strlen(command_template) +
        strlen("65535\n4294967295\t?\t\t\t?\t# uid=32767\n\n\f?success?");
    if (size > (size_t)ret) {
      char* np = static_cast<char*>(realloc(buf, size));
      if (np) {
        buf = np;
      } else {
        size = ret;
      }
    } else {
      size = ret;
    }
    // Ask event log tag service for an existing entry
    if (__send_log_msg(buf, size) >= 0) {
      buf[size - 1] = '\0';
      char* ep;
      unsigned long val = strtoul(buf, &ep, 10);  // return size
      const char* cp = ep;
      if ((buf != cp) && (val > 0) && (*cp == '\n')) {  // truncation OK
        ++cp;
        if (!scanTagLine(map, cp, 0)) {
          free(buf);
          return map->find(tag);
        }
      }
    }
    free(buf);
  }
  return NULL;
}

// Look up an entry in the map.
LIBLOG_ABI_PUBLIC const char* android_lookupEventTag_len(const EventTagMap* map,
                                                         size_t* len,
                                                         unsigned int tag) {
  if (len) *len = 0;
  const TagFmt* str = map->find(tag);
  if (!str) {
    str = __getEventTag(const_cast<EventTagMap*>(map), tag);
  }
  if (!str) return NULL;
  if (len) *len = str->first.length();
  return str->first.data();
}

// Look up an entry in the map.
LIBLOG_ABI_PUBLIC const char* android_lookupEventFormat_len(
    const EventTagMap* map, size_t* len, unsigned int tag) {
  if (len) *len = 0;
  const TagFmt* str = map->find(tag);
  if (!str) {
    str = __getEventTag(const_cast<EventTagMap*>(map), tag);
  }
  if (!str) return NULL;
  if (len) *len = str->second.length();
  return str->second.data();
}

// This function is deprecated and replaced with android_lookupEventTag_len
// since it will cause the map to change from Shared and backed by a file,
// to Private Dirty and backed up by swap, albeit highly compressible. By
// deprecating this function everywhere, we save 100s of MB of memory space.
LIBLOG_ABI_PUBLIC const char* android_lookupEventTag(const EventTagMap* map,
                                                     unsigned int tag) {
  size_t len;
  const char* tagStr = android_lookupEventTag_len(map, &len, tag);

  if (!tagStr) return tagStr;
  char* cp = const_cast<char*>(tagStr);
  cp += len;
  if (*cp) *cp = '\0';  // Trigger copy on write :-( and why deprecated.
  return tagStr;
}

// Look up tagname, generate one if necessary, and return a tag
LIBLOG_ABI_PUBLIC int android_lookupEventTagNum(EventTagMap* map,
                                                const char* tagname,
                                                const char* format, int prio) {
  const char* ep = endOfTag(tagname);
  size_t len = ep - tagname;
  if (!len || *ep) {
    errno = EINVAL;
    return -1;
  }

  if ((prio != ANDROID_LOG_UNKNOWN) && (prio < ANDROID_LOG_SILENT) &&
      !__android_log_is_loggable_len(prio, tagname, len,
                                     __android_log_is_debuggable()
                                         ? ANDROID_LOG_VERBOSE
                                         : ANDROID_LOG_DEBUG)) {
    errno = EPERM;
    return -1;
  }

  if (!format) format = "";
  ssize_t fmtLen = strlen(format);
  int ret = map->find(TagFmt(
      std::make_pair(MapString(tagname, len), MapString(format, fmtLen))));
  if (ret != -1) return ret;

  // call event tag service to arrange for a new tag
  char* buf = NULL;
  // Can not use android::base::StringPrintf, asprintf + free instead.
  static const char command_template[] = "getEventTag name=%s format=\"%s\"";
  ret = asprintf(&buf, command_template, tagname, format);
  if (ret > 0) {
    // Add some buffer margin for an estimate of the full return content.
    char* cp;
    size_t size =
        ret - strlen(command_template) +
        strlen("65535\n4294967295\t?\t\t\t?\t# uid=32767\n\n\f?success?");
    if (size > (size_t)ret) {
      cp = static_cast<char*>(realloc(buf, size));
      if (cp) {
        buf = cp;
      } else {
        size = ret;
      }
    } else {
      size = ret;
    }
    // Ask event log tag service for an allocation
    if (__send_log_msg(buf, size) >= 0) {
      buf[size - 1] = '\0';
      unsigned long val = strtoul(buf, &cp, 10);        // return size
      if ((buf != cp) && (val > 0) && (*cp == '\n')) {  // truncation OK
        val = strtoul(cp + 1, &cp, 10);                 // allocated tag number
        if ((val > 0) && (val < UINT32_MAX) && (*cp == '\t')) {
          free(buf);
          ret = val;
          // cache
          map->emplaceUnique(ret, TagFmt(std::make_pair(
                                      MapString(std::string(tagname, len)),
                                      MapString(std::string(format, fmtLen)))));
          return ret;
        }
      }
    }
    free(buf);
  }

  // Hail Mary
  ret = map->find(MapString(tagname, len));
  if (ret == -1) errno = ESRCH;
  return ret;
}
