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


#ifndef _INIT_DESCRIPTORS_H
#define _INIT_DESCRIPTORS_H

#include <sys/types.h>

#include <string>

namespace android {
namespace init {

class DescriptorInfo {
 public:
  DescriptorInfo(const std::string& name, const std::string& type, uid_t uid,
                 gid_t gid, int perm, const std::string& context);
  virtual ~DescriptorInfo();

  friend std::ostream& operator<<(std::ostream& os, const class DescriptorInfo& info);
  bool operator==(const DescriptorInfo& other) const;

  void CreateAndPublish(const std::string& globalContext) const;
  virtual void Clean() const;

 protected:
  const std::string& name() const { return name_; }
  const std::string& type() const { return type_; }
  uid_t uid() const { return uid_; }
  gid_t gid() const { return gid_; }
  int perm() const { return perm_; }
  const std::string& context() const { return context_; }

 private:
  std::string name_;
  std::string type_;
  uid_t uid_;
  gid_t gid_;
  int perm_;
  std::string context_;

  virtual int Create(const std::string& globalContext) const = 0;
  virtual const std::string key() const = 0;
};

std::ostream& operator<<(std::ostream& os, const DescriptorInfo& info);

class SocketInfo : public DescriptorInfo {
 public:
  SocketInfo(const std::string& name, const std::string& type, uid_t uid,
             gid_t gid, int perm, const std::string& context);
  void Clean() const override;
 private:
  virtual int Create(const std::string& context) const override;
  virtual const std::string key() const override;
};

class FileInfo : public DescriptorInfo {
 public:
  FileInfo(const std::string& name, const std::string& type, uid_t uid,
           gid_t gid, int perm, const std::string& context);
 private:
  virtual int Create(const std::string& context) const override;
  virtual const std::string key() const override;
};

}  // namespace init
}  // namespace android

#endif
