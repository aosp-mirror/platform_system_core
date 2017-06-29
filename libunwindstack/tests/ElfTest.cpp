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

#include <elf.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include "Elf.h"

#include "MemoryFake.h"

#if !defined(PT_ARM_EXIDX)
#define PT_ARM_EXIDX 0x70000001
#endif

class ElfTest : public ::testing::Test {
 protected:
  void SetUp() override {
    memory_ = new MemoryFake;
  }

  template <typename Ehdr>
  void InitEhdr(Ehdr* ehdr) {
    memset(ehdr, 0, sizeof(Ehdr));
    memcpy(&ehdr->e_ident[0], ELFMAG, SELFMAG);
    ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
    ehdr->e_ident[EI_VERSION] = EV_CURRENT;
    ehdr->e_ident[EI_OSABI] = ELFOSABI_SYSV;

    ehdr->e_type = ET_DYN;
    ehdr->e_version = EV_CURRENT;
  }

  void InitElf32(uint32_t machine) {
    Elf32_Ehdr ehdr;

    InitEhdr<Elf32_Ehdr>(&ehdr);
    ehdr.e_ident[EI_CLASS] = ELFCLASS32;

    ehdr.e_machine = machine;
    ehdr.e_entry = 0;
    ehdr.e_phoff = 0x100;
    ehdr.e_shoff = 0;
    ehdr.e_flags = 0;
    ehdr.e_ehsize = sizeof(ehdr);
    ehdr.e_phentsize = sizeof(Elf32_Phdr);
    ehdr.e_phnum = 1;
    ehdr.e_shentsize = sizeof(Elf32_Shdr);
    ehdr.e_shnum = 0;
    ehdr.e_shstrndx = 0;
    if (machine == EM_ARM) {
      ehdr.e_flags = 0x5000200;
      ehdr.e_phnum = 2;
    }
    memory_->SetMemory(0, &ehdr, sizeof(ehdr));

    Elf32_Phdr phdr;
    memset(&phdr, 0, sizeof(phdr));
    phdr.p_type = PT_LOAD;
    phdr.p_offset = 0;
    phdr.p_vaddr = 0;
    phdr.p_paddr = 0;
    phdr.p_filesz = 0x10000;
    phdr.p_memsz = 0x10000;
    phdr.p_flags = PF_R | PF_X;
    phdr.p_align = 0x1000;
    memory_->SetMemory(0x100, &phdr, sizeof(phdr));

    if (machine == EM_ARM) {
      memset(&phdr, 0, sizeof(phdr));
      phdr.p_type = PT_ARM_EXIDX;
      phdr.p_offset = 0x30000;
      phdr.p_vaddr = 0x30000;
      phdr.p_paddr = 0x30000;
      phdr.p_filesz = 16;
      phdr.p_memsz = 16;
      phdr.p_flags = PF_R;
      phdr.p_align = 0x4;
      memory_->SetMemory(0x100 + sizeof(phdr), &phdr, sizeof(phdr));
    }
  }

  void InitElf64(uint32_t machine) {
    Elf64_Ehdr ehdr;

    InitEhdr<Elf64_Ehdr>(&ehdr);
    ehdr.e_ident[EI_CLASS] = ELFCLASS64;

    ehdr.e_machine = machine;
    ehdr.e_entry = 0;
    ehdr.e_phoff = 0x100;
    ehdr.e_shoff = 0;
    ehdr.e_flags = 0x5000200;
    ehdr.e_ehsize = sizeof(ehdr);
    ehdr.e_phentsize = sizeof(Elf64_Phdr);
    ehdr.e_phnum = 1;
    ehdr.e_shentsize = sizeof(Elf64_Shdr);
    ehdr.e_shnum = 0;
    ehdr.e_shstrndx = 0;
    memory_->SetMemory(0, &ehdr, sizeof(ehdr));

    Elf64_Phdr phdr;
    memset(&phdr, 0, sizeof(phdr));
    phdr.p_type = PT_LOAD;
    phdr.p_offset = 0;
    phdr.p_vaddr = 0;
    phdr.p_paddr = 0;
    phdr.p_filesz = 0x10000;
    phdr.p_memsz = 0x10000;
    phdr.p_flags = PF_R | PF_X;
    phdr.p_align = 0x1000;
    memory_->SetMemory(0x100, &phdr, sizeof(phdr));
  }

  template <typename Ehdr, typename Shdr>
  void GnuDebugdataInitFail(Ehdr* ehdr);

  template <typename Ehdr, typename Shdr>
  void GnuDebugdataInit(Ehdr* ehdr);

  MemoryFake* memory_;
};

TEST_F(ElfTest, invalid_memory) {
  Elf elf(memory_);

  ASSERT_FALSE(elf.Init());
  ASSERT_FALSE(elf.valid());
}

TEST_F(ElfTest, elf_invalid) {
  Elf elf(memory_);

  InitElf32(EM_386);

  // Corrupt the ELF signature.
  memory_->SetData32(0, 0x7f000000);

  ASSERT_FALSE(elf.Init());
  ASSERT_FALSE(elf.valid());
  ASSERT_TRUE(elf.interface() == nullptr);

  std::string name;
  ASSERT_FALSE(elf.GetSoname(&name));

  uint64_t func_offset;
  ASSERT_FALSE(elf.GetFunctionName(0, &name, &func_offset));

  ASSERT_FALSE(elf.Step(0, nullptr, nullptr));
}

TEST_F(ElfTest, elf_arm) {
  Elf elf(memory_);

  InitElf32(EM_ARM);

  ASSERT_TRUE(elf.Init());
  ASSERT_TRUE(elf.valid());
  ASSERT_EQ(static_cast<uint32_t>(EM_ARM), elf.machine_type());
  ASSERT_EQ(ELFCLASS32, elf.class_type());
  ASSERT_TRUE(elf.interface() != nullptr);
}

TEST_F(ElfTest, elf_x86) {
  Elf elf(memory_);

  InitElf32(EM_386);

  ASSERT_TRUE(elf.Init());
  ASSERT_TRUE(elf.valid());
  ASSERT_EQ(static_cast<uint32_t>(EM_386), elf.machine_type());
  ASSERT_EQ(ELFCLASS32, elf.class_type());
  ASSERT_TRUE(elf.interface() != nullptr);
}

TEST_F(ElfTest, elf_arm64) {
  Elf elf(memory_);

  InitElf64(EM_AARCH64);

  ASSERT_TRUE(elf.Init());
  ASSERT_TRUE(elf.valid());
  ASSERT_EQ(static_cast<uint32_t>(EM_AARCH64), elf.machine_type());
  ASSERT_EQ(ELFCLASS64, elf.class_type());
  ASSERT_TRUE(elf.interface() != nullptr);
}

TEST_F(ElfTest, elf_x86_64) {
  Elf elf(memory_);

  InitElf64(EM_X86_64);

  ASSERT_TRUE(elf.Init());
  ASSERT_TRUE(elf.valid());
  ASSERT_EQ(static_cast<uint32_t>(EM_X86_64), elf.machine_type());
  ASSERT_EQ(ELFCLASS64, elf.class_type());
  ASSERT_TRUE(elf.interface() != nullptr);
}

template <typename Ehdr, typename Shdr>
void ElfTest::GnuDebugdataInitFail(Ehdr* ehdr) {
  Elf elf(memory_);

  uint64_t offset = 0x2000;

  ehdr->e_shoff = offset;
  ehdr->e_shnum = 3;
  ehdr->e_shentsize = sizeof(Shdr);
  ehdr->e_shstrndx = 2;
  memory_->SetMemory(0, ehdr, sizeof(*ehdr));

  Shdr shdr;
  memset(&shdr, 0, sizeof(shdr));
  shdr.sh_type = SHT_NULL;
  memory_->SetMemory(offset, &shdr, sizeof(shdr));
  offset += ehdr->e_shentsize;

  memset(&shdr, 0, sizeof(shdr));
  shdr.sh_type = SHT_PROGBITS;
  shdr.sh_name = 0x100;
  shdr.sh_addr = 0x5000;
  shdr.sh_offset = 0x5000;
  shdr.sh_entsize = 0x100;
  shdr.sh_size = 0x800;
  memory_->SetMemory(offset, &shdr, sizeof(shdr));
  offset += ehdr->e_shentsize;

  memset(&shdr, 0, sizeof(shdr));
  shdr.sh_type = SHT_STRTAB;
  shdr.sh_name = 0x200000;
  shdr.sh_offset = 0xf000;
  shdr.sh_size = 0x1000;
  memory_->SetMemory(offset, &shdr, sizeof(shdr));
  offset += ehdr->e_shentsize;

  memory_->SetMemory(0xf100, ".gnu_debugdata", sizeof(".gnu_debugdata"));

  ASSERT_TRUE(elf.Init());
  ASSERT_TRUE(elf.interface() != nullptr);
  ASSERT_TRUE(elf.gnu_debugdata_interface() == nullptr);
  EXPECT_EQ(0x5000U, elf.interface()->gnu_debugdata_offset());
  EXPECT_EQ(0x800U, elf.interface()->gnu_debugdata_size());

  elf.InitGnuDebugdata();
}

TEST_F(ElfTest, gnu_debugdata_init_fail32) {
  Elf32_Ehdr ehdr;
  InitEhdr<Elf32_Ehdr>(&ehdr);
  ehdr.e_ident[EI_CLASS] = ELFCLASS32;
  ehdr.e_machine = EM_ARM;

  GnuDebugdataInitFail<Elf32_Ehdr, Elf32_Shdr>(&ehdr);
}

TEST_F(ElfTest, gnu_debugdata_init_fail64) {
  Elf64_Ehdr ehdr;
  InitEhdr<Elf64_Ehdr>(&ehdr);
  ehdr.e_ident[EI_CLASS] = ELFCLASS64;
  ehdr.e_machine = EM_AARCH64;

  GnuDebugdataInitFail<Elf64_Ehdr, Elf64_Shdr>(&ehdr);
}

template <typename Ehdr, typename Shdr>
void ElfTest::GnuDebugdataInit(Ehdr* ehdr) {
  Elf elf(memory_);

  uint64_t offset = 0x2000;

  ehdr->e_shoff = offset;
  ehdr->e_shnum = 3;
  ehdr->e_shentsize = sizeof(Shdr);
  ehdr->e_shstrndx = 2;
  memory_->SetMemory(0, ehdr, sizeof(*ehdr));

  Shdr shdr;
  memset(&shdr, 0, sizeof(shdr));
  shdr.sh_type = SHT_NULL;
  memory_->SetMemory(offset, &shdr, sizeof(shdr));
  offset += ehdr->e_shentsize;

  uint64_t gnu_offset = offset;
  offset += ehdr->e_shentsize;

  memset(&shdr, 0, sizeof(shdr));
  shdr.sh_type = SHT_STRTAB;
  shdr.sh_name = 0x200000;
  shdr.sh_offset = 0xf000;
  shdr.sh_size = 0x1000;
  memory_->SetMemory(offset, &shdr, sizeof(shdr));
  offset += ehdr->e_shentsize;

  memory_->SetMemory(0xf100, ".gnu_debugdata", sizeof(".gnu_debugdata"));

  // Read in the compressed elf data and put it in our fake memory.
  std::string name("tests/");
  if (sizeof(Ehdr) == sizeof(Elf32_Ehdr)) {
    name += "elf32.xz";
  } else {
    name += "elf64.xz";
  }
  int fd = TEMP_FAILURE_RETRY(open(name.c_str(), O_RDONLY));
  ASSERT_NE(-1, fd) << "Cannot open " + name;
  // Assumes the file is less than 1024 bytes.
  std::vector<uint8_t> buf(1024);
  ssize_t bytes = TEMP_FAILURE_RETRY(read(fd, buf.data(), buf.size()));
  ASSERT_GT(bytes, 0);
  // Make sure the file isn't too big.
  ASSERT_NE(static_cast<size_t>(bytes), buf.size())
      << "File " + name + " is too big, increase buffer size.";
  close(fd);
  buf.resize(bytes);
  memory_->SetMemory(0x5000, buf);

  memset(&shdr, 0, sizeof(shdr));
  shdr.sh_type = SHT_PROGBITS;
  shdr.sh_name = 0x100;
  shdr.sh_addr = 0x5000;
  shdr.sh_offset = 0x5000;
  shdr.sh_size = bytes;
  memory_->SetMemory(gnu_offset, &shdr, sizeof(shdr));

  ASSERT_TRUE(elf.Init());
  ASSERT_TRUE(elf.interface() != nullptr);
  ASSERT_TRUE(elf.gnu_debugdata_interface() == nullptr);
  EXPECT_EQ(0x5000U, elf.interface()->gnu_debugdata_offset());

  elf.InitGnuDebugdata();
  ASSERT_TRUE(elf.gnu_debugdata_interface() != nullptr);
}

TEST_F(ElfTest, gnu_debugdata_init32) {
  Elf32_Ehdr ehdr;
  InitEhdr<Elf32_Ehdr>(&ehdr);
  ehdr.e_ident[EI_CLASS] = ELFCLASS32;
  ehdr.e_machine = EM_ARM;

  GnuDebugdataInit<Elf32_Ehdr, Elf32_Shdr>(&ehdr);
}

TEST_F(ElfTest, gnu_debugdata_init64) {
  Elf64_Ehdr ehdr;
  InitEhdr<Elf64_Ehdr>(&ehdr);
  ehdr.e_ident[EI_CLASS] = ELFCLASS64;
  ehdr.e_machine = EM_AARCH64;

  GnuDebugdataInit<Elf64_Ehdr, Elf64_Shdr>(&ehdr);
}
