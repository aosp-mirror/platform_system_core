/*
 * Copyright (C) 2013 The Android Open Source Project
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

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <linux/ion_test.h>

#include <gtest/gtest.h>

#include <ion/ion.h>

#include "ion_test_fixture.h"

#define ALIGN(x,y) (((x) + ((y) - 1)) & ~((y) - 1))

class Device : public IonAllHeapsTest {
 public:
    virtual void SetUp();
    virtual void TearDown();
    int m_deviceFd;
    void readDMA(int fd, void *buf, size_t size);
    void writeDMA(int fd, void *buf, size_t size);
    void readKernel(int fd, void *buf, size_t size);
    void writeKernel(int fd, void *buf, size_t size);
    void blowCache();
    void dirtyCache(void *ptr, size_t size);
};

void Device::SetUp()
{
    IonAllHeapsTest::SetUp();
    m_deviceFd = open("/dev/ion-test", O_RDWR);
    ASSERT_GE(m_deviceFd, 0);
}

void Device::TearDown()
{
    ASSERT_EQ(0, close(m_deviceFd));
    IonAllHeapsTest::TearDown();
}

void Device::readDMA(int fd, void *buf, size_t size)
{
    ASSERT_EQ(0, ioctl(m_deviceFd, ION_IOC_TEST_SET_FD, fd));
    struct ion_test_rw_data ion_test_rw_data = {
            .ptr = (uint64_t)buf,
            .offset = 0,
            .size = size,
            .write = 0,
    };

    ASSERT_EQ(0, ioctl(m_deviceFd, ION_IOC_TEST_DMA_MAPPING, &ion_test_rw_data));
    ASSERT_EQ(0, ioctl(m_deviceFd, ION_IOC_TEST_SET_FD, -1));
}

void Device::writeDMA(int fd, void *buf, size_t size)
{
    ASSERT_EQ(0, ioctl(m_deviceFd, ION_IOC_TEST_SET_FD, fd));
    struct ion_test_rw_data ion_test_rw_data = {
            .ptr = (uint64_t)buf,
            .offset = 0,
            .size = size,
            .write = 1,
    };

    ASSERT_EQ(0, ioctl(m_deviceFd, ION_IOC_TEST_DMA_MAPPING, &ion_test_rw_data));
    ASSERT_EQ(0, ioctl(m_deviceFd, ION_IOC_TEST_SET_FD, -1));
}

void Device::readKernel(int fd, void *buf, size_t size)
{
    ASSERT_EQ(0, ioctl(m_deviceFd, ION_IOC_TEST_SET_FD, fd));
    struct ion_test_rw_data ion_test_rw_data = {
            .ptr = (uint64_t)buf,
            .offset = 0,
            .size = size,
            .write = 0,
    };

    ASSERT_EQ(0, ioctl(m_deviceFd, ION_IOC_TEST_KERNEL_MAPPING, &ion_test_rw_data));
    ASSERT_EQ(0, ioctl(m_deviceFd, ION_IOC_TEST_SET_FD, -1));
}

void Device::writeKernel(int fd, void *buf, size_t size)
{
    ASSERT_EQ(0, ioctl(m_deviceFd, ION_IOC_TEST_SET_FD, fd));
    struct ion_test_rw_data ion_test_rw_data = {
            .ptr = (uint64_t)buf,
            .offset = 0,
            .size = size,
            .write = 1,
    };

    ASSERT_EQ(0, ioctl(m_deviceFd, ION_IOC_TEST_KERNEL_MAPPING, &ion_test_rw_data));
    ASSERT_EQ(0, ioctl(m_deviceFd, ION_IOC_TEST_SET_FD, -1));
}

void Device::blowCache()
{
    const size_t bigger_than_cache = 8*1024*1024;
    void *buf1 = malloc(bigger_than_cache);
    void *buf2 = malloc(bigger_than_cache);
    memset(buf1, 0xaa, bigger_than_cache);
    memcpy(buf2, buf1, bigger_than_cache);
    free(buf1);
    free(buf2);
}

void Device::dirtyCache(void *ptr, size_t size)
{
    /* try to dirty cache lines */
    for (size_t i = size-1; i > 0; i--) {
        ((volatile char *)ptr)[i];
        ((char *)ptr)[i] = i;
    }
}

TEST_F(Device, KernelReadCached)
{
    void *alloc = malloc(8192 + 1024);
    void *buf = (void *)(ALIGN((unsigned long)alloc, 4096) + 1024);

    for (unsigned int heapMask : m_allHeaps) {
        SCOPED_TRACE(::testing::Message() << "heap " << heapMask);
        int map_fd = -1;
        unsigned int flags = ION_FLAG_CACHED;

        ASSERT_EQ(0, ion_alloc_fd(m_ionFd, 4096, 0, heapMask, flags, &map_fd));
        ASSERT_GE(map_fd, 0);

        void *ptr;
        ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
        ASSERT_TRUE(ptr != NULL);

        for (int i = 0; i < 4096; i++)
            ((char *)ptr)[i] = i;

        ((char*)buf)[4096] = 0x12;
        readKernel(map_fd, buf, 4096);
        ASSERT_EQ(((char*)buf)[4096], 0x12);

        for (int i = 0; i < 4096; i++)
            ASSERT_EQ((char)i, ((char *)buf)[i]);

        ASSERT_EQ(0, munmap(ptr, 4096));
        ASSERT_EQ(0, close(map_fd));
    }

    free(alloc);
}

TEST_F(Device, KernelWriteCached)
{
    void *alloc = malloc(8192 + 1024);
    void *buf = (void *)(ALIGN((unsigned long)alloc, 4096) + 1024);

    for (int i = 0; i < 4096; i++)
        ((char *)buf)[i] = i;

    for (unsigned int heapMask : m_allHeaps) {
        SCOPED_TRACE(::testing::Message() << "heap " << heapMask);
        int map_fd = -1;
        unsigned int flags = ION_FLAG_CACHED;

        ASSERT_EQ(0, ion_alloc_fd(m_ionFd, 4096, 0, heapMask, flags, &map_fd));
        ASSERT_GE(map_fd, 0);

        void *ptr;
        ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
        ASSERT_TRUE(ptr != NULL);

        dirtyCache(ptr, 4096);

        writeKernel(map_fd, buf, 4096);

        for (int i = 0; i < 4096; i++)
            ASSERT_EQ((char)i, ((char *)ptr)[i]) << i;

        ASSERT_EQ(0, munmap(ptr, 4096));
        ASSERT_EQ(0, close(map_fd));
    }

    free(alloc);
}

TEST_F(Device, DMAReadCached)
{
    void *alloc = malloc(8192 + 1024);
    void *buf = (void *)(ALIGN((unsigned long)alloc, 4096) + 1024);

    for (unsigned int heapMask : m_allHeaps) {
        SCOPED_TRACE(::testing::Message() << "heap " << heapMask);
        int map_fd = -1;
        unsigned int flags = ION_FLAG_CACHED;

        ASSERT_EQ(0, ion_alloc_fd(m_ionFd, 4096, 0, heapMask, flags, &map_fd));
        ASSERT_GE(map_fd, 0);

        void *ptr;
        ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
        ASSERT_TRUE(ptr != NULL);

        for (int i = 0; i < 4096; i++)
            ((char *)ptr)[i] = i;

        readDMA(map_fd, buf, 4096);

        for (int i = 0; i < 4096; i++)
            ASSERT_EQ((char)i, ((char *)buf)[i]);

        ASSERT_EQ(0, munmap(ptr, 4096));
        ASSERT_EQ(0, close(map_fd));
    }

    free(alloc);
}

TEST_F(Device, DMAWriteCached)
{
    void *alloc = malloc(8192 + 1024);
    void *buf = (void *)(ALIGN((unsigned long)alloc, 4096) + 1024);

    for (int i = 0; i < 4096; i++)
        ((char *)buf)[i] = i;

    for (unsigned int heapMask : m_allHeaps) {
        SCOPED_TRACE(::testing::Message() << "heap " << heapMask);
        int map_fd = -1;
        unsigned int flags = ION_FLAG_CACHED;

        ASSERT_EQ(0, ion_alloc_fd(m_ionFd, 4096, 0, heapMask, flags, &map_fd));
        ASSERT_GE(map_fd, 0);

        void *ptr;
        ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
        ASSERT_TRUE(ptr != NULL);

        dirtyCache(ptr, 4096);

        writeDMA(map_fd, buf, 4096);

        for (int i = 0; i < 4096; i++)
            ASSERT_EQ((char)i, ((char *)ptr)[i]) << i;

        ASSERT_EQ(0, munmap(ptr, 4096));
        ASSERT_EQ(0, close(map_fd));
    }

    free(alloc);
}

TEST_F(Device, KernelReadCachedNeedsSync)
{
    void *alloc = malloc(8192 + 1024);
    void *buf = (void *)(ALIGN((unsigned long)alloc, 4096) + 1024);

    for (unsigned int heapMask : m_allHeaps) {
        SCOPED_TRACE(::testing::Message() << "heap " << heapMask);
        int map_fd = -1;
        unsigned int flags = ION_FLAG_CACHED | ION_FLAG_CACHED_NEEDS_SYNC;

        ASSERT_EQ(0, ion_alloc_fd(m_ionFd, 4096, 0, heapMask, flags, &map_fd));
        ASSERT_GE(map_fd, 0);

        void *ptr;
        ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
        ASSERT_TRUE(ptr != NULL);

        for (int i = 0; i < 4096; i++)
            ((char *)ptr)[i] = i;

        ((char*)buf)[4096] = 0x12;
        readKernel(map_fd, buf, 4096);
        ASSERT_EQ(((char*)buf)[4096], 0x12);

        for (int i = 0; i < 4096; i++)
            ASSERT_EQ((char)i, ((char *)buf)[i]);

        ASSERT_EQ(0, munmap(ptr, 4096));
        ASSERT_EQ(0, close(map_fd));
    }

    free(alloc);
}

TEST_F(Device, KernelWriteCachedNeedsSync)
{
    void *alloc = malloc(8192 + 1024);
    void *buf = (void *)(ALIGN((unsigned long)alloc, 4096) + 1024);

    for (int i = 0; i < 4096; i++)
        ((char *)buf)[i] = i;

    for (unsigned int heapMask : m_allHeaps) {
        SCOPED_TRACE(::testing::Message() << "heap " << heapMask);
        int map_fd = -1;
        unsigned int flags = ION_FLAG_CACHED | ION_FLAG_CACHED_NEEDS_SYNC;

        ASSERT_EQ(0, ion_alloc_fd(m_ionFd, 4096, 0, heapMask, flags, &map_fd));
        ASSERT_GE(map_fd, 0);

        void *ptr;
        ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
        ASSERT_TRUE(ptr != NULL);

        dirtyCache(ptr, 4096);

        writeKernel(map_fd, buf, 4096);

        for (int i = 0; i < 4096; i++)
            ASSERT_EQ((char)i, ((char *)ptr)[i]) << i;

        ASSERT_EQ(0, munmap(ptr, 4096));
        ASSERT_EQ(0, close(map_fd));
    }

    free(alloc);
}

TEST_F(Device, DMAReadCachedNeedsSync)
{
    void *alloc = malloc(8192 + 1024);
    void *buf = (void *)(ALIGN((unsigned long)alloc, 4096) + 1024);

    for (unsigned int heapMask : m_allHeaps) {
        SCOPED_TRACE(::testing::Message() << "heap " << heapMask);
        int map_fd = -1;
        unsigned int flags = ION_FLAG_CACHED | ION_FLAG_CACHED_NEEDS_SYNC;

        ASSERT_EQ(0, ion_alloc_fd(m_ionFd, 4096, 0, heapMask, flags, &map_fd));
        ASSERT_GE(map_fd, 0);

        void *ptr;
        ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
        ASSERT_TRUE(ptr != NULL);

        for (int i = 0; i < 4096; i++)
            ((char *)ptr)[i] = i;

        ion_sync_fd(m_ionFd, map_fd);

        readDMA(map_fd, buf, 4096);

        for (int i = 0; i < 4096; i++)
            ASSERT_EQ((char)i, ((char *)buf)[i]);

        ASSERT_EQ(0, munmap(ptr, 4096));
        ASSERT_EQ(0, close(map_fd));
    }

    free(alloc);
}

TEST_F(Device, DMAWriteCachedNeedsSync)
{
    void *alloc = malloc(8192 + 1024);
    void *buf = (void *)(ALIGN((unsigned long)alloc, 4096) + 1024);

    for (int i = 0; i < 4096; i++)
        ((char *)buf)[i] = i;

    for (unsigned int heapMask : m_allHeaps) {
        SCOPED_TRACE(::testing::Message() << "heap " << heapMask);
        int map_fd = -1;
        unsigned int flags = ION_FLAG_CACHED | ION_FLAG_CACHED_NEEDS_SYNC;

        ASSERT_EQ(0, ion_alloc_fd(m_ionFd, 4096, 0, heapMask, flags, &map_fd));
        ASSERT_GE(map_fd, 0);

        void *ptr;
        ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
        ASSERT_TRUE(ptr != NULL);

        dirtyCache(ptr, 4096);

        writeDMA(map_fd, buf, 4096);

        ion_sync_fd(m_ionFd, map_fd);

        for (int i = 0; i < 4096; i++)
            ASSERT_EQ((char)i, ((char *)ptr)[i]) << i;

        ASSERT_EQ(0, munmap(ptr, 4096));
        ASSERT_EQ(0, close(map_fd));
    }

    free(alloc);
}
TEST_F(Device, KernelRead)
{
    void *alloc = malloc(8192 + 1024);
    void *buf = (void *)(ALIGN((unsigned long)alloc, 4096) + 1024);

    for (unsigned int heapMask : m_allHeaps) {
        SCOPED_TRACE(::testing::Message() << "heap " << heapMask);
        int map_fd = -1;
        unsigned int flags = 0;

        ASSERT_EQ(0, ion_alloc_fd(m_ionFd, 4096, 0, heapMask, flags, &map_fd));
        ASSERT_GE(map_fd, 0);

        void *ptr;
        ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
        ASSERT_TRUE(ptr != NULL);

        for (int i = 0; i < 4096; i++)
            ((char *)ptr)[i] = i;

        ((char*)buf)[4096] = 0x12;
        readKernel(map_fd, buf, 4096);
        ASSERT_EQ(((char*)buf)[4096], 0x12);

        for (int i = 0; i < 4096; i++)
            ASSERT_EQ((char)i, ((char *)buf)[i]);

        ASSERT_EQ(0, munmap(ptr, 4096));
        ASSERT_EQ(0, close(map_fd));
    }

    free(alloc);
}

TEST_F(Device, KernelWrite)
{
    void *alloc = malloc(8192 + 1024);
    void *buf = (void *)(ALIGN((unsigned long)alloc, 4096) + 1024);

    for (int i = 0; i < 4096; i++)
        ((char *)buf)[i] = i;

    for (unsigned int heapMask : m_allHeaps) {
        SCOPED_TRACE(::testing::Message() << "heap " << heapMask);
        int map_fd = -1;
        unsigned int flags = 0;

        ASSERT_EQ(0, ion_alloc_fd(m_ionFd, 4096, 0, heapMask, flags, &map_fd));
        ASSERT_GE(map_fd, 0);

        void *ptr;
        ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
        ASSERT_TRUE(ptr != NULL);

        dirtyCache(ptr, 4096);

        writeKernel(map_fd, buf, 4096);

        for (int i = 0; i < 4096; i++)
            ASSERT_EQ((char)i, ((char *)ptr)[i]) << i;

        ASSERT_EQ(0, munmap(ptr, 4096));
        ASSERT_EQ(0, close(map_fd));
    }

    free(alloc);
}

TEST_F(Device, DMARead)
{
    void *alloc = malloc(8192 + 1024);
    void *buf = (void *)(ALIGN((unsigned long)alloc, 4096) + 1024);

    for (unsigned int heapMask : m_allHeaps) {
        SCOPED_TRACE(::testing::Message() << "heap " << heapMask);
        int map_fd = -1;
        unsigned int flags = 0;

        ASSERT_EQ(0, ion_alloc_fd(m_ionFd, 4096, 0, heapMask, flags, &map_fd));
        ASSERT_GE(map_fd, 0);

        void *ptr;
        ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
        ASSERT_TRUE(ptr != NULL);

        for (int i = 0; i < 4096; i++)
            ((char *)ptr)[i] = i;

        readDMA(map_fd, buf, 4096);

        for (int i = 0; i < 4096; i++)
            ASSERT_EQ((char)i, ((char *)buf)[i]);

        ASSERT_EQ(0, munmap(ptr, 4096));
        ASSERT_EQ(0, close(map_fd));
    }

    free(alloc);
}

TEST_F(Device, DMAWrite)
{
    void *alloc = malloc(8192 + 1024);
    void *buf = (void *)(ALIGN((unsigned long)alloc, 4096) + 1024);

    for (int i = 0; i < 4096; i++)
        ((char *)buf)[i] = i;

    for (unsigned int heapMask : m_allHeaps) {
        SCOPED_TRACE(::testing::Message() << "heap " << heapMask);
        int map_fd = -1;
        unsigned int flags = 0;

        ASSERT_EQ(0, ion_alloc_fd(m_ionFd, 4096, 0, heapMask, flags, &map_fd));
        ASSERT_GE(map_fd, 0);

        void *ptr;
        ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
        ASSERT_TRUE(ptr != NULL);

        dirtyCache(ptr, 4096);

        writeDMA(map_fd, buf, 4096);

        for (int i = 0; i < 4096; i++)
            ASSERT_EQ((char)i, ((char *)ptr)[i]) << i;

        ASSERT_EQ(0, munmap(ptr, 4096));
        ASSERT_EQ(0, close(map_fd));
    }

    free(alloc);
}

TEST_F(Device, IsCached)
{
    void *buf = malloc(4096);

    for (unsigned int heapMask : m_allHeaps) {
        SCOPED_TRACE(::testing::Message() << "heap " << heapMask);
        int map_fd = -1;
        unsigned int flags = ION_FLAG_CACHED | ION_FLAG_CACHED_NEEDS_SYNC;

        ASSERT_EQ(0, ion_alloc_fd(m_ionFd, 4096, 0, heapMask, flags, &map_fd));
        ASSERT_GE(map_fd, 0);

        void *ptr;
        ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
        ASSERT_TRUE(ptr != NULL);

        dirtyCache(ptr, 4096);

        readDMA(map_fd, buf, 4096);

        bool same = true;
        for (int i = 4096-16; i >= 0; i -= 16)
            if (((char *)buf)[i] != i)
                same = false;
        ASSERT_FALSE(same);

        ASSERT_EQ(0, munmap(ptr, 4096));
        ASSERT_EQ(0, close(map_fd));
    }
}
