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

#include <errno.h>
#include <fcntl.h>

#include <adf/adf.h>
#include <gtest/gtest.h>
#include <sys/mman.h>

class AdfTest : public testing::Test {
public:
    AdfTest() : intf_id(0), intf(-1), eng_id(0), eng(-1) { }

    virtual void SetUp() {
        int err = adf_device_open(dev_id, O_RDWR, &dev);
        ASSERT_GE(err, 0) << "opening ADF device " << dev_id <<
                " failed: " << strerror(-err);

        err = adf_find_simple_post_configuration(&dev, fmt8888, n_fmt8888,
                &intf_id, &eng_id);
        ASSERT_GE(err, 0) << "finding ADF configuration failed: " <<
                strerror(-err);

        intf = adf_interface_open(&dev, intf_id, O_RDWR);
        ASSERT_GE(intf, 0) << "opening ADF interface " << dev_id << "." <<
                intf_id << " failed: " << strerror(-intf);

        eng = adf_overlay_engine_open(&dev, eng_id, O_RDWR);
        ASSERT_GE(eng, 0) << "opening ADF overlay engine " << dev_id << "." <<
                eng_id << " failed: " << strerror(-eng);
    }

    virtual void TearDown() {
        if (eng >= 0)
            close(eng);
        if (intf >= 0)
            close(intf);
        adf_device_close(&dev);
    }

    void get8888Format(uint32_t &fmt) {
        adf_overlay_engine_data data;
        int err = adf_get_overlay_engine_data(eng, &data);
        ASSERT_GE(err, 0) << "getting ADF overlay engine data failed: " <<
                strerror(-err);

        for (size_t i = 0; i < data.n_supported_formats; i++) {
            for (size_t j = 0; j < n_fmt8888; j++) {
                if (data.supported_formats[i] == fmt8888[j]) {
                    fmt = data.supported_formats[i];
                    adf_free_overlay_engine_data(&data);
                    return;
                }
            }
        }

        adf_free_overlay_engine_data(&data);
        FAIL(); /* this should never happen */
    }

    void drawCheckerboard(void *buf, uint32_t w, uint32_t h, uint32_t pitch) {
        uint8_t *buf8 = reinterpret_cast<uint8_t *>(buf);
        for (uint32_t y = 0; y < h / 2; y++) {
            uint32_t *scanline = reinterpret_cast<uint32_t *>(buf8 + y * pitch);
            for (uint32_t x = 0; x < w / 2; x++)
                scanline[x] = 0xFF0000FF;
            for (uint32_t x = w / 2; x < w; x++)
                scanline[x] = 0xFF00FFFF;
        }
        for (uint32_t y = h / 2; y < h; y++) {
            uint32_t *scanline = reinterpret_cast<uint32_t *>(buf8 + y * pitch);
            for (uint32_t x = 0; x < w / 2; x++)
                scanline[x] = 0xFFFF00FF;
            for (uint32_t x = w / 2; x < w; x++)
                scanline[x] = 0xFFFFFFFF;
        }
    }

    /* various helpers to call ADF and die on failure */

    void getInterfaceData(adf_interface_data &data) {
         int err = adf_get_interface_data(intf, &data);
         ASSERT_GE(err, 0) << "getting ADF interface data failed: " <<
                 strerror(-err);
    }

    void blank(uint8_t mode) {
        int err = adf_interface_blank(intf, mode);
        ASSERT_FALSE(err < 0 && err != -EBUSY) <<
                "unblanking interface failed: " << strerror(-err);
    }

    void readVsyncTimestamp(uint64_t &timestamp) {
        adf_event *event;
        int err = adf_read_event(intf, &event);
        ASSERT_GE(err, 0) << "reading ADF event failed: " << strerror(-err);

        ASSERT_EQ(ADF_EVENT_VSYNC, event->type);
        ASSERT_EQ(sizeof(adf_vsync_event), event->length);

        adf_vsync_event *vsync_event =
                reinterpret_cast<adf_vsync_event *>(event);
        timestamp = vsync_event->timestamp;
        free(event);
    }

protected:
    adf_device dev;
    adf_id_t intf_id;
    int intf;
    adf_id_t eng_id;
    int eng;

private:
    const static adf_id_t dev_id = 0;
    const static __u32 fmt8888[];
    const static size_t n_fmt8888;
};

const __u32 AdfTest::fmt8888[] = {
   DRM_FORMAT_XRGB8888,
   DRM_FORMAT_XBGR8888,
   DRM_FORMAT_RGBX8888,
   DRM_FORMAT_BGRX8888,
   DRM_FORMAT_ARGB8888,
   DRM_FORMAT_ABGR8888,
   DRM_FORMAT_RGBA8888,
   DRM_FORMAT_BGRA8888
};
const size_t AdfTest::n_fmt8888 = sizeof(fmt8888) / sizeof(fmt8888[0]);

TEST(adf, devices) {
    adf_id_t *devs;
    ssize_t n_devs = adf_devices(&devs);
    free(devs);

    ASSERT_GE(n_devs, 0) << "enumerating ADF devices failed: " <<
            strerror(-n_devs);
    ASSERT_TRUE(devs != NULL);
}

TEST_F(AdfTest, device_data) {
    adf_device_data data;
    int err = adf_get_device_data(&dev, &data);
    ASSERT_GE(err, 0) << "getting ADF device data failed: " << strerror(-err);

    EXPECT_LT(data.n_attachments, ADF_MAX_ATTACHMENTS);
    EXPECT_GT(data.n_allowed_attachments, 0);
    EXPECT_LT(data.n_allowed_attachments, ADF_MAX_ATTACHMENTS);
    EXPECT_LT(data.custom_data_size, ADF_MAX_CUSTOM_DATA_SIZE);
    adf_free_device_data(&data);
}

TEST_F(AdfTest, interface_data) {
    adf_interface_data data;
    ASSERT_NO_FATAL_FAILURE(getInterfaceData(data));

    EXPECT_LT(data.type, ADF_INTF_TYPE_MAX);
    EXPECT_LE(data.dpms_state, DRM_MODE_DPMS_OFF);
    EXPECT_EQ(1, data.hotplug_detect);
    EXPECT_GT(data.n_available_modes, 0);
    EXPECT_LT(data.custom_data_size, ADF_MAX_CUSTOM_DATA_SIZE);
    adf_free_interface_data(&data);
}

TEST_F(AdfTest, overlay_engine_data) {
    adf_overlay_engine_data data;
    int err = adf_get_overlay_engine_data(eng, &data);
    ASSERT_GE(err, 0) << "getting ADF overlay engine failed: " <<
            strerror(-err);

    EXPECT_GT(data.n_supported_formats, 0);
    EXPECT_LT(data.n_supported_formats, ADF_MAX_SUPPORTED_FORMATS);
    EXPECT_LT(data.custom_data_size, ADF_MAX_CUSTOM_DATA_SIZE);
    adf_free_overlay_engine_data(&data);
}

TEST_F(AdfTest, blank) {
    ASSERT_NO_FATAL_FAILURE(blank(DRM_MODE_DPMS_OFF));
    ASSERT_NO_FATAL_FAILURE(blank(DRM_MODE_DPMS_ON));

    adf_interface_data data;
    ASSERT_NO_FATAL_FAILURE(getInterfaceData(data));
    EXPECT_EQ(DRM_MODE_DPMS_ON, data.dpms_state);
    adf_free_interface_data(&data);
}

TEST_F(AdfTest, event) {
    int err = adf_set_event(intf, ADF_EVENT_VSYNC, true);
    ASSERT_GE(err, 0) << "enabling vsync event failed: " << strerror(-err);

    ASSERT_NO_FATAL_FAILURE(blank(DRM_MODE_DPMS_ON));

    uint64_t timestamp1, timestamp2;
    ASSERT_NO_FATAL_FAILURE(readVsyncTimestamp(timestamp1));
    ASSERT_NO_FATAL_FAILURE(readVsyncTimestamp(timestamp2));
    EXPECT_GT(timestamp2, timestamp1);

    err = adf_set_event(intf, ADF_EVENT_VSYNC, false);
    EXPECT_GE(err, 0) << "disabling vsync event failed: " << strerror(-err);
}

TEST_F(AdfTest, simple_buffer) {
    adf_interface_data data;
    ASSERT_NO_FATAL_FAILURE(getInterfaceData(data));
    uint32_t w = data.current_mode.hdisplay;
    uint32_t h = data.current_mode.vdisplay;
    adf_free_interface_data(&data);

    uint32_t format = 0;
    ASSERT_NO_FATAL_FAILURE(get8888Format(format));
    char format_str[ADF_FORMAT_STR_SIZE];
    adf_format_str(format, format_str);

    uint32_t offset;
    uint32_t pitch;
    int buf_fd = adf_interface_simple_buffer_alloc(intf, w, h, format, &offset,
            &pitch);
    ASSERT_GE(buf_fd, 0) << "allocating " << w << "x" << h << " " <<
            format_str << " buffer failed: " << strerror(-buf_fd);
    EXPECT_GE(pitch, w * 4);

    void *mapped = mmap(NULL, pitch * h, PROT_WRITE, MAP_SHARED, buf_fd,
            offset);
    ASSERT_NE(mapped, MAP_FAILED) << "mapping " << w << "x" << h << " " <<
            format_str << " buffer failed: " << strerror(-errno);
    drawCheckerboard(mapped, w, h, pitch);
    munmap(mapped, pitch * h);

    int err = adf_device_attach(&dev, eng_id, intf_id);
    ASSERT_FALSE(err < 0 && err != -EALREADY) << "attaching overlay engine " <<
            eng_id << " to interface " << intf_id << " failed: " <<
            strerror(-err);

    ASSERT_NO_FATAL_FAILURE(blank(DRM_MODE_DPMS_ON));

    int release_fence = adf_interface_simple_post(intf, eng_id, w, h, format,
            buf_fd, offset, pitch, -1);
    close(buf_fd);
    ASSERT_GE(release_fence, 0) << "posting " << w << "x" << h << " " <<
            format_str << " buffer failed: " << strerror(-release_fence);
    close(release_fence);
}
