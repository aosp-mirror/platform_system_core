/*
 * Copyright (C) 2019 The Android Open Source Project
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

package com.android.fastdeploy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import androidx.test.filters.SmallTest;
import androidx.test.runner.AndroidJUnit4;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.android.fastdeploy.ApkArchive;

import java.io.File;
import java.io.IOException;

@SmallTest
@RunWith(AndroidJUnit4.class)
public class ApkArchiveTest {
    private static final File SAMPLE_APK = new File("/data/local/tmp/FastDeployTests/sample.apk");
    private static final File WRONG_APK = new File("/data/local/tmp/FastDeployTests/sample.cd");

    @Test
    public void testApkArchiveSizes() throws IOException {
        ApkArchive archive = new ApkArchive(SAMPLE_APK);

        ApkArchive.Location cdLoc = archive.getCDLocation();
        assertNotEquals(cdLoc, null);
        assertEquals(cdLoc.offset, 2044145);
        assertEquals(cdLoc.size, 49390);

        // Check that block can be retrieved
        ApkArchive.Location sigLoc = archive.getSignatureLocation(cdLoc.offset);
        assertNotEquals(sigLoc, null);
        assertEquals(sigLoc.offset, 2040049);
        assertEquals(sigLoc.size, 4088);
    }

    @Test
    public void testApkArchiveDump() throws IOException {
        ApkArchive archive = new ApkArchive(SAMPLE_APK);

        ApkArchive.Dump dump = archive.extractMetadata();
        assertNotEquals(dump, null);
        assertNotEquals(dump.cd, null);
        assertNotEquals(dump.signature, null);
        assertEquals(dump.cd.length, 49390);
        assertEquals(dump.signature.length, 4088);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testApkArchiveDumpWrongApk() throws IOException {
        ApkArchive archive = new ApkArchive(WRONG_APK);

        archive.extractMetadata();
    }
}
