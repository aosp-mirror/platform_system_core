/*
 * Copyright (C) 2018 The Android Open Source Project
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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.android.compatibility.common.tradefed.build.CompatibilityBuildHelper;
import com.android.ddmlib.Log.LogLevel;
import com.android.tradefed.device.DeviceNotAvailableException;
import com.android.tradefed.log.LogUtil.CLog;
import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.util.Arrays;

@RunWith(DeviceJUnit4ClassRunner.class)
public class FastDeployTest extends BaseHostJUnit4Test {

    private static final String TEST_APP_PACKAGE = "com.example.helloworld";
    private static final String TEST_APK5_NAME = "helloworld5.apk";
    private static final String TEST_APK7_NAME = "helloworld7.apk";

    private String mTestApk5Path;
    private String mTestApk7Path;

    @Before
    public void setUp() throws Exception {
        CompatibilityBuildHelper buildHelper = new CompatibilityBuildHelper(getBuild());
        getDevice().uninstallPackage(TEST_APP_PACKAGE);
        mTestApk5Path = buildHelper.getTestFile(TEST_APK5_NAME).getAbsolutePath();
        mTestApk7Path = buildHelper.getTestFile(TEST_APK7_NAME).getAbsolutePath();
    }

    @Test
    public void testAppInstalls() throws Exception {
        fastInstallPackage(mTestApk5Path);
        assertTrue(isAppInstalled(TEST_APP_PACKAGE));
        getDevice().uninstallPackage(TEST_APP_PACKAGE);
        assertFalse(isAppInstalled(TEST_APP_PACKAGE));
    }

    @Test
    public void testAppPatch() throws Exception {
        fastInstallPackage(mTestApk5Path);
        assertTrue(isAppInstalled(TEST_APP_PACKAGE));
        fastInstallPackage(mTestApk7Path);
        assertTrue(isAppInstalled(TEST_APP_PACKAGE));
        getDevice().uninstallPackage(TEST_APP_PACKAGE);
        assertFalse(isAppInstalled(TEST_APP_PACKAGE));
    }

    private boolean isAppInstalled(String packageName) throws DeviceNotAvailableException {
        final String result = getDevice().executeShellCommand("pm list packages");
        CLog.logAndDisplay(LogLevel.INFO, result);
        final int prefixLength = "package:".length();
        return Arrays.stream(result.split("\\r?\\n"))
                .anyMatch(line -> line.substring(prefixLength).equals(packageName));
    }

    // Mostly copied from PkgInstallSignatureVerificationTest.java.
    private void fastInstallPackage(String apkPath)
            throws IOException, DeviceNotAvailableException {
        String result = getDevice().executeAdbCommand("install", "-t", "--fastdeploy", "--force-agent",
                apkPath);
        CLog.logAndDisplay(LogLevel.INFO, result);
    }
}


