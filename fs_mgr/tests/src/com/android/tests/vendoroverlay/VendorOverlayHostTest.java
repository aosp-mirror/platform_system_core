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

package com.android.tests.vendoroverlay;

import com.android.tradefed.device.DeviceNotAvailableException;
import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
import com.android.tradefed.util.CommandResult;
import com.android.tradefed.util.CommandStatus;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.After;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * Test the vendor overlay feature. Requires adb remount with OverlayFS.
 */
@RunWith(DeviceJUnit4ClassRunner.class)
public class VendorOverlayHostTest extends BaseHostJUnit4Test {
  boolean wasRoot = false;
  String vndkVersion = null;

  @Before
  public void setup() throws DeviceNotAvailableException {
    vndkVersion = getDevice().executeShellV2Command("getprop ro.vndk.version").getStdout();
    Assume.assumeTrue(
        "Vendor Overlay is disabled for VNDK deprecated devices",
        vndkVersion != null && !vndkVersion.trim().isEmpty());

    wasRoot = getDevice().isAdbRoot();
    if (!wasRoot) {
      Assume.assumeTrue("Test requires root", getDevice().enableAdbRoot());
    }

    Assume.assumeTrue("Skipping vendor overlay test due to lack of necessary OverlayFS support",
        testConditionsMet());

    getDevice().remountSystemWritable();
    // Was OverlayFS used by adb remount? Without it we can't safely re-enable dm-verity.
    Pattern vendorPattern = Pattern.compile("^overlay .+ /vendor$", Pattern.MULTILINE);
    Pattern productPattern = Pattern.compile("^overlay .+ /product$", Pattern.MULTILINE);
    CommandResult result = getDevice().executeShellV2Command("df");
    Assume.assumeTrue("OverlayFS not used for adb remount on /vendor",
        vendorPattern.matcher(result.getStdout()).find());
    Assume.assumeTrue("OverlayFS not used for adb remount on /product",
        productPattern.matcher(result.getStdout()).find());
  }

  private boolean cmdSucceeded(CommandResult result) {
    return result.getStatus() == CommandStatus.SUCCESS;
  }

  private void assumeMkdirSuccess(String dir) throws DeviceNotAvailableException {
    CommandResult result = getDevice().executeShellV2Command("mkdir -p " + dir);
    Assume.assumeTrue("Couldn't create " + dir, cmdSucceeded(result));
  }

  /**
   * Tests that files in the appropriate /product/vendor_overlay dir are overlaid onto /vendor.
   */
  @Test
  public void testVendorOverlay() throws DeviceNotAvailableException {
    // Create files and modify policy
    CommandResult result = getDevice().executeShellV2Command(
        "echo '/(product|system/product)/vendor_overlay/" + vndkVersion +
        "/.* u:object_r:vendor_file:s0'" + " >> /system/etc/selinux/plat_file_contexts");
    Assume.assumeTrue("Couldn't modify plat_file_contexts", cmdSucceeded(result));
    assumeMkdirSuccess("/vendor/testdir");
    assumeMkdirSuccess("/vendor/diffcontext");
    assumeMkdirSuccess("/product/vendor_overlay/'" + vndkVersion + "'/testdir");
    result = getDevice().executeShellV2Command(
        "echo overlay > /product/vendor_overlay/'" + vndkVersion + "'/testdir/test");
    Assume.assumeTrue("Couldn't create text file in testdir", cmdSucceeded(result));
    assumeMkdirSuccess("/product/vendor_overlay/'" + vndkVersion + "'/noexist/test");
    assumeMkdirSuccess("/product/vendor_overlay/'" + vndkVersion + "'/diffcontext/test");
    result = getDevice().executeShellV2Command(
        "restorecon -r /product/vendor_overlay/'" + vndkVersion + "'/testdir");
    Assume.assumeTrue("Couldn't write testdir context", cmdSucceeded(result));

    getDevice().reboot();

    // Test that the file was overlaid properly
    result = getDevice().executeShellV2Command("[ $(cat /vendor/testdir/test) = overlay ]");
    Assert.assertTrue("test file was not overlaid onto /vendor/", cmdSucceeded(result));
    result = getDevice().executeShellV2Command("[ ! -d /vendor/noexist/test ]");
    Assert.assertTrue("noexist dir shouldn't exist on /vendor", cmdSucceeded(result));
    result = getDevice().executeShellV2Command("[ ! -d /vendor/diffcontext/test ]");
    Assert.assertTrue("diffcontext dir shouldn't exist on /vendor", cmdSucceeded(result));
  }

  // Duplicate of fs_mgr_overlayfs_valid() logic
  // Requires root
  public boolean testConditionsMet() throws DeviceNotAvailableException {
    if (cmdSucceeded(getDevice().executeShellV2Command(
        "[ -e /sys/module/overlay/parameters/override_creds ]"))) {
      return true;
    }
    if (cmdSucceeded(getDevice().executeShellV2Command("[ ! -e /sys/module/overlay ]"))) {
      return false;
    }
    CommandResult result = getDevice().executeShellV2Command("awk '{ print $3 }' /proc/version");
    Pattern kernelVersionPattern = Pattern.compile("([1-9])[.]([0-9]+).*");
    Matcher kernelVersionMatcher = kernelVersionPattern.matcher(result.getStdout());
    kernelVersionMatcher.find();
    int majorKernelVersion;
    int minorKernelVersion;
    try {
      majorKernelVersion = Integer.parseInt(kernelVersionMatcher.group(1));
      minorKernelVersion = Integer.parseInt(kernelVersionMatcher.group(2));
    } catch (Exception e) {
      return false;
    }
    if (majorKernelVersion < 4) {
      return true;
    }
    if (majorKernelVersion > 4) {
      return false;
    }
    if (minorKernelVersion > 6) {
      return false;
    }
    return true;
  }

  @After
  public void tearDown() throws DeviceNotAvailableException {
    if (getDevice().executeAdbCommand("enable-verity").contains("Now reboot your device")) {
      getDevice().reboot();
    }
    if (!wasRoot) {
      getDevice().disableAdbRoot();
    }
  }
}

