/*
 * Copyright (C) 2022 The Android Open Source Project
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

package com.android.tests.init;

import static com.google.common.truth.Truth.assertThat;

import static org.junit.Assume.assumeTrue;

import com.android.server.os.TombstoneProtos.Tombstone;
import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
import com.android.tradefed.util.CommandResult;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.ArrayList;

@RunWith(DeviceJUnit4ClassRunner.class)
public class MteUpgradeTest extends BaseHostJUnit4Test {
    @Before
    public void setUp() throws Exception {
        CommandResult result =
                getDevice().executeShellV2Command("/system/bin/mte_upgrade_test_helper --checking");
        assumeTrue("mte_upgrade_test_binary needs to segfault", result.getExitCode() == 139);
    }

    @After
    public void tearDown() throws Exception {
        // Easier here than in a finally in testCrash, and doesn't really hurt.
        getDevice().executeShellV2Command("stop mte_upgrade_test_helper");
        getDevice().executeShellV2Command("stop mte_upgrade_test_helper_overridden");
        getDevice().setProperty("sys.mte_crash_test_uuid", "");
    }

    Tombstone parseTombstone(String tombstonePath) throws Exception {
        File tombstoneFile = getDevice().pullFile(tombstonePath);
        InputStream istr = new FileInputStream(tombstoneFile);
        Tombstone tombstoneProto;
        try {
            tombstoneProto = Tombstone.parseFrom(istr);
        } finally {
            istr.close();
        }
        return tombstoneProto;
    }

    @Test
    public void testCrash() throws Exception {
        String uuid = java.util.UUID.randomUUID().toString();
        getDevice().reboot();
        assertThat(getDevice().setProperty("sys.mte_crash_test_uuid", uuid)).isTrue();

        CommandResult result = getDevice().executeShellV2Command("start mte_upgrade_test_helper");
        assertThat(result.getExitCode()).isEqualTo(0);
        java.lang.Thread.sleep(20000);
        String[] tombstonesAfter = getDevice().getChildren("/data/tombstones");
        ArrayList<String> segvCodeNames = new ArrayList<String>();
        for (String tombstone : tombstonesAfter) {
            if (!tombstone.endsWith(".pb")) {
                continue;
            }
            String tombstoneFilename = "/data/tombstones/" + tombstone;
            Tombstone tombstoneProto = parseTombstone(tombstoneFilename);
            if (!tombstoneProto.getCommandLineList().stream().anyMatch(x -> x.contains(uuid))) {
                continue;
            }
            assertThat(tombstoneProto.getSignalInfo().getName()).isEqualTo("SIGSEGV");
            segvCodeNames.add(tombstoneProto.getSignalInfo().getCodeName());
            getDevice().deleteFile(tombstoneFilename);
            // remove the non .pb file as well.
            getDevice().deleteFile(tombstoneFilename.substring(0, tombstoneFilename.length() - 3));
        }
        assertThat(segvCodeNames.size()).isAtLeast(3);
        assertThat(segvCodeNames.get(0)).isEqualTo("SEGV_MTEAERR");
        assertThat(segvCodeNames.get(1)).isEqualTo("SEGV_MTESERR");
        assertThat(segvCodeNames.get(2)).isEqualTo("SEGV_MTEAERR");
    }

    @Test
    public void testCrashOverridden() throws Exception {
        String uuid = java.util.UUID.randomUUID().toString();
        getDevice().reboot();
        assertThat(getDevice().setProperty("sys.mte_crash_test_uuid", uuid)).isTrue();

        CommandResult result =
                getDevice().executeShellV2Command("start mte_upgrade_test_helper_overridden");
        assertThat(result.getExitCode()).isEqualTo(0);
        java.lang.Thread.sleep(20000);
        String[] tombstonesAfter = getDevice().getChildren("/data/tombstones");
        ArrayList<String> segvCodeNames = new ArrayList<String>();
        for (String tombstone : tombstonesAfter) {
            if (!tombstone.endsWith(".pb")) {
                continue;
            }
            String tombstoneFilename = "/data/tombstones/" + tombstone;
            Tombstone tombstoneProto = parseTombstone(tombstoneFilename);
            if (!tombstoneProto.getCommandLineList().stream().anyMatch(x -> x.contains(uuid))) {
                continue;
            }
            assertThat(tombstoneProto.getSignalInfo().getName()).isEqualTo("SIGSEGV");
            segvCodeNames.add(tombstoneProto.getSignalInfo().getCodeName());
            getDevice().deleteFile(tombstoneFilename);
            // remove the non .pb file as well.
            getDevice().deleteFile(tombstoneFilename.substring(0, tombstoneFilename.length() - 3));
        }
        assertThat(segvCodeNames.size()).isAtLeast(3);
        assertThat(segvCodeNames.get(0)).isEqualTo("SEGV_MTEAERR");
        assertThat(segvCodeNames.get(1)).isEqualTo("SEGV_MTEAERR");
        assertThat(segvCodeNames.get(2)).isEqualTo("SEGV_MTEAERR");
    }

    @Test
    public void testDowngrade() throws Exception {
        CommandResult result =
                getDevice()
                        .executeShellV2Command(
                                "MEMTAG_OPTIONS=async BIONIC_MEMTAG_UPGRADE_SECS=5"
                                        + " /system/bin/mte_upgrade_test_helper --check-downgrade");
        assertThat(result.getExitCode()).isEqualTo(0);
    }

    @Test
    public void testAppProcess() throws Exception {
        CommandResult result =
                getDevice()
                        .executeShellV2Command(
                                "MEMTAG_OPTIONS=async BIONIC_MEMTAG_UPGRADE_SECS=5"
                                        + " /data/local/tmp/app_process64 --get-mode");
        assertThat(result.getExitCode()).isEqualTo(1);  // ASYNC
    }
}
