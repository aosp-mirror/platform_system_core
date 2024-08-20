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
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Arrays;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(DeviceJUnit4ClassRunner.class)
public class PermissiveMteTest extends BaseHostJUnit4Test {
  String mUUID;

  @Before
  public void setUp() throws Exception {
    mUUID = java.util.UUID.randomUUID().toString();
    CommandResult result =
        getDevice().executeShellV2Command("/data/local/tmp/mte_crash setUp " + mUUID);
    assumeTrue("mte_crash needs to segfault", result.getExitCode() == 139);
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

  @After
  public void tearDown() throws Exception {
    String[] tombstones = getDevice().getChildren("/data/tombstones");
    for (String tombstone : tombstones) {
      if (!tombstone.endsWith(".pb")) {
        continue;
      }
      String tombstonePath = "/data/tombstones/" + tombstone;
      Tombstone tombstoneProto = parseTombstone(tombstonePath);
      if (!tombstoneProto.getCommandLineList().stream().anyMatch(x -> x.contains(mUUID))) {
        continue;
      }
      getDevice().deleteFile(tombstonePath);
      // remove the non .pb file as well.
      getDevice().deleteFile(tombstonePath.substring(0, tombstonePath.length() - 3));
    }
  }

  @Test
  public void testCrash() throws Exception {
    CommandResult result = getDevice().executeShellV2Command(
        "MTE_PERMISSIVE=1 /data/local/tmp/mte_crash testCrash " + mUUID);
    assertThat(result.getExitCode()).isEqualTo(0);
    int numberTombstones = 0;
    String[] tombstones = getDevice().getChildren("/data/tombstones");
    for (String tombstone : tombstones) {
      if (!tombstone.endsWith(".pb")) {
        continue;
      }
      String tombstonePath = "/data/tombstones/" + tombstone;
      Tombstone tombstoneProto = parseTombstone(tombstonePath);
      if (!tombstoneProto.getCommandLineList().stream().anyMatch(x -> x.contains(mUUID))) {
        continue;
      }
      if (!tombstoneProto.getCommandLineList().stream().anyMatch(x -> x.contains("testCrash"))) {
        continue;
      }
      numberTombstones++;
    }
    assertThat(numberTombstones).isEqualTo(1);
  }

  @Test
  public void testReenableCrash() throws Exception {
    CommandResult result =
        getDevice().executeShellV2Command("MTE_PERMISSIVE=1 MTE_PERMISSIVE_REENABLE_TIME_CPUMS=1 "
                                          + "/data/local/tmp/mte_crash testReenableCrash "
                                          + mUUID);
    assertThat(result.getExitCode()).isEqualTo(0);
    int numberTombstones = 0;
    String[] tombstones = getDevice().getChildren("/data/tombstones");
    for (String tombstone : tombstones) {
      if (!tombstone.endsWith(".pb")) {
        continue;
      }
      String tombstonePath = "/data/tombstones/" + tombstone;
      Tombstone tombstoneProto = parseTombstone(tombstonePath);
      if (!tombstoneProto.getCommandLineList().stream().anyMatch(x -> x.contains(mUUID))) {
        continue;
      }
      if (!tombstoneProto.getCommandLineList().stream().anyMatch(
              x -> x.contains("testReenableCrash"))) {
        continue;
      }
      numberTombstones++;
    }
    assertThat(numberTombstones).isEqualTo(2);
  }

  @Test
  public void testCrashProperty() throws Exception {
    String prevValue = getDevice().getProperty("persist.sys.mte.permissive");
    if (prevValue == null) {
      prevValue = "";
    }
    assertThat(getDevice().setProperty("persist.sys.mte.permissive", "1")).isTrue();
    CommandResult result =
        getDevice().executeShellV2Command("/data/local/tmp/mte_crash testCrash " + mUUID);
    assertThat(result.getExitCode()).isEqualTo(0);
    int numberTombstones = 0;
    String[] tombstones = getDevice().getChildren("/data/tombstones");
    for (String tombstone : tombstones) {
      if (!tombstone.endsWith(".pb")) {
        continue;
      }
      String tombstonePath = "/data/tombstones/" + tombstone;
      Tombstone tombstoneProto = parseTombstone(tombstonePath);
      if (!tombstoneProto.getCommandLineList().stream().anyMatch(x -> x.contains(mUUID))) {
        continue;
      }
      if (!tombstoneProto.getCommandLineList().stream().anyMatch(x -> x.contains("testCrash"))) {
        continue;
      }
      numberTombstones++;
    }
    assertThat(numberTombstones).isEqualTo(1);
    assertThat(getDevice().setProperty("persist.sys.mte.permissive", prevValue)).isTrue();
  }
}
