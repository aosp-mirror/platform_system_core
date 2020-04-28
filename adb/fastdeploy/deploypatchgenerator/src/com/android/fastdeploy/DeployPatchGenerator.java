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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.StringBuilder;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.ArrayList;

import java.nio.charset.StandardCharsets;
import static java.nio.charset.StandardCharsets.UTF_8;

import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.AbstractMap.SimpleEntry;

import com.android.fastdeploy.APKMetaData;
import com.android.fastdeploy.APKEntry;

public final class DeployPatchGenerator {
    private static final int BUFFER_SIZE = 128 * 1024;

    public static void main(String[] args) {
        try {
            if (args.length < 2) {
                showUsage(0);
            }

            boolean verbose = false;
            if (args.length > 2) {
                String verboseFlag = args[2];
                if (verboseFlag.compareTo("--verbose") == 0) {
                    verbose = true;
                }
            }

            StringBuilder sb = null;
            String apkPath = args[0];
            String deviceMetadataPath = args[1];
            File hostFile = new File(apkPath);

            List<APKEntry> deviceZipEntries = getMetadataFromFile(deviceMetadataPath);
            System.err.println("Device Entries (" + deviceZipEntries.size() + ")");
            if (verbose) {
                sb = new StringBuilder();
                for (APKEntry entry : deviceZipEntries) {
                    APKEntryToString(entry, sb);
                }
                System.err.println(sb.toString());
            }

            List<APKEntry> hostFileEntries = PatchUtils.getAPKMetaData(hostFile).getEntriesList();
            System.err.println("Host Entries (" + hostFileEntries.size() + ")");
            if (verbose) {
                sb = new StringBuilder();
                for (APKEntry entry : hostFileEntries) {
                    APKEntryToString(entry, sb);
                }
                System.err.println(sb.toString());
            }

            List<SimpleEntry<APKEntry, APKEntry>> identicalContentsEntrySet =
                getIdenticalContents(deviceZipEntries, hostFileEntries);
            reportIdenticalContents(identicalContentsEntrySet, hostFile);

            if (verbose) {
                sb = new StringBuilder();
                for (SimpleEntry<APKEntry, APKEntry> identicalEntry : identicalContentsEntrySet) {
                    APKEntry entry = identicalEntry.getValue();
                    APKEntryToString(entry, sb);
                }
                System.err.println("Identical Entries (" + identicalContentsEntrySet.size() + ")");
                System.err.println(sb.toString());
            }

            createPatch(identicalContentsEntrySet, hostFile, System.out);
        } catch (Exception e) {
            System.err.println("Error: " + e);
            e.printStackTrace();
            System.exit(2);
        }
        System.exit(0);
    }

    private static void showUsage(int exitCode) {
        System.err.println("usage: deploypatchgenerator <apkpath> <deviceapkmetadata> [--verbose]");
        System.err.println("");
        System.exit(exitCode);
    }

    private static void APKEntryToString(APKEntry entry, StringBuilder outputString) {
        outputString.append(String.format("Filename: %s\n", entry.getFileName()));
        outputString.append(String.format("CRC32: 0x%08X\n", entry.getCrc32()));
        outputString.append(String.format("Data Offset: %d\n", entry.getDataOffset()));
        outputString.append(String.format("Compressed Size: %d\n", entry.getCompressedSize()));
        outputString.append(String.format("Uncompressed Size: %d\n", entry.getUncompressedSize()));
    }

    private static List<APKEntry> getMetadataFromFile(String deviceMetadataPath) throws IOException {
        InputStream is = new FileInputStream(new File(deviceMetadataPath));
        APKMetaData apkMetaData = APKMetaData.parseDelimitedFrom(is);
        return apkMetaData.getEntriesList();
    }

    private static List<SimpleEntry<APKEntry, APKEntry>> getIdenticalContents(
        List<APKEntry> deviceZipEntries, List<APKEntry> hostZipEntries) throws IOException {
        List<SimpleEntry<APKEntry, APKEntry>> identicalContents =
            new ArrayList<SimpleEntry<APKEntry, APKEntry>>();

        for (APKEntry deviceZipEntry : deviceZipEntries) {
            for (APKEntry hostZipEntry : hostZipEntries) {
                if (deviceZipEntry.getCrc32() == hostZipEntry.getCrc32() &&
                    deviceZipEntry.getFileName().equals(hostZipEntry.getFileName())) {
                    identicalContents.add(new SimpleEntry(deviceZipEntry, hostZipEntry));
                }
            }
        }

        Collections.sort(identicalContents, new Comparator<SimpleEntry<APKEntry, APKEntry>>() {
            @Override
            public int compare(
                SimpleEntry<APKEntry, APKEntry> p1, SimpleEntry<APKEntry, APKEntry> p2) {
                return Long.compare(p1.getValue().getDataOffset(), p2.getValue().getDataOffset());
            }
        });

        return identicalContents;
    }

    private static void reportIdenticalContents(
        List<SimpleEntry<APKEntry, APKEntry>> identicalContentsEntrySet, File hostFile)
        throws IOException {
        long totalEqualBytes = 0;
        int totalEqualFiles = 0;
        for (SimpleEntry<APKEntry, APKEntry> entries : identicalContentsEntrySet) {
            APKEntry hostAPKEntry = entries.getValue();
            totalEqualBytes += hostAPKEntry.getCompressedSize();
            totalEqualFiles++;
        }

        float savingPercent = (float) (totalEqualBytes * 100) / hostFile.length();

        System.err.println("Detected " + totalEqualFiles + " equal APK entries");
        System.err.println(totalEqualBytes + " bytes are equal out of " + hostFile.length() + " ("
            + savingPercent + "%)");
    }

    static void createPatch(List<SimpleEntry<APKEntry, APKEntry>> zipEntrySimpleEntrys,
        File hostFile, OutputStream patchStream) throws IOException, PatchFormatException {
        FileInputStream hostFileInputStream = new FileInputStream(hostFile);

        patchStream.write(PatchUtils.SIGNATURE.getBytes(StandardCharsets.US_ASCII));
        PatchUtils.writeFormattedLong(hostFile.length(), patchStream);

        byte[] buffer = new byte[BUFFER_SIZE];
        long totalBytesWritten = 0;
        Iterator<SimpleEntry<APKEntry, APKEntry>> entrySimpleEntryIterator =
            zipEntrySimpleEntrys.iterator();
        while (entrySimpleEntryIterator.hasNext()) {
            SimpleEntry<APKEntry, APKEntry> entrySimpleEntry = entrySimpleEntryIterator.next();
            APKEntry deviceAPKEntry = entrySimpleEntry.getKey();
            APKEntry hostAPKEntry = entrySimpleEntry.getValue();

            long newDataLen = hostAPKEntry.getDataOffset() - totalBytesWritten;
            long oldDataOffset = deviceAPKEntry.getDataOffset();
            long oldDataLen = deviceAPKEntry.getCompressedSize();

            PatchUtils.writeFormattedLong(newDataLen, patchStream);
            PatchUtils.pipe(hostFileInputStream, patchStream, buffer, newDataLen);
            PatchUtils.writeFormattedLong(oldDataOffset, patchStream);
            PatchUtils.writeFormattedLong(oldDataLen, patchStream);

            long skip = hostFileInputStream.skip(oldDataLen);
            if (skip != oldDataLen) {
                throw new PatchFormatException("skip error: attempted to skip " + oldDataLen
                    + " bytes but return code was " + skip);
            }
            totalBytesWritten += oldDataLen + newDataLen;
        }
        long remainderLen = hostFile.length() - totalBytesWritten;
        PatchUtils.writeFormattedLong(remainderLen, patchStream);
        PatchUtils.pipe(hostFileInputStream, patchStream, buffer, remainderLen);
        PatchUtils.writeFormattedLong(0, patchStream);
        PatchUtils.writeFormattedLong(0, patchStream);
        patchStream.flush();
    }
}
