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
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;

import com.android.tools.build.apkzlib.zip.ZFile;
import com.android.tools.build.apkzlib.zip.ZFileOptions;
import com.android.tools.build.apkzlib.zip.StoredEntry;
import com.android.tools.build.apkzlib.zip.StoredEntryType;
import com.android.tools.build.apkzlib.zip.CentralDirectoryHeaderCompressInfo;
import com.android.tools.build.apkzlib.zip.CentralDirectoryHeader;

import com.android.fastdeploy.APKMetaData;
import com.android.fastdeploy.APKEntry;

class PatchUtils {
    private static final long NEGATIVE_MASK = 1L << 63;
    private static final long NEGATIVE_LONG_SIGN_MASK = 1L << 63;
    public static final String SIGNATURE = "HAMADI/IHD";

    private static long getOffsetFromEntry(StoredEntry entry) {
        return entry.getCentralDirectoryHeader().getOffset() + entry.getLocalHeaderSize();
    }

    public static APKMetaData getAPKMetaData(File apkFile) throws IOException {
        APKMetaData.Builder apkEntriesBuilder = APKMetaData.newBuilder();
        ZFileOptions options = new ZFileOptions();
        ZFile zFile = new ZFile(apkFile, options);

        ArrayList<StoredEntry> metaDataEntries = new ArrayList<StoredEntry>();

        for (StoredEntry entry : zFile.entries()) {
            if (entry.getType() != StoredEntryType.FILE) {
                continue;
            }
            metaDataEntries.add(entry);
        }

        Collections.sort(metaDataEntries, new Comparator<StoredEntry>() {
            private long getOffsetFromEntry(StoredEntry entry) {
                return PatchUtils.getOffsetFromEntry(entry);
            }

            @Override
            public int compare(StoredEntry lhs, StoredEntry rhs) {
                // -1 - less than, 1 - greater than, 0 - equal, all inversed for descending
                return Long.compare(getOffsetFromEntry(lhs), getOffsetFromEntry(rhs));
            }
        });

        for (StoredEntry entry : metaDataEntries) {
            CentralDirectoryHeader cdh = entry.getCentralDirectoryHeader();
            CentralDirectoryHeaderCompressInfo cdhci = cdh.getCompressionInfoWithWait();

            APKEntry.Builder entryBuilder = APKEntry.newBuilder();
            entryBuilder.setCrc32(cdh.getCrc32());
            entryBuilder.setFileName(cdh.getName());
            entryBuilder.setCompressedSize(cdhci.getCompressedSize());
            entryBuilder.setUncompressedSize(cdh.getUncompressedSize());
            entryBuilder.setDataOffset(getOffsetFromEntry(entry));

            apkEntriesBuilder.addEntries(entryBuilder);
            apkEntriesBuilder.build();
        }
        return apkEntriesBuilder.build();
    }

    /**
     * Writes a 64-bit signed integer to the specified {@link OutputStream}. The least significant
     * byte is written first and the most significant byte is written last.
     * @param value the value to write
     * @param outputStream the stream to write to
     */
    static void writeFormattedLong(final long value, OutputStream outputStream) throws IOException {
        long y = value;
        if (y < 0) {
            y = (-y) | NEGATIVE_MASK;
        }

        for (int i = 0; i < 8; ++i) {
            outputStream.write((byte) (y & 0xff));
            y >>>= 8;
        }
    }

    /**
     * Reads a 64-bit signed integer written by {@link #writeFormattedLong(long, OutputStream)} from
     * the specified {@link InputStream}.
     * @param inputStream the stream to read from
     */
    static long readFormattedLong(InputStream inputStream) throws IOException {
        long result = 0;
        for (int bitshift = 0; bitshift < 64; bitshift += 8) {
            result |= ((long) inputStream.read()) << bitshift;
        }

        if ((result - NEGATIVE_MASK) > 0) {
            result = (result & ~NEGATIVE_MASK) * -1;
        }
        return result;
    }

    static final long readBsdiffLong(InputStream in) throws PatchFormatException, IOException {
        long result = 0;
        for (int bitshift = 0; bitshift < 64; bitshift += 8) {
            result |= ((long) in.read()) << bitshift;
        }

        if (result == NEGATIVE_LONG_SIGN_MASK) {
            // "Negative zero", which is valid in signed-magnitude format.
            // NB: No sane patch generator should ever produce such a value.
            throw new PatchFormatException("read negative zero");
        }

        if ((result & NEGATIVE_LONG_SIGN_MASK) != 0) {
            result = -(result & ~NEGATIVE_LONG_SIGN_MASK);
        }

        return result;
    }

    static void readFully(final InputStream in, final byte[] destination, final int startAt,
        final int numBytes) throws IOException {
        int numRead = 0;
        while (numRead < numBytes) {
            int readNow = in.read(destination, startAt + numRead, numBytes - numRead);
            if (readNow == -1) {
                throw new IOException("truncated input stream");
            }
            numRead += readNow;
        }
    }

    static void pipe(final InputStream in, final OutputStream out, final byte[] buffer,
        long copyLength) throws IOException {
        while (copyLength > 0) {
            int maxCopy = Math.min(buffer.length, (int) copyLength);
            readFully(in, buffer, 0, maxCopy);
            out.write(buffer, 0, maxCopy);
            copyLength -= maxCopy;
        }
    }

    static void pipe(final RandomAccessFile in, final OutputStream out, final byte[] buffer,
        long copyLength) throws IOException {
        while (copyLength > 0) {
            int maxCopy = Math.min(buffer.length, (int) copyLength);
            in.readFully(buffer, 0, maxCopy);
            out.write(buffer, 0, maxCopy);
            copyLength -= maxCopy;
        }
    }

    static void fill(byte value, final OutputStream out, final byte[] buffer, long fillLength)
        throws IOException {
        while (fillLength > 0) {
            int maxCopy = Math.min(buffer.length, (int) fillLength);
            Arrays.fill(buffer, 0, maxCopy, value);
            out.write(buffer, 0, maxCopy);
            fillLength -= maxCopy;
        }
    }
}
