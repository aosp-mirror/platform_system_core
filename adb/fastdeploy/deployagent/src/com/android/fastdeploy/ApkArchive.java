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

import android.util.Log;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;

/**
 * Extremely light-weight APK parser class.
 * Aware of Central Directory, Local File Headers and Signature.
 * No Zip64 support yet.
 */
public final class ApkArchive {
    private static final String TAG = "ApkArchive";

    // Central Directory constants.
    private static final int EOCD_SIGNATURE = 0x06054b50;
    private static final int EOCD_MIN_SIZE = 22;
    private static final long EOCD_MAX_SIZE = 65_535L + EOCD_MIN_SIZE;

    private static final int CD_ENTRY_HEADER_SIZE_BYTES = 22;
    private static final int CD_LOCAL_FILE_HEADER_SIZE_OFFSET = 12;

    // Signature constants.
    private static final int EOSIGNATURE_SIZE = 24;

    public final static class Dump {
        final byte[] cd;
        final byte[] signature;

        Dump(byte[] cd, byte[] signature) {
            this.cd = cd;
            this.signature = signature;
        }
    }

    final static class Location {
        final long offset;
        final long size;

        public Location(long offset, long size) {
            this.offset = offset;
            this.size = size;
        }
    }

    private final RandomAccessFile mFile;
    private final FileChannel mChannel;

    public ApkArchive(File apk) throws IOException {
        mFile = new RandomAccessFile(apk, "r");
        mChannel = mFile.getChannel();
    }

    /**
     * Extract the APK metadata: content of Central Directory and Signature.
     *
     * @return raw content from APK representing CD and Signature data.
     */
    public Dump extractMetadata() throws IOException {
        Location cdLoc = getCDLocation();
        byte[] cd = readMetadata(cdLoc);

        byte[] signature = null;
        Location sigLoc = getSignatureLocation(cdLoc.offset);
        if (sigLoc != null) {
            signature = readMetadata(sigLoc);
            long size = ByteBuffer.wrap(signature).order(ByteOrder.LITTLE_ENDIAN).getLong();
            if (sigLoc.size != size) {
                Log.e(TAG, "Mismatching signature sizes: " + sigLoc.size + " != " + size);
                signature = null;
            }
        }

        return new Dump(cd, signature);
    }

    private long findEndOfCDRecord() throws IOException {
        final long fileSize = mChannel.size();
        int sizeToRead = Math.toIntExact(Math.min(fileSize, EOCD_MAX_SIZE));
        final long readOffset = fileSize - sizeToRead;
        ByteBuffer buffer = mChannel.map(FileChannel.MapMode.READ_ONLY, readOffset,
                sizeToRead).order(ByteOrder.LITTLE_ENDIAN);

        buffer.position(sizeToRead - EOCD_MIN_SIZE);
        while (true) {
            int signature = buffer.getInt(); // Read 4 bytes.
            if (signature == EOCD_SIGNATURE) {
                return readOffset + buffer.position() - 4;
            }
            if (buffer.position() == 4) {
                break;
            }
            buffer.position(buffer.position() - Integer.BYTES - 1); // Backtrack 5 bytes.
        }

        return -1L;
    }

    private Location findCDRecord(ByteBuffer buf) {
        if (buf.order() != ByteOrder.LITTLE_ENDIAN) {
            throw new IllegalArgumentException("ByteBuffer byte order must be little endian");
        }
        if (buf.remaining() < CD_ENTRY_HEADER_SIZE_BYTES) {
            throw new IllegalArgumentException(
                    "Input too short. Need at least " + CD_ENTRY_HEADER_SIZE_BYTES
                            + " bytes, available: " + buf.remaining() + "bytes.");
        }

        int originalPosition = buf.position();
        int recordSignature = buf.getInt();
        if (recordSignature != EOCD_SIGNATURE) {
            throw new IllegalArgumentException(
                    "Not a Central Directory record. Signature: 0x"
                            + Long.toHexString(recordSignature & 0xffffffffL));
        }

        buf.position(originalPosition + CD_LOCAL_FILE_HEADER_SIZE_OFFSET);
        long size = buf.getInt() & 0xffffffffL;
        long offset = buf.getInt() & 0xffffffffL;
        return new Location(offset, size);
    }

    // Retrieve the location of the Central Directory Record.
    Location getCDLocation() throws IOException {
        long eocdRecord = findEndOfCDRecord();
        if (eocdRecord < 0) {
            throw new IllegalArgumentException("Unable to find End of Central Directory record.");
        }

        Location location = findCDRecord(mChannel.map(FileChannel.MapMode.READ_ONLY, eocdRecord,
                CD_ENTRY_HEADER_SIZE_BYTES).order(ByteOrder.LITTLE_ENDIAN));
        if (location == null) {
            throw new IllegalArgumentException("Unable to find Central Directory File Header.");
        }

        return location;
    }

    // Retrieve the location of the signature block starting from Central
    // Directory Record or null if signature is not found.
    Location getSignatureLocation(long cdRecordOffset) throws IOException {
        long signatureOffset = cdRecordOffset - EOSIGNATURE_SIZE;
        if (signatureOffset < 0) {
            Log.e(TAG, "Unable to find Signature.");
            return null;
        }

        ByteBuffer signature = mChannel.map(FileChannel.MapMode.READ_ONLY, signatureOffset,
                EOSIGNATURE_SIZE).order(ByteOrder.LITTLE_ENDIAN);

        long size = signature.getLong();

        byte[] sign = new byte[16];
        signature.get(sign);
        String signAsString = new String(sign);
        if (!"APK Sig Block 42".equals(signAsString)) {
            Log.e(TAG, "Signature magic does not match: " + signAsString);
            return null;
        }

        long offset = cdRecordOffset - size - 8;

        return new Location(offset, size);
    }

    private byte[] readMetadata(Location loc) throws IOException {
        byte[] payload = new byte[(int) loc.size];
        ByteBuffer buffer = mChannel.map(FileChannel.MapMode.READ_ONLY, loc.offset, loc.size);
        buffer.get(payload);
        return payload;
    }
}
