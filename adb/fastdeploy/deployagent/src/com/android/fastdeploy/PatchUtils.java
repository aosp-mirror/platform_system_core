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

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

class PatchUtils {
    public static final String SIGNATURE = "FASTDEPLOY";

    /**
     * Reads a 64-bit signed integer in Little Endian format from the specified {@link
     * DataInputStream}.
     *
     * @param in the stream to read from.
     */
    static long readLELong(InputStream in) throws IOException {
        byte[] buffer = new byte[Long.BYTES];
        readFully(in, buffer);
        ByteBuffer buf = ByteBuffer.wrap(buffer).order(ByteOrder.LITTLE_ENDIAN);
        return buf.getLong();
    }

    static String readString(InputStream in) throws IOException {
        int size = (int) readLELong(in);
        byte[] buffer = new byte[size];
        readFully(in, buffer);
        return new String(buffer);
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

    static void readFully(final InputStream in, final byte[] destination) throws IOException {
        readFully(in, destination, 0, destination.length);
    }

    static void pipe(final InputStream in, final OutputStream out, final byte[] buffer,
            long copyLength) throws IOException {
        while (copyLength > 0) {
            int maxCopy = (int) Math.min(buffer.length, copyLength);
            readFully(in, buffer, 0, maxCopy);
            out.write(buffer, 0, maxCopy);
            copyLength -= maxCopy;
        }
    }
}
