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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.channels.WritableByteChannel;

import com.android.fastdeploy.PatchFormatException;
import com.android.fastdeploy.ApkArchive;
import com.android.fastdeploy.APKDump;
import com.android.fastdeploy.APKMetaData;
import com.android.fastdeploy.PatchUtils;

import com.google.protobuf.ByteString;

public final class DeployAgent {
    private static final int BUFFER_SIZE = 128 * 1024;
    private static final int AGENT_VERSION = 0x00000003;

    public static void main(String[] args) {
        int exitCode = 0;
        try {
            if (args.length < 1) {
                showUsage(0);
            }

            String commandString = args[0];
            switch (commandString) {
                case "dump": {
                    if (args.length != 3) {
                        showUsage(1);
                    }

                    String requiredVersion = args[1];
                    if (AGENT_VERSION == Integer.parseInt(requiredVersion)) {
                        String packageName = args[2];
                        String packagePath = getFilenameFromPackageName(packageName);
                        if (packagePath != null) {
                            dumpApk(packageName, packagePath);
                        } else {
                            exitCode = 3;
                        }
                    } else {
                        System.out.printf("0x%08X\n", AGENT_VERSION);
                        exitCode = 4;
                    }
                    break;
                }
                case "apply": {
                    if (args.length < 3) {
                        showUsage(1);
                    }

                    String patchPath = args[1];
                    String outputParam = args[2];

                    InputStream deltaInputStream = null;
                    if (patchPath.compareTo("-") == 0) {
                        deltaInputStream = System.in;
                    } else {
                        deltaInputStream = new FileInputStream(patchPath);
                    }

                    if (outputParam.equals("-o")) {
                        OutputStream outputStream = null;
                        if (args.length > 3) {
                            String outputPath = args[3];
                            if (!outputPath.equals("-")) {
                                outputStream = new FileOutputStream(outputPath);
                            }
                        }
                        if (outputStream == null) {
                            outputStream = System.out;
                        }
                        writePatchToStream(deltaInputStream, outputStream);
                    } else if (outputParam.equals("-pm")) {
                        String[] sessionArgs = null;
                        if (args.length > 3) {
                            int numSessionArgs = args.length - 3;
                            sessionArgs = new String[numSessionArgs];
                            for (int i = 0; i < numSessionArgs; i++) {
                                sessionArgs[i] = args[i + 3];
                            }
                        }
                        exitCode = applyPatch(deltaInputStream, sessionArgs);
                    }
                    break;
                }
                default:
                    showUsage(1);
                    break;
            }
        } catch (Exception e) {
            System.err.println("Error: " + e);
            e.printStackTrace();
            System.exit(2);
        }
        System.exit(exitCode);
    }

    private static void showUsage(int exitCode) {
        System.err.println(
                "usage: deployagent <command> [<args>]\n\n" +
                        "commands:\n" +
                        "dump VERSION PKGNAME  dump info for an installed package given that " +
                        "VERSION equals current agent's version\n" +
                        "apply PATCHFILE [-o|-pm]    apply a patch from PATCHFILE " +
                        "(- for stdin) to an installed package\n" +
                        " -o <FILE> directs output to FILE, default or - for stdout\n" +
                        " -pm <ARGS> directs output to package manager, passes <ARGS> to " +
                        "'pm install-create'\n"
        );
        System.exit(exitCode);
    }

    private static Process executeCommand(String command) throws IOException {
        try {
            Process p;
            p = Runtime.getRuntime().exec(command);
            p.waitFor();
            return p;
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        return null;
    }

    private static String getFilenameFromPackageName(String packageName) throws IOException {
        StringBuilder commandBuilder = new StringBuilder();
        commandBuilder.append("pm list packages -f " + packageName);

        Process p = executeCommand(commandBuilder.toString());
        BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));

        String packagePrefix = "package:";
        String packageSuffix = "=" + packageName;
        String line = "";
        while ((line = reader.readLine()) != null) {
            if (line.endsWith(packageSuffix)) {
                int packageIndex = line.indexOf(packagePrefix);
                if (packageIndex == -1) {
                    throw new IOException("error reading package list");
                }
                int equalsIndex = line.lastIndexOf(packageSuffix);
                String fileName =
                        line.substring(packageIndex + packagePrefix.length(), equalsIndex);
                return fileName;
            }
        }
        return null;
    }

    private static void dumpApk(String packageName, String packagePath) throws IOException {
        File apk = new File(packagePath);
        ApkArchive.Dump dump = new ApkArchive(apk).extractMetadata();

        APKDump.Builder apkDumpBuilder = APKDump.newBuilder();
        apkDumpBuilder.setName(packageName);
        if (dump.cd != null) {
            apkDumpBuilder.setCd(ByteString.copyFrom(dump.cd));
        }
        if (dump.signature != null) {
            apkDumpBuilder.setSignature(ByteString.copyFrom(dump.signature));
        }
        apkDumpBuilder.setAbsolutePath(apk.getAbsolutePath());

        apkDumpBuilder.build().writeTo(System.out);
    }

    private static int createInstallSession(String[] args) throws IOException {
        StringBuilder commandBuilder = new StringBuilder();
        commandBuilder.append("pm install-create ");
        for (int i = 0; args != null && i < args.length; i++) {
            commandBuilder.append(args[i] + " ");
        }

        Process p = executeCommand(commandBuilder.toString());

        BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line = "";
        String successLineStart = "Success: created install session [";
        String successLineEnd = "]";
        while ((line = reader.readLine()) != null) {
            if (line.startsWith(successLineStart) && line.endsWith(successLineEnd)) {
                return Integer.parseInt(line.substring(successLineStart.length(),
                        line.lastIndexOf(successLineEnd)));
            }
        }

        return -1;
    }

    private static int commitInstallSession(int sessionId) throws IOException {
        StringBuilder commandBuilder = new StringBuilder();
        commandBuilder.append(String.format("pm install-commit %d -- - ", sessionId));
        Process p = executeCommand(commandBuilder.toString());
        return p.exitValue();
    }

    private static int applyPatch(InputStream deltaStream, String[] sessionArgs)
            throws IOException, PatchFormatException {
        int sessionId = createInstallSession(sessionArgs);
        if (sessionId < 0) {
            System.err.println("PM Create Session Failed");
            return -1;
        }

        int writeExitCode = writePatchedDataToSession(deltaStream, sessionId);
        if (writeExitCode == 0) {
            return commitInstallSession(sessionId);
        } else {
            return -1;
        }
    }

    private static long writePatchToStream(InputStream patchData,
            OutputStream outputStream) throws IOException, PatchFormatException {
        long newSize = readPatchHeader(patchData);
        long bytesWritten = writePatchedDataToStream(newSize, patchData, outputStream);
        outputStream.flush();
        if (bytesWritten != newSize) {
            throw new PatchFormatException(String.format(
                    "output size mismatch (expected %ld but wrote %ld)", newSize, bytesWritten));
        }
        return bytesWritten;
    }

    private static long readPatchHeader(InputStream patchData)
            throws IOException, PatchFormatException {
        byte[] signatureBuffer = new byte[PatchUtils.SIGNATURE.length()];
        try {
            PatchUtils.readFully(patchData, signatureBuffer);
        } catch (IOException e) {
            throw new PatchFormatException("truncated signature");
        }

        String signature = new String(signatureBuffer);
        if (!PatchUtils.SIGNATURE.equals(signature)) {
            throw new PatchFormatException("bad signature");
        }

        long newSize = PatchUtils.readLELong(patchData);
        if (newSize < 0) {
            throw new PatchFormatException("bad newSize: " + newSize);
        }

        return newSize;
    }

    // Note that this function assumes patchData has been seek'ed to the start of the delta stream
    // (i.e. the signature has already been read by readPatchHeader). For a stream that points to
    // the start of a patch file call writePatchToStream
    private static long writePatchedDataToStream(long newSize, InputStream patchData,
            OutputStream outputStream) throws IOException {
        String deviceFile = PatchUtils.readString(patchData);
        RandomAccessFile oldDataFile = new RandomAccessFile(deviceFile, "r");
        FileChannel oldData = oldDataFile.getChannel();

        WritableByteChannel newData = Channels.newChannel(outputStream);

        long newDataBytesWritten = 0;
        byte[] buffer = new byte[BUFFER_SIZE];

        while (newDataBytesWritten < newSize) {
            long newDataLen = PatchUtils.readLELong(patchData);
            if (newDataLen > 0) {
                PatchUtils.pipe(patchData, outputStream, buffer, newDataLen);
            }

            long oldDataOffset = PatchUtils.readLELong(patchData);
            long oldDataLen = PatchUtils.readLELong(patchData);
            if (oldDataLen >= 0) {
                long offset = oldDataOffset;
                long len = oldDataLen;
                while (len > 0) {
                    long chunkLen = Math.min(len, 1024*1024*1024);
                    oldData.transferTo(offset, chunkLen, newData);
                    offset += chunkLen;
                    len -= chunkLen;
                }
            }
            newDataBytesWritten += newDataLen + oldDataLen;
        }

        return newDataBytesWritten;
    }

    private static int writePatchedDataToSession(InputStream patchData, int sessionId)
            throws IOException, PatchFormatException {
        try {
            Process p;
            long newSize = readPatchHeader(patchData);
            String command = String.format("pm install-write -S %d %d -- -", newSize, sessionId);
            p = Runtime.getRuntime().exec(command);

            OutputStream sessionOutputStream = p.getOutputStream();
            long bytesWritten = writePatchedDataToStream(newSize, patchData, sessionOutputStream);
            sessionOutputStream.flush();
            p.waitFor();
            if (bytesWritten != newSize) {
                throw new PatchFormatException(
                        String.format("output size mismatch (expected %d but wrote %)", newSize,
                                bytesWritten));
            }
            return p.exitValue();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        return -1;
    }
}
