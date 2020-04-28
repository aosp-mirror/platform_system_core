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
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.TimeUnit;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.util.Set;

import com.android.fastdeploy.APKMetaData;
import com.android.fastdeploy.PatchUtils;

public final class DeployAgent {
    private static final int BUFFER_SIZE = 128 * 1024;
    private static final int AGENT_VERSION = 0x00000002;

    public static void main(String[] args) {
        int exitCode = 0;
        try {
            if (args.length < 1) {
                showUsage(0);
            }

            String commandString = args[0];

            if (commandString.equals("extract")) {
                if (args.length != 2) {
                    showUsage(1);
                }

                String packageName = args[1];
                extractMetaData(packageName);
            } else if (commandString.equals("find")) {
                if (args.length != 2) {
                    showUsage(1);
                }

                String packageName = args[1];
                if (getFilenameFromPackageName(packageName) == null) {
                    exitCode = 3;
                }
            } else if (commandString.equals("apply")) {
                if (args.length < 4) {
                    showUsage(1);
                }

                String packageName = args[1];
                String patchPath = args[2];
                String outputParam = args[3];

                InputStream deltaInputStream = null;
                if (patchPath.compareTo("-") == 0) {
                    deltaInputStream = System.in;
                } else {
                    deltaInputStream = new FileInputStream(patchPath);
                }

                if (outputParam.equals("-o")) {
                    OutputStream outputStream = null;
                    if (args.length > 4) {
                        String outputPath = args[4];
                        if (!outputPath.equals("-")) {
                            outputStream = new FileOutputStream(outputPath);
                        }
                    }
                    if (outputStream == null) {
                        outputStream = System.out;
                    }
                    File deviceFile = getFileFromPackageName(packageName);
                    writePatchToStream(
                            new RandomAccessFile(deviceFile, "r"), deltaInputStream, outputStream);
                } else if (outputParam.equals("-pm")) {
                    String[] sessionArgs = null;
                    if (args.length > 4) {
                        int numSessionArgs = args.length-4;
                        sessionArgs = new String[numSessionArgs];
                        for (int i=0 ; i<numSessionArgs ; i++) {
                            sessionArgs[i] = args[i+4];
                        }
                    }
                    exitCode = applyPatch(packageName, deltaInputStream, sessionArgs);
                }
            } else if (commandString.equals("version")) {
                System.out.printf("0x%08X\n", AGENT_VERSION);
            } else {
                showUsage(1);
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
            "version                             get the version\n" +
            "find PKGNAME                        return zero if package found, else non-zero\n" +
            "extract PKGNAME                     extract an installed package's metadata\n" +
            "apply PKGNAME PATCHFILE [-o|-pm]    apply a patch from PATCHFILE (- for stdin) to an installed package\n" +
            " -o <FILE> directs output to FILE, default or - for stdout\n" +
            " -pm <ARGS> directs output to package manager, passes <ARGS> to 'pm install-create'\n"
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

    private static File getFileFromPackageName(String packageName) throws IOException {
        String filename = getFilenameFromPackageName(packageName);
        if (filename == null) {
            // Should not happen (function is only called when we know the package exists)
            throw new IOException("package not found");
        }
        return new File(filename);
    }

    private static void extractMetaData(String packageName) throws IOException {
        File apkFile = getFileFromPackageName(packageName);
        APKMetaData apkMetaData = PatchUtils.getAPKMetaData(apkFile);
        apkMetaData.writeDelimitedTo(System.out);
    }

    private static int createInstallSession(String[] args) throws IOException {
        StringBuilder commandBuilder = new StringBuilder();
        commandBuilder.append("pm install-create ");
        for (int i=0 ; args != null && i<args.length ; i++) {
            commandBuilder.append(args[i] + " ");
        }

        Process p = executeCommand(commandBuilder.toString());

        BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line = "";
        String successLineStart = "Success: created install session [";
        String successLineEnd = "]";
        while ((line = reader.readLine()) != null) {
            if (line.startsWith(successLineStart) && line.endsWith(successLineEnd)) {
                return Integer.parseInt(line.substring(successLineStart.length(), line.lastIndexOf(successLineEnd)));
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

    private static int applyPatch(String packageName, InputStream deltaStream, String[] sessionArgs)
            throws IOException, PatchFormatException {
        File deviceFile = getFileFromPackageName(packageName);
        int sessionId = createInstallSession(sessionArgs);
        if (sessionId < 0) {
            System.err.println("PM Create Session Failed");
            return -1;
        }

        int writeExitCode = writePatchedDataToSession(new RandomAccessFile(deviceFile, "r"), deltaStream, sessionId);

        if (writeExitCode == 0) {
            return commitInstallSession(sessionId);
        } else {
            return -1;
        }
    }

    private static long writePatchToStream(RandomAccessFile oldData, InputStream patchData,
        OutputStream outputStream) throws IOException, PatchFormatException {
        long newSize = readPatchHeader(patchData);
        long bytesWritten = writePatchedDataToStream(oldData, newSize, patchData, outputStream);
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
            PatchUtils.readFully(patchData, signatureBuffer, 0, signatureBuffer.length);
        } catch (IOException e) {
            throw new PatchFormatException("truncated signature");
        }

        String signature = new String(signatureBuffer, 0, signatureBuffer.length, "US-ASCII");
        if (!PatchUtils.SIGNATURE.equals(signature)) {
            throw new PatchFormatException("bad signature");
        }

        long newSize = PatchUtils.readBsdiffLong(patchData);
        if (newSize < 0 || newSize > Integer.MAX_VALUE) {
            throw new PatchFormatException("bad newSize");
        }

        return newSize;
    }

    // Note that this function assumes patchData has been seek'ed to the start of the delta stream
    // (i.e. the signature has already been read by readPatchHeader). For a stream that points to the
    // start of a patch file call writePatchToStream
    private static long writePatchedDataToStream(RandomAccessFile oldData, long newSize,
        InputStream patchData, OutputStream outputStream) throws IOException {
        long newDataBytesWritten = 0;
        byte[] buffer = new byte[BUFFER_SIZE];

        while (newDataBytesWritten < newSize) {
            long copyLen = PatchUtils.readFormattedLong(patchData);
            if (copyLen > 0) {
                PatchUtils.pipe(patchData, outputStream, buffer, (int) copyLen);
            }

            long oldDataOffset = PatchUtils.readFormattedLong(patchData);
            long oldDataLen = PatchUtils.readFormattedLong(patchData);
            oldData.seek(oldDataOffset);
            if (oldDataLen > 0) {
                PatchUtils.pipe(oldData, outputStream, buffer, (int) oldDataLen);
            }

            newDataBytesWritten += copyLen + oldDataLen;
        }

        return newDataBytesWritten;
    }

    private static int writePatchedDataToSession(RandomAccessFile oldData, InputStream patchData, int sessionId)
            throws IOException, PatchFormatException {
        try {
            Process p;
            long newSize = readPatchHeader(patchData);
            StringBuilder commandBuilder = new StringBuilder();
            commandBuilder.append(String.format("pm install-write -S %d %d -- -", newSize, sessionId));

            String command = commandBuilder.toString();
            p = Runtime.getRuntime().exec(command);

            OutputStream sessionOutputStream = p.getOutputStream();
            long bytesWritten = writePatchedDataToStream(oldData, newSize, patchData, sessionOutputStream);
            sessionOutputStream.flush();
            p.waitFor();
            if (bytesWritten != newSize) {
                throw new PatchFormatException(
                        String.format("output size mismatch (expected %d but wrote %)", newSize, bytesWritten));
            }
            return p.exitValue();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        return -1;
    }
}
