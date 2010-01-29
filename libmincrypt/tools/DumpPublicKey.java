/*
 * Copyright (C) 2008 The Android Open Source Project
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

package com.android.dumpkey;

import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.cert.CertificateFactory;
import java.security.cert.Certificate;
import java.security.KeyStore;
import java.security.Key;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import sun.misc.BASE64Encoder;

/**
 * Command line tool to extract RSA public keys from X.509 certificates
 * and output source code with data initializers for the keys.
 * @hide
 */
class DumpPublicKey {
    /**
     * @param key to perform sanity checks on
     * @throws Exception if the key has the wrong size or public exponent
     */
    static void check(RSAPublicKey key) throws Exception {
        BigInteger pubexp = key.getPublicExponent();
        BigInteger modulus = key.getModulus();

        if (!pubexp.equals(BigInteger.valueOf(3)))
                throw new Exception("Public exponent should be 3 but is " +
                        pubexp.toString(10) + ".");

        if (modulus.bitLength() != 2048)
             throw new Exception("Modulus should be 2048 bits long but is " +
                        modulus.bitLength() + " bits.");
    }

    /**
     * @param key to output
     * @return a C initializer representing this public key.
     */
    static String print(RSAPublicKey key) throws Exception {
        check(key);

        BigInteger N = key.getModulus();

        StringBuilder result = new StringBuilder();

        int nwords = N.bitLength() / 32;    // # of 32 bit integers in modulus

        result.append("{");
        result.append(nwords);

        BigInteger B = BigInteger.valueOf(0x100000000L);  // 2^32
        BigInteger N0inv = B.subtract(N.modInverse(B));   // -1 / N[0] mod 2^32

        result.append(",0x");
        result.append(N0inv.toString(16));

        BigInteger R = BigInteger.valueOf(2).pow(N.bitLength());
        BigInteger RR = R.multiply(R).mod(N);    // 2^4096 mod N

        // Write out modulus as little endian array of integers.
        result.append(",{");
        for (int i = 0; i < nwords; ++i) {
            long n = N.mod(B).longValue();
            result.append(n);

            if (i != nwords - 1) {
                result.append(",");
            }

            N = N.divide(B);
        }
        result.append("}");

        // Write R^2 as little endian array of integers.
        result.append(",{");
        for (int i = 0; i < nwords; ++i) {
            long rr = RR.mod(B).longValue();
            result.append(rr);

            if (i != nwords - 1) {
                result.append(",");
            }

            RR = RR.divide(B);
        }
        result.append("}");

        result.append("}");
        return result.toString();
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: DumpPublicKey certfile ... > source.c");
            System.exit(1);
        }
        try {
            for (int i = 0; i < args.length; i++) {
                FileInputStream input = new FileInputStream(args[i]);
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                Certificate cert = cf.generateCertificate(input);
                RSAPublicKey key = (RSAPublicKey) (cert.getPublicKey());
                check(key);
                System.out.print(print(key));
                System.out.println(i < args.length - 1 ? "," : "");
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
        System.exit(0);
    }
}
