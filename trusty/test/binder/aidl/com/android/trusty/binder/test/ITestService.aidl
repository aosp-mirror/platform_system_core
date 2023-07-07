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

package com.android.trusty.binder.test;

import com.android.trusty.binder.test.ByteEnum;
import com.android.trusty.binder.test.IntEnum;
import com.android.trusty.binder.test.LongEnum;

interface ITestService {
    const @utf8InCpp String PORT = "com.android.trusty.binder.test.service";

    const int TEST_CONSTANT = 42;
    const int TEST_CONSTANT2 = -42;
    const int TEST_CONSTANT3 = +42;
    const int TEST_CONSTANT4 = +4;
    const int TEST_CONSTANT5 = -4;
    const int TEST_CONSTANT6 = -0;
    const int TEST_CONSTANT7 = +0;
    const int TEST_CONSTANT8 = 0;
    const int TEST_CONSTANT9 = 0x56;
    const int TEST_CONSTANT10 = 0xa5;
    const int TEST_CONSTANT11 = 0xFA;
    const int TEST_CONSTANT12 = 0xffffffff;

    const byte BYTE_TEST_CONSTANT = 17;
    const long LONG_TEST_CONSTANT = 1L << 40;

    const String STRING_TEST_CONSTANT = "foo";
    const String STRING_TEST_CONSTANT2 = "bar";

    // Test that primitives work as parameters and return types.
    boolean RepeatBoolean(boolean token);
    byte RepeatByte(byte token);
    char RepeatChar(char token);
    int RepeatInt(int token);
    long RepeatLong(long token);
    float RepeatFloat(float token);
    double RepeatDouble(double token);
    String RepeatString(String token);
    ByteEnum RepeatByteEnum(ByteEnum token);
    IntEnum RepeatIntEnum(IntEnum token);
    LongEnum RepeatLongEnum(LongEnum token);

    // Test that arrays work as parameters and return types.
    boolean[] ReverseBoolean(in boolean[] input, out boolean[] repeated);
    byte[] ReverseByte(in byte[] input, out byte[] repeated);
    char[] ReverseChar(in char[] input, out char[] repeated);
    int[] ReverseInt(in int[] input, out int[] repeated);
    long[] ReverseLong(in long[] input, out long[] repeated);
    float[] ReverseFloat(in float[] input, out float[] repeated);
    double[] ReverseDouble(in double[] input, out double[] repeated);
    String[] ReverseString(in String[] input, out String[] repeated);
    ByteEnum[] ReverseByteEnum(in ByteEnum[] input, out ByteEnum[] repeated);
    IntEnum[] ReverseIntEnum(in IntEnum[] input, out IntEnum[] repeated);
    LongEnum[] ReverseLongEnum(in LongEnum[] input, out LongEnum[] repeated);
}
