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

#include "stats_event.h"
#include <gtest/gtest.h>
#include <utils/SystemClock.h>

// Keep in sync with stats_event.c. Consider moving to separate header file to avoid duplication.
/* ERRORS */
#define ERROR_NO_TIMESTAMP 0x1
#define ERROR_NO_ATOM_ID 0x2
#define ERROR_OVERFLOW 0x4
#define ERROR_ATTRIBUTION_CHAIN_TOO_LONG 0x8
#define ERROR_TOO_MANY_KEY_VALUE_PAIRS 0x10
#define ERROR_ANNOTATION_DOES_NOT_FOLLOW_FIELD 0x20
#define ERROR_INVALID_ANNOTATION_ID 0x40
#define ERROR_ANNOTATION_ID_TOO_LARGE 0x80
#define ERROR_TOO_MANY_ANNOTATIONS 0x100
#define ERROR_TOO_MANY_FIELDS 0x200
#define ERROR_INVALID_VALUE_TYPE 0x400
#define ERROR_STRING_NOT_NULL_TERMINATED 0x800
#define ERROR_ATOM_ID_INVALID_POSITION 0x2000

/* TYPE IDS */
#define INT32_TYPE 0x00
#define INT64_TYPE 0x01
#define STRING_TYPE 0x02
#define LIST_TYPE 0x03
#define FLOAT_TYPE 0x04
#define BOOL_TYPE 0x05
#define BYTE_ARRAY_TYPE 0x06
#define OBJECT_TYPE 0x07
#define KEY_VALUE_PAIRS_TYPE 0x08
#define ATTRIBUTION_CHAIN_TYPE 0x09
#define ERROR_TYPE 0x0F

using std::string;
using std::vector;

// Side-effect: this function moves the start of the buffer past the read value
template <class T>
T readNext(uint8_t** buffer) {
    T value;
    if ((reinterpret_cast<uintptr_t>(*buffer) % alignof(T)) == 0) {
        value = *(T*)(*buffer);
    } else {
        memcpy(&value, *buffer, sizeof(T));
    }
    *buffer += sizeof(T);
    return value;
}

void checkTypeHeader(uint8_t** buffer, uint8_t typeId, uint8_t numAnnotations = 0) {
    uint8_t typeHeader = (numAnnotations << 4) | typeId;
    EXPECT_EQ(readNext<uint8_t>(buffer), typeHeader);
}

template <class T>
void checkScalar(uint8_t** buffer, T expectedValue) {
    EXPECT_EQ(readNext<T>(buffer), expectedValue);
}

void checkString(uint8_t** buffer, const string& expectedString) {
    uint32_t size = readNext<uint32_t>(buffer);
    string parsedString((char*)(*buffer), size);
    EXPECT_EQ(parsedString, expectedString);
    *buffer += size;  // move buffer past string we just read
}

void checkByteArray(uint8_t** buffer, const vector<uint8_t>& expectedByteArray) {
    uint32_t size = readNext<uint32_t>(buffer);
    vector<uint8_t> parsedByteArray(*buffer, *buffer + size);
    EXPECT_EQ(parsedByteArray, expectedByteArray);
    *buffer += size;  // move buffer past byte array we just read
}

template <class T>
void checkAnnotation(uint8_t** buffer, uint8_t annotationId, uint8_t typeId, T annotationValue) {
    EXPECT_EQ(readNext<uint8_t>(buffer), annotationId);
    EXPECT_EQ(readNext<uint8_t>(buffer), typeId);
    checkScalar<T>(buffer, annotationValue);
}

void checkMetadata(uint8_t** buffer, uint8_t numElements, int64_t startTime, int64_t endTime,
                   uint32_t atomId, uint8_t numAtomLevelAnnotations = 0) {
    // All events start with OBJECT_TYPE id.
    checkTypeHeader(buffer, OBJECT_TYPE);

    // We increment by 2 because the number of elements listed in the
    // serialization accounts for the timestamp and atom id as well.
    checkScalar(buffer, static_cast<uint8_t>(numElements + 2));

    // Check timestamp
    checkTypeHeader(buffer, INT64_TYPE);
    int64_t timestamp = readNext<int64_t>(buffer);
    EXPECT_GE(timestamp, startTime);
    EXPECT_LE(timestamp, endTime);

    // Check atom id
    checkTypeHeader(buffer, INT32_TYPE, numAtomLevelAnnotations);
    checkScalar(buffer, atomId);
}

TEST(StatsEventTest, TestScalars) {
    uint32_t atomId = 100;
    int32_t int32Value = -5;
    int64_t int64Value = -2 * android::elapsedRealtimeNano();
    float floatValue = 2.0;
    bool boolValue = false;

    int64_t startTime = android::elapsedRealtimeNano();
    AStatsEvent* event = AStatsEvent_obtain();
    AStatsEvent_setAtomId(event, atomId);
    AStatsEvent_writeInt32(event, int32Value);
    AStatsEvent_writeInt64(event, int64Value);
    AStatsEvent_writeFloat(event, floatValue);
    AStatsEvent_writeBool(event, boolValue);
    AStatsEvent_build(event);
    int64_t endTime = android::elapsedRealtimeNano();

    size_t bufferSize;
    uint8_t* buffer = AStatsEvent_getBuffer(event, &bufferSize);
    uint8_t* bufferEnd = buffer + bufferSize;

    checkMetadata(&buffer, /*numElements=*/4, startTime, endTime, atomId);

    // check int32 element
    checkTypeHeader(&buffer, INT32_TYPE);
    checkScalar(&buffer, int32Value);

    // check int64 element
    checkTypeHeader(&buffer, INT64_TYPE);
    checkScalar(&buffer, int64Value);

    // check float element
    checkTypeHeader(&buffer, FLOAT_TYPE);
    checkScalar(&buffer, floatValue);

    // check bool element
    checkTypeHeader(&buffer, BOOL_TYPE);
    checkScalar(&buffer, boolValue);

    EXPECT_EQ(buffer, bufferEnd);  // ensure that we have read the entire buffer
    EXPECT_EQ(AStatsEvent_getErrors(event), 0);
    AStatsEvent_release(event);
}

TEST(StatsEventTest, TestStrings) {
    uint32_t atomId = 100;
    string str = "test_string";

    int64_t startTime = android::elapsedRealtimeNano();
    AStatsEvent* event = AStatsEvent_obtain();
    AStatsEvent_setAtomId(event, atomId);
    AStatsEvent_writeString(event, str.c_str());
    AStatsEvent_build(event);
    int64_t endTime = android::elapsedRealtimeNano();

    size_t bufferSize;
    uint8_t* buffer = AStatsEvent_getBuffer(event, &bufferSize);
    uint8_t* bufferEnd = buffer + bufferSize;

    checkMetadata(&buffer, /*numElements=*/1, startTime, endTime, atomId);

    checkTypeHeader(&buffer, STRING_TYPE);
    checkString(&buffer, str);

    EXPECT_EQ(buffer, bufferEnd);  // ensure that we have read the entire buffer
    EXPECT_EQ(AStatsEvent_getErrors(event), 0);
    AStatsEvent_release(event);
}

TEST(StatsEventTest, TestByteArrays) {
    uint32_t atomId = 100;
    vector<uint8_t> message = {'b', 'y', 't', '\0', 'e', 's'};

    int64_t startTime = android::elapsedRealtimeNano();
    AStatsEvent* event = AStatsEvent_obtain();
    AStatsEvent_setAtomId(event, atomId);
    AStatsEvent_writeByteArray(event, message.data(), message.size());
    AStatsEvent_build(event);
    int64_t endTime = android::elapsedRealtimeNano();

    size_t bufferSize;
    uint8_t* buffer = AStatsEvent_getBuffer(event, &bufferSize);
    uint8_t* bufferEnd = buffer + bufferSize;

    checkMetadata(&buffer, /*numElements=*/1, startTime, endTime, atomId);

    checkTypeHeader(&buffer, BYTE_ARRAY_TYPE);
    checkByteArray(&buffer, message);

    EXPECT_EQ(buffer, bufferEnd);  // ensure that we have read the entire buffer
    EXPECT_EQ(AStatsEvent_getErrors(event), 0);
    AStatsEvent_release(event);
}

TEST(StatsEventTest, TestAttributionChains) {
    uint32_t atomId = 100;

    uint8_t numNodes = 50;
    uint32_t uids[numNodes];
    vector<string> tags(numNodes);  // storage that cTag elements point to
    const char* cTags[numNodes];
    for (int i = 0; i < (int)numNodes; i++) {
        uids[i] = i;
        tags.push_back("test" + std::to_string(i));
        cTags[i] = tags[i].c_str();
    }

    int64_t startTime = android::elapsedRealtimeNano();
    AStatsEvent* event = AStatsEvent_obtain();
    AStatsEvent_setAtomId(event, atomId);
    AStatsEvent_writeAttributionChain(event, uids, cTags, numNodes);
    AStatsEvent_build(event);
    int64_t endTime = android::elapsedRealtimeNano();

    size_t bufferSize;
    uint8_t* buffer = AStatsEvent_getBuffer(event, &bufferSize);
    uint8_t* bufferEnd = buffer + bufferSize;

    checkMetadata(&buffer, /*numElements=*/1, startTime, endTime, atomId);

    checkTypeHeader(&buffer, ATTRIBUTION_CHAIN_TYPE);
    checkScalar(&buffer, numNodes);
    for (int i = 0; i < numNodes; i++) {
        checkScalar(&buffer, uids[i]);
        checkString(&buffer, tags[i]);
    }

    EXPECT_EQ(buffer, bufferEnd);  // ensure that we have read the entire buffer
    EXPECT_EQ(AStatsEvent_getErrors(event), 0);
    AStatsEvent_release(event);
}

TEST(StatsEventTest, TestFieldAnnotations) {
    uint32_t atomId = 100;

    // first element information
    bool boolValue = false;
    uint8_t boolAnnotation1Id = 1;
    uint8_t boolAnnotation2Id = 2;
    bool boolAnnotation1Value = true;
    int32_t boolAnnotation2Value = 3;

    // second element information
    float floatValue = -5.0;
    uint8_t floatAnnotation1Id = 3;
    uint8_t floatAnnotation2Id = 4;
    int32_t floatAnnotation1Value = 8;
    bool floatAnnotation2Value = false;

    int64_t startTime = android::elapsedRealtimeNano();
    AStatsEvent* event = AStatsEvent_obtain();
    AStatsEvent_setAtomId(event, atomId);
    AStatsEvent_writeBool(event, boolValue);
    AStatsEvent_addBoolAnnotation(event, boolAnnotation1Id, boolAnnotation1Value);
    AStatsEvent_addInt32Annotation(event, boolAnnotation2Id, boolAnnotation2Value);
    AStatsEvent_writeFloat(event, floatValue);
    AStatsEvent_addInt32Annotation(event, floatAnnotation1Id, floatAnnotation1Value);
    AStatsEvent_addBoolAnnotation(event, floatAnnotation2Id, floatAnnotation2Value);
    AStatsEvent_build(event);
    int64_t endTime = android::elapsedRealtimeNano();

    size_t bufferSize;
    uint8_t* buffer = AStatsEvent_getBuffer(event, &bufferSize);
    uint8_t* bufferEnd = buffer + bufferSize;

    checkMetadata(&buffer, /*numElements=*/2, startTime, endTime, atomId);

    // check first element
    checkTypeHeader(&buffer, BOOL_TYPE, /*numAnnotations=*/2);
    checkScalar(&buffer, boolValue);
    checkAnnotation(&buffer, boolAnnotation1Id, BOOL_TYPE, boolAnnotation1Value);
    checkAnnotation(&buffer, boolAnnotation2Id, INT32_TYPE, boolAnnotation2Value);

    // check second element
    checkTypeHeader(&buffer, FLOAT_TYPE, /*numAnnotations=*/2);
    checkScalar(&buffer, floatValue);
    checkAnnotation(&buffer, floatAnnotation1Id, INT32_TYPE, floatAnnotation1Value);
    checkAnnotation(&buffer, floatAnnotation2Id, BOOL_TYPE, floatAnnotation2Value);

    EXPECT_EQ(buffer, bufferEnd);  // ensure that we have read the entire buffer
    EXPECT_EQ(AStatsEvent_getErrors(event), 0);
    AStatsEvent_release(event);
}

TEST(StatsEventTest, TestAtomLevelAnnotations) {
    uint32_t atomId = 100;
    // atom-level annotation information
    uint8_t boolAnnotationId = 1;
    uint8_t int32AnnotationId = 2;
    bool boolAnnotationValue = false;
    int32_t int32AnnotationValue = 5;

    float fieldValue = -3.5;

    int64_t startTime = android::elapsedRealtimeNano();
    AStatsEvent* event = AStatsEvent_obtain();
    AStatsEvent_setAtomId(event, atomId);
    AStatsEvent_addBoolAnnotation(event, boolAnnotationId, boolAnnotationValue);
    AStatsEvent_addInt32Annotation(event, int32AnnotationId, int32AnnotationValue);
    AStatsEvent_writeFloat(event, fieldValue);
    AStatsEvent_build(event);
    int64_t endTime = android::elapsedRealtimeNano();

    size_t bufferSize;
    uint8_t* buffer = AStatsEvent_getBuffer(event, &bufferSize);
    uint8_t* bufferEnd = buffer + bufferSize;

    checkMetadata(&buffer, /*numElements=*/1, startTime, endTime, atomId,
                  /*numAtomLevelAnnotations=*/2);

    // check atom-level annotations
    checkAnnotation(&buffer, boolAnnotationId, BOOL_TYPE, boolAnnotationValue);
    checkAnnotation(&buffer, int32AnnotationId, INT32_TYPE, int32AnnotationValue);

    // check first element
    checkTypeHeader(&buffer, FLOAT_TYPE);
    checkScalar(&buffer, fieldValue);

    EXPECT_EQ(buffer, bufferEnd);  // ensure that we have read the entire buffer
    EXPECT_EQ(AStatsEvent_getErrors(event), 0);
    AStatsEvent_release(event);
}

TEST(StatsEventTest, TestNoAtomIdError) {
    AStatsEvent* event = AStatsEvent_obtain();
    // Don't set the atom id in order to trigger the error.
    AStatsEvent_build(event);

    uint32_t errors = AStatsEvent_getErrors(event);
    EXPECT_EQ(errors & ERROR_NO_ATOM_ID, ERROR_NO_ATOM_ID);

    AStatsEvent_release(event);
}

TEST(StatsEventTest, TestPushOverflowError) {
    const char* str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const int writeCount = 120;  // Number of times to write str in the event.

    AStatsEvent* event = AStatsEvent_obtain();
    AStatsEvent_setAtomId(event, 100);

    // Add str to the event 120 times. Each str takes >35 bytes so this will
    // overflow the 4068 byte buffer.
    // We want to keep writeCount less than 127 to avoid hitting
    // ERROR_TOO_MANY_FIELDS.
    for (int i = 0; i < writeCount; i++) {
        AStatsEvent_writeString(event, str);
    }
    AStatsEvent_write(event);

    uint32_t errors = AStatsEvent_getErrors(event);
    EXPECT_EQ(errors & ERROR_OVERFLOW, ERROR_OVERFLOW);

    AStatsEvent_release(event);
}

TEST(StatsEventTest, TestPullOverflowError) {
    const uint32_t atomId = 10100;
    const vector<uint8_t> bytes(430 /* number of elements */, 1 /* value of each element */);
    const int writeCount = 120;  // Number of times to write bytes in the event.

    AStatsEvent* event = AStatsEvent_obtain();
    AStatsEvent_setAtomId(event, atomId);

    // Add bytes to the event 120 times. Size of bytes is 430 so this will
    // overflow the 50 KB pulled event buffer.
    // We want to keep writeCount less than 127 to avoid hitting
    // ERROR_TOO_MANY_FIELDS.
    for (int i = 0; i < writeCount; i++) {
        AStatsEvent_writeByteArray(event, bytes.data(), bytes.size());
    }
    AStatsEvent_build(event);

    uint32_t errors = AStatsEvent_getErrors(event);
    EXPECT_EQ(errors & ERROR_OVERFLOW, ERROR_OVERFLOW);

    AStatsEvent_release(event);
}

TEST(StatsEventTest, TestLargePull) {
    const uint32_t atomId = 100;
    const string str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const int writeCount = 120;  // Number of times to write str in the event.
    const int64_t startTime = android::elapsedRealtimeNano();

    AStatsEvent* event = AStatsEvent_obtain();
    AStatsEvent_setAtomId(event, atomId);

    // Add str to the event 120 times.
    // We want to keep writeCount less than 127 to avoid hitting
    // ERROR_TOO_MANY_FIELDS.
    for (int i = 0; i < writeCount; i++) {
        AStatsEvent_writeString(event, str.c_str());
    }
    AStatsEvent_build(event);
    int64_t endTime = android::elapsedRealtimeNano();

    size_t bufferSize;
    uint8_t* buffer = AStatsEvent_getBuffer(event, &bufferSize);
    uint8_t* bufferEnd = buffer + bufferSize;

    checkMetadata(&buffer, writeCount, startTime, endTime, atomId);

    // Check all instances of str have been written.
    for (int i = 0; i < writeCount; i++) {
        checkTypeHeader(&buffer, STRING_TYPE);
        checkString(&buffer, str);
    }

    EXPECT_EQ(buffer, bufferEnd);  // Ensure that we have read the entire buffer.
    EXPECT_EQ(AStatsEvent_getErrors(event), 0);
    AStatsEvent_release(event);
}

TEST(StatsEventTest, TestAtomIdInvalidPositionError) {
    AStatsEvent* event = AStatsEvent_obtain();
    AStatsEvent_writeInt32(event, 0);
    AStatsEvent_setAtomId(event, 100);
    AStatsEvent_writeBool(event, true);
    AStatsEvent_build(event);

    uint32_t errors = AStatsEvent_getErrors(event);
    EXPECT_EQ(errors & ERROR_ATOM_ID_INVALID_POSITION, ERROR_ATOM_ID_INVALID_POSITION);

    AStatsEvent_release(event);
}

TEST(StatsEventTest, TestOverwriteTimestamp) {
    uint32_t atomId = 100;
    int64_t expectedTimestamp = 0x123456789;
    AStatsEvent* event = AStatsEvent_obtain();
    AStatsEvent_setAtomId(event, atomId);
    AStatsEvent_overwriteTimestamp(event, expectedTimestamp);
    AStatsEvent_build(event);

    uint8_t* buffer = AStatsEvent_getBuffer(event, NULL);

    // Make sure that the timestamp is being overwritten.
    checkMetadata(&buffer, /*numElements=*/0, /*startTime=*/expectedTimestamp,
                  /*endTime=*/expectedTimestamp, atomId);

    EXPECT_EQ(AStatsEvent_getErrors(event), 0);
    AStatsEvent_release(event);
}
