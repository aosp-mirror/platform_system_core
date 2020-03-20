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

using std::string;
using std::vector;

// Side-effect: this function moves the start of the buffer past the read value
template <class T>
T readNext(uint8_t** buffer) {
    T value = *(T*)(*buffer);
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
                   uint32_t atomId) {
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
    checkTypeHeader(buffer, INT32_TYPE);
    checkScalar(buffer, atomId);
}

TEST(StatsEventTest, TestScalars) {
    uint32_t atomId = 100;
    int32_t int32Value = -5;
    int64_t int64Value = -2 * android::elapsedRealtimeNano();
    float floatValue = 2.0;
    bool boolValue = false;

    int64_t startTime = android::elapsedRealtimeNano();
    struct stats_event* event = stats_event_obtain();
    stats_event_set_atom_id(event, atomId);
    stats_event_write_int32(event, int32Value);
    stats_event_write_int64(event, int64Value);
    stats_event_write_float(event, floatValue);
    stats_event_write_bool(event, boolValue);
    stats_event_build(event);
    int64_t endTime = android::elapsedRealtimeNano();

    size_t bufferSize;
    uint8_t* buffer = stats_event_get_buffer(event, &bufferSize);
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
    EXPECT_EQ(stats_event_get_errors(event), 0);
    stats_event_release(event);
}

TEST(StatsEventTest, TestStrings) {
    uint32_t atomId = 100;
    string str = "test_string";

    int64_t startTime = android::elapsedRealtimeNano();
    struct stats_event* event = stats_event_obtain();
    stats_event_set_atom_id(event, atomId);
    stats_event_write_string8(event, str.c_str());
    stats_event_build(event);
    int64_t endTime = android::elapsedRealtimeNano();

    size_t bufferSize;
    uint8_t* buffer = stats_event_get_buffer(event, &bufferSize);
    uint8_t* bufferEnd = buffer + bufferSize;

    checkMetadata(&buffer, /*numElements=*/1, startTime, endTime, atomId);

    checkTypeHeader(&buffer, STRING_TYPE);
    checkString(&buffer, str);

    EXPECT_EQ(buffer, bufferEnd);  // ensure that we have read the entire buffer
    EXPECT_EQ(stats_event_get_errors(event), 0);
    stats_event_release(event);
}

TEST(StatsEventTest, TestByteArrays) {
    uint32_t atomId = 100;
    vector<uint8_t> message = {'b', 'y', 't', '\0', 'e', 's'};

    int64_t startTime = android::elapsedRealtimeNano();
    struct stats_event* event = stats_event_obtain();
    stats_event_set_atom_id(event, atomId);
    stats_event_write_byte_array(event, message.data(), message.size());
    stats_event_build(event);
    int64_t endTime = android::elapsedRealtimeNano();

    size_t bufferSize;
    uint8_t* buffer = stats_event_get_buffer(event, &bufferSize);
    uint8_t* bufferEnd = buffer + bufferSize;

    checkMetadata(&buffer, /*numElements=*/1, startTime, endTime, atomId);

    checkTypeHeader(&buffer, BYTE_ARRAY_TYPE);
    checkByteArray(&buffer, message);

    EXPECT_EQ(buffer, bufferEnd);  // ensure that we have read the entire buffer
    EXPECT_EQ(stats_event_get_errors(event), 0);
    stats_event_release(event);
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
    struct stats_event* event = stats_event_obtain();
    stats_event_set_atom_id(event, atomId);
    stats_event_write_attribution_chain(event, uids, cTags, numNodes);
    stats_event_build(event);
    int64_t endTime = android::elapsedRealtimeNano();

    size_t bufferSize;
    uint8_t* buffer = stats_event_get_buffer(event, &bufferSize);
    uint8_t* bufferEnd = buffer + bufferSize;

    checkMetadata(&buffer, /*numElements=*/1, startTime, endTime, atomId);

    checkTypeHeader(&buffer, ATTRIBUTION_CHAIN_TYPE);
    checkScalar(&buffer, numNodes);
    for (int i = 0; i < numNodes; i++) {
        checkScalar(&buffer, uids[i]);
        checkString(&buffer, tags[i]);
    }

    EXPECT_EQ(buffer, bufferEnd);  // ensure that we have read the entire buffer
    EXPECT_EQ(stats_event_get_errors(event), 0);
    stats_event_release(event);
}

TEST(StatsEventTest, TestKeyValuePairs) {
    uint32_t atomId = 100;

    uint8_t numPairs = 4;
    struct key_value_pair pairs[numPairs];
    pairs[0] = {.key = 0, .valueType = INT32_TYPE, .int32Value = -1};
    pairs[1] = {.key = 1, .valueType = INT64_TYPE, .int64Value = 0x123456789};
    pairs[2] = {.key = 2, .valueType = FLOAT_TYPE, .floatValue = 5.5};
    string str = "test_key_value_pair_string";
    pairs[3] = {.key = 3, .valueType = STRING_TYPE, .stringValue = str.c_str()};

    int64_t startTime = android::elapsedRealtimeNano();
    struct stats_event* event = stats_event_obtain();
    stats_event_set_atom_id(event, atomId);
    stats_event_write_key_value_pairs(event, pairs, numPairs);
    stats_event_build(event);
    int64_t endTime = android::elapsedRealtimeNano();

    size_t bufferSize;
    uint8_t* buffer = stats_event_get_buffer(event, &bufferSize);
    uint8_t* bufferEnd = buffer + bufferSize;

    checkMetadata(&buffer, /*numElements=*/1, startTime, endTime, atomId);

    checkTypeHeader(&buffer, KEY_VALUE_PAIRS_TYPE);
    checkScalar(&buffer, numPairs);

    // first pair
    checkScalar(&buffer, pairs[0].key);
    checkTypeHeader(&buffer, pairs[0].valueType);
    checkScalar(&buffer, pairs[0].int32Value);

    // second pair
    checkScalar(&buffer, pairs[1].key);
    checkTypeHeader(&buffer, pairs[1].valueType);
    checkScalar(&buffer, pairs[1].int64Value);

    // third pair
    checkScalar(&buffer, pairs[2].key);
    checkTypeHeader(&buffer, pairs[2].valueType);
    checkScalar(&buffer, pairs[2].floatValue);

    // fourth pair
    checkScalar(&buffer, pairs[3].key);
    checkTypeHeader(&buffer, pairs[3].valueType);
    checkString(&buffer, str);

    EXPECT_EQ(buffer, bufferEnd);  // ensure that we have read the entire buffer
    EXPECT_EQ(stats_event_get_errors(event), 0);
    stats_event_release(event);
}

TEST(StatsEventTest, TestAnnotations) {
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
    struct stats_event* event = stats_event_obtain();
    stats_event_set_atom_id(event, 100);
    stats_event_write_bool(event, boolValue);
    stats_event_add_bool_annotation(event, boolAnnotation1Id, boolAnnotation1Value);
    stats_event_add_int32_annotation(event, boolAnnotation2Id, boolAnnotation2Value);
    stats_event_write_float(event, floatValue);
    stats_event_add_int32_annotation(event, floatAnnotation1Id, floatAnnotation1Value);
    stats_event_add_bool_annotation(event, floatAnnotation2Id, floatAnnotation2Value);
    stats_event_build(event);
    int64_t endTime = android::elapsedRealtimeNano();

    size_t bufferSize;
    uint8_t* buffer = stats_event_get_buffer(event, &bufferSize);
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
    EXPECT_EQ(stats_event_get_errors(event), 0);
    stats_event_release(event);
}

TEST(StatsEventTest, TestNoAtomIdError) {
    struct stats_event* event = stats_event_obtain();
    // Don't set the atom id in order to trigger the error.
    stats_event_build(event);

    uint32_t errors = stats_event_get_errors(event);
    EXPECT_NE(errors | ERROR_NO_ATOM_ID, 0);

    stats_event_release(event);
}

TEST(StatsEventTest, TestOverflowError) {
    struct stats_event* event = stats_event_obtain();
    stats_event_set_atom_id(event, 100);
    // Add 1000 int32s to the event. Each int32 takes 5 bytes so this will
    // overflow the 4068 byte buffer.
    for (int i = 0; i < 1000; i++) {
        stats_event_write_int32(event, 0);
    }
    stats_event_build(event);

    uint32_t errors = stats_event_get_errors(event);
    EXPECT_NE(errors | ERROR_OVERFLOW, 0);

    stats_event_release(event);
}
