/*
 * Copyright (C) 2007 The Android Open Source Project
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

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <ctest/ctest.h>

#define MAX_TESTS 255

/** Semi-random number used to identify assertion errors. */
#define ASSERTION_ERROR 42
    
typedef void TestCase();

/** A suite of tests. */
typedef struct {
    int size;
    const char* testNames[MAX_TESTS];
    TestCase* tests[MAX_TESTS];
    int currentTest;
    FILE* out;
} TestSuite;

/** Gets the test suite. Creates it if necessary. */
static TestSuite* getTestSuite() {
    static TestSuite* suite = NULL;
    
    if (suite != NULL) {
        return suite;
    }
    
    suite = calloc(1, sizeof(TestSuite));
    assert(suite != NULL);
    
    suite->out = tmpfile();
    assert(suite->out != NULL);
    
    return suite;
}

void addNamedTest(const char* name, TestCase* test) {
    TestSuite* testSuite = getTestSuite();
    assert(testSuite->size <= MAX_TESTS);
    
    int index = testSuite->size;
    testSuite->testNames[index] = name;
    testSuite->tests[index] = test;
    
    testSuite->size++;
}

/** Prints failures to stderr. */
static void printFailures(int failures) {
    TestSuite* suite = getTestSuite();

    fprintf(stderr, "FAILURE! %d of %d tests failed. Failures:\n", 
            failures, suite->size);

    // Copy test output to stdout.
    rewind(suite->out);
    char buffer[512];
    size_t read;
    while ((read = fread(buffer, sizeof(char), 512, suite->out)) > 0) {
        // TODO: Make sure we actually wrote 'read' bytes.
        fwrite(buffer, sizeof(char), read, stderr);
    }
}

/** Runs a single test case. */
static int runCurrentTest() {
    TestSuite* suite = getTestSuite();
    
    pid_t pid = fork();
    if (pid == 0) {
        // Child process. Runs test case.
        suite->tests[suite->currentTest]();
        
        // Exit successfully.
        exit(0);
    } else if (pid < 0) {
        fprintf(stderr, "Fork failed.");
        exit(1); 
    } else {
        // Parent process. Wait for child.
        int status;
        waitpid(pid, &status, 0);
        
        if (!WIFEXITED(status)) {
            return -1;
        }
        
        return WEXITSTATUS(status);
    }
}

void runTests() {
    TestSuite* suite = getTestSuite();
   
    int failures = 0;
    for (suite->currentTest = 0; suite->currentTest < suite->size; 
            suite->currentTest++) {
        // Flush stdout before forking.
        fflush(stdout);
        
        int result = runCurrentTest();
       
        if (result != 0) {
            printf("X");
            
            failures++;

            // Handle errors other than assertions.
            if (result != ASSERTION_ERROR) {
                // TODO: Report file name.
                fprintf(suite->out, "Process failed: [%s] status: %d\n",
                        suite->testNames[suite->currentTest], result);
                fflush(suite->out);
            }
        } else {
            printf(".");
        }
    }

    printf("\n");
    
    if (failures > 0) {
        printFailures(failures);
    } else {
        printf("SUCCESS! %d tests ran successfully.\n", suite->size);
    }
}

void assertTrueWithSource(int value, const char* file, int line, char* message) {
    if (!value) {
        TestSuite* suite = getTestSuite();

        fprintf(suite->out, "Assertion failed: [%s:%d] %s: %s\n", file, line, 
                suite->testNames[suite->currentTest], message);
        fflush(suite->out);
        
        // Exit the process for this test case.
        exit(ASSERTION_ERROR);
    }
}
