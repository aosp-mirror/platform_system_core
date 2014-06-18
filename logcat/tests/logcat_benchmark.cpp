/*
 * Copyright (C) 2013-2014 The Android Open Source Project
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gtest/gtest.h>

static const char begin[] = "--------- beginning of ";

TEST(logcat, sorted_order) {
    FILE *fp;

    ASSERT_TRUE(NULL != (fp = popen(
      "logcat -v time -b radio -b events -b system -b main -d 2>/dev/null",
      "r")));

    class timestamp {
    private:
        int month;
        int day;
        int hour;
        int minute;
        int second;
        int millisecond;
        bool ok;

    public:
        void init(const char *buffer)
        {
            ok = false;
            if (buffer != NULL) {
                ok = sscanf(buffer, "%d-%d %d:%d:%d.%d ",
                    &month, &day, &hour, &minute, &second, &millisecond) == 6;
            }
        }

        timestamp(const char *buffer)
        {
            init(buffer);
        }

        bool operator< (timestamp &T)
        {
            return !ok || !T.ok
             || (month < T.month)
             || ((month == T.month)
              && ((day < T.day)
               || ((day == T.day)
                && ((hour < T.hour)
                 || ((hour == T.hour)
                  && ((minute < T.minute)
                   || ((minute == T.minute)
                    && ((second < T.second)
                     || ((second == T.second)
                      && (millisecond < T.millisecond))))))))));
        }

        bool valid(void)
        {
            return ok;
        }
    } last(NULL);

    char *last_buffer = NULL;
    char buffer[5120];

    int count = 0;
    int next_lt_last = 0;

    while (fgets(buffer, sizeof(buffer), fp)) {
        if (!strncmp(begin, buffer, sizeof(begin) - 1)) {
            continue;
        }
        if (!last.valid()) {
            free(last_buffer);
            last_buffer = strdup(buffer);
            last.init(buffer);
        }
        timestamp next(buffer);
        if (next < last) {
            if (last_buffer) {
                fprintf(stderr, "<%s", last_buffer);
            }
            fprintf(stderr, ">%s", buffer);
            ++next_lt_last;
        }
        if (next.valid()) {
            free(last_buffer);
            last_buffer = strdup(buffer);
            last.init(buffer);
        }
        ++count;
    }
    free(last_buffer);

    pclose(fp);

    static const int max_ok = 2;

    // Allow few fails, happens with readers active
    fprintf(stderr, "%s: %d/%d out of order entries\n",
            (next_lt_last)
                ? ((next_lt_last <= max_ok)
                    ? "WARNING"
                    : "ERROR")
                : "INFO",
            next_lt_last, count);

    EXPECT_GE(max_ok, next_lt_last);

    // sample statistically too small
    EXPECT_LT(100, count);
}
