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

#ifndef _ERRORCODE_H
#define _ERRORCODE_H

class ErrorCode {
public:
    // 100 series - Requestion action was initiated; expect another reply
    // before proceeding with a new command.
    static const int ActionInitiated = 100;

    static const int WifiScanResult = 125;
    static const int WifiNetworkList = 126;

    static const int PropertyRead = 127;
    static const int PropertySet = 128;
    static const int PropertyList = 129;

    // 200 series - Requested action has been successfully completed
    static const int CommandOkay = 200;

    // 400 series - The command was accepted but the requested action
    // did not take place.
    static const int OperationFailed = 400;

    // 500 series - The command was not accepted and the requested
    // action did not take place.
    static const int CommandSyntaxError = 500;
    static const int CommandParameterError = 501;

    // 600 series - Unsolicited broadcasts
    static const int UnsolicitedInformational = 600;
};
#endif
