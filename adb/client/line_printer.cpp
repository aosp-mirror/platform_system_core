// Copyright 2013 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "line_printer.h"

#include <stdio.h>
#include <stdlib.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <sys/time.h>
#endif

// Make sure printf is really adb_printf which works for UTF-8 on Windows.
#include <sysdeps.h>

// Stuff from ninja's util.h that's needed below.
#include <vector>
using namespace std;
string ElideMiddle(const string& str, size_t width) {
  const int kMargin = 3;  // Space for "...".
  string result = str;
  if (result.size() + kMargin > width) {
    size_t elide_size = (width - kMargin) / 2;
    result = result.substr(0, elide_size)
      + "..."
      + result.substr(result.size() - elide_size, elide_size);
  }
  return result;
}

LinePrinter::LinePrinter() : have_blank_line_(true) {
#ifndef _WIN32
  const char* term = getenv("TERM");
  smart_terminal_ = unix_isatty(1) && term && string(term) != "dumb";
#else
  // Disable output buffer.  It'd be nice to use line buffering but
  // MSDN says: "For some systems, [_IOLBF] provides line
  // buffering. However, for Win32, the behavior is the same as _IOFBF
  // - Full Buffering."
  setvbuf(stdout, nullptr, _IONBF, 0);
  console_ = GetStdHandle(STD_OUTPUT_HANDLE);
  CONSOLE_SCREEN_BUFFER_INFO csbi;
  smart_terminal_ = GetConsoleScreenBufferInfo(console_, &csbi);
#endif
}

static void Out(const std::string& s) {
  // Avoid printf and C strings, since the actual output might contain null
  // bytes like UTF-16 does (yuck).
  fwrite(s.data(), 1, s.size(), stdout);
}

void LinePrinter::Print(string to_print, LineType type) {
  if (!smart_terminal_) {
    Out(to_print + "\n");
    return;
  }

  // Print over previous line, if any.
  // On Windows, calling a C library function writing to stdout also handles
  // pausing the executable when the "Pause" key or Ctrl-S is pressed.
  printf("\r");

  if (type == INFO) {
#ifdef _WIN32
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(console_, &csbi);

    // TODO: std::wstring to_print_wide; if (!android::base::UTF8ToWide(to_print, &to_print_wide)...
    // TODO: wstring ElideMiddle.
    to_print = ElideMiddle(to_print, static_cast<size_t>(csbi.dwSize.X));
    // We don't want to have the cursor spamming back and forth, so instead of
    // printf use WriteConsoleOutput which updates the contents of the buffer,
    // but doesn't move the cursor position.
    COORD buf_size = { csbi.dwSize.X, 1 };
    COORD zero_zero = { 0, 0 };
    SMALL_RECT target = {
      csbi.dwCursorPosition.X, csbi.dwCursorPosition.Y,
      static_cast<SHORT>(csbi.dwCursorPosition.X + csbi.dwSize.X - 1),
      csbi.dwCursorPosition.Y
    };
    vector<CHAR_INFO> char_data(csbi.dwSize.X);
    for (size_t i = 0; i < static_cast<size_t>(csbi.dwSize.X); ++i) {
      // TODO: UnicodeChar instead of AsciiChar, to_print_wide[i].
      char_data[i].Char.AsciiChar = i < to_print.size() ? to_print[i] : ' ';
      char_data[i].Attributes = csbi.wAttributes;
    }
    // TODO: WriteConsoleOutputW.
    WriteConsoleOutput(console_, &char_data[0], buf_size, zero_zero, &target);
#else
    // Limit output to width of the terminal if provided so we don't cause
    // line-wrapping.
    winsize size;
    if ((ioctl(0, TIOCGWINSZ, &size) == 0) && size.ws_col) {
      to_print = ElideMiddle(to_print, size.ws_col);
    }
    Out(to_print);
    printf("\x1B[K");  // Clear to end of line.
    fflush(stdout);
#endif

    have_blank_line_ = false;
  } else {
    Out(to_print);
    Out("\n");
    have_blank_line_ = true;
  }
}

void LinePrinter::KeepInfoLine() {
  if (!have_blank_line_) Out("\n");
  have_blank_line_ = true;
}
