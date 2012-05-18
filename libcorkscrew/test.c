#include <corkscrew/backtrace.h>
#include <stdio.h>
#include <stdlib.h>

void do_backtrace() {
  const size_t MAX_DEPTH = 32;
  backtrace_frame_t* frames = (backtrace_frame_t*) malloc(sizeof(backtrace_frame_t) * MAX_DEPTH);
  ssize_t frame_count = unwind_backtrace(frames, 0, MAX_DEPTH);
  fprintf(stderr, "frame_count=%d\n", (int) frame_count);

  backtrace_symbol_t* backtrace_symbols = (backtrace_symbol_t*) malloc(sizeof(backtrace_symbol_t) * frame_count);
  get_backtrace_symbols(frames, frame_count, backtrace_symbols);

  for (size_t i = 0; i < (size_t) frame_count; ++i) {
    char line[MAX_BACKTRACE_LINE_LENGTH];
    format_backtrace_line(i, &frames[i], &backtrace_symbols[i],
                          line, MAX_BACKTRACE_LINE_LENGTH);
    fprintf(stderr, "  %s\n", line);
  }

  free_backtrace_symbols(backtrace_symbols, frame_count);
  free(backtrace_symbols);
  free(frames);
}

__attribute__ ((noinline)) void g() {
  fprintf(stderr, "g()\n");
  do_backtrace();
}

__attribute__ ((noinline)) int f(int i) {
  fprintf(stderr, "f(%i)\n", i);
  if (i == 0) {
    g();
    return 0;
  }
  return f(i - 1);
}

int main() {
  return f(5);
}
