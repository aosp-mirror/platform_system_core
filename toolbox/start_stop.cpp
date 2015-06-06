#include <error.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cutils/properties.h>

static const char* services[] = {
  "netd",
  "surfaceflinger",
  "zygote",
  "zygote_secondary",
};

static int start_stop(bool start, int argc, char* argv[]) {
  if (getuid() != 0) error(1, 0, "must be root");
  const char* property = start ? "ctl.start" : "ctl.stop";
  if (argc > 2) {
    error(1, 0, "usage: %s [SERVICE]\n", argv[0]);
  } else if (argc == 2) {
    property_set(property, argv[1]);
  } else {
    if (start) {
      for (size_t i = 0; i < sizeof(services)/sizeof(services[0]); ++i) {
        property_set(property, services[i]);
      }
    } else {
      for (int i = sizeof(services)/sizeof(services[0]) - 1; i >= 0; --i) {
        property_set(property, services[i]);
      }
    }
  }
  return 0;
}

extern "C" int start_main(int argc, char* argv[]) {
  return start_stop(true, argc, argv);
}

extern "C" int stop_main(int argc, char* argv[]) {
  return start_stop(false, argc, argv);
}
