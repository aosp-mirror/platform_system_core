
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <cutils/properties.h>

int start_main(int argc, char *argv[])
{
    char buf[1024];

    if(argc > 1) {
        property_set("ctl.start", argv[1]);
    } else {
        /* defaults to starting the common services stopped by stop.c */
        property_set("ctl.start", "surfaceflinger");
        property_set("ctl.start", "zygote");
    }

    return 0;
}
