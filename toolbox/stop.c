#include <stdio.h>
#include <string.h>

#include <cutils/properties.h>

int stop_main(int argc, char *argv[])
{
    char buf[1024];

    if(argc > 1) {
        property_set("ctl.stop", argv[1]);
    } else{
        /* defaults to stopping the common services */
        property_set("ctl.stop", "zygote");
        property_set("ctl.stop", "surfaceflinger");
    }

    return 0;
}
