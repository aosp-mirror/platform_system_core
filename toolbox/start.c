
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
        /* default to "start zygote" "start runtime" */
        property_set("ctl.start", "zygote");
        property_set("ctl.start", "runtime");
    }
    
    return 0;
}
