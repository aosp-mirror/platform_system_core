#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <cutils/properties.h>

#include <sys/atomics.h>

#define _REALLY_INCLUDE_SYS__SYSTEM_PROPERTIES_H_
#include <sys/_system_properties.h>

typedef struct pwatch pwatch;

struct pwatch
{
    const prop_info *pi;
    unsigned serial;
};

static pwatch watchlist[1024];

static void announce(const prop_info *pi)
{
    char name[PROP_NAME_MAX];
    char value[PROP_VALUE_MAX];
    char *x;
    
    __system_property_read(pi, name, value);

    for(x = value; *x; x++) {
        if((*x < 32) || (*x > 127)) *x = '.';
    }

    fprintf(stderr,"%10d %s = '%s'\n", (int) time(0), name, value);
}

int watchprops_main(int argc, char *argv[])
{
    unsigned serial = 0;
    unsigned count;
    unsigned n;
    
    for(n = 0; n < 1024; n++) {
        watchlist[n].pi = __system_property_find_nth(n);
        if (watchlist[n].pi == 0)
            break;
        watchlist[n].serial = __system_property_serial(watchlist[n].pi);
    }

    count = n;
    if (count == 1024)
        exit(1);

    for(;;) {
        serial = __system_property_wait_any(serial);
        while(count < 1024){
            watchlist[count].pi = __system_property_find_nth(count);
            if (watchlist[count].pi == 0)
                break;
            watchlist[count].serial = __system_property_serial(watchlist[n].pi);
            announce(watchlist[count].pi);
            count++;
            if(count == 1024) exit(1);
        }

        for(n = 0; n < count; n++){
            unsigned tmp = __system_property_serial(watchlist[n].pi);
            if(watchlist[n].serial != tmp) {
                announce(watchlist[n].pi);
                watchlist[n].serial = tmp;
            }
        }
    }
    return 0;
}
