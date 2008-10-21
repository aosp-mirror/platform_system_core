#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <cutils/properties.h>

#include <sys/atomics.h>

#define _REALLY_INCLUDE_SYS__SYSTEM_PROPERTIES_H_
#include <sys/_system_properties.h>


extern prop_area *__system_property_area__;

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
    prop_area *pa = __system_property_area__;
    unsigned serial = pa->serial;
    unsigned count = pa->count;
    unsigned n;
    
    if(count >= 1024) exit(1);

    for(n = 0; n < count; n++) {
        watchlist[n].pi = __system_property_find_nth(n);
        watchlist[n].serial = watchlist[n].pi->serial;
    }

    for(;;) {
        do {
            __futex_wait(&pa->serial, serial, 0);
        } while(pa->serial == serial);

        while(count < pa->count){
            watchlist[count].pi = __system_property_find_nth(count);
            watchlist[count].serial = watchlist[n].pi->serial;
            announce(watchlist[count].pi);
            count++;
            if(count == 1024) exit(1);
        }

        for(n = 0; n < count; n++){
            unsigned tmp = watchlist[n].pi->serial;
            if(watchlist[n].serial != tmp) {
                announce(watchlist[n].pi);
                watchlist[n].serial = tmp;
            }
        }
    }
    return 0;
}
