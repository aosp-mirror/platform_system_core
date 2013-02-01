
//#include <cutils/misc.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <errno.h>

#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/socket.h>

#include <pthread.h>

#include <cutils/sockets.h>

void crash1(void);
void crashnostack(void);
void maybeabort(void);

static void debuggerd_connect()
{
    char tmp[1];
    int s;
    sprintf(tmp, "%d", gettid());
    s = socket_local_client("android:debuggerd",
            ANDROID_SOCKET_NAMESPACE_ABSTRACT, SOCK_STREAM);    
    if(s >= 0) {
        read(s, tmp, 1);
        close(s);
    }
}

void test_call1()
{
    *((int*) 32) = 1;
}

void *test_thread(void *x)
{
    printf("crasher: thread pid=%d tid=%d\n", getpid(), gettid());

    sleep(1);
    test_call1();
    printf("goodbye\n");

    return 0;
}

void *noisy(void *x)
{
    char c = (unsigned) x;
    for(;;) {
        usleep(250*1000);
        write(2, &c, 1);
        if(c == 'C') *((unsigned*) 0) = 42;
    }
    return 0;
}

int ctest()
{
    pthread_t thr;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&thr, &attr, noisy, (void*) 'A');
    pthread_create(&thr, &attr, noisy, (void*) 'B');
    pthread_create(&thr, &attr, noisy, (void*) 'C');
    for(;;) ;
    return 0;
}

int main(int argc, char **argv)
{
    pthread_t thr;
    pthread_attr_t attr;

    fprintf(stderr,"crasher: " __TIME__ "!@\n");
    fprintf(stderr,"crasher: init pid=%d tid=%d\n", getpid(), gettid());

    if(argc > 1) {
        if(!strcmp(argv[1],"nostack")) crashnostack();
        if(!strcmp(argv[1],"ctest")) return ctest();
        if(!strcmp(argv[1],"exit")) exit(1);
        if(!strcmp(argv[1],"abort")) maybeabort();
        
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_create(&thr, &attr, test_thread, 0);
        while(1) sleep(1);
    } else {
        crash1();
//        *((int*) 0) = 42;
    }
    
    return 0;
}

void maybeabort()
{
    if(time(0) != 42) abort();
}
