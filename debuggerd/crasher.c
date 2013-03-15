
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
int do_action(const char* arg);

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

int smash_stack(int i) {
    printf("crasher: deliberately corrupting stack...\n");
    // Unless there's a "big enough" buffer on the stack, gcc
    // doesn't bother inserting checks.
    char buf[8];
    // If we don't write something relatively unpredicatable
    // into the buffer and then do something with it, gcc
    // optimizes everything away and just returns a constant.
    *(int*)(&buf[7]) = (uintptr_t) &buf[0];
    return *(int*)(&buf[0]);
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

static void* thread_callback(void* raw_arg)
{
    return (void*) do_action((const char*) raw_arg);
}

int do_action_on_thread(const char* arg)
{
    pthread_t t;
    pthread_create(&t, NULL, thread_callback, (void*) arg);
    void* result = NULL;
    pthread_join(t, &result);
    return (int) result;
}

__attribute__((noinline)) int crash3(int a) {
   *((int*) 0xdead) = a;
   return a*4;
}

__attribute__((noinline)) int crash2(int a) {
   a = crash3(a) + 2;
   return a*3;
}

__attribute__((noinline)) int crash(int a) {
   a = crash2(a) + 1;
   return a*2;
}

int do_action(const char* arg)
{
    if(!strncmp(arg, "thread-", strlen("thread-"))) {
        return do_action_on_thread(arg + strlen("thread-"));
    }

    if(!strcmp(arg,"smash-stack")) return smash_stack(42);
    if(!strcmp(arg,"nostack")) crashnostack();
    if(!strcmp(arg,"ctest")) return ctest();
    if(!strcmp(arg,"exit")) exit(1);
    if(!strcmp(arg,"crash")) return crash(42);
    if(!strcmp(arg,"abort")) maybeabort();

    pthread_t thr;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&thr, &attr, test_thread, 0);
    while(1) sleep(1);
}

int main(int argc, char **argv)
{
    fprintf(stderr,"crasher: built at " __TIME__ "!@\n");
    fprintf(stderr,"crasher: init pid=%d tid=%d\n", getpid(), gettid());

    if(argc > 1) {
        return do_action(argv[1]);
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
