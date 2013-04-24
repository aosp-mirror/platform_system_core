
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

extern const char* __progname;

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

__attribute__((noinline)) void overflow_stack(void* p) {
    fprintf(stderr, "p = %p\n", p);
    void* buf[1];
    buf[0] = p;
    overflow_stack(&buf);
}

void test_call1()
{
    *((int*) 32) = 1;
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
    fprintf(stderr,"crasher: init pid=%d tid=%d\n", getpid(), gettid());

    if (!strncmp(arg, "thread-", strlen("thread-"))) {
        return do_action_on_thread(arg + strlen("thread-"));
    } else if (!strcmp(arg,"smash-stack")) {
        return smash_stack(42);
    } else if (!strcmp(arg,"stack-overflow")) {
        overflow_stack(NULL);
    } else if (!strcmp(arg,"nostack")) {
        crashnostack();
    } else if (!strcmp(arg,"ctest")) {
        return ctest();
    } else if (!strcmp(arg,"exit")) {
        exit(1);
    } else if (!strcmp(arg,"crash")) {
        return crash(42);
    } else if (!strcmp(arg,"abort")) {
        maybeabort();
    }

    fprintf(stderr, "%s OP\n", __progname);
    fprintf(stderr, "where OP is:\n");
    fprintf(stderr, "  smash-stack     overwrite a stack-guard canary\n");
    fprintf(stderr, "  stack-overflow  recurse until the stack overflows\n");
    fprintf(stderr, "  nostack         crash with a NULL stack pointer\n");
    fprintf(stderr, "  ctest           (obsoleted by thread-crash?)\n");
    fprintf(stderr, "  exit            call exit(1)\n");
    fprintf(stderr, "  crash           cause a SIGSEGV\n");
    fprintf(stderr, "  abort           call abort()\n");
    fprintf(stderr, "prefix any of the above with 'thread-' to not run\n");
    fprintf(stderr, "on the process' main thread.\n");
    return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
    fprintf(stderr,"crasher: built at " __TIME__ "!@\n");

    if(argc > 1) {
        return do_action(argv[1]);
    } else {
        crash1();
    }
    
    return 0;
}

void maybeabort()
{
    if(time(0) != 42) abort();
}
