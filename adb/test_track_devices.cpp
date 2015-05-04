// TODO: replace this with a shell/python script.

/* a simple test program, connects to ADB server, and opens a track-devices session */
#include <netdb.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <memory.h>

#include <base/file.h>

static void
panic( const char*  msg )
{
    fprintf(stderr, "PANIC: %s: %s\n", msg, strerror(errno));
    exit(1);
}

int main(int argc, char* argv[]) {
    const char* request = "host:track-devices";

    if (argv[1] && strcmp(argv[1], "--jdwp") == 0) {
        request = "track-jdwp";
    }

    int                  ret;
    struct sockaddr_in   server;
    char                 buffer[1024];

    memset( &server, 0, sizeof(server) );
    server.sin_family      = AF_INET;
    server.sin_port        = htons(5037);
    server.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    int s = socket( PF_INET, SOCK_STREAM, 0 );
    ret = connect( s, (struct sockaddr*) &server, sizeof(server) );
    if (ret < 0) panic( "could not connect to server" );

    /* send the request */
    int len = snprintf(buffer, sizeof(buffer), "%04zx%s", strlen(request), request);
    if (!android::base::WriteFully(s, buffer, len))
        panic( "could not send request" );

    /* read the OKAY answer */
    if (!android::base::ReadFully(s, buffer, 4))
        panic( "could not read request" );

    printf( "server answer: %.*s\n", 4, buffer );

    /* now loop */
    while (true) {
        char  head[5] = "0000";

        if (!android::base::ReadFully(s, head, 4))
            panic("could not read length");

        int len;
        if (sscanf(head, "%04x", &len) != 1 )
            panic("could not decode length");

        if (!android::base::ReadFully(s, buffer, len))
            panic("could not read data");

        printf( "received header %.*s (%d bytes):\n%.*s----\n", 4, head, len, len, buffer );
    }
    close(s);
}
