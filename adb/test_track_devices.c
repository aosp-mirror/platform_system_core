/* a simple test program, connects to ADB server, and opens a track-devices session */
#include <netdb.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <memory.h>

static void
panic( const char*  msg )
{
    fprintf(stderr, "PANIC: %s: %s\n", msg, strerror(errno));
    exit(1);
}

static int
unix_write( int  fd, const char*  buf, int  len )
{
    int  result = 0;
    while (len > 0) {
        int  len2 = write(fd, buf, len);
        if (len2 < 0) {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            return -1;
        }
        result += len2;
        len -= len2;
        buf += len2;
    }
    return  result;
}

static int
unix_read( int  fd, char*  buf, int  len )
{
    int  result = 0;
    while (len > 0) {
        int  len2 = read(fd, buf, len);
        if (len2 < 0) {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            return -1;
        }
        result += len2;
        len -= len2;
        buf += len2;
    }
    return  result;
}


int  main( void )
{
    int                  ret, s;
    struct sockaddr_in   server;
    char                 buffer[1024];
    const char*          request = "host:track-devices";
    int                  len;

    memset( &server, 0, sizeof(server) );
    server.sin_family      = AF_INET;
    server.sin_port        = htons(5037);
    server.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    s = socket( PF_INET, SOCK_STREAM, 0 );
    ret = connect( s, (struct sockaddr*) &server, sizeof(server) );
    if (ret < 0) panic( "could not connect to server" );

    /* send the request */
    len = snprintf( buffer, sizeof buffer, "%04x%s", strlen(request), request );
    if (unix_write(s, buffer, len) < 0)
        panic( "could not send request" );

    /* read the OKAY answer */
    if (unix_read(s, buffer, 4) != 4)
        panic( "could not read request" );

    printf( "server answer: %.*s\n", 4, buffer );

    /* now loop */
    for (;;) {
        char  head[5] = "0000";

        if (unix_read(s, head, 4) < 0)
            panic("could not read length");

        if ( sscanf( head, "%04x", &len ) != 1 )
            panic("could not decode length");

        if (unix_read(s, buffer, len) != len)
            panic("could not read data");

        printf( "received header %.*s (%d bytes):\n%.*s", 4, head, len, len, buffer );
    }
    close(s);
}
