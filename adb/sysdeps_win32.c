#include "sysdeps.h"
#include <windows.h>
#include <winsock2.h>
#include <stdio.h>
#include <errno.h>
#define  TRACE_TAG  TRACE_SYSDEPS
#include "adb.h"

extern void fatal(const char *fmt, ...);

#define assert(cond)  do { if (!(cond)) fatal( "assertion failed '%s' on %s:%ld\n", #cond, __FILE__, __LINE__ ); } while (0)

/**************************************************************************/
/**************************************************************************/
/*****                                                                *****/
/*****      replaces libs/cutils/load_file.c                          *****/
/*****                                                                *****/
/**************************************************************************/
/**************************************************************************/

void *load_file(const char *fn, unsigned *_sz)
{
    HANDLE    file;
    char     *data;
    DWORD     file_size;

    file = CreateFile( fn,
                       GENERIC_READ,
                       FILE_SHARE_READ,
                       NULL,
                       OPEN_EXISTING,
                       0,
                       NULL );

    if (file == INVALID_HANDLE_VALUE)
        return NULL;

    file_size = GetFileSize( file, NULL );
    data      = NULL;

    if (file_size > 0) {
        data = (char*) malloc( file_size + 1 );
        if (data == NULL) {
            D("load_file: could not allocate %ld bytes\n", file_size );
            file_size = 0;
        } else {
            DWORD  out_bytes;

            if ( !ReadFile( file, data, file_size, &out_bytes, NULL ) ||
                 out_bytes != file_size )
            {
                D("load_file: could not read %ld bytes from '%s'\n", file_size, fn);
                free(data);
                data      = NULL;
                file_size = 0;
            }
        }
    }
    CloseHandle( file );

    *_sz = (unsigned) file_size;
    return  data;
}

/**************************************************************************/
/**************************************************************************/
/*****                                                                *****/
/*****    common file descriptor handling                             *****/
/*****                                                                *****/
/**************************************************************************/
/**************************************************************************/

typedef const struct FHClassRec_*   FHClass;

typedef struct FHRec_*          FH;

typedef struct EventHookRec_*  EventHook;

typedef struct FHClassRec_
{
    void (*_fh_init) ( FH  f );
    int  (*_fh_close)( FH  f );
    int  (*_fh_lseek)( FH  f, int  pos, int  origin );
    int  (*_fh_read) ( FH  f, void*  buf, int  len );
    int  (*_fh_write)( FH  f, const void*  buf, int  len );
    void (*_fh_hook) ( FH  f, int  events, EventHook  hook );

} FHClassRec;

/* used to emulate unix-domain socket pairs */
typedef struct SocketPairRec_*  SocketPair;

typedef struct FHRec_
{
    FHClass    clazz;
    int        used;
    int        eof;
    union {
        HANDLE      handle;
        SOCKET      socket;
        SocketPair  pair;
    } u;

    HANDLE    event;
    int       mask;

    char  name[32];

} FHRec;

#define  fh_handle  u.handle
#define  fh_socket  u.socket
#define  fh_pair    u.pair

#define  WIN32_FH_BASE    100

#define  WIN32_MAX_FHS    128

static adb_mutex_t   _win32_lock;
static  FHRec        _win32_fhs[ WIN32_MAX_FHS ];
static  int          _win32_fh_count;

static FH
_fh_from_int( int   fd )
{
    FH  f;

    fd -= WIN32_FH_BASE;

    if (fd < 0 || fd >= _win32_fh_count) {
        D( "_fh_from_int: invalid fd %d\n", fd + WIN32_FH_BASE );
        errno = EBADF;
        return NULL;
    }

    f = &_win32_fhs[fd];

    if (f->used == 0) {
        D( "_fh_from_int: invalid fd %d\n", fd + WIN32_FH_BASE );
        errno = EBADF;
        return NULL;
    }

    return f;
}


static int
_fh_to_int( FH  f )
{
    if (f && f->used && f >= _win32_fhs && f < _win32_fhs + WIN32_MAX_FHS)
        return (int)(f - _win32_fhs) + WIN32_FH_BASE;

    return -1;
}

static FH
_fh_alloc( FHClass  clazz )
{
    int  nn;
    FH   f = NULL;

    adb_mutex_lock( &_win32_lock );

    if (_win32_fh_count < WIN32_MAX_FHS) {
        f = &_win32_fhs[ _win32_fh_count++ ];
        goto Exit;
    }

    for (nn = 0; nn < WIN32_MAX_FHS; nn++) {
        if ( _win32_fhs[nn].clazz == NULL) {
            f = &_win32_fhs[nn];
            goto Exit;
        }
    }
    D( "_fh_alloc: no more free file descriptors\n" );
Exit:
    if (f) {
        f->clazz = clazz;
        f->used  = 1;
        f->eof   = 0;
        clazz->_fh_init(f);
    }
    adb_mutex_unlock( &_win32_lock );
    return f;
}


static int
_fh_close( FH   f )
{
    if ( f->used ) {
        f->clazz->_fh_close( f );
        f->used = 0;
        f->eof  = 0;
        f->clazz = NULL;
    }
    return 0;
}

/* forward definitions */
static const FHClassRec   _fh_file_class;
static const FHClassRec   _fh_socket_class;

/**************************************************************************/
/**************************************************************************/
/*****                                                                *****/
/*****    file-based descriptor handling                              *****/
/*****                                                                *****/
/**************************************************************************/
/**************************************************************************/

static void
_fh_file_init( FH  f )
{
    f->fh_handle = INVALID_HANDLE_VALUE;
}

static int
_fh_file_close( FH  f )
{
    CloseHandle( f->fh_handle );
    f->fh_handle = INVALID_HANDLE_VALUE;
    return 0;
}

static int
_fh_file_read( FH  f,  void*  buf, int   len )
{
    DWORD  read_bytes;

    if ( !ReadFile( f->fh_handle, buf, (DWORD)len, &read_bytes, NULL ) ) {
        D( "adb_read: could not read %d bytes from %s\n", len, f->name );
        errno = EIO;
        return -1;
    } else if (read_bytes < (DWORD)len) {
        f->eof = 1;
    }
    return (int)read_bytes;
}

static int
_fh_file_write( FH  f,  const void*  buf, int   len )
{
    DWORD  wrote_bytes;

    if ( !WriteFile( f->fh_handle, buf, (DWORD)len, &wrote_bytes, NULL ) ) {
        D( "adb_file_write: could not write %d bytes from %s\n", len, f->name );
        errno = EIO;
        return -1;
    } else if (wrote_bytes < (DWORD)len) {
        f->eof = 1;
    }
    return  (int)wrote_bytes;
}

static int
_fh_file_lseek( FH  f, int  pos, int  origin )
{
    DWORD  method;
    DWORD  result;

    switch (origin)
    {
        case SEEK_SET:  method = FILE_BEGIN; break;
        case SEEK_CUR:  method = FILE_CURRENT; break;
        case SEEK_END:  method = FILE_END; break;
        default:
            errno = EINVAL;
            return -1;
    }

    result = SetFilePointer( f->fh_handle, pos, NULL, method );
    if (result == INVALID_SET_FILE_POINTER) {
        errno = EIO;
        return -1;
    } else {
        f->eof = 0;
    }
    return (int)result;
}

static void  _fh_file_hook( FH  f, int  event, EventHook  eventhook );  /* forward */

static const FHClassRec  _fh_file_class =
{
    _fh_file_init,
    _fh_file_close,
    _fh_file_lseek,
    _fh_file_read,
    _fh_file_write,
    _fh_file_hook
};

/**************************************************************************/
/**************************************************************************/
/*****                                                                *****/
/*****    file-based descriptor handling                              *****/
/*****                                                                *****/
/**************************************************************************/
/**************************************************************************/

int  adb_open(const char*  path, int  options)
{
    FH  f;

    DWORD  desiredAccess       = 0;
    DWORD  shareMode           = FILE_SHARE_READ | FILE_SHARE_WRITE;

    switch (options) {
        case O_RDONLY:
            desiredAccess = GENERIC_READ;
            break;
        case O_WRONLY:
            desiredAccess = GENERIC_WRITE;
            break;
        case O_RDWR:
            desiredAccess = GENERIC_READ | GENERIC_WRITE;
            break;
        default:
            D("adb_open: invalid options (0x%0x)\n", options);
            errno = EINVAL;
            return -1;
    }

    f = _fh_alloc( &_fh_file_class );
    if ( !f ) {
        errno = ENOMEM;
        return -1;
    }

    f->fh_handle = CreateFile( path, desiredAccess, shareMode, NULL, OPEN_EXISTING,
                               0, NULL );

    if ( f->fh_handle == INVALID_HANDLE_VALUE ) {
        _fh_close(f);
        D( "adb_open: could not open '%s':", path );
        switch (GetLastError()) {
            case ERROR_FILE_NOT_FOUND:
                D( "file not found\n" );
                errno = ENOENT;
                return -1;

            case ERROR_PATH_NOT_FOUND:
                D( "path not found\n" );
                errno = ENOTDIR;
                return -1;

            default:
                D( "unknown error\n" );
                errno = ENOENT;
                return -1;
        }
    }

    snprintf( f->name, sizeof(f->name), "%d(%s)", _fh_to_int(f), path );
    D( "adb_open: '%s' => fd %d\n", path, _fh_to_int(f) );
    return _fh_to_int(f);
}

/* ignore mode on Win32 */
int  adb_creat(const char*  path, int  mode)
{
    FH  f;

    f = _fh_alloc( &_fh_file_class );
    if ( !f ) {
        errno = ENOMEM;
        return -1;
    }

    f->fh_handle = CreateFile( path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                               NULL );

    if ( f->fh_handle == INVALID_HANDLE_VALUE ) {
        _fh_close(f);
        D( "adb_creat: could not open '%s':", path );
        switch (GetLastError()) {
            case ERROR_FILE_NOT_FOUND:
                D( "file not found\n" );
                errno = ENOENT;
                return -1;

            case ERROR_PATH_NOT_FOUND:
                D( "path not found\n" );
                errno = ENOTDIR;
                return -1;

            default:
                D( "unknown error\n" );
                errno = ENOENT;
                return -1;
        }
    }
    snprintf( f->name, sizeof(f->name), "%d(%s)", _fh_to_int(f), path );
    D( "adb_creat: '%s' => fd %d\n", path, _fh_to_int(f) );
    return _fh_to_int(f);
}


int  adb_read(int  fd, void* buf, int len)
{
    FH     f = _fh_from_int(fd);

    if (f == NULL) {
        return -1;
    }

    return f->clazz->_fh_read( f, buf, len );
}


int  adb_write(int  fd, const void*  buf, int  len)
{
    FH     f = _fh_from_int(fd);

    if (f == NULL) {
        return -1;
    }

    return f->clazz->_fh_write(f, buf, len);
}


int  adb_lseek(int  fd, int  pos, int  where)
{
    FH     f = _fh_from_int(fd);

    if (!f) {
        return -1;
    }

    return f->clazz->_fh_lseek(f, pos, where);
}


int  adb_shutdown(int  fd)
{
    FH   f = _fh_from_int(fd);

    if (!f) {
        return -1;
    }

    D( "adb_shutdown: %s\n", f->name);
    shutdown( f->fh_socket, SD_BOTH );
    return 0;
}


int  adb_close(int  fd)
{
    FH   f = _fh_from_int(fd);

    if (!f) {
        return -1;
    }

    D( "adb_close: %s\n", f->name);
    _fh_close(f);
    return 0;
}

/**************************************************************************/
/**************************************************************************/
/*****                                                                *****/
/*****    socket-based file descriptors                               *****/
/*****                                                                *****/
/**************************************************************************/
/**************************************************************************/

static void
_socket_set_errno( void )
{
    switch (WSAGetLastError()) {
    case 0:              errno = 0; break;
    case WSAEWOULDBLOCK: errno = EAGAIN; break;
    case WSAEINTR:       errno = EINTR; break;
    default:
        D( "_socket_set_errno: unhandled value %d\n", WSAGetLastError() );
        errno = EINVAL;
    }
}

static void
_fh_socket_init( FH  f )
{
    f->fh_socket = INVALID_SOCKET;
    f->event     = WSACreateEvent();
    f->mask      = 0;
}

static int
_fh_socket_close( FH  f )
{
    /* gently tell any peer that we're closing the socket */
    shutdown( f->fh_socket, SD_BOTH );
    closesocket( f->fh_socket );
    f->fh_socket = INVALID_SOCKET;
    CloseHandle( f->event );
    f->mask = 0;
    return 0;
}

static int
_fh_socket_lseek( FH  f, int pos, int origin )
{
    errno = EPIPE;
    return -1;
}

static int
_fh_socket_read( FH  f, void*  buf, int  len )
{
    int  result = recv( f->fh_socket, buf, len, 0 );
    if (result == SOCKET_ERROR) {
        _socket_set_errno();
        result = -1;
    }
    return  result;
}

static int
_fh_socket_write( FH  f, const void*  buf, int  len )
{
    int  result = send( f->fh_socket, buf, len, 0 );
    if (result == SOCKET_ERROR) {
        _socket_set_errno();
        result = -1;
    }
    return result;
}

static void  _fh_socket_hook( FH  f, int  event, EventHook  hook );  /* forward */

static const FHClassRec  _fh_socket_class =
{
    _fh_socket_init,
    _fh_socket_close,
    _fh_socket_lseek,
    _fh_socket_read,
    _fh_socket_write,
    _fh_socket_hook
};

/**************************************************************************/
/**************************************************************************/
/*****                                                                *****/
/*****    replacement for libs/cutils/socket_xxxx.c                   *****/
/*****                                                                *****/
/**************************************************************************/
/**************************************************************************/

#include <winsock2.h>

static int  _winsock_init;

static void
_cleanup_winsock( void )
{
    WSACleanup();
}

static void
_init_winsock( void )
{
    if (!_winsock_init) {
        WSADATA  wsaData;
        int      rc = WSAStartup( MAKEWORD(2,2), &wsaData);
        if (rc != 0) {
            fatal( "adb: could not initialize Winsock\n" );
        }
        atexit( _cleanup_winsock );
        _winsock_init = 1;
    }
}

int socket_loopback_client(int port, int type)
{
    FH  f = _fh_alloc( &_fh_socket_class );
    struct sockaddr_in addr;
    SOCKET  s;

    if (!f)
        return -1;

    if (!_winsock_init)
        _init_winsock();

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    s = socket(AF_INET, type, 0);
    if(s == INVALID_SOCKET) {
        D("socket_loopback_client: could not create socket\n" );
        _fh_close(f);
        return -1;
    }

    f->fh_socket = s;
    if(connect(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        D("socket_loopback_client: could not connect to %s:%d\n", type != SOCK_STREAM ? "udp" : "tcp", port );
        _fh_close(f);
        return -1;
    }
    snprintf( f->name, sizeof(f->name), "%d(lo-client:%s%d)", _fh_to_int(f), type != SOCK_STREAM ? "udp:" : "", port );
    D( "socket_loopback_client: port %d type %s => fd %d\n", port, type != SOCK_STREAM ? "udp" : "tcp", _fh_to_int(f) );
    return _fh_to_int(f);
}

#define LISTEN_BACKLOG 4

int socket_loopback_server(int port, int type)
{
    FH   f = _fh_alloc( &_fh_socket_class );
    struct sockaddr_in addr;
    SOCKET  s;
    int  n;

    if (!f) {
        return -1;
    }

    if (!_winsock_init)
        _init_winsock();

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    s = socket(AF_INET, type, 0);
    if(s == INVALID_SOCKET) return -1;

    f->fh_socket = s;

    n = 1;
    setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char*)&n, sizeof(n));

    if(bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        _fh_close(f);
        return -1;
    }
    if (type == SOCK_STREAM) {
        int ret;

        ret = listen(s, LISTEN_BACKLOG);
        if (ret < 0) {
            _fh_close(f);
            return -1;
        }
    }
    snprintf( f->name, sizeof(f->name), "%d(lo-server:%s%d)", _fh_to_int(f), type != SOCK_STREAM ? "udp:" : "", port );
    D( "socket_loopback_server: port %d type %s => fd %d\n", port, type != SOCK_STREAM ? "udp" : "tcp", _fh_to_int(f) );
    return _fh_to_int(f);
}


int socket_network_client(const char *host, int port, int type)
{
    FH  f = _fh_alloc( &_fh_socket_class );
    struct hostent *hp;
    struct sockaddr_in addr;
    SOCKET s;

    if (!f)
        return -1;

    if (!_winsock_init)
        _init_winsock();

    hp = gethostbyname(host);
    if(hp == 0) {
        _fh_close(f);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = hp->h_addrtype;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr, hp->h_addr, hp->h_length);

    s = socket(hp->h_addrtype, type, 0);
    if(s == INVALID_SOCKET) {
        _fh_close(f);
        return -1;
    }
    f->fh_socket = s;

    if(connect(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        _fh_close(f);
        return -1;
    }

    snprintf( f->name, sizeof(f->name), "%d(net-client:%s%d)", _fh_to_int(f), type != SOCK_STREAM ? "udp:" : "", port );
    D( "socket_network_client: host '%s' port %d type %s => fd %d\n", host, port, type != SOCK_STREAM ? "udp" : "tcp", _fh_to_int(f) );
    return _fh_to_int(f);
}


int socket_inaddr_any_server(int port, int type)
{
    FH  f = _fh_alloc( &_fh_socket_class );
    struct sockaddr_in addr;
    SOCKET  s;
    int n;

    if (!f)
        return -1;

    if (!_winsock_init)
        _init_winsock();

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, type, 0);
    if(s == INVALID_SOCKET) {
        _fh_close(f);
        return -1;
    }

    f->fh_socket = s;
    n = 1;
    setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char*)&n, sizeof(n));

    if(bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        _fh_close(f);
        return -1;
    }

    if (type == SOCK_STREAM) {
        int ret;

        ret = listen(s, LISTEN_BACKLOG);
        if (ret < 0) {
            _fh_close(f);
            return -1;
        }
    }
    snprintf( f->name, sizeof(f->name), "%d(any-server:%s%d)", _fh_to_int(f), type != SOCK_STREAM ? "udp:" : "", port );
    D( "socket_inaddr_server: port %d type %s => fd %d\n", port, type != SOCK_STREAM ? "udp" : "tcp", _fh_to_int(f) );
    return _fh_to_int(f);
}

#undef accept
int  adb_socket_accept(int  serverfd, struct sockaddr*  addr, socklen_t  *addrlen)
{
    FH   serverfh = _fh_from_int(serverfd);
    FH   fh;

    if ( !serverfh || serverfh->clazz != &_fh_socket_class ) {
        D( "adb_socket_accept: invalid fd %d\n", serverfd );
        return -1;
    }

    fh = _fh_alloc( &_fh_socket_class );
    if (!fh) {
        D( "adb_socket_accept: not enough memory to allocate accepted socket descriptor\n" );
        return -1;
    }

    fh->fh_socket = accept( serverfh->fh_socket, addr, addrlen );
    if (fh->fh_socket == INVALID_SOCKET) {
        _fh_close( fh );
        D( "adb_socket_accept: accept on fd %d return error %ld\n", serverfd, GetLastError() );
        return -1;
    }

    snprintf( fh->name, sizeof(fh->name), "%d(accept:%s)", _fh_to_int(fh), serverfh->name );
    D( "adb_socket_accept on fd %d returns fd %d\n", serverfd, _fh_to_int(fh) );
    return  _fh_to_int(fh);
}


void  disable_tcp_nagle(int fd)
{
    FH   fh = _fh_from_int(fd);
    int  on = 1;

    if ( !fh || fh->clazz != &_fh_socket_class )
        return;

    setsockopt( fh->fh_socket, IPPROTO_TCP, TCP_NODELAY, (const char*)&on, sizeof(on) );
}

/**************************************************************************/
/**************************************************************************/
/*****                                                                *****/
/*****    emulated socketpairs                                       *****/
/*****                                                                *****/
/**************************************************************************/
/**************************************************************************/

/* we implement socketpairs directly in use space for the following reasons:
 *   - it avoids copying data from/to the Nt kernel
 *   - it allows us to implement fdevent hooks easily and cheaply, something
 *     that is not possible with standard Win32 pipes !!
 *
 * basically, we use two circular buffers, each one corresponding to a given
 * direction.
 *
 * each buffer is implemented as two regions:
 *
 *   region A which is (a_start,a_end)
 *   region B which is (0, b_end)  with b_end <= a_start
 *
 * an empty buffer has:  a_start = a_end = b_end = 0
 *
 * a_start is the pointer where we start reading data
 * a_end is the pointer where we start writing data, unless it is BUFFER_SIZE,
 * then you start writing at b_end
 *
 * the buffer is full when  b_end == a_start && a_end == BUFFER_SIZE
 *
 * there is room when b_end < a_start || a_end < BUFER_SIZE
 *
 * when reading, a_start is incremented, it a_start meets a_end, then
 * we do:  a_start = 0, a_end = b_end, b_end = 0, and keep going on..
 */

#define  BIP_BUFFER_SIZE   4096

#if 0
#include <stdio.h>
#  define  BIPD(x)      D x
#  define  BIPDUMP   bip_dump_hex

static void  bip_dump_hex( const unsigned char*  ptr, size_t  len )
{
    int  nn, len2 = len;

    if (len2 > 8) len2 = 8;

    for (nn = 0; nn < len2; nn++)
        printf("%02x", ptr[nn]);
    printf("  ");

    for (nn = 0; nn < len2; nn++) {
        int  c = ptr[nn];
        if (c < 32 || c > 127)
            c = '.';
        printf("%c", c);
    }
    printf("\n");
    fflush(stdout);
}

#else
#  define  BIPD(x)        do {} while (0)
#  define  BIPDUMP(p,l)   BIPD(p)
#endif

typedef struct BipBufferRec_
{
    int                a_start;
    int                a_end;
    int                b_end;
    int                fdin;
    int                fdout;
    int                closed;
    int                can_write;  /* boolean */
    HANDLE             evt_write;  /* event signaled when one can write to a buffer  */
    int                can_read;   /* boolean */
    HANDLE             evt_read;   /* event signaled when one can read from a buffer */
    CRITICAL_SECTION  lock;
    unsigned char      buff[ BIP_BUFFER_SIZE ];

} BipBufferRec, *BipBuffer;

static void
bip_buffer_init( BipBuffer  buffer )
{
    D( "bit_buffer_init %p\n", buffer );
    buffer->a_start   = 0;
    buffer->a_end     = 0;
    buffer->b_end     = 0;
    buffer->can_write = 1;
    buffer->can_read  = 0;
    buffer->fdin      = 0;
    buffer->fdout     = 0;
    buffer->closed    = 0;
    buffer->evt_write = CreateEvent( NULL, TRUE, TRUE, NULL );
    buffer->evt_read  = CreateEvent( NULL, TRUE, FALSE, NULL );
    InitializeCriticalSection( &buffer->lock );
}

static void
bip_buffer_close( BipBuffer  bip )
{
    bip->closed = 1;

    if (!bip->can_read) {
        SetEvent( bip->evt_read );
    }
    if (!bip->can_write) {
        SetEvent( bip->evt_write );
    }
}

static void
bip_buffer_done( BipBuffer  bip )
{
    BIPD(( "bip_buffer_done: %d->%d\n", bip->fdin, bip->fdout ));
    CloseHandle( bip->evt_read );
    CloseHandle( bip->evt_write );
    DeleteCriticalSection( &bip->lock );
}

static int
bip_buffer_write( BipBuffer  bip, const void* src, int  len )
{
    int  avail, count = 0;

    if (len <= 0)
        return 0;

    BIPD(( "bip_buffer_write: enter %d->%d len %d\n", bip->fdin, bip->fdout, len ));
    BIPDUMP( src, len );

    EnterCriticalSection( &bip->lock );

    while (!bip->can_write) {
        int  ret;
        LeaveCriticalSection( &bip->lock );

        if (bip->closed) {
            errno = EPIPE;
            return -1;
        }
        /* spinlocking here is probably unfair, but let's live with it */
        ret = WaitForSingleObject( bip->evt_write, INFINITE );
        if (ret != WAIT_OBJECT_0) {  /* buffer probably closed */
            D( "bip_buffer_write: error %d->%d WaitForSingleObject returned %d, error %ld\n", bip->fdin, bip->fdout, ret, GetLastError() );
            return 0;
        }
        if (bip->closed) {
            errno = EPIPE;
            return -1;
        }
        EnterCriticalSection( &bip->lock );
    }

    BIPD(( "bip_buffer_write: exec %d->%d len %d\n", bip->fdin, bip->fdout, len ));

    avail = BIP_BUFFER_SIZE - bip->a_end;
    if (avail > 0)
    {
        /* we can append to region A */
        if (avail > len)
            avail = len;

        memcpy( bip->buff + bip->a_end, src, avail );
        src   += avail;
        count += avail;
        len   -= avail;

        bip->a_end += avail;
        if (bip->a_end == BIP_BUFFER_SIZE && bip->a_start == 0) {
            bip->can_write = 0;
            ResetEvent( bip->evt_write );
            goto Exit;
        }
    }

    if (len == 0)
        goto Exit;

    avail = bip->a_start - bip->b_end;
    assert( avail > 0 );  /* since can_write is TRUE */

    if (avail > len)
        avail = len;

    memcpy( bip->buff + bip->b_end, src, avail );
    count += avail;
    bip->b_end += avail;

    if (bip->b_end == bip->a_start) {
        bip->can_write = 0;
        ResetEvent( bip->evt_write );
    }

Exit:
    assert( count > 0 );

    if ( !bip->can_read ) {
        bip->can_read = 1;
        SetEvent( bip->evt_read );
    }

    BIPD(( "bip_buffer_write: exit %d->%d count %d (as=%d ae=%d be=%d cw=%d cr=%d\n",
            bip->fdin, bip->fdout, count, bip->a_start, bip->a_end, bip->b_end, bip->can_write, bip->can_read ));
    LeaveCriticalSection( &bip->lock );

    return count;
 }

static int
bip_buffer_read( BipBuffer  bip, void*  dst, int  len )
{
    int  avail, count = 0;

    if (len <= 0)
        return 0;

    BIPD(( "bip_buffer_read: enter %d->%d len %d\n", bip->fdin, bip->fdout, len ));

    EnterCriticalSection( &bip->lock );
    while ( !bip->can_read )
    {
#if 0
        LeaveCriticalSection( &bip->lock );
        errno = EAGAIN;
        return -1;
#else
        int  ret;
        LeaveCriticalSection( &bip->lock );

        if (bip->closed) {
            errno = EPIPE;
            return -1;
        }

        ret = WaitForSingleObject( bip->evt_read, INFINITE );
        if (ret != WAIT_OBJECT_0) { /* probably closed buffer */
            D( "bip_buffer_read: error %d->%d WaitForSingleObject returned %d, error %ld\n", bip->fdin, bip->fdout, ret, GetLastError());
            return 0;
        }
        if (bip->closed) {
            errno = EPIPE;
            return -1;
        }
        EnterCriticalSection( &bip->lock );
#endif
    }

    BIPD(( "bip_buffer_read: exec %d->%d len %d\n", bip->fdin, bip->fdout, len ));

    avail = bip->a_end - bip->a_start;
    assert( avail > 0 );  /* since can_read is TRUE */

    if (avail > len)
        avail = len;

    memcpy( dst, bip->buff + bip->a_start, avail );
    dst   += avail;
    count += avail;
    len   -= avail;

    bip->a_start += avail;
    if (bip->a_start < bip->a_end)
        goto Exit;

    bip->a_start = 0;
    bip->a_end   = bip->b_end;
    bip->b_end   = 0;

    avail = bip->a_end;
    if (avail > 0) {
        if (avail > len)
            avail = len;
        memcpy( dst, bip->buff, avail );
        count += avail;
        bip->a_start += avail;

        if ( bip->a_start < bip->a_end )
            goto Exit;

        bip->a_start = bip->a_end = 0;
    }

    bip->can_read = 0;
    ResetEvent( bip->evt_read );

Exit:
    assert( count > 0 );

    if (!bip->can_write ) {
        bip->can_write = 1;
        SetEvent( bip->evt_write );
    }

    BIPDUMP( (const unsigned char*)dst - count, count );
    BIPD(( "bip_buffer_read: exit %d->%d count %d (as=%d ae=%d be=%d cw=%d cr=%d\n",
            bip->fdin, bip->fdout, count, bip->a_start, bip->a_end, bip->b_end, bip->can_write, bip->can_read ));
    LeaveCriticalSection( &bip->lock );

    return count;
}

typedef struct SocketPairRec_
{
    BipBufferRec  a2b_bip;
    BipBufferRec  b2a_bip;
    FH            a_fd;
    int           used;

} SocketPairRec;

void _fh_socketpair_init( FH  f )
{
    f->fh_pair = NULL;
}

static int
_fh_socketpair_close( FH  f )
{
    if ( f->fh_pair ) {
        SocketPair  pair = f->fh_pair;

        if ( f == pair->a_fd ) {
            pair->a_fd = NULL;
        }

        bip_buffer_close( &pair->b2a_bip );
        bip_buffer_close( &pair->a2b_bip );

        if ( --pair->used == 0 ) {
            bip_buffer_done( &pair->b2a_bip );
            bip_buffer_done( &pair->a2b_bip );
            free( pair );
        }
        f->fh_pair = NULL;
    }
    return 0;
}

static int
_fh_socketpair_lseek( FH  f, int pos, int  origin )
{
    errno = ESPIPE;
    return -1;
}

static int
_fh_socketpair_read( FH  f, void* buf, int  len )
{
    SocketPair  pair = f->fh_pair;
    BipBuffer   bip;

    if (!pair)
        return -1;

    if ( f == pair->a_fd )
        bip = &pair->b2a_bip;
    else
        bip = &pair->a2b_bip;

    return bip_buffer_read( bip, buf, len );
}

static int
_fh_socketpair_write( FH  f, const void*  buf, int  len )
{
    SocketPair  pair = f->fh_pair;
    BipBuffer   bip;

    if (!pair)
        return -1;

    if ( f == pair->a_fd )
        bip = &pair->a2b_bip;
    else
        bip = &pair->b2a_bip;

    return bip_buffer_write( bip, buf, len );
}


static void  _fh_socketpair_hook( FH  f, int  event, EventHook  hook );  /* forward */

static const FHClassRec  _fh_socketpair_class =
{
    _fh_socketpair_init,
    _fh_socketpair_close,
    _fh_socketpair_lseek,
    _fh_socketpair_read,
    _fh_socketpair_write,
    _fh_socketpair_hook
};


int  adb_socketpair( int  sv[2] )
{
    FH          fa, fb;
    SocketPair  pair;

    fa = _fh_alloc( &_fh_socketpair_class );
    fb = _fh_alloc( &_fh_socketpair_class );

    if (!fa || !fb)
        goto Fail;

    pair = malloc( sizeof(*pair) );
    if (pair == NULL) {
        D("adb_socketpair: not enough memory to allocate pipes\n" );
        goto Fail;
    }

    bip_buffer_init( &pair->a2b_bip );
    bip_buffer_init( &pair->b2a_bip );

    fa->fh_pair = pair;
    fb->fh_pair = pair;
    pair->used  = 2;
    pair->a_fd  = fa;

    sv[0] = _fh_to_int(fa);
    sv[1] = _fh_to_int(fb);

    pair->a2b_bip.fdin  = sv[0];
    pair->a2b_bip.fdout = sv[1];
    pair->b2a_bip.fdin  = sv[1];
    pair->b2a_bip.fdout = sv[0];

    snprintf( fa->name, sizeof(fa->name), "%d(pair:%d)", sv[0], sv[1] );
    snprintf( fb->name, sizeof(fb->name), "%d(pair:%d)", sv[1], sv[0] );
    D( "adb_socketpair: returns (%d, %d)\n", sv[0], sv[1] );
    return 0;

Fail:
    _fh_close(fb);
    _fh_close(fa);
    return -1;
}

/**************************************************************************/
/**************************************************************************/
/*****                                                                *****/
/*****    fdevents emulation                                          *****/
/*****                                                                *****/
/*****   this is a very simple implementation, we rely on the fact    *****/
/*****   that ADB doesn't use FDE_ERROR.                              *****/
/*****                                                                *****/
/**************************************************************************/
/**************************************************************************/

#define FATAL(x...) fatal(__FUNCTION__, x)

#if DEBUG
static void dump_fde(fdevent *fde, const char *info)
{
    fprintf(stderr,"FDE #%03d %c%c%c %s\n", fde->fd,
            fde->state & FDE_READ ? 'R' : ' ',
            fde->state & FDE_WRITE ? 'W' : ' ',
            fde->state & FDE_ERROR ? 'E' : ' ',
            info);
}
#else
#define dump_fde(fde, info) do { } while(0)
#endif

#define FDE_EVENTMASK  0x00ff
#define FDE_STATEMASK  0xff00

#define FDE_ACTIVE     0x0100
#define FDE_PENDING    0x0200
#define FDE_CREATED    0x0400

static void fdevent_plist_enqueue(fdevent *node);
static void fdevent_plist_remove(fdevent *node);
static fdevent *fdevent_plist_dequeue(void);

static fdevent list_pending = {
    .next = &list_pending,
    .prev = &list_pending,
};

static fdevent **fd_table = 0;
static int       fd_table_max = 0;

typedef struct EventLooperRec_*  EventLooper;

typedef struct EventHookRec_
{
    EventHook    next;
    FH           fh;
    HANDLE       h;
    int          wanted;   /* wanted event flags */
    int          ready;    /* ready event flags  */
    void*        aux;
    void        (*prepare)( EventHook  hook );
    int         (*start)  ( EventHook  hook );
    void        (*stop)   ( EventHook  hook );
    int         (*check)  ( EventHook  hook );
    int         (*peek)   ( EventHook  hook );
} EventHookRec;

static EventHook  _free_hooks;

static EventHook
event_hook_alloc( FH  fh )
{
    EventHook  hook = _free_hooks;
    if (hook != NULL)
        _free_hooks = hook->next;
    else {
        hook = malloc( sizeof(*hook) );
        if (hook == NULL)
            fatal( "could not allocate event hook\n" );
    }
    hook->next   = NULL;
    hook->fh     = fh;
    hook->wanted = 0;
    hook->ready  = 0;
    hook->h      = INVALID_HANDLE_VALUE;
    hook->aux    = NULL;

    hook->prepare = NULL;
    hook->start   = NULL;
    hook->stop    = NULL;
    hook->check   = NULL;
    hook->peek    = NULL;

    return hook;
}

static void
event_hook_free( EventHook  hook )
{
    hook->fh     = NULL;
    hook->wanted = 0;
    hook->ready  = 0;
    hook->next   = _free_hooks;
    _free_hooks  = hook;
}


static void
event_hook_signal( EventHook  hook )
{
    FH        f   = hook->fh;
    int       fd  = _fh_to_int(f);
    fdevent*  fde = fd_table[ fd - WIN32_FH_BASE ];

    if (fde != NULL && fde->fd == fd) {
        if ((fde->state & FDE_PENDING) == 0) {
            fde->state |= FDE_PENDING;
            fdevent_plist_enqueue( fde );
        }
        fde->events |= hook->wanted;
    }
}


#define  MAX_LOOPER_HANDLES  WIN32_MAX_FHS

typedef struct EventLooperRec_
{
    EventHook    hooks;
    HANDLE       htab[ MAX_LOOPER_HANDLES ];
    int          htab_count;

} EventLooperRec;

static EventHook*
event_looper_find_p( EventLooper  looper, FH  fh )
{
    EventHook  *pnode = &looper->hooks;
    EventHook   node  = *pnode;
    for (;;) {
        if ( node == NULL || node->fh == fh )
            break;
        pnode = &node->next;
        node  = *pnode;
    }
    return  pnode;
}

static void
event_looper_hook( EventLooper  looper, int  fd, int  events )
{
    FH          f = _fh_from_int(fd);
    EventHook  *pnode;
    EventHook   node;

    if (f == NULL)  /* invalid arg */ {
        D("event_looper_hook: invalid fd=%d\n", fd);
        return;
    }

    pnode = event_looper_find_p( looper, f );
    node  = *pnode;
    if ( node == NULL ) {
        node       = event_hook_alloc( f );
        node->next = *pnode;
        *pnode     = node;
    }

    if ( (node->wanted & events) != events ) {
        /* this should update start/stop/check/peek */
        D("event_looper_hook: call hook for %d (new=%x, old=%x)\n",
           fd, node->wanted, events);
        f->clazz->_fh_hook( f, events & ~node->wanted, node );
        node->wanted |= events;
    } else {
        D("event_looper_hook: ignoring events %x for %d wanted=%x)\n",
           events, fd, node->wanted);
    }
}

static void
event_looper_unhook( EventLooper  looper, int  fd, int  events )
{
    FH          fh    = _fh_from_int(fd);
    EventHook  *pnode = event_looper_find_p( looper, fh );
    EventHook   node  = *pnode;

    if (node != NULL) {
        int  events2 = events & node->wanted;
        if ( events2 == 0 ) {
            D( "event_looper_unhook: events %x not registered for fd %d\n", events, fd );
            return;
        }
        node->wanted &= ~events2;
        if (!node->wanted) {
            *pnode = node->next;
            event_hook_free( node );
        }
    }
}

/*
 * A fixer for WaitForMultipleObjects on condition that there are more than 64
 * handles to wait on.
 *
 * In cetain cases DDMS may establish more than 64 connections with ADB. For
 * instance, this may happen if there are more than 64 processes running on a
 * device, or there are multiple devices connected (including the emulator) with
 * the combined number of running processes greater than 64. In this case using
 * WaitForMultipleObjects to wait on connection events simply wouldn't cut,
 * because of the API limitations (64 handles max). So, we need to provide a way
 * to scale WaitForMultipleObjects to accept an arbitrary number of handles. The
 * easiest (and "Microsoft recommended") way to do that would be dividing the
 * handle array into chunks with the chunk size less than 64, and fire up as many
 * waiting threads as there are chunks. Then each thread would wait on a chunk of
 * handles, and will report back to the caller which handle has been set.
 * Here is the implementation of that algorithm.
 */

/* Number of handles to wait on in each wating thread. */
#define WAIT_ALL_CHUNK_SIZE 63

/* Descriptor for a wating thread */
typedef struct WaitForAllParam {
    /* A handle to an event to signal when waiting is over. This handle is shared
     * accross all the waiting threads, so each waiting thread knows when any
     * other thread has exited, so it can exit too. */
    HANDLE          main_event;
    /* Upon exit from a waiting thread contains the index of the handle that has
     * been signaled. The index is an absolute index of the signaled handle in
     * the original array. This pointer is shared accross all the waiting threads
     * and it's not guaranteed (due to a race condition) that when all the
     * waiting threads exit, the value contained here would indicate the first
     * handle that was signaled. This is fine, because the caller cares only
     * about any handle being signaled. It doesn't care about the order, nor
     * about the whole list of handles that were signaled. */
    LONG volatile   *signaled_index;
    /* Array of handles to wait on in a waiting thread. */
    HANDLE*         handles;
    /* Number of handles in 'handles' array to wait on. */
    int             handles_count;
    /* Index inside the main array of the first handle in the 'handles' array. */
    int             first_handle_index;
    /* Waiting thread handle. */
    HANDLE          thread;
} WaitForAllParam;

/* Waiting thread routine. */
static unsigned __stdcall
_in_waiter_thread(void*  arg)
{
    HANDLE wait_on[WAIT_ALL_CHUNK_SIZE + 1];
    int res;
    WaitForAllParam* const param = (WaitForAllParam*)arg;

    /* We have to wait on the main_event in order to be notified when any of the
     * sibling threads is exiting. */
    wait_on[0] = param->main_event;
    /* The rest of the handles go behind the main event handle. */
    memcpy(wait_on + 1, param->handles, param->handles_count * sizeof(HANDLE));

    res = WaitForMultipleObjects(param->handles_count + 1, wait_on, FALSE, INFINITE);
    if (res > 0 && res < (param->handles_count + 1)) {
        /* One of the original handles got signaled. Save its absolute index into
         * the output variable. */
        InterlockedCompareExchange(param->signaled_index,
                                   res - 1L + param->first_handle_index, -1L);
    }

    /* Notify the caller (and the siblings) that the wait is over. */
    SetEvent(param->main_event);

    _endthreadex(0);
    return 0;
}

/* WaitForMultipeObjects fixer routine.
 * Param:
 *  handles Array of handles to wait on.
 *  handles_count Number of handles in the array.
 * Return:
 *  (>= 0 && < handles_count) - Index of the signaled handle in the array, or
 *  WAIT_FAILED on an error.
 */
static int
_wait_for_all(HANDLE* handles, int handles_count)
{
    WaitForAllParam* threads;
    HANDLE main_event;
    int chunks, chunk, remains;

    /* This variable is going to be accessed by several threads at the same time,
     * this is bound to fail randomly when the core is run on multi-core machines.
     * To solve this, we need to do the following (1 _and_ 2):
     * 1. Use the "volatile" qualifier to ensure the compiler doesn't optimize
     *    out the reads/writes in this function unexpectedly.
     * 2. Ensure correct memory ordering. The "simple" way to do that is to wrap
     *    all accesses inside a critical section. But we can also use
     *    InterlockedCompareExchange() which always provide a full memory barrier
     *    on Win32.
     */
    volatile LONG sig_index = -1;

    /* Calculate number of chunks, and allocate thread param array. */
    chunks = handles_count / WAIT_ALL_CHUNK_SIZE;
    remains = handles_count % WAIT_ALL_CHUNK_SIZE;
    threads = (WaitForAllParam*)malloc((chunks + (remains ? 1 : 0)) *
                                        sizeof(WaitForAllParam));
    if (threads == NULL) {
        D("Unable to allocate thread array for %d handles.", handles_count);
        return (int)WAIT_FAILED;
    }

    /* Create main event to wait on for all waiting threads. This is a "manualy
     * reset" event that will remain set once it was set. */
    main_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (main_event == NULL) {
        D("Unable to create main event. Error: %d", GetLastError());
        free(threads);
        return (int)WAIT_FAILED;
    }

    /*
     * Initialize waiting thread parameters.
     */

    for (chunk = 0; chunk < chunks; chunk++) {
        threads[chunk].main_event = main_event;
        threads[chunk].signaled_index = &sig_index;
        threads[chunk].first_handle_index = WAIT_ALL_CHUNK_SIZE * chunk;
        threads[chunk].handles = handles + threads[chunk].first_handle_index;
        threads[chunk].handles_count = WAIT_ALL_CHUNK_SIZE;
    }
    if (remains) {
        threads[chunk].main_event = main_event;
        threads[chunk].signaled_index = &sig_index;
        threads[chunk].first_handle_index = WAIT_ALL_CHUNK_SIZE * chunk;
        threads[chunk].handles = handles + threads[chunk].first_handle_index;
        threads[chunk].handles_count = remains;
        chunks++;
    }

    /* Start the waiting threads. */
    for (chunk = 0; chunk < chunks; chunk++) {
        /* Note that using adb_thread_create is not appropriate here, since we
         * need a handle to wait on for thread termination. */
        threads[chunk].thread = (HANDLE)_beginthreadex(NULL, 0, _in_waiter_thread,
                                                       &threads[chunk], 0, NULL);
        if (threads[chunk].thread == NULL) {
            /* Unable to create a waiter thread. Collapse. */
            D("Unable to create a waiting thread %d of %d. errno=%d",
              chunk, chunks, errno);
            chunks = chunk;
            SetEvent(main_event);
            break;
        }
    }

    /* Wait on any of the threads to get signaled. */
    WaitForSingleObject(main_event, INFINITE);

    /* Wait on all the waiting threads to exit. */
    for (chunk = 0; chunk < chunks; chunk++) {
        WaitForSingleObject(threads[chunk].thread, INFINITE);
        CloseHandle(threads[chunk].thread);
    }

    CloseHandle(main_event);
    free(threads);


    const int ret = (int)InterlockedCompareExchange(&sig_index, -1, -1);
    return (ret >= 0) ? ret : (int)WAIT_FAILED;
}

static EventLooperRec  win32_looper;

static void fdevent_init(void)
{
    win32_looper.htab_count = 0;
    win32_looper.hooks      = NULL;
}

static void fdevent_connect(fdevent *fde)
{
    EventLooper  looper = &win32_looper;
    int          events = fde->state & FDE_EVENTMASK;

    if (events != 0)
        event_looper_hook( looper, fde->fd, events );
}

static void fdevent_disconnect(fdevent *fde)
{
    EventLooper  looper = &win32_looper;
    int          events = fde->state & FDE_EVENTMASK;

    if (events != 0)
        event_looper_unhook( looper, fde->fd, events );
}

static void fdevent_update(fdevent *fde, unsigned events)
{
    EventLooper  looper  = &win32_looper;
    unsigned     events0 = fde->state & FDE_EVENTMASK;

    if (events != events0) {
        int  removes = events0 & ~events;
        int  adds    = events  & ~events0;
        if (removes) {
            D("fdevent_update: remove %x from %d\n", removes, fde->fd);
            event_looper_unhook( looper, fde->fd, removes );
        }
        if (adds) {
            D("fdevent_update: add %x to %d\n", adds, fde->fd);
            event_looper_hook  ( looper, fde->fd, adds );
        }
    }
}

static void fdevent_process()
{
    EventLooper  looper = &win32_looper;
    EventHook    hook;
    int          gotone = 0;

    /* if we have at least one ready hook, execute it/them */
    for (hook = looper->hooks; hook; hook = hook->next) {
        hook->ready = 0;
        if (hook->prepare) {
            hook->prepare(hook);
            if (hook->ready != 0) {
                event_hook_signal( hook );
                gotone = 1;
            }
        }
    }

    /* nothing's ready yet, so wait for something to happen */
    if (!gotone)
    {
        looper->htab_count = 0;

        for (hook = looper->hooks; hook; hook = hook->next)
        {
            if (hook->start && !hook->start(hook)) {
                D( "fdevent_process: error when starting a hook\n" );
                return;
            }
            if (hook->h != INVALID_HANDLE_VALUE) {
                int  nn;

                for (nn = 0; nn < looper->htab_count; nn++)
                {
                    if ( looper->htab[nn] == hook->h )
                        goto DontAdd;
                }
                looper->htab[ looper->htab_count++ ] = hook->h;
            DontAdd:
                ;
            }
        }

        if (looper->htab_count == 0) {
            D( "fdevent_process: nothing to wait for !!\n" );
            return;
        }

        do
        {
            int   wait_ret;

            D( "adb_win32: waiting for %d events\n", looper->htab_count );
            if (looper->htab_count > MAXIMUM_WAIT_OBJECTS) {
                D("handle count %d exceeds MAXIMUM_WAIT_OBJECTS.\n", looper->htab_count);
                wait_ret = _wait_for_all(looper->htab, looper->htab_count);
            } else {
                wait_ret = WaitForMultipleObjects( looper->htab_count, looper->htab, FALSE, INFINITE );
            }
            if (wait_ret == (int)WAIT_FAILED) {
                D( "adb_win32: wait failed, error %ld\n", GetLastError() );
            } else {
                D( "adb_win32: got one (index %d)\n", wait_ret );

                /* according to Cygwin, some objects like consoles wake up on "inappropriate" events
                 * like mouse movements. we need to filter these with the "check" function
                 */
                if ((unsigned)wait_ret < (unsigned)looper->htab_count)
                {
                    for (hook = looper->hooks; hook; hook = hook->next)
                    {
                        if ( looper->htab[wait_ret] == hook->h       &&
                         (!hook->check || hook->check(hook)) )
                        {
                            D( "adb_win32: signaling %s for %x\n", hook->fh->name, hook->ready );
                            event_hook_signal( hook );
                            gotone = 1;
                            break;
                        }
                    }
                }
            }
        }
        while (!gotone);

        for (hook = looper->hooks; hook; hook = hook->next) {
            if (hook->stop)
                hook->stop( hook );
        }
    }

    for (hook = looper->hooks; hook; hook = hook->next) {
        if (hook->peek && hook->peek(hook))
                event_hook_signal( hook );
    }
}


static void fdevent_register(fdevent *fde)
{
    int  fd = fde->fd - WIN32_FH_BASE;

    if(fd < 0) {
        FATAL("bogus negative fd (%d)\n", fde->fd);
    }

    if(fd >= fd_table_max) {
        int oldmax = fd_table_max;
        if(fde->fd > 32000) {
            FATAL("bogus huuuuge fd (%d)\n", fde->fd);
        }
        if(fd_table_max == 0) {
            fdevent_init();
            fd_table_max = 256;
        }
        while(fd_table_max <= fd) {
            fd_table_max *= 2;
        }
        fd_table = realloc(fd_table, sizeof(fdevent*) * fd_table_max);
        if(fd_table == 0) {
            FATAL("could not expand fd_table to %d entries\n", fd_table_max);
        }
        memset(fd_table + oldmax, 0, sizeof(int) * (fd_table_max - oldmax));
    }

    fd_table[fd] = fde;
}

static void fdevent_unregister(fdevent *fde)
{
    int  fd = fde->fd - WIN32_FH_BASE;

    if((fd < 0) || (fd >= fd_table_max)) {
        FATAL("fd out of range (%d)\n", fde->fd);
    }

    if(fd_table[fd] != fde) {
        FATAL("fd_table out of sync");
    }

    fd_table[fd] = 0;

    if(!(fde->state & FDE_DONT_CLOSE)) {
        dump_fde(fde, "close");
        adb_close(fde->fd);
    }
}

static void fdevent_plist_enqueue(fdevent *node)
{
    fdevent *list = &list_pending;

    node->next = list;
    node->prev = list->prev;
    node->prev->next = node;
    list->prev = node;
}

static void fdevent_plist_remove(fdevent *node)
{
    node->prev->next = node->next;
    node->next->prev = node->prev;
    node->next = 0;
    node->prev = 0;
}

static fdevent *fdevent_plist_dequeue(void)
{
    fdevent *list = &list_pending;
    fdevent *node = list->next;

    if(node == list) return 0;

    list->next = node->next;
    list->next->prev = list;
    node->next = 0;
    node->prev = 0;

    return node;
}

fdevent *fdevent_create(int fd, fd_func func, void *arg)
{
    fdevent *fde = (fdevent*) malloc(sizeof(fdevent));
    if(fde == 0) return 0;
    fdevent_install(fde, fd, func, arg);
    fde->state |= FDE_CREATED;
    return fde;
}

void fdevent_destroy(fdevent *fde)
{
    if(fde == 0) return;
    if(!(fde->state & FDE_CREATED)) {
        FATAL("fde %p not created by fdevent_create()\n", fde);
    }
    fdevent_remove(fde);
}

void fdevent_install(fdevent *fde, int fd, fd_func func, void *arg)
{
    memset(fde, 0, sizeof(fdevent));
    fde->state = FDE_ACTIVE;
    fde->fd = fd;
    fde->func = func;
    fde->arg = arg;

    fdevent_register(fde);
    dump_fde(fde, "connect");
    fdevent_connect(fde);
    fde->state |= FDE_ACTIVE;
}

void fdevent_remove(fdevent *fde)
{
    if(fde->state & FDE_PENDING) {
        fdevent_plist_remove(fde);
    }

    if(fde->state & FDE_ACTIVE) {
        fdevent_disconnect(fde);
        dump_fde(fde, "disconnect");
        fdevent_unregister(fde);
    }

    fde->state = 0;
    fde->events = 0;
}


void fdevent_set(fdevent *fde, unsigned events)
{
    events &= FDE_EVENTMASK;

    if((fde->state & FDE_EVENTMASK) == (int)events) return;

    if(fde->state & FDE_ACTIVE) {
        fdevent_update(fde, events);
        dump_fde(fde, "update");
    }

    fde->state = (fde->state & FDE_STATEMASK) | events;

    if(fde->state & FDE_PENDING) {
            /* if we're pending, make sure
            ** we don't signal an event that
            ** is no longer wanted.
            */
        fde->events &= (~events);
        if(fde->events == 0) {
            fdevent_plist_remove(fde);
            fde->state &= (~FDE_PENDING);
        }
    }
}

void fdevent_add(fdevent *fde, unsigned events)
{
    fdevent_set(
        fde, (fde->state & FDE_EVENTMASK) | (events & FDE_EVENTMASK));
}

void fdevent_del(fdevent *fde, unsigned events)
{
    fdevent_set(
        fde, (fde->state & FDE_EVENTMASK) & (~(events & FDE_EVENTMASK)));
}

void fdevent_loop()
{
    fdevent *fde;

    for(;;) {
#if DEBUG
        fprintf(stderr,"--- ---- waiting for events\n");
#endif
        fdevent_process();

        while((fde = fdevent_plist_dequeue())) {
            unsigned events = fde->events;
            fde->events = 0;
            fde->state &= (~FDE_PENDING);
            dump_fde(fde, "callback");
            fde->func(fde->fd, events, fde->arg);
        }
    }
}

/**  FILE EVENT HOOKS
 **/

static void  _event_file_prepare( EventHook  hook )
{
    if (hook->wanted & (FDE_READ|FDE_WRITE)) {
        /* we can always read/write */
        hook->ready |= hook->wanted & (FDE_READ|FDE_WRITE);
    }
}

static int  _event_file_peek( EventHook  hook )
{
    return (hook->wanted & (FDE_READ|FDE_WRITE));
}

static void  _fh_file_hook( FH  f, int  events, EventHook  hook )
{
    hook->h       = f->fh_handle;
    hook->prepare = _event_file_prepare;
    hook->peek    = _event_file_peek;
}

/** SOCKET EVENT HOOKS
 **/

static void  _event_socket_verify( EventHook  hook, WSANETWORKEVENTS*  evts )
{
    if ( evts->lNetworkEvents & (FD_READ|FD_ACCEPT|FD_CLOSE) ) {
        if (hook->wanted & FDE_READ)
            hook->ready |= FDE_READ;
        if ((evts->iErrorCode[FD_READ] != 0) && hook->wanted & FDE_ERROR)
            hook->ready |= FDE_ERROR;
    }
    if ( evts->lNetworkEvents & (FD_WRITE|FD_CONNECT|FD_CLOSE) ) {
        if (hook->wanted & FDE_WRITE)
            hook->ready |= FDE_WRITE;
        if ((evts->iErrorCode[FD_WRITE] != 0) && hook->wanted & FDE_ERROR)
            hook->ready |= FDE_ERROR;
    }
    if ( evts->lNetworkEvents & FD_OOB ) {
        if (hook->wanted & FDE_ERROR)
            hook->ready |= FDE_ERROR;
    }
}

static void  _event_socket_prepare( EventHook  hook )
{
    WSANETWORKEVENTS  evts;

    /* look if some of the events we want already happened ? */
    if (!WSAEnumNetworkEvents( hook->fh->fh_socket, NULL, &evts ))
        _event_socket_verify( hook, &evts );
}

static int  _socket_wanted_to_flags( int  wanted )
{
    int  flags = 0;
    if (wanted & FDE_READ)
        flags |= FD_READ | FD_ACCEPT | FD_CLOSE;

    if (wanted & FDE_WRITE)
        flags |= FD_WRITE | FD_CONNECT | FD_CLOSE;

    if (wanted & FDE_ERROR)
        flags |= FD_OOB;

    return flags;
}

static int _event_socket_start( EventHook  hook )
{
    /* create an event which we're going to wait for */
    FH    fh    = hook->fh;
    long  flags = _socket_wanted_to_flags( hook->wanted );

    hook->h = fh->event;
    if (hook->h == INVALID_HANDLE_VALUE) {
        D( "_event_socket_start: no event for %s\n", fh->name );
        return 0;
    }

    if ( flags != fh->mask ) {
        D( "_event_socket_start: hooking %s for %x (flags %ld)\n", hook->fh->name, hook->wanted, flags );
        if ( WSAEventSelect( fh->fh_socket, hook->h, flags ) ) {
            D( "_event_socket_start: WSAEventSelect() for %s failed, error %d\n", hook->fh->name, WSAGetLastError() );
            CloseHandle( hook->h );
            hook->h = INVALID_HANDLE_VALUE;
            exit(1);
            return 0;
        }
        fh->mask = flags;
    }
    return 1;
}

static void _event_socket_stop( EventHook  hook )
{
    hook->h = INVALID_HANDLE_VALUE;
}

static int  _event_socket_check( EventHook  hook )
{
    int               result = 0;
    FH                fh = hook->fh;
    WSANETWORKEVENTS  evts;

    if (!WSAEnumNetworkEvents( fh->fh_socket, hook->h, &evts ) ) {
        _event_socket_verify( hook, &evts );
        result = (hook->ready != 0);
        if (result) {
            ResetEvent( hook->h );
        }
    }
    D( "_event_socket_check %s returns %d\n", fh->name, result );
    return  result;
}

static int  _event_socket_peek( EventHook  hook )
{
    WSANETWORKEVENTS  evts;
    FH                fh = hook->fh;

    /* look if some of the events we want already happened ? */
    if (!WSAEnumNetworkEvents( fh->fh_socket, NULL, &evts )) {
        _event_socket_verify( hook, &evts );
        if (hook->ready)
            ResetEvent( hook->h );
    }

    return hook->ready != 0;
}



static void  _fh_socket_hook( FH  f, int  events, EventHook  hook )
{
    hook->prepare = _event_socket_prepare;
    hook->start   = _event_socket_start;
    hook->stop    = _event_socket_stop;
    hook->check   = _event_socket_check;
    hook->peek    = _event_socket_peek;

    _event_socket_start( hook );
}

/** SOCKETPAIR EVENT HOOKS
 **/

static void  _event_socketpair_prepare( EventHook  hook )
{
    FH          fh   = hook->fh;
    SocketPair  pair = fh->fh_pair;
    BipBuffer   rbip = (pair->a_fd == fh) ? &pair->b2a_bip : &pair->a2b_bip;
    BipBuffer   wbip = (pair->a_fd == fh) ? &pair->a2b_bip : &pair->b2a_bip;

    if (hook->wanted & FDE_READ && rbip->can_read)
        hook->ready |= FDE_READ;

    if (hook->wanted & FDE_WRITE && wbip->can_write)
        hook->ready |= FDE_WRITE;
 }

 static int  _event_socketpair_start( EventHook  hook )
 {
    FH          fh   = hook->fh;
    SocketPair  pair = fh->fh_pair;
    BipBuffer   rbip = (pair->a_fd == fh) ? &pair->b2a_bip : &pair->a2b_bip;
    BipBuffer   wbip = (pair->a_fd == fh) ? &pair->a2b_bip : &pair->b2a_bip;

    if (hook->wanted == FDE_READ)
        hook->h = rbip->evt_read;

    else if (hook->wanted == FDE_WRITE)
        hook->h = wbip->evt_write;

    else {
        D("_event_socketpair_start: can't handle FDE_READ+FDE_WRITE\n" );
        return 0;
    }
    D( "_event_socketpair_start: hook %s for %x wanted=%x\n",
       hook->fh->name, _fh_to_int(fh), hook->wanted);
    return 1;
}

static int  _event_socketpair_peek( EventHook  hook )
{
    _event_socketpair_prepare( hook );
    return hook->ready != 0;
}

static void  _fh_socketpair_hook( FH  fh, int  events, EventHook  hook )
{
    hook->prepare = _event_socketpair_prepare;
    hook->start   = _event_socketpair_start;
    hook->peek    = _event_socketpair_peek;
}


void
adb_sysdeps_init( void )
{
#define  ADB_MUTEX(x)  InitializeCriticalSection( & x );
#include "mutex_list.h"
    InitializeCriticalSection( &_win32_lock );
}

/* Windows doesn't have strtok_r.  Use the one from bionic. */

/*
 * Copyright (c) 1988 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

char *
adb_strtok_r(char *s, const char *delim, char **last)
{
	char *spanp;
	int c, sc;
	char *tok;


	if (s == NULL && (s = *last) == NULL)
		return (NULL);

	/*
	 * Skip (span) leading delimiters (s += strspn(s, delim), sort of).
	 */
cont:
	c = *s++;
	for (spanp = (char *)delim; (sc = *spanp++) != 0;) {
		if (c == sc)
			goto cont;
	}

	if (c == 0) {		/* no non-delimiter characters */
		*last = NULL;
		return (NULL);
	}
	tok = s - 1;

	/*
	 * Scan token (scan for delimiters: s += strcspn(s, delim), sort of).
	 * Note that delim must have one NUL; we stop if we see that, too.
	 */
	for (;;) {
		c = *s++;
		spanp = (char *)delim;
		do {
			if ((sc = *spanp++) == c) {
				if (c == 0)
					s = NULL;
				else
					s[-1] = 0;
				*last = s;
				return (tok);
			}
		} while (sc != 0);
	}
	/* NOTREACHED */
}
