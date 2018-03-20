/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define TRACE_TAG SYSDEPS

#include "sysdeps.h"

#include <winsock2.h> /* winsock.h *must* be included before windows.h. */
#include <windows.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <algorithm>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <cutils/sockets.h>

#include <android-base/errors.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/utf8.h>

#include "adb.h"
#include "adb_utils.h"

extern void fatal(const char *fmt, ...);

/* forward declarations */

typedef const struct FHClassRec_* FHClass;
typedef struct FHRec_* FH;
typedef struct EventHookRec_* EventHook;

typedef struct FHClassRec_ {
    void (*_fh_init)(FH);
    int (*_fh_close)(FH);
    int (*_fh_lseek)(FH, int, int);
    int (*_fh_read)(FH, void*, int);
    int (*_fh_write)(FH, const void*, int);
} FHClassRec;

static void _fh_file_init(FH);
static int _fh_file_close(FH);
static int _fh_file_lseek(FH, int, int);
static int _fh_file_read(FH, void*, int);
static int _fh_file_write(FH, const void*, int);

static const FHClassRec _fh_file_class = {
    _fh_file_init,
    _fh_file_close,
    _fh_file_lseek,
    _fh_file_read,
    _fh_file_write,
};

static void _fh_socket_init(FH);
static int _fh_socket_close(FH);
static int _fh_socket_lseek(FH, int, int);
static int _fh_socket_read(FH, void*, int);
static int _fh_socket_write(FH, const void*, int);

static const FHClassRec _fh_socket_class = {
    _fh_socket_init,
    _fh_socket_close,
    _fh_socket_lseek,
    _fh_socket_read,
    _fh_socket_write,
};

#define assert(cond)                                                                       \
    do {                                                                                   \
        if (!(cond)) fatal("assertion failed '%s' on %s:%d\n", #cond, __FILE__, __LINE__); \
    } while (0)

void handle_deleter::operator()(HANDLE h) {
    // CreateFile() is documented to return INVALID_HANDLE_FILE on error,
    // implying that NULL is a valid handle, but this is probably impossible.
    // Other APIs like CreateEvent() are documented to return NULL on error,
    // implying that INVALID_HANDLE_VALUE is a valid handle, but this is also
    // probably impossible. Thus, consider both NULL and INVALID_HANDLE_VALUE
    // as invalid handles. std::unique_ptr won't call a deleter with NULL, so we
    // only need to check for INVALID_HANDLE_VALUE.
    if (h != INVALID_HANDLE_VALUE) {
        if (!CloseHandle(h)) {
            D("CloseHandle(%p) failed: %s", h,
              android::base::SystemErrorCodeToString(GetLastError()).c_str());
        }
    }
}

/**************************************************************************/
/**************************************************************************/
/*****                                                                *****/
/*****    common file descriptor handling                             *****/
/*****                                                                *****/
/**************************************************************************/
/**************************************************************************/

typedef struct FHRec_
{
    FHClass    clazz;
    int        used;
    int        eof;
    union {
        HANDLE      handle;
        SOCKET      socket;
    } u;

    char  name[32];
} FHRec;

#define  fh_handle  u.handle
#define  fh_socket  u.socket

#define  WIN32_FH_BASE    2048
#define  WIN32_MAX_FHS    2048

static  std::mutex&  _win32_lock = *new std::mutex();
static  FHRec        _win32_fhs[ WIN32_MAX_FHS ];
static  int          _win32_fh_next;  // where to start search for free FHRec

static FH
_fh_from_int( int   fd, const char*   func )
{
    FH  f;

    fd -= WIN32_FH_BASE;

    if (fd < 0 || fd >= WIN32_MAX_FHS) {
        D( "_fh_from_int: invalid fd %d passed to %s", fd + WIN32_FH_BASE,
           func );
        errno = EBADF;
        return NULL;
    }

    f = &_win32_fhs[fd];

    if (f->used == 0) {
        D( "_fh_from_int: invalid fd %d passed to %s", fd + WIN32_FH_BASE,
           func );
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
    FH   f = NULL;

    std::lock_guard<std::mutex> lock(_win32_lock);

    for (int i = _win32_fh_next; i < WIN32_MAX_FHS; ++i) {
        if (_win32_fhs[i].clazz == NULL) {
            f = &_win32_fhs[i];
            _win32_fh_next = i + 1;
            f->clazz = clazz;
            f->used = 1;
            f->eof = 0;
            f->name[0] = '\0';
            clazz->_fh_init(f);
            return f;
        }
    }

    D("_fh_alloc: no more free file descriptors");
    errno = EMFILE;  // Too many open files
    return nullptr;
}


static int
_fh_close( FH   f )
{
    // Use lock so that closing only happens once and so that _fh_alloc can't
    // allocate a FH that we're in the middle of closing.
    std::lock_guard<std::mutex> lock(_win32_lock);

    int offset = f - _win32_fhs;
    if (_win32_fh_next > offset) {
        _win32_fh_next = offset;
    }

    if (f->used) {
        f->clazz->_fh_close( f );
        f->name[0] = '\0';
        f->eof     = 0;
        f->used    = 0;
        f->clazz   = NULL;
    }
    return 0;
}

// Deleter for unique_fh.
class fh_deleter {
 public:
  void operator()(struct FHRec_* fh) {
    // We're called from a destructor and destructors should not overwrite
    // errno because callers may do:
    //   errno = EBLAH;
    //   return -1; // calls destructor, which should not overwrite errno
    const int saved_errno = errno;
    _fh_close(fh);
    errno = saved_errno;
  }
};

// Like std::unique_ptr, but calls _fh_close() instead of operator delete().
typedef std::unique_ptr<struct FHRec_, fh_deleter> unique_fh;

/**************************************************************************/
/**************************************************************************/
/*****                                                                *****/
/*****    file-based descriptor handling                              *****/
/*****                                                                *****/
/**************************************************************************/
/**************************************************************************/

static void _fh_file_init( FH  f ) {
    f->fh_handle = INVALID_HANDLE_VALUE;
}

static int _fh_file_close( FH  f ) {
    CloseHandle( f->fh_handle );
    f->fh_handle = INVALID_HANDLE_VALUE;
    return 0;
}

static int _fh_file_read( FH  f,  void*  buf, int   len ) {
    DWORD  read_bytes;

    if ( !ReadFile( f->fh_handle, buf, (DWORD)len, &read_bytes, NULL ) ) {
        D( "adb_read: could not read %d bytes from %s", len, f->name );
        errno = EIO;
        return -1;
    } else if (read_bytes < (DWORD)len) {
        f->eof = 1;
    }
    return (int)read_bytes;
}

static int _fh_file_write( FH  f,  const void*  buf, int   len ) {
    DWORD  wrote_bytes;

    if ( !WriteFile( f->fh_handle, buf, (DWORD)len, &wrote_bytes, NULL ) ) {
        D( "adb_file_write: could not write %d bytes from %s", len, f->name );
        errno = EIO;
        return -1;
    } else if (wrote_bytes < (DWORD)len) {
        f->eof = 1;
    }
    return  (int)wrote_bytes;
}

static int _fh_file_lseek( FH  f, int  pos, int  origin ) {
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
            D("adb_open: invalid options (0x%0x)", options);
            errno = EINVAL;
            return -1;
    }

    f = _fh_alloc( &_fh_file_class );
    if ( !f ) {
        return -1;
    }

    std::wstring path_wide;
    if (!android::base::UTF8ToWide(path, &path_wide)) {
        return -1;
    }
    f->fh_handle = CreateFileW( path_wide.c_str(), desiredAccess, shareMode,
                                NULL, OPEN_EXISTING, 0, NULL );

    if ( f->fh_handle == INVALID_HANDLE_VALUE ) {
        const DWORD err = GetLastError();
        _fh_close(f);
        D( "adb_open: could not open '%s': ", path );
        switch (err) {
            case ERROR_FILE_NOT_FOUND:
                D( "file not found" );
                errno = ENOENT;
                return -1;

            case ERROR_PATH_NOT_FOUND:
                D( "path not found" );
                errno = ENOTDIR;
                return -1;

            default:
                D("unknown error: %s", android::base::SystemErrorCodeToString(err).c_str());
                errno = ENOENT;
                return -1;
        }
    }

    snprintf( f->name, sizeof(f->name), "%d(%s)", _fh_to_int(f), path );
    D( "adb_open: '%s' => fd %d", path, _fh_to_int(f) );
    return _fh_to_int(f);
}

/* ignore mode on Win32 */
int  adb_creat(const char*  path, int  mode)
{
    FH  f;

    f = _fh_alloc( &_fh_file_class );
    if ( !f ) {
        return -1;
    }

    std::wstring path_wide;
    if (!android::base::UTF8ToWide(path, &path_wide)) {
        return -1;
    }
    f->fh_handle = CreateFileW( path_wide.c_str(), GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE,
                                NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                                NULL );

    if ( f->fh_handle == INVALID_HANDLE_VALUE ) {
        const DWORD err = GetLastError();
        _fh_close(f);
        D( "adb_creat: could not open '%s': ", path );
        switch (err) {
            case ERROR_FILE_NOT_FOUND:
                D( "file not found" );
                errno = ENOENT;
                return -1;

            case ERROR_PATH_NOT_FOUND:
                D( "path not found" );
                errno = ENOTDIR;
                return -1;

            default:
                D("unknown error: %s", android::base::SystemErrorCodeToString(err).c_str());
                errno = ENOENT;
                return -1;
        }
    }
    snprintf( f->name, sizeof(f->name), "%d(%s)", _fh_to_int(f), path );
    D( "adb_creat: '%s' => fd %d", path, _fh_to_int(f) );
    return _fh_to_int(f);
}


int  adb_read(int  fd, void* buf, int len)
{
    FH     f = _fh_from_int(fd, __func__);

    if (f == NULL) {
        return -1;
    }

    return f->clazz->_fh_read( f, buf, len );
}


int  adb_write(int  fd, const void*  buf, int  len)
{
    FH     f = _fh_from_int(fd, __func__);

    if (f == NULL) {
        return -1;
    }

    return f->clazz->_fh_write(f, buf, len);
}


int  adb_lseek(int  fd, int  pos, int  where)
{
    FH     f = _fh_from_int(fd, __func__);

    if (!f) {
        return -1;
    }

    return f->clazz->_fh_lseek(f, pos, where);
}


int  adb_close(int  fd)
{
    FH   f = _fh_from_int(fd, __func__);

    if (!f) {
        return -1;
    }

    D( "adb_close: %s", f->name);
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

#undef setsockopt

static void _socket_set_errno( const DWORD err ) {
    // Because the Windows C Runtime (MSVCRT.DLL) strerror() does not support a
    // lot of POSIX and socket error codes, some of the resulting error codes
    // are mapped to strings by adb_strerror().
    switch ( err ) {
    case 0:              errno = 0; break;
    // Don't map WSAEINTR since that is only for Winsock 1.1 which we don't use.
    // case WSAEINTR:    errno = EINTR; break;
    case WSAEFAULT:      errno = EFAULT; break;
    case WSAEINVAL:      errno = EINVAL; break;
    case WSAEMFILE:      errno = EMFILE; break;
    // Mapping WSAEWOULDBLOCK to EAGAIN is absolutely critical because
    // non-blocking sockets can cause an error code of WSAEWOULDBLOCK and
    // callers check specifically for EAGAIN.
    case WSAEWOULDBLOCK: errno = EAGAIN; break;
    case WSAENOTSOCK:    errno = ENOTSOCK; break;
    case WSAENOPROTOOPT: errno = ENOPROTOOPT; break;
    case WSAEOPNOTSUPP:  errno = EOPNOTSUPP; break;
    case WSAENETDOWN:    errno = ENETDOWN; break;
    case WSAENETRESET:   errno = ENETRESET; break;
    // Map WSAECONNABORTED to EPIPE instead of ECONNABORTED because POSIX seems
    // to use EPIPE for these situations and there are some callers that look
    // for EPIPE.
    case WSAECONNABORTED: errno = EPIPE; break;
    case WSAECONNRESET:  errno = ECONNRESET; break;
    case WSAENOBUFS:     errno = ENOBUFS; break;
    case WSAENOTCONN:    errno = ENOTCONN; break;
    // Don't map WSAETIMEDOUT because we don't currently use SO_RCVTIMEO or
    // SO_SNDTIMEO which would cause WSAETIMEDOUT to be returned. Future
    // considerations: Reportedly send() can return zero on timeout, and POSIX
    // code may expect EAGAIN instead of ETIMEDOUT on timeout.
    // case WSAETIMEDOUT: errno = ETIMEDOUT; break;
    case WSAEHOSTUNREACH: errno = EHOSTUNREACH; break;
    default:
        errno = EINVAL;
        D( "_socket_set_errno: mapping Windows error code %lu to errno %d",
           err, errno );
    }
}

extern int adb_poll(adb_pollfd* fds, size_t nfds, int timeout) {
    // WSAPoll doesn't handle invalid/non-socket handles, so we need to handle them ourselves.
    int skipped = 0;
    std::vector<WSAPOLLFD> sockets;
    std::vector<adb_pollfd*> original;
    for (size_t i = 0; i < nfds; ++i) {
        FH fh = _fh_from_int(fds[i].fd, __func__);
        if (!fh || !fh->used || fh->clazz != &_fh_socket_class) {
            D("adb_poll received bad FD %d", fds[i].fd);
            fds[i].revents = POLLNVAL;
            ++skipped;
        } else {
            WSAPOLLFD wsapollfd = {
                .fd = fh->u.socket,
                .events = static_cast<short>(fds[i].events)
            };
            sockets.push_back(wsapollfd);
            original.push_back(&fds[i]);
        }
    }

    if (sockets.empty()) {
        return skipped;
    }

    int result = WSAPoll(sockets.data(), sockets.size(), timeout);
    if (result == SOCKET_ERROR) {
        _socket_set_errno(WSAGetLastError());
        return -1;
    }

    // Map the results back onto the original set.
    for (size_t i = 0; i < sockets.size(); ++i) {
        original[i]->revents = sockets[i].revents;
    }

    // WSAPoll appears to return the number of unique FDs with avaiable events, instead of how many
    // of the pollfd elements have a non-zero revents field, which is what it and poll are specified
    // to do. Ignore its result and calculate the proper return value.
    result = 0;
    for (size_t i = 0; i < nfds; ++i) {
        if (fds[i].revents != 0) {
            ++result;
        }
    }
    return result;
}

static void _fh_socket_init(FH f) {
    f->fh_socket = INVALID_SOCKET;
}

static int _fh_socket_close( FH  f ) {
    if (f->fh_socket != INVALID_SOCKET) {
        /* gently tell any peer that we're closing the socket */
        if (shutdown(f->fh_socket, SD_BOTH) == SOCKET_ERROR) {
            // If the socket is not connected, this returns an error. We want to
            // minimize logging spam, so don't log these errors for now.
#if 0
            D("socket shutdown failed: %s",
              android::base::SystemErrorCodeToString(WSAGetLastError()).c_str());
#endif
        }
        if (closesocket(f->fh_socket) == SOCKET_ERROR) {
            // Don't set errno here, since adb_close will ignore it.
            const DWORD err = WSAGetLastError();
            D("closesocket failed: %s", android::base::SystemErrorCodeToString(err).c_str());
        }
        f->fh_socket = INVALID_SOCKET;
    }
    return 0;
}

static int _fh_socket_lseek( FH  f, int pos, int origin ) {
    errno = EPIPE;
    return -1;
}

static int _fh_socket_read(FH f, void* buf, int len) {
    int  result = recv(f->fh_socket, reinterpret_cast<char*>(buf), len, 0);
    if (result == SOCKET_ERROR) {
        const DWORD err = WSAGetLastError();
        // WSAEWOULDBLOCK is normal with a non-blocking socket, so don't trace
        // that to reduce spam and confusion.
        if (err != WSAEWOULDBLOCK) {
            D("recv fd %d failed: %s", _fh_to_int(f),
              android::base::SystemErrorCodeToString(err).c_str());
        }
        _socket_set_errno(err);
        result = -1;
    }
    return  result;
}

static int _fh_socket_write(FH f, const void* buf, int len) {
    int  result = send(f->fh_socket, reinterpret_cast<const char*>(buf), len, 0);
    if (result == SOCKET_ERROR) {
        const DWORD err = WSAGetLastError();
        // WSAEWOULDBLOCK is normal with a non-blocking socket, so don't trace
        // that to reduce spam and confusion.
        if (err != WSAEWOULDBLOCK) {
            D("send fd %d failed: %s", _fh_to_int(f),
              android::base::SystemErrorCodeToString(err).c_str());
        }
        _socket_set_errno(err);
        result = -1;
    } else {
        // According to https://code.google.com/p/chromium/issues/detail?id=27870
        // Winsock Layered Service Providers may cause this.
        CHECK_LE(result, len) << "Tried to write " << len << " bytes to "
                              << f->name << ", but " << result
                              << " bytes reportedly written";
    }
    return result;
}

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
_init_winsock( void )
{
    // TODO: Multiple threads calling this may potentially cause multiple calls
    // to WSAStartup() which offers no real benefit.
    if (!_winsock_init) {
        WSADATA  wsaData;
        int      rc = WSAStartup( MAKEWORD(2,2), &wsaData);
        if (rc != 0) {
            fatal("adb: could not initialize Winsock: %s",
                  android::base::SystemErrorCodeToString(rc).c_str());
        }
        _winsock_init = 1;

        // Note that we do not call atexit() to register WSACleanup to be called
        // at normal process termination because:
        // 1) When exit() is called, there are still threads actively using
        //    Winsock because we don't cleanly shutdown all threads, so it
        //    doesn't make sense to call WSACleanup() and may cause problems
        //    with those threads.
        // 2) A deadlock can occur when exit() holds a C Runtime lock, then it
        //    calls WSACleanup() which tries to unload a DLL, which tries to
        //    grab the LoaderLock. This conflicts with the device_poll_thread
        //    which holds the LoaderLock because AdbWinApi.dll calls
        //    setupapi.dll which tries to load wintrust.dll which tries to load
        //    crypt32.dll which calls atexit() which tries to acquire the C
        //    Runtime lock that the other thread holds.
    }
}

// Map a socket type to an explicit socket protocol instead of using the socket
// protocol of 0. Explicit socket protocols are used by most apps and we should
// do the same to reduce the chance of exercising uncommon code-paths that might
// have problems or that might load different Winsock service providers that
// have problems.
static int GetSocketProtocolFromSocketType(int type) {
    switch (type) {
        case SOCK_STREAM:
            return IPPROTO_TCP;
        case SOCK_DGRAM:
            return IPPROTO_UDP;
        default:
            LOG(FATAL) << "Unknown socket type: " << type;
            return 0;
    }
}

int network_loopback_client(int port, int type, std::string* error) {
    struct sockaddr_in addr;
    SOCKET s;

    unique_fh f(_fh_alloc(&_fh_socket_class));
    if (!f) {
        *error = strerror(errno);
        return -1;
    }

    if (!_winsock_init) _init_winsock();

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    s = socket(AF_INET, type, GetSocketProtocolFromSocketType(type));
    if (s == INVALID_SOCKET) {
        const DWORD err = WSAGetLastError();
        *error = android::base::StringPrintf("cannot create socket: %s",
                                             android::base::SystemErrorCodeToString(err).c_str());
        D("%s", error->c_str());
        _socket_set_errno(err);
        return -1;
    }
    f->fh_socket = s;

    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        // Save err just in case inet_ntoa() or ntohs() changes the last error.
        const DWORD err = WSAGetLastError();
        *error = android::base::StringPrintf("cannot connect to %s:%u: %s",
                                             inet_ntoa(addr.sin_addr), ntohs(addr.sin_port),
                                             android::base::SystemErrorCodeToString(err).c_str());
        D("could not connect to %s:%d: %s", type != SOCK_STREAM ? "udp" : "tcp", port,
          error->c_str());
        _socket_set_errno(err);
        return -1;
    }

    const int fd = _fh_to_int(f.get());
    snprintf(f->name, sizeof(f->name), "%d(lo-client:%s%d)", fd, type != SOCK_STREAM ? "udp:" : "",
             port);
    D("port %d type %s => fd %d", port, type != SOCK_STREAM ? "udp" : "tcp", fd);
    f.release();
    return fd;
}

// interface_address is INADDR_LOOPBACK or INADDR_ANY.
static int _network_server(int port, int type, u_long interface_address, std::string* error) {
    struct sockaddr_in addr;
    SOCKET s;
    int n;

    unique_fh f(_fh_alloc(&_fh_socket_class));
    if (!f) {
        *error = strerror(errno);
        return -1;
    }

    if (!_winsock_init) _init_winsock();

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(interface_address);

    // TODO: Consider using dual-stack socket that can simultaneously listen on
    // IPv4 and IPv6.
    s = socket(AF_INET, type, GetSocketProtocolFromSocketType(type));
    if (s == INVALID_SOCKET) {
        const DWORD err = WSAGetLastError();
        *error = android::base::StringPrintf("cannot create socket: %s",
                                             android::base::SystemErrorCodeToString(err).c_str());
        D("%s", error->c_str());
        _socket_set_errno(err);
        return -1;
    }

    f->fh_socket = s;

    // Note: SO_REUSEADDR on Windows allows multiple processes to bind to the
    // same port, so instead use SO_EXCLUSIVEADDRUSE.
    n = 1;
    if (setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char*)&n, sizeof(n)) == SOCKET_ERROR) {
        const DWORD err = WSAGetLastError();
        *error = android::base::StringPrintf("cannot set socket option SO_EXCLUSIVEADDRUSE: %s",
                                             android::base::SystemErrorCodeToString(err).c_str());
        D("%s", error->c_str());
        _socket_set_errno(err);
        return -1;
    }

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        // Save err just in case inet_ntoa() or ntohs() changes the last error.
        const DWORD err = WSAGetLastError();
        *error = android::base::StringPrintf("cannot bind to %s:%u: %s", inet_ntoa(addr.sin_addr),
                                             ntohs(addr.sin_port),
                                             android::base::SystemErrorCodeToString(err).c_str());
        D("could not bind to %s:%d: %s", type != SOCK_STREAM ? "udp" : "tcp", port, error->c_str());
        _socket_set_errno(err);
        return -1;
    }
    if (type == SOCK_STREAM) {
        if (listen(s, SOMAXCONN) == SOCKET_ERROR) {
            const DWORD err = WSAGetLastError();
            *error = android::base::StringPrintf(
                "cannot listen on socket: %s", android::base::SystemErrorCodeToString(err).c_str());
            D("could not listen on %s:%d: %s", type != SOCK_STREAM ? "udp" : "tcp", port,
              error->c_str());
            _socket_set_errno(err);
            return -1;
        }
    }
    const int fd = _fh_to_int(f.get());
    snprintf(f->name, sizeof(f->name), "%d(%s-server:%s%d)", fd,
             interface_address == INADDR_LOOPBACK ? "lo" : "any", type != SOCK_STREAM ? "udp:" : "",
             port);
    D("port %d type %s => fd %d", port, type != SOCK_STREAM ? "udp" : "tcp", fd);
    f.release();
    return fd;
}

int network_loopback_server(int port, int type, std::string* error) {
    return _network_server(port, type, INADDR_LOOPBACK, error);
}

int network_inaddr_any_server(int port, int type, std::string* error) {
    return _network_server(port, type, INADDR_ANY, error);
}

int network_connect(const std::string& host, int port, int type, int timeout, std::string* error) {
    unique_fh f(_fh_alloc(&_fh_socket_class));
    if (!f) {
        *error = strerror(errno);
        return -1;
    }

    if (!_winsock_init) _init_winsock();

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = type;
    hints.ai_protocol = GetSocketProtocolFromSocketType(type);

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo* addrinfo_ptr = nullptr;

#if (NTDDI_VERSION >= NTDDI_WINXPSP2) || (_WIN32_WINNT >= _WIN32_WINNT_WS03)
// TODO: When the Android SDK tools increases the Windows system
// requirements >= WinXP SP2, switch to android::base::UTF8ToWide() + GetAddrInfoW().
#else
// Otherwise, keep using getaddrinfo(), or do runtime API detection
// with GetProcAddress("GetAddrInfoW").
#endif
    if (getaddrinfo(host.c_str(), port_str, &hints, &addrinfo_ptr) != 0) {
        const DWORD err = WSAGetLastError();
        *error = android::base::StringPrintf("cannot resolve host '%s' and port %s: %s",
                                             host.c_str(), port_str,
                                             android::base::SystemErrorCodeToString(err).c_str());

        D("%s", error->c_str());
        _socket_set_errno(err);
        return -1;
    }
    std::unique_ptr<struct addrinfo, decltype(&freeaddrinfo)> addrinfo(addrinfo_ptr, freeaddrinfo);
    addrinfo_ptr = nullptr;

    // TODO: Try all the addresses if there's more than one? This just uses
    // the first. Or, could call WSAConnectByName() (Windows Vista and newer)
    // which tries all addresses, takes a timeout and more.
    SOCKET s = socket(addrinfo->ai_family, addrinfo->ai_socktype, addrinfo->ai_protocol);
    if (s == INVALID_SOCKET) {
        const DWORD err = WSAGetLastError();
        *error = android::base::StringPrintf("cannot create socket: %s",
                                             android::base::SystemErrorCodeToString(err).c_str());
        D("%s", error->c_str());
        _socket_set_errno(err);
        return -1;
    }
    f->fh_socket = s;

    // TODO: Implement timeouts for Windows. Seems like the default in theory
    // (according to http://serverfault.com/a/671453) and in practice is 21 sec.
    if (connect(s, addrinfo->ai_addr, addrinfo->ai_addrlen) == SOCKET_ERROR) {
        // TODO: Use WSAAddressToString or inet_ntop on address.
        const DWORD err = WSAGetLastError();
        *error = android::base::StringPrintf("cannot connect to %s:%s: %s", host.c_str(), port_str,
                                             android::base::SystemErrorCodeToString(err).c_str());
        D("could not connect to %s:%s:%s: %s", type != SOCK_STREAM ? "udp" : "tcp", host.c_str(),
          port_str, error->c_str());
        _socket_set_errno(err);
        return -1;
    }

    const int fd = _fh_to_int(f.get());
    snprintf(f->name, sizeof(f->name), "%d(net-client:%s%d)", fd, type != SOCK_STREAM ? "udp:" : "",
             port);
    D("host '%s' port %d type %s => fd %d", host.c_str(), port, type != SOCK_STREAM ? "udp" : "tcp",
      fd);
    f.release();
    return fd;
}

int  adb_register_socket(SOCKET s) {
    FH f = _fh_alloc( &_fh_socket_class );
    f->fh_socket = s;
    return _fh_to_int(f);
}

#undef accept
int  adb_socket_accept(int  serverfd, struct sockaddr*  addr, socklen_t  *addrlen)
{
    FH   serverfh = _fh_from_int(serverfd, __func__);

    if ( !serverfh || serverfh->clazz != &_fh_socket_class ) {
        D("adb_socket_accept: invalid fd %d", serverfd);
        errno = EBADF;
        return -1;
    }

    unique_fh fh(_fh_alloc( &_fh_socket_class ));
    if (!fh) {
        PLOG(ERROR) << "adb_socket_accept: failed to allocate accepted socket "
                       "descriptor";
        return -1;
    }

    fh->fh_socket = accept( serverfh->fh_socket, addr, addrlen );
    if (fh->fh_socket == INVALID_SOCKET) {
        const DWORD err = WSAGetLastError();
        LOG(ERROR) << "adb_socket_accept: accept on fd " << serverfd <<
                      " failed: " + android::base::SystemErrorCodeToString(err);
        _socket_set_errno( err );
        return -1;
    }

    const int fd = _fh_to_int(fh.get());
    snprintf( fh->name, sizeof(fh->name), "%d(accept:%s)", fd, serverfh->name );
    D( "adb_socket_accept on fd %d returns fd %d", serverfd, fd );
    fh.release();
    return  fd;
}


int  adb_setsockopt( int  fd, int  level, int  optname, const void*  optval, socklen_t  optlen )
{
    FH   fh = _fh_from_int(fd, __func__);

    if ( !fh || fh->clazz != &_fh_socket_class ) {
        D("adb_setsockopt: invalid fd %d", fd);
        errno = EBADF;
        return -1;
    }

    // TODO: Once we can assume Windows Vista or later, if the caller is trying
    // to set SOL_SOCKET, SO_SNDBUF/SO_RCVBUF, ignore it since the OS has
    // auto-tuning.

    int result = setsockopt( fh->fh_socket, level, optname,
                             reinterpret_cast<const char*>(optval), optlen );
    if ( result == SOCKET_ERROR ) {
        const DWORD err = WSAGetLastError();
        D("adb_setsockopt: setsockopt on fd %d level %d optname %d failed: %s\n",
          fd, level, optname, android::base::SystemErrorCodeToString(err).c_str());
        _socket_set_errno( err );
        result = -1;
    }
    return result;
}

int adb_getsockname(int fd, struct sockaddr* sockaddr, socklen_t* optlen) {
    FH fh = _fh_from_int(fd, __func__);

    if (!fh || fh->clazz != &_fh_socket_class) {
        D("adb_getsockname: invalid fd %d", fd);
        errno = EBADF;
        return -1;
    }

    int result = getsockname(fh->fh_socket, sockaddr, optlen);
    if (result == SOCKET_ERROR) {
        const DWORD err = WSAGetLastError();
        D("adb_getsockname: setsockopt on fd %d failed: %s\n", fd,
          android::base::SystemErrorCodeToString(err).c_str());
        _socket_set_errno(err);
        result = -1;
    }
    return result;
}

int adb_socket_get_local_port(int fd) {
    sockaddr_storage addr_storage;
    socklen_t addr_len = sizeof(addr_storage);

    if (adb_getsockname(fd, reinterpret_cast<sockaddr*>(&addr_storage), &addr_len) < 0) {
        D("adb_socket_get_local_port: adb_getsockname failed: %s", strerror(errno));
        return -1;
    }

    if (!(addr_storage.ss_family == AF_INET || addr_storage.ss_family == AF_INET6)) {
        D("adb_socket_get_local_port: unknown address family received: %d", addr_storage.ss_family);
        errno = ECONNABORTED;
        return -1;
    }

    return ntohs(reinterpret_cast<sockaddr_in*>(&addr_storage)->sin_port);
}

int  adb_shutdown(int  fd)
{
    FH   f = _fh_from_int(fd, __func__);

    if (!f || f->clazz != &_fh_socket_class) {
        D("adb_shutdown: invalid fd %d", fd);
        errno = EBADF;
        return -1;
    }

    D( "adb_shutdown: %s", f->name);
    if (shutdown(f->fh_socket, SD_BOTH) == SOCKET_ERROR) {
        const DWORD err = WSAGetLastError();
        D("socket shutdown fd %d failed: %s", fd,
          android::base::SystemErrorCodeToString(err).c_str());
        _socket_set_errno(err);
        return -1;
    }
    return 0;
}

// Emulate socketpair(2) by binding and connecting to a socket.
int adb_socketpair(int sv[2]) {
    int server = -1;
    int client = -1;
    int accepted = -1;
    int local_port = -1;
    std::string error;

    server = network_loopback_server(0, SOCK_STREAM, &error);
    if (server < 0) {
        D("adb_socketpair: failed to create server: %s", error.c_str());
        goto fail;
    }

    local_port = adb_socket_get_local_port(server);
    if (local_port < 0) {
        D("adb_socketpair: failed to get server port number: %s", error.c_str());
        goto fail;
    }
    D("adb_socketpair: bound on port %d", local_port);

    client = network_loopback_client(local_port, SOCK_STREAM, &error);
    if (client < 0) {
        D("adb_socketpair: failed to connect client: %s", error.c_str());
        goto fail;
    }

    accepted = adb_socket_accept(server, nullptr, nullptr);
    if (accepted < 0) {
        D("adb_socketpair: failed to accept: %s", strerror(errno));
        goto fail;
    }
    adb_close(server);
    sv[0] = client;
    sv[1] = accepted;
    return 0;

fail:
    if (server >= 0) {
        adb_close(server);
    }
    if (client >= 0) {
        adb_close(client);
    }
    if (accepted >= 0) {
        adb_close(accepted);
    }
    return -1;
}

bool set_file_block_mode(int fd, bool block) {
    FH fh = _fh_from_int(fd, __func__);

    if (!fh || !fh->used) {
        errno = EBADF;
        D("Setting nonblocking on bad file descriptor %d", fd);
        return false;
    }

    if (fh->clazz == &_fh_socket_class) {
        u_long x = !block;
        if (ioctlsocket(fh->u.socket, FIONBIO, &x) != 0) {
            int error = WSAGetLastError();
            _socket_set_errno(error);
            D("Setting %d nonblocking failed (%d)", fd, error);
            return false;
        }
        return true;
    } else {
        errno = ENOTSOCK;
        D("Setting nonblocking on non-socket %d", fd);
        return false;
    }
}

bool set_tcp_keepalive(int fd, int interval_sec) {
    FH fh = _fh_from_int(fd, __func__);

    if (!fh || fh->clazz != &_fh_socket_class) {
        D("set_tcp_keepalive(%d) failed: invalid fd", fd);
        errno = EBADF;
        return false;
    }

    tcp_keepalive keepalive;
    keepalive.onoff = (interval_sec > 0);
    keepalive.keepalivetime = interval_sec * 1000;
    keepalive.keepaliveinterval = interval_sec * 1000;

    DWORD bytes_returned = 0;
    if (WSAIoctl(fh->fh_socket, SIO_KEEPALIVE_VALS, &keepalive, sizeof(keepalive), nullptr, 0,
                 &bytes_returned, nullptr, nullptr) != 0) {
        const DWORD err = WSAGetLastError();
        D("set_tcp_keepalive(%d) failed: %s", fd,
          android::base::SystemErrorCodeToString(err).c_str());
        _socket_set_errno(err);
        return false;
    }

    return true;
}

/**************************************************************************/
/**************************************************************************/
/*****                                                                *****/
/*****      Console Window Terminal Emulation                         *****/
/*****                                                                *****/
/**************************************************************************/
/**************************************************************************/

// This reads input from a Win32 console window and translates it into Unix
// terminal-style sequences. This emulates mostly Gnome Terminal (in Normal
// mode, not Application mode), which itself emulates xterm. Gnome Terminal
// is emulated instead of xterm because it is probably more popular than xterm:
// Ubuntu's default Ctrl-Alt-T shortcut opens Gnome Terminal, Gnome Terminal
// supports modern fonts, etc. It seems best to emulate the terminal that most
// Android developers use because they'll fix apps (the shell, etc.) to keep
// working with that terminal's emulation.
//
// The point of this emulation is not to be perfect or to solve all issues with
// console windows on Windows, but to be better than the original code which
// just called read() (which called ReadFile(), which called ReadConsoleA())
// which did not support Ctrl-C, tab completion, shell input line editing
// keys, server echo, and more.
//
// This implementation reconfigures the console with SetConsoleMode(), then
// calls ReadConsoleInput() to get raw input which it remaps to Unix
// terminal-style sequences which is returned via unix_read() which is used
// by the 'adb shell' command.
//
// Code organization:
//
// * _get_console_handle() and unix_isatty() provide console information.
// * stdin_raw_init() and stdin_raw_restore() reconfigure the console.
// * unix_read() detects console windows (as opposed to pipes, files, etc.).
// * _console_read() is the main code of the emulation.

// Returns a console HANDLE if |fd| is a console, otherwise returns nullptr.
// If a valid HANDLE is returned and |mode| is not null, |mode| is also filled
// with the console mode. Requires GENERIC_READ access to the underlying HANDLE.
static HANDLE _get_console_handle(int fd, DWORD* mode=nullptr) {
    // First check isatty(); this is very fast and eliminates most non-console
    // FDs, but returns 1 for both consoles and character devices like NUL.
#pragma push_macro("isatty")
#undef isatty
    if (!isatty(fd)) {
        return nullptr;
    }
#pragma pop_macro("isatty")

    // To differentiate between character devices and consoles we need to get
    // the underlying HANDLE and use GetConsoleMode(), which is what requires
    // GENERIC_READ permissions.
    const intptr_t intptr_handle = _get_osfhandle(fd);
    if (intptr_handle == -1) {
        return nullptr;
    }
    const HANDLE handle = reinterpret_cast<const HANDLE>(intptr_handle);
    DWORD temp_mode = 0;
    if (!GetConsoleMode(handle, mode ? mode : &temp_mode)) {
        return nullptr;
    }

    return handle;
}

// Returns a console handle if |stream| is a console, otherwise returns nullptr.
static HANDLE _get_console_handle(FILE* const stream) {
    // Save and restore errno to make it easier for callers to prevent from overwriting errno.
    android::base::ErrnoRestorer er;
    const int fd = fileno(stream);
    if (fd < 0) {
        return nullptr;
    }
    return _get_console_handle(fd);
}

int unix_isatty(int fd) {
    return _get_console_handle(fd) ? 1 : 0;
}

// Get the next KEY_EVENT_RECORD that should be processed.
static bool _get_key_event_record(const HANDLE console, INPUT_RECORD* const input_record) {
    for (;;) {
        DWORD read_count = 0;
        memset(input_record, 0, sizeof(*input_record));
        if (!ReadConsoleInputA(console, input_record, 1, &read_count)) {
            D("_get_key_event_record: ReadConsoleInputA() failed: %s\n",
              android::base::SystemErrorCodeToString(GetLastError()).c_str());
            errno = EIO;
            return false;
        }

        if (read_count == 0) {   // should be impossible
            fatal("ReadConsoleInputA returned 0");
        }

        if (read_count != 1) {   // should be impossible
            fatal("ReadConsoleInputA did not return one input record");
        }

        // If the console window is resized, emulate SIGWINCH by breaking out
        // of read() with errno == EINTR. Note that there is no event on
        // vertical resize because we don't give the console our own custom
        // screen buffer (with CreateConsoleScreenBuffer() +
        // SetConsoleActiveScreenBuffer()). Instead, we use the default which
        // supports scrollback, but doesn't seem to raise an event for vertical
        // window resize.
        if (input_record->EventType == WINDOW_BUFFER_SIZE_EVENT) {
            errno = EINTR;
            return false;
        }

        if ((input_record->EventType == KEY_EVENT) &&
            (input_record->Event.KeyEvent.bKeyDown)) {
            if (input_record->Event.KeyEvent.wRepeatCount == 0) {
                fatal("ReadConsoleInputA returned a key event with zero repeat"
                      " count");
            }

            // Got an interesting INPUT_RECORD, so return
            return true;
        }
    }
}

static __inline__ bool _is_shift_pressed(const DWORD control_key_state) {
    return (control_key_state & SHIFT_PRESSED) != 0;
}

static __inline__ bool _is_ctrl_pressed(const DWORD control_key_state) {
    return (control_key_state & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED)) != 0;
}

static __inline__ bool _is_alt_pressed(const DWORD control_key_state) {
    return (control_key_state & (LEFT_ALT_PRESSED | RIGHT_ALT_PRESSED)) != 0;
}

static __inline__ bool _is_numlock_on(const DWORD control_key_state) {
    return (control_key_state & NUMLOCK_ON) != 0;
}

static __inline__ bool _is_capslock_on(const DWORD control_key_state) {
    return (control_key_state & CAPSLOCK_ON) != 0;
}

static __inline__ bool _is_enhanced_key(const DWORD control_key_state) {
    return (control_key_state & ENHANCED_KEY) != 0;
}

// Constants from MSDN for ToAscii().
static const BYTE TOASCII_KEY_OFF = 0x00;
static const BYTE TOASCII_KEY_DOWN = 0x80;
static const BYTE TOASCII_KEY_TOGGLED_ON = 0x01;   // for CapsLock

// Given a key event, ignore a modifier key and return the character that was
// entered without the modifier. Writes to *ch and returns the number of bytes
// written.
static size_t _get_char_ignoring_modifier(char* const ch,
    const KEY_EVENT_RECORD* const key_event, const DWORD control_key_state,
    const WORD modifier) {
    // If there is no character from Windows, try ignoring the specified
    // modifier and look for a character. Note that if AltGr is being used,
    // there will be a character from Windows.
    if (key_event->uChar.AsciiChar == '\0') {
        // Note that we read the control key state from the passed in argument
        // instead of from key_event since the argument has been normalized.
        if (((modifier == VK_SHIFT)   &&
            _is_shift_pressed(control_key_state)) ||
            ((modifier == VK_CONTROL) &&
            _is_ctrl_pressed(control_key_state)) ||
            ((modifier == VK_MENU)    && _is_alt_pressed(control_key_state))) {

            BYTE key_state[256]   = {0};
            key_state[VK_SHIFT]   = _is_shift_pressed(control_key_state) ?
                TOASCII_KEY_DOWN : TOASCII_KEY_OFF;
            key_state[VK_CONTROL] = _is_ctrl_pressed(control_key_state)  ?
                TOASCII_KEY_DOWN : TOASCII_KEY_OFF;
            key_state[VK_MENU]    = _is_alt_pressed(control_key_state)   ?
                TOASCII_KEY_DOWN : TOASCII_KEY_OFF;
            key_state[VK_CAPITAL] = _is_capslock_on(control_key_state)   ?
                TOASCII_KEY_TOGGLED_ON : TOASCII_KEY_OFF;

            // cause this modifier to be ignored
            key_state[modifier]   = TOASCII_KEY_OFF;

            WORD translated = 0;
            if (ToAscii(key_event->wVirtualKeyCode,
                key_event->wVirtualScanCode, key_state, &translated, 0) == 1) {
                // Ignoring the modifier, we found a character.
                *ch = (CHAR)translated;
                return 1;
            }
        }
    }

    // Just use whatever Windows told us originally.
    *ch = key_event->uChar.AsciiChar;

    // If the character from Windows is NULL, return a size of zero.
    return (*ch == '\0') ? 0 : 1;
}

// If a Ctrl key is pressed, lookup the character, ignoring the Ctrl key,
// but taking into account the shift key. This is because for a sequence like
// Ctrl-Alt-0, we want to find the character '0' and for Ctrl-Alt-Shift-0,
// we want to find the character ')'.
//
// Note that Windows doesn't seem to pass bKeyDown for Ctrl-Shift-NoAlt-0
// because it is the default key-sequence to switch the input language.
// This is configurable in the Region and Language control panel.
static __inline__ size_t _get_non_control_char(char* const ch,
    const KEY_EVENT_RECORD* const key_event, const DWORD control_key_state) {
    return _get_char_ignoring_modifier(ch, key_event, control_key_state,
        VK_CONTROL);
}

// Get without Alt.
static __inline__ size_t _get_non_alt_char(char* const ch,
    const KEY_EVENT_RECORD* const key_event, const DWORD control_key_state) {
    return _get_char_ignoring_modifier(ch, key_event, control_key_state,
        VK_MENU);
}

// Ignore the control key, find the character from Windows, and apply any
// Control key mappings (for example, Ctrl-2 is a NULL character). Writes to
// *pch and returns number of bytes written.
static size_t _get_control_character(char* const pch,
    const KEY_EVENT_RECORD* const key_event, const DWORD control_key_state) {
    const size_t len = _get_non_control_char(pch, key_event,
        control_key_state);

    if ((len == 1) && _is_ctrl_pressed(control_key_state)) {
        char ch = *pch;
        switch (ch) {
        case '2':
        case '@':
        case '`':
            ch = '\0';
            break;
        case '3':
        case '[':
        case '{':
            ch = '\x1b';
            break;
        case '4':
        case '\\':
        case '|':
            ch = '\x1c';
            break;
        case '5':
        case ']':
        case '}':
            ch = '\x1d';
            break;
        case '6':
        case '^':
        case '~':
            ch = '\x1e';
            break;
        case '7':
        case '-':
        case '_':
            ch = '\x1f';
            break;
        case '8':
            ch = '\x7f';
            break;
        case '/':
            if (!_is_alt_pressed(control_key_state)) {
                ch = '\x1f';
            }
            break;
        case '?':
            if (!_is_alt_pressed(control_key_state)) {
                ch = '\x7f';
            }
            break;
        }
        *pch = ch;
    }

    return len;
}

static DWORD _normalize_altgr_control_key_state(
    const KEY_EVENT_RECORD* const key_event) {
    DWORD control_key_state = key_event->dwControlKeyState;

    // If we're in an AltGr situation where the AltGr key is down (depending on
    // the keyboard layout, that might be the physical right alt key which
    // produces a control_key_state where Right-Alt and Left-Ctrl are down) or
    // AltGr-equivalent keys are down (any Ctrl key + any Alt key), and we have
    // a character (which indicates that there was an AltGr mapping), then act
    // as if alt and control are not really down for the purposes of modifiers.
    // This makes it so that if the user with, say, a German keyboard layout
    // presses AltGr-] (which we see as Right-Alt + Left-Ctrl + key), we just
    // output the key and we don't see the Alt and Ctrl keys.
    if (_is_ctrl_pressed(control_key_state) &&
        _is_alt_pressed(control_key_state)
        && (key_event->uChar.AsciiChar != '\0')) {
        // Try to remove as few bits as possible to improve our chances of
        // detecting combinations like Left-Alt + AltGr, Right-Ctrl + AltGr, or
        // Left-Alt + Right-Ctrl + AltGr.
        if ((control_key_state & RIGHT_ALT_PRESSED) != 0) {
            // Remove Right-Alt.
            control_key_state &= ~RIGHT_ALT_PRESSED;
            // If uChar is set, a Ctrl key is pressed, and Right-Alt is
            // pressed, Left-Ctrl is almost always set, except if the user
            // presses Right-Ctrl, then AltGr (in that specific order) for
            // whatever reason. At any rate, make sure the bit is not set.
            control_key_state &= ~LEFT_CTRL_PRESSED;
        } else if ((control_key_state & LEFT_ALT_PRESSED) != 0) {
            // Remove Left-Alt.
            control_key_state &= ~LEFT_ALT_PRESSED;
            // Whichever Ctrl key is down, remove it from the state. We only
            // remove one key, to improve our chances of detecting the
            // corner-case of Left-Ctrl + Left-Alt + Right-Ctrl.
            if ((control_key_state & LEFT_CTRL_PRESSED) != 0) {
                // Remove Left-Ctrl.
                control_key_state &= ~LEFT_CTRL_PRESSED;
            } else if ((control_key_state & RIGHT_CTRL_PRESSED) != 0) {
                // Remove Right-Ctrl.
                control_key_state &= ~RIGHT_CTRL_PRESSED;
            }
        }

        // Note that this logic isn't 100% perfect because Windows doesn't
        // allow us to detect all combinations because a physical AltGr key
        // press shows up as two bits, plus some combinations are ambiguous
        // about what is actually physically pressed.
    }

    return control_key_state;
}

// If NumLock is on and Shift is pressed, SHIFT_PRESSED is not set in
// dwControlKeyState for the following keypad keys: period, 0-9. If we detect
// this scenario, set the SHIFT_PRESSED bit so we can add modifiers
// appropriately.
static DWORD _normalize_keypad_control_key_state(const WORD vk,
    const DWORD control_key_state) {
    if (!_is_numlock_on(control_key_state)) {
        return control_key_state;
    }
    if (!_is_enhanced_key(control_key_state)) {
        switch (vk) {
            case VK_INSERT: // 0
            case VK_DELETE: // .
            case VK_END:    // 1
            case VK_DOWN:   // 2
            case VK_NEXT:   // 3
            case VK_LEFT:   // 4
            case VK_CLEAR:  // 5
            case VK_RIGHT:  // 6
            case VK_HOME:   // 7
            case VK_UP:     // 8
            case VK_PRIOR:  // 9
                return control_key_state | SHIFT_PRESSED;
        }
    }

    return control_key_state;
}

static const char* _get_keypad_sequence(const DWORD control_key_state,
    const char* const normal, const char* const shifted) {
    if (_is_shift_pressed(control_key_state)) {
        // Shift is pressed and NumLock is off
        return shifted;
    } else {
        // Shift is not pressed and NumLock is off, or,
        // Shift is pressed and NumLock is on, in which case we want the
        // NumLock and Shift to neutralize each other, thus, we want the normal
        // sequence.
        return normal;
    }
    // If Shift is not pressed and NumLock is on, a different virtual key code
    // is returned by Windows, which can be taken care of by a different case
    // statement in _console_read().
}

// Write sequence to buf and return the number of bytes written.
static size_t _get_modifier_sequence(char* const buf, const WORD vk,
    DWORD control_key_state, const char* const normal) {
    // Copy the base sequence into buf.
    const size_t len = strlen(normal);
    memcpy(buf, normal, len);

    int code = 0;

    control_key_state = _normalize_keypad_control_key_state(vk,
        control_key_state);

    if (_is_shift_pressed(control_key_state)) {
        code |= 0x1;
    }
    if (_is_alt_pressed(control_key_state)) {   // any alt key pressed
        code |= 0x2;
    }
    if (_is_ctrl_pressed(control_key_state)) {  // any control key pressed
        code |= 0x4;
    }
    // If some modifier was held down, then we need to insert the modifier code
    if (code != 0) {
        if (len == 0) {
            // Should be impossible because caller should pass a string of
            // non-zero length.
            return 0;
        }
        size_t index = len - 1;
        const char lastChar = buf[index];
        if (lastChar != '~') {
            buf[index++] = '1';
        }
        buf[index++] = ';';         // modifier separator
        // 2 = shift, 3 = alt, 4 = shift & alt, 5 = control,
        // 6 = shift & control, 7 = alt & control, 8 = shift & alt & control
        buf[index++] = '1' + code;
        buf[index++] = lastChar;    // move ~ (or other last char) to the end
        return index;
    }
    return len;
}

// Write sequence to buf and return the number of bytes written.
static size_t _get_modifier_keypad_sequence(char* const buf, const WORD vk,
    const DWORD control_key_state, const char* const normal,
    const char shifted) {
    if (_is_shift_pressed(control_key_state)) {
        // Shift is pressed and NumLock is off
        if (shifted != '\0') {
            buf[0] = shifted;
            return sizeof(buf[0]);
        } else {
            return 0;
        }
    } else {
        // Shift is not pressed and NumLock is off, or,
        // Shift is pressed and NumLock is on, in which case we want the
        // NumLock and Shift to neutralize each other, thus, we want the normal
        // sequence.
        return _get_modifier_sequence(buf, vk, control_key_state, normal);
    }
    // If Shift is not pressed and NumLock is on, a different virtual key code
    // is returned by Windows, which can be taken care of by a different case
    // statement in _console_read().
}

// The decimal key on the keypad produces a '.' for U.S. English and a ',' for
// Standard German. Figure this out at runtime so we know what to output for
// Shift-VK_DELETE.
static char _get_decimal_char() {
    return (char)MapVirtualKeyA(VK_DECIMAL, MAPVK_VK_TO_CHAR);
}

// Prefix the len bytes in buf with the escape character, and then return the
// new buffer length.
size_t _escape_prefix(char* const buf, const size_t len) {
    // If nothing to prefix, don't do anything. We might be called with
    // len == 0, if alt was held down with a dead key which produced nothing.
    if (len == 0) {
        return 0;
    }

    memmove(&buf[1], buf, len);
    buf[0] = '\x1b';
    return len + 1;
}

// Internal buffer to satisfy future _console_read() calls.
static auto& g_console_input_buffer = *new std::vector<char>();

// Writes to buffer buf (of length len), returning number of bytes written or -1 on error. Never
// returns zero on console closure because Win32 consoles are never 'closed' (as far as I can tell).
static int _console_read(const HANDLE console, void* buf, size_t len) {
    for (;;) {
        // Read of zero bytes should not block waiting for something from the console.
        if (len == 0) {
            return 0;
        }

        // Flush as much as possible from input buffer.
        if (!g_console_input_buffer.empty()) {
            const int bytes_read = std::min(len, g_console_input_buffer.size());
            memcpy(buf, g_console_input_buffer.data(), bytes_read);
            const auto begin = g_console_input_buffer.begin();
            g_console_input_buffer.erase(begin, begin + bytes_read);
            return bytes_read;
        }

        // Read from the actual console. This may block until input.
        INPUT_RECORD input_record;
        if (!_get_key_event_record(console, &input_record)) {
            return -1;
        }

        KEY_EVENT_RECORD* const key_event = &input_record.Event.KeyEvent;
        const WORD vk = key_event->wVirtualKeyCode;
        const CHAR ch = key_event->uChar.AsciiChar;
        const DWORD control_key_state = _normalize_altgr_control_key_state(
            key_event);

        // The following emulation code should write the output sequence to
        // either seqstr or to seqbuf and seqbuflen.
        const char* seqstr = NULL;  // NULL terminated C-string
        // Enough space for max sequence string below, plus modifiers and/or
        // escape prefix.
        char seqbuf[16];
        size_t seqbuflen = 0;       // Space used in seqbuf.

#define MATCH(vk, normal) \
            case (vk): \
            { \
                seqstr = (normal); \
            } \
            break;

        // Modifier keys should affect the output sequence.
#define MATCH_MODIFIER(vk, normal) \
            case (vk): \
            { \
                seqbuflen = _get_modifier_sequence(seqbuf, (vk), \
                    control_key_state, (normal)); \
            } \
            break;

        // The shift key should affect the output sequence.
#define MATCH_KEYPAD(vk, normal, shifted) \
            case (vk): \
            { \
                seqstr = _get_keypad_sequence(control_key_state, (normal), \
                    (shifted)); \
            } \
            break;

        // The shift key and other modifier keys should affect the output
        // sequence.
#define MATCH_MODIFIER_KEYPAD(vk, normal, shifted) \
            case (vk): \
            { \
                seqbuflen = _get_modifier_keypad_sequence(seqbuf, (vk), \
                    control_key_state, (normal), (shifted)); \
            } \
            break;

#define ESC "\x1b"
#define CSI ESC "["
#define SS3 ESC "O"

        // Only support normal mode, not application mode.

        // Enhanced keys:
        // * 6-pack: insert, delete, home, end, page up, page down
        // * cursor keys: up, down, right, left
        // * keypad: divide, enter
        // * Undocumented: VK_PAUSE (Ctrl-NumLock), VK_SNAPSHOT,
        //   VK_CANCEL (Ctrl-Pause/Break), VK_NUMLOCK
        if (_is_enhanced_key(control_key_state)) {
            switch (vk) {
                case VK_RETURN: // Enter key on keypad
                    if (_is_ctrl_pressed(control_key_state)) {
                        seqstr = "\n";
                    } else {
                        seqstr = "\r";
                    }
                    break;

                MATCH_MODIFIER(VK_PRIOR, CSI "5~"); // Page Up
                MATCH_MODIFIER(VK_NEXT,  CSI "6~"); // Page Down

                // gnome-terminal currently sends SS3 "F" and SS3 "H", but that
                // will be fixed soon to match xterm which sends CSI "F" and
                // CSI "H". https://bugzilla.redhat.com/show_bug.cgi?id=1119764
                MATCH(VK_END,  CSI "F");
                MATCH(VK_HOME, CSI "H");

                MATCH_MODIFIER(VK_LEFT,  CSI "D");
                MATCH_MODIFIER(VK_UP,    CSI "A");
                MATCH_MODIFIER(VK_RIGHT, CSI "C");
                MATCH_MODIFIER(VK_DOWN,  CSI "B");

                MATCH_MODIFIER(VK_INSERT, CSI "2~");
                MATCH_MODIFIER(VK_DELETE, CSI "3~");

                MATCH(VK_DIVIDE, "/");
            }
        } else {    // Non-enhanced keys:
            switch (vk) {
                case VK_BACK:   // backspace
                    if (_is_alt_pressed(control_key_state)) {
                        seqstr = ESC "\x7f";
                    } else {
                        seqstr = "\x7f";
                    }
                    break;

                case VK_TAB:
                    if (_is_shift_pressed(control_key_state)) {
                        seqstr = CSI "Z";
                    } else {
                        seqstr = "\t";
                    }
                    break;

                // Number 5 key in keypad when NumLock is off, or if NumLock is
                // on and Shift is down.
                MATCH_KEYPAD(VK_CLEAR, CSI "E", "5");

                case VK_RETURN:     // Enter key on main keyboard
                    if (_is_alt_pressed(control_key_state)) {
                        seqstr = ESC "\n";
                    } else if (_is_ctrl_pressed(control_key_state)) {
                        seqstr = "\n";
                    } else {
                        seqstr = "\r";
                    }
                    break;

                // VK_ESCAPE: Don't do any special handling. The OS uses many
                // of the sequences with Escape and many of the remaining
                // sequences don't produce bKeyDown messages, only !bKeyDown
                // for whatever reason.

                case VK_SPACE:
                    if (_is_alt_pressed(control_key_state)) {
                        seqstr = ESC " ";
                    } else if (_is_ctrl_pressed(control_key_state)) {
                        seqbuf[0] = '\0';   // NULL char
                        seqbuflen = 1;
                    } else {
                        seqstr = " ";
                    }
                    break;

                MATCH_MODIFIER_KEYPAD(VK_PRIOR, CSI "5~", '9'); // Page Up
                MATCH_MODIFIER_KEYPAD(VK_NEXT,  CSI "6~", '3'); // Page Down

                MATCH_KEYPAD(VK_END,  CSI "4~", "1");
                MATCH_KEYPAD(VK_HOME, CSI "1~", "7");

                MATCH_MODIFIER_KEYPAD(VK_LEFT,  CSI "D", '4');
                MATCH_MODIFIER_KEYPAD(VK_UP,    CSI "A", '8');
                MATCH_MODIFIER_KEYPAD(VK_RIGHT, CSI "C", '6');
                MATCH_MODIFIER_KEYPAD(VK_DOWN,  CSI "B", '2');

                MATCH_MODIFIER_KEYPAD(VK_INSERT, CSI "2~", '0');
                MATCH_MODIFIER_KEYPAD(VK_DELETE, CSI "3~",
                    _get_decimal_char());

                case 0x30:          // 0
                case 0x31:          // 1
                case 0x39:          // 9
                case VK_OEM_1:      // ;:
                case VK_OEM_PLUS:   // =+
                case VK_OEM_COMMA:  // ,<
                case VK_OEM_PERIOD: // .>
                case VK_OEM_7:      // '"
                case VK_OEM_102:    // depends on keyboard, could be <> or \|
                case VK_OEM_2:      // /?
                case VK_OEM_3:      // `~
                case VK_OEM_4:      // [{
                case VK_OEM_5:      // \|
                case VK_OEM_6:      // ]}
                {
                    seqbuflen = _get_control_character(seqbuf, key_event,
                        control_key_state);

                    if (_is_alt_pressed(control_key_state)) {
                        seqbuflen = _escape_prefix(seqbuf, seqbuflen);
                    }
                }
                break;

                case 0x32:          // 2
                case 0x33:          // 3
                case 0x34:          // 4
                case 0x35:          // 5
                case 0x36:          // 6
                case 0x37:          // 7
                case 0x38:          // 8
                case VK_OEM_MINUS:  // -_
                {
                    seqbuflen = _get_control_character(seqbuf, key_event,
                        control_key_state);

                    // If Alt is pressed and it isn't Ctrl-Alt-ShiftUp, then
                    // prefix with escape.
                    if (_is_alt_pressed(control_key_state) &&
                        !(_is_ctrl_pressed(control_key_state) &&
                        !_is_shift_pressed(control_key_state))) {
                        seqbuflen = _escape_prefix(seqbuf, seqbuflen);
                    }
                }
                break;

                case 0x41:  // a
                case 0x42:  // b
                case 0x43:  // c
                case 0x44:  // d
                case 0x45:  // e
                case 0x46:  // f
                case 0x47:  // g
                case 0x48:  // h
                case 0x49:  // i
                case 0x4a:  // j
                case 0x4b:  // k
                case 0x4c:  // l
                case 0x4d:  // m
                case 0x4e:  // n
                case 0x4f:  // o
                case 0x50:  // p
                case 0x51:  // q
                case 0x52:  // r
                case 0x53:  // s
                case 0x54:  // t
                case 0x55:  // u
                case 0x56:  // v
                case 0x57:  // w
                case 0x58:  // x
                case 0x59:  // y
                case 0x5a:  // z
                {
                    seqbuflen = _get_non_alt_char(seqbuf, key_event,
                        control_key_state);

                    // If Alt is pressed, then prefix with escape.
                    if (_is_alt_pressed(control_key_state)) {
                        seqbuflen = _escape_prefix(seqbuf, seqbuflen);
                    }
                }
                break;

                // These virtual key codes are generated by the keys on the
                // keypad *when NumLock is on* and *Shift is up*.
                MATCH(VK_NUMPAD0, "0");
                MATCH(VK_NUMPAD1, "1");
                MATCH(VK_NUMPAD2, "2");
                MATCH(VK_NUMPAD3, "3");
                MATCH(VK_NUMPAD4, "4");
                MATCH(VK_NUMPAD5, "5");
                MATCH(VK_NUMPAD6, "6");
                MATCH(VK_NUMPAD7, "7");
                MATCH(VK_NUMPAD8, "8");
                MATCH(VK_NUMPAD9, "9");

                MATCH(VK_MULTIPLY, "*");
                MATCH(VK_ADD,      "+");
                MATCH(VK_SUBTRACT, "-");
                // VK_DECIMAL is generated by the . key on the keypad *when
                // NumLock is on* and *Shift is up* and the sequence is not
                // Ctrl-Alt-NoShift-. (which causes Ctrl-Alt-Del and the
                // Windows Security screen to come up).
                case VK_DECIMAL:
                    // U.S. English uses '.', Germany German uses ','.
                    seqbuflen = _get_non_control_char(seqbuf, key_event,
                        control_key_state);
                    break;

                MATCH_MODIFIER(VK_F1,  SS3 "P");
                MATCH_MODIFIER(VK_F2,  SS3 "Q");
                MATCH_MODIFIER(VK_F3,  SS3 "R");
                MATCH_MODIFIER(VK_F4,  SS3 "S");
                MATCH_MODIFIER(VK_F5,  CSI "15~");
                MATCH_MODIFIER(VK_F6,  CSI "17~");
                MATCH_MODIFIER(VK_F7,  CSI "18~");
                MATCH_MODIFIER(VK_F8,  CSI "19~");
                MATCH_MODIFIER(VK_F9,  CSI "20~");
                MATCH_MODIFIER(VK_F10, CSI "21~");
                MATCH_MODIFIER(VK_F11, CSI "23~");
                MATCH_MODIFIER(VK_F12, CSI "24~");

                MATCH_MODIFIER(VK_F13, CSI "25~");
                MATCH_MODIFIER(VK_F14, CSI "26~");
                MATCH_MODIFIER(VK_F15, CSI "28~");
                MATCH_MODIFIER(VK_F16, CSI "29~");
                MATCH_MODIFIER(VK_F17, CSI "31~");
                MATCH_MODIFIER(VK_F18, CSI "32~");
                MATCH_MODIFIER(VK_F19, CSI "33~");
                MATCH_MODIFIER(VK_F20, CSI "34~");

                // MATCH_MODIFIER(VK_F21, ???);
                // MATCH_MODIFIER(VK_F22, ???);
                // MATCH_MODIFIER(VK_F23, ???);
                // MATCH_MODIFIER(VK_F24, ???);
            }
        }

#undef MATCH
#undef MATCH_MODIFIER
#undef MATCH_KEYPAD
#undef MATCH_MODIFIER_KEYPAD
#undef ESC
#undef CSI
#undef SS3

        const char* out;
        size_t outlen;

        // Check for output in any of:
        // * seqstr is set (and strlen can be used to determine the length).
        // * seqbuf and seqbuflen are set
        // Fallback to ch from Windows.
        if (seqstr != NULL) {
            out = seqstr;
            outlen = strlen(seqstr);
        } else if (seqbuflen > 0) {
            out = seqbuf;
            outlen = seqbuflen;
        } else if (ch != '\0') {
            // Use whatever Windows told us it is.
            seqbuf[0] = ch;
            seqbuflen = 1;
            out = seqbuf;
            outlen = seqbuflen;
        } else {
            // No special handling for the virtual key code and Windows isn't
            // telling us a character code, then we don't know how to translate
            // the key press.
            //
            // Consume the input and 'continue' to cause us to get a new key
            // event.
            D("_console_read: unknown virtual key code: %d, enhanced: %s",
                vk, _is_enhanced_key(control_key_state) ? "true" : "false");
            continue;
        }

        // put output wRepeatCount times into g_console_input_buffer
        while (key_event->wRepeatCount-- > 0) {
            g_console_input_buffer.insert(g_console_input_buffer.end(), out, out + outlen);
        }

        // Loop around and try to flush g_console_input_buffer
    }
}

static DWORD _old_console_mode; // previous GetConsoleMode() result
static HANDLE _console_handle;  // when set, console mode should be restored

void stdin_raw_init() {
    const HANDLE in = _get_console_handle(STDIN_FILENO, &_old_console_mode);
    if (in == nullptr) {
        return;
    }

    // Disable ENABLE_PROCESSED_INPUT so that Ctrl-C is read instead of
    // calling the process Ctrl-C routine (configured by
    // SetConsoleCtrlHandler()).
    // Disable ENABLE_LINE_INPUT so that input is immediately sent.
    // Disable ENABLE_ECHO_INPUT to disable local echo. Disabling this
    // flag also seems necessary to have proper line-ending processing.
    DWORD new_console_mode = _old_console_mode & ~(ENABLE_PROCESSED_INPUT |
                                                   ENABLE_LINE_INPUT |
                                                   ENABLE_ECHO_INPUT);
    // Enable ENABLE_WINDOW_INPUT to get window resizes.
    new_console_mode |= ENABLE_WINDOW_INPUT;

    if (!SetConsoleMode(in, new_console_mode)) {
        // This really should not fail.
        D("stdin_raw_init: SetConsoleMode() failed: %s",
          android::base::SystemErrorCodeToString(GetLastError()).c_str());
    }

    // Once this is set, it means that stdin has been configured for
    // reading from and that the old console mode should be restored later.
    _console_handle = in;

    // Note that we don't need to configure C Runtime line-ending
    // translation because _console_read() does not call the C Runtime to
    // read from the console.
}

void stdin_raw_restore() {
    if (_console_handle != NULL) {
        const HANDLE in = _console_handle;
        _console_handle = NULL;  // clear state

        if (!SetConsoleMode(in, _old_console_mode)) {
            // This really should not fail.
            D("stdin_raw_restore: SetConsoleMode() failed: %s",
              android::base::SystemErrorCodeToString(GetLastError()).c_str());
        }
    }
}

// Called by 'adb shell' and 'adb exec-in' (via unix_read()) to read from stdin.
int unix_read_interruptible(int fd, void* buf, size_t len) {
    if ((fd == STDIN_FILENO) && (_console_handle != NULL)) {
        // If it is a request to read from stdin, and stdin_raw_init() has been
        // called, and it successfully configured the console, then read from
        // the console using Win32 console APIs and partially emulate a unix
        // terminal.
        return _console_read(_console_handle, buf, len);
    } else {
        // On older versions of Windows (definitely 7, definitely not 10),
        // ReadConsole() with a size >= 31367 fails, so if |fd| is a console
        // we need to limit the read size.
        if (len > 4096 && unix_isatty(fd)) {
            len = 4096;
        }
        // Just call into C Runtime which can read from pipes/files and which
        // can do LF/CR translation (which is overridable with _setmode()).
        // Undefine the macro that is set in sysdeps.h which bans calls to
        // plain read() in favor of unix_read() or adb_read().
#pragma push_macro("read")
#undef read
        return read(fd, buf, len);
#pragma pop_macro("read")
    }
}

/**************************************************************************/
/**************************************************************************/
/*****                                                                *****/
/*****      Unicode support                                           *****/
/*****                                                                *****/
/**************************************************************************/
/**************************************************************************/

// This implements support for using files with Unicode filenames and for
// outputting Unicode text to a Win32 console window. This is inspired from
// http://utf8everywhere.org/.
//
// Background
// ----------
//
// On POSIX systems, to deal with files with Unicode filenames, just pass UTF-8
// filenames to APIs such as open(). This works because filenames are largely
// opaque 'cookies' (perhaps excluding path separators).
//
// On Windows, the native file APIs such as CreateFileW() take 2-byte wchar_t
// UTF-16 strings. There is an API, CreateFileA() that takes 1-byte char
// strings, but the strings are in the ANSI codepage and not UTF-8. (The
// CreateFile() API is really just a macro that adds the W/A based on whether
// the UNICODE preprocessor symbol is defined).
//
// Options
// -------
//
// Thus, to write a portable program, there are a few options:
//
// 1. Write the program with wchar_t filenames (wchar_t path[256];).
//    For Windows, just call CreateFileW(). For POSIX, write a wrapper openW()
//    that takes a wchar_t string, converts it to UTF-8 and then calls the real
//    open() API.
//
// 2. Write the program with a TCHAR typedef that is 2 bytes on Windows and
//    1 byte on POSIX. Make T-* wrappers for various OS APIs and call those,
//    potentially touching a lot of code.
//
// 3. Write the program with a 1-byte char filenames (char path[256];) that are
//    UTF-8. For POSIX, just call open(). For Windows, write a wrapper that
//    takes a UTF-8 string, converts it to UTF-16 and then calls the real OS
//    or C Runtime API.
//
// The Choice
// ----------
//
// The code below chooses option 3, the UTF-8 everywhere strategy. It uses
// android::base::WideToUTF8() which converts UTF-16 to UTF-8. This is used by the
// NarrowArgs helper class that is used to convert wmain() args into UTF-8
// args that are passed to main() at the beginning of program startup. We also use
// android::base::UTF8ToWide() which converts from UTF-8 to UTF-16. This is used to
// implement wrappers below that call UTF-16 OS and C Runtime APIs.
//
// Unicode console output
// ----------------------
//
// The way to output Unicode to a Win32 console window is to call
// WriteConsoleW() with UTF-16 text. (The user must also choose a proper font
// such as Lucida Console or Consolas, and in the case of East Asian languages
// (such as Chinese, Japanese, Korean), the user must go to the Control Panel
// and change the "system locale" to Chinese, etc., which allows a Chinese, etc.
// font to be used in console windows.)
//
// The problem is getting the C Runtime to make fprintf and related APIs call
// WriteConsoleW() under the covers. The C Runtime API, _setmode() sounds
// promising, but the various modes have issues:
//
// 1. _setmode(_O_TEXT) (the default) does not use WriteConsoleW() so UTF-8 and
//    UTF-16 do not display properly.
// 2. _setmode(_O_BINARY) does not use WriteConsoleW() and the text comes out
//    totally wrong.
// 3. _setmode(_O_U8TEXT) seems to cause the C Runtime _invalid_parameter
//    handler to be called (upon a later I/O call), aborting the process.
// 4. _setmode(_O_U16TEXT) and _setmode(_O_WTEXT) cause non-wide printf/fprintf
//    to output nothing.
//
// So the only solution is to write our own adb_fprintf() that converts UTF-8
// to UTF-16 and then calls WriteConsoleW().


// Constructor for helper class to convert wmain() UTF-16 args to UTF-8 to
// be passed to main().
NarrowArgs::NarrowArgs(const int argc, wchar_t** const argv) {
    narrow_args = new char*[argc + 1];

    for (int i = 0; i < argc; ++i) {
        std::string arg_narrow;
        if (!android::base::WideToUTF8(argv[i], &arg_narrow)) {
            fatal_errno("cannot convert argument from UTF-16 to UTF-8");
        }
        narrow_args[i] = strdup(arg_narrow.c_str());
    }
    narrow_args[argc] = nullptr;   // terminate
}

NarrowArgs::~NarrowArgs() {
    if (narrow_args != nullptr) {
        for (char** argp = narrow_args; *argp != nullptr; ++argp) {
            free(*argp);
        }
        delete[] narrow_args;
        narrow_args = nullptr;
    }
}

int unix_open(const char* path, int options, ...) {
    std::wstring path_wide;
    if (!android::base::UTF8ToWide(path, &path_wide)) {
        return -1;
    }
    if ((options & O_CREAT) == 0) {
        return _wopen(path_wide.c_str(), options);
    } else {
        int      mode;
        va_list  args;
        va_start(args, options);
        mode = va_arg(args, int);
        va_end(args);
        return _wopen(path_wide.c_str(), options, mode);
    }
}

// Version of opendir() that takes a UTF-8 path.
DIR* adb_opendir(const char* path) {
    std::wstring path_wide;
    if (!android::base::UTF8ToWide(path, &path_wide)) {
        return nullptr;
    }

    // Just cast _WDIR* to DIR*. This doesn't work if the caller reads any of
    // the fields, but right now all the callers treat the structure as
    // opaque.
    return reinterpret_cast<DIR*>(_wopendir(path_wide.c_str()));
}

// Version of readdir() that returns UTF-8 paths.
struct dirent* adb_readdir(DIR* dir) {
    _WDIR* const wdir = reinterpret_cast<_WDIR*>(dir);
    struct _wdirent* const went = _wreaddir(wdir);
    if (went == nullptr) {
        return nullptr;
    }

    // Convert from UTF-16 to UTF-8.
    std::string name_utf8;
    if (!android::base::WideToUTF8(went->d_name, &name_utf8)) {
        return nullptr;
    }

    // Cast the _wdirent* to dirent* and overwrite the d_name field (which has
    // space for UTF-16 wchar_t's) with UTF-8 char's.
    struct dirent* ent = reinterpret_cast<struct dirent*>(went);

    if (name_utf8.length() + 1 > sizeof(went->d_name)) {
        // Name too big to fit in existing buffer.
        errno = ENOMEM;
        return nullptr;
    }

    // Note that sizeof(_wdirent::d_name) is bigger than sizeof(dirent::d_name)
    // because _wdirent contains wchar_t instead of char. So even if name_utf8
    // can fit in _wdirent::d_name, the resulting dirent::d_name field may be
    // bigger than the caller expects because they expect a dirent structure
    // which has a smaller d_name field. Ignore this since the caller should be
    // resilient.

    // Rewrite the UTF-16 d_name field to UTF-8.
    strcpy(ent->d_name, name_utf8.c_str());

    return ent;
}

// Version of closedir() to go with our version of adb_opendir().
int adb_closedir(DIR* dir) {
    return _wclosedir(reinterpret_cast<_WDIR*>(dir));
}

// Version of unlink() that takes a UTF-8 path.
int adb_unlink(const char* path) {
    std::wstring wpath;
    if (!android::base::UTF8ToWide(path, &wpath)) {
        return -1;
    }

    int  rc = _wunlink(wpath.c_str());

    if (rc == -1 && errno == EACCES) {
        /* unlink returns EACCES when the file is read-only, so we first */
        /* try to make it writable, then unlink again...                 */
        rc = _wchmod(wpath.c_str(), _S_IREAD | _S_IWRITE);
        if (rc == 0)
            rc = _wunlink(wpath.c_str());
    }
    return rc;
}

// Version of mkdir() that takes a UTF-8 path.
int adb_mkdir(const std::string& path, int mode) {
    std::wstring path_wide;
    if (!android::base::UTF8ToWide(path, &path_wide)) {
        return -1;
    }

    return _wmkdir(path_wide.c_str());
}

// Version of utime() that takes a UTF-8 path.
int adb_utime(const char* path, struct utimbuf* u) {
    std::wstring path_wide;
    if (!android::base::UTF8ToWide(path, &path_wide)) {
        return -1;
    }

    static_assert(sizeof(struct utimbuf) == sizeof(struct _utimbuf),
        "utimbuf and _utimbuf should be the same size because they both "
        "contain the same types, namely time_t");
    return _wutime(path_wide.c_str(), reinterpret_cast<struct _utimbuf*>(u));
}

// Version of chmod() that takes a UTF-8 path.
int adb_chmod(const char* path, int mode) {
    std::wstring path_wide;
    if (!android::base::UTF8ToWide(path, &path_wide)) {
        return -1;
    }

    return _wchmod(path_wide.c_str(), mode);
}

// From libutils/Unicode.cpp, get the length of a UTF-8 sequence given the lead byte.
static inline size_t utf8_codepoint_len(uint8_t ch) {
    return ((0xe5000000 >> ((ch >> 3) & 0x1e)) & 3) + 1;
}

namespace internal {

// Given a sequence of UTF-8 bytes (denoted by the range [first, last)), return the number of bytes
// (from the beginning) that are complete UTF-8 sequences and append the remaining bytes to
// remaining_bytes.
size_t ParseCompleteUTF8(const char* const first, const char* const last,
                         std::vector<char>* const remaining_bytes) {
    // Walk backwards from the end of the sequence looking for the beginning of a UTF-8 sequence.
    // Current_after points one byte past the current byte to be examined.
    for (const char* current_after = last; current_after != first; --current_after) {
        const char* const current = current_after - 1;
        const char ch = *current;
        const char kHighBit = 0x80u;
        const char kTwoHighestBits = 0xC0u;
        if ((ch & kHighBit) == 0) { // high bit not set
            // The buffer ends with a one-byte UTF-8 sequence, possibly followed by invalid trailing
            // bytes with no leading byte, so return the entire buffer.
            break;
        } else if ((ch & kTwoHighestBits) == kTwoHighestBits) { // top two highest bits set
            // Lead byte in UTF-8 sequence, so check if we have all the bytes in the sequence.
            const size_t bytes_available = last - current;
            if (bytes_available < utf8_codepoint_len(ch)) {
                // We don't have all the bytes in the UTF-8 sequence, so return all the bytes
                // preceding the current incomplete UTF-8 sequence and append the remaining bytes
                // to remaining_bytes.
                remaining_bytes->insert(remaining_bytes->end(), current, last);
                return current - first;
            } else {
                // The buffer ends with a complete UTF-8 sequence, possibly followed by invalid
                // trailing bytes with no lead byte, so return the entire buffer.
                break;
            }
        } else {
            // Trailing byte, so keep going backwards looking for the lead byte.
        }
    }

    // Return the size of the entire buffer. It is possible that we walked backward past invalid
    // trailing bytes with no lead byte, in which case we want to return all those invalid bytes
    // so that they can be processed.
    return last - first;
}

}

// Bytes that have not yet been output to the console because they are incomplete UTF-8 sequences.
// Note that we use only one buffer even though stderr and stdout are logically separate streams.
// This matches the behavior of Linux.

// Internal helper function to write UTF-8 bytes to a console. Returns -1 on error.
static int _console_write_utf8(const char* const buf, const size_t buf_size, FILE* stream,
                               HANDLE console) {
    static std::mutex& console_output_buffer_lock = *new std::mutex();
    static auto& console_output_buffer = *new std::vector<char>();

    const int saved_errno = errno;
    std::vector<char> combined_buffer;

    // Complete UTF-8 sequences that should be immediately written to the console.
    const char* utf8;
    size_t utf8_size;

    {
        std::lock_guard<std::mutex> lock(console_output_buffer_lock);
        if (console_output_buffer.empty()) {
            // If console_output_buffer doesn't have a buffered up incomplete UTF-8 sequence (the
            // common case with plain ASCII), parse buf directly.
            utf8 = buf;
            utf8_size = internal::ParseCompleteUTF8(buf, buf + buf_size, &console_output_buffer);
        } else {
            // If console_output_buffer has a buffered up incomplete UTF-8 sequence, move it to
            // combined_buffer (and effectively clear console_output_buffer) and append buf to
            // combined_buffer, then parse it all together.
            combined_buffer.swap(console_output_buffer);
            combined_buffer.insert(combined_buffer.end(), buf, buf + buf_size);

            utf8 = combined_buffer.data();
            utf8_size = internal::ParseCompleteUTF8(utf8, utf8 + combined_buffer.size(),
                                                    &console_output_buffer);
        }
    }

    std::wstring utf16;

    // Try to convert from data that might be UTF-8 to UTF-16, ignoring errors (just like Linux
    // which does not return an error on bad UTF-8). Data might not be UTF-8 if the user cat's
    // random data, runs dmesg (which might have non-UTF-8), etc.
    // This could throw std::bad_alloc.
    (void)android::base::UTF8ToWide(utf8, utf8_size, &utf16);

    // Note that this does not do \n => \r\n translation because that
    // doesn't seem necessary for the Windows console. For the Windows
    // console \r moves to the beginning of the line and \n moves to a new
    // line.

    // Flush any stream buffering so that our output is afterwards which
    // makes sense because our call is afterwards.
    (void)fflush(stream);

    // Write UTF-16 to the console.
    DWORD written = 0;
    if (!WriteConsoleW(console, utf16.c_str(), utf16.length(), &written, NULL)) {
        errno = EIO;
        return -1;
    }

    // Return the size of the original buffer passed in, signifying that we consumed it all, even
    // if nothing was displayed, in the case of being passed an incomplete UTF-8 sequence. This
    // matches the Linux behavior.
    errno = saved_errno;
    return buf_size;
}

// Function prototype because attributes cannot be placed on func definitions.
static int _console_vfprintf(const HANDLE console, FILE* stream,
                             const char *format, va_list ap)
    __attribute__((__format__(ADB_FORMAT_ARCHETYPE, 3, 0)));

// Internal function to format a UTF-8 string and write it to a Win32 console.
// Returns -1 on error.
static int _console_vfprintf(const HANDLE console, FILE* stream,
                             const char *format, va_list ap) {
    const int saved_errno = errno;
    std::string output_utf8;

    // Format the string.
    // This could throw std::bad_alloc.
    android::base::StringAppendV(&output_utf8, format, ap);

    const int result = _console_write_utf8(output_utf8.c_str(), output_utf8.length(), stream,
                                           console);
    if (result != -1) {
        errno = saved_errno;
    } else {
        // If -1 was returned, errno has been set.
    }
    return result;
}

// Version of vfprintf() that takes UTF-8 and can write Unicode to a
// Windows console.
int adb_vfprintf(FILE *stream, const char *format, va_list ap) {
    const HANDLE console = _get_console_handle(stream);

    // If there is an associated Win32 console, write to it specially,
    // otherwise defer to the regular C Runtime, passing it UTF-8.
    if (console != NULL) {
        return _console_vfprintf(console, stream, format, ap);
    } else {
        // If vfprintf is a macro, undefine it, so we can call the real
        // C Runtime API.
#pragma push_macro("vfprintf")
#undef vfprintf
        return vfprintf(stream, format, ap);
#pragma pop_macro("vfprintf")
    }
}

// Version of vprintf() that takes UTF-8 and can write Unicode to a Windows console.
int adb_vprintf(const char *format, va_list ap) {
    return adb_vfprintf(stdout, format, ap);
}

// Version of fprintf() that takes UTF-8 and can write Unicode to a
// Windows console.
int adb_fprintf(FILE *stream, const char *format, ...) {
    va_list ap;
    va_start(ap, format);
    const int result = adb_vfprintf(stream, format, ap);
    va_end(ap);

    return result;
}

// Version of printf() that takes UTF-8 and can write Unicode to a
// Windows console.
int adb_printf(const char *format, ...) {
    va_list ap;
    va_start(ap, format);
    const int result = adb_vfprintf(stdout, format, ap);
    va_end(ap);

    return result;
}

// Version of fputs() that takes UTF-8 and can write Unicode to a
// Windows console.
int adb_fputs(const char* buf, FILE* stream) {
    // adb_fprintf returns -1 on error, which is conveniently the same as EOF
    // which fputs (and hence adb_fputs) should return on error.
    static_assert(EOF == -1, "EOF is not -1, so this code needs to be fixed");
    return adb_fprintf(stream, "%s", buf);
}

// Version of fputc() that takes UTF-8 and can write Unicode to a
// Windows console.
int adb_fputc(int ch, FILE* stream) {
    const int result = adb_fprintf(stream, "%c", ch);
    if (result == -1) {
        return EOF;
    }
    // For success, fputc returns the char, cast to unsigned char, then to int.
    return static_cast<unsigned char>(ch);
}

// Version of putchar() that takes UTF-8 and can write Unicode to a Windows console.
int adb_putchar(int ch) {
    return adb_fputc(ch, stdout);
}

// Version of puts() that takes UTF-8 and can write Unicode to a Windows console.
int adb_puts(const char* buf) {
    // adb_printf returns -1 on error, which is conveniently the same as EOF
    // which puts (and hence adb_puts) should return on error.
    static_assert(EOF == -1, "EOF is not -1, so this code needs to be fixed");
    return adb_printf("%s\n", buf);
}

// Internal function to write UTF-8 to a Win32 console. Returns the number of
// items (of length size) written. On error, returns a short item count or 0.
static size_t _console_fwrite(const void* ptr, size_t size, size_t nmemb,
                              FILE* stream, HANDLE console) {
    const int result = _console_write_utf8(reinterpret_cast<const char*>(ptr), size * nmemb, stream,
                                           console);
    if (result == -1) {
        return 0;
    }
    return result / size;
}

// Version of fwrite() that takes UTF-8 and can write Unicode to a
// Windows console.
size_t adb_fwrite(const void* ptr, size_t size, size_t nmemb, FILE* stream) {
    const HANDLE console = _get_console_handle(stream);

    // If there is an associated Win32 console, write to it specially,
    // otherwise defer to the regular C Runtime, passing it UTF-8.
    if (console != NULL) {
        return _console_fwrite(ptr, size, nmemb, stream, console);
    } else {
        // If fwrite is a macro, undefine it, so we can call the real
        // C Runtime API.
#pragma push_macro("fwrite")
#undef fwrite
        return fwrite(ptr, size, nmemb, stream);
#pragma pop_macro("fwrite")
    }
}

// Version of fopen() that takes a UTF-8 filename and can access a file with
// a Unicode filename.
FILE* adb_fopen(const char* path, const char* mode) {
    std::wstring path_wide;
    if (!android::base::UTF8ToWide(path, &path_wide)) {
        return nullptr;
    }

    std::wstring mode_wide;
    if (!android::base::UTF8ToWide(mode, &mode_wide)) {
        return nullptr;
    }

    return _wfopen(path_wide.c_str(), mode_wide.c_str());
}

// Return a lowercase version of the argument. Uses C Runtime tolower() on
// each byte which is not UTF-8 aware, and theoretically uses the current C
// Runtime locale (which in practice is not changed, so this becomes a ASCII
// conversion).
static std::string ToLower(const std::string& anycase) {
    // copy string
    std::string str(anycase);
    // transform the copy
    std::transform(str.begin(), str.end(), str.begin(), tolower);
    return str;
}

extern "C" int main(int argc, char** argv);

// Link with -municode to cause this wmain() to be used as the program
// entrypoint. It will convert the args from UTF-16 to UTF-8 and call the
// regular main() with UTF-8 args.
extern "C" int wmain(int argc, wchar_t **argv) {
    // Convert args from UTF-16 to UTF-8 and pass that to main().
    NarrowArgs narrow_args(argc, argv);
    return main(argc, narrow_args.data());
}

// Shadow UTF-8 environment variable name/value pairs that are created from
// _wenviron the first time that adb_getenv() is called. Note that this is not
// currently updated if putenv, setenv, unsetenv are called. Note that no
// thread synchronization is done, but we're called early enough in
// single-threaded startup that things work ok.
static auto& g_environ_utf8 = *new std::unordered_map<std::string, char*>();

// Make sure that shadow UTF-8 environment variables are setup.
static void _ensure_env_setup() {
    // If some name/value pairs exist, then we've already done the setup below.
    if (g_environ_utf8.size() != 0) {
        return;
    }

    if (_wenviron == nullptr) {
        // If _wenviron is null, then -municode probably wasn't used. That
        // linker flag will cause the entry point to setup _wenviron. It will
        // also require an implementation of wmain() (which we provide above).
        fatal("_wenviron is not set, did you link with -municode?");
    }

    // Read name/value pairs from UTF-16 _wenviron and write new name/value
    // pairs to UTF-8 g_environ_utf8. Note that it probably does not make sense
    // to use the D() macro here because that tracing only works if the
    // ADB_TRACE environment variable is setup, but that env var can't be read
    // until this code completes.
    for (wchar_t** env = _wenviron; *env != nullptr; ++env) {
        wchar_t* const equal = wcschr(*env, L'=');
        if (equal == nullptr) {
            // Malformed environment variable with no equal sign. Shouldn't
            // really happen, but we should be resilient to this.
            continue;
        }

        // If we encounter an error converting UTF-16, don't error-out on account of a single env
        // var because the program might never even read this particular variable.
        std::string name_utf8;
        if (!android::base::WideToUTF8(*env, equal - *env, &name_utf8)) {
            continue;
        }

        // Store lowercase name so that we can do case-insensitive searches.
        name_utf8 = ToLower(name_utf8);

        std::string value_utf8;
        if (!android::base::WideToUTF8(equal + 1, &value_utf8)) {
            continue;
        }

        char* const value_dup = strdup(value_utf8.c_str());

        // Don't overwrite a previus env var with the same name. In reality,
        // the system probably won't let two env vars with the same name exist
        // in _wenviron.
        g_environ_utf8.insert({name_utf8, value_dup});
    }
}

// Version of getenv() that takes a UTF-8 environment variable name and
// retrieves a UTF-8 value. Case-insensitive to match getenv() on Windows.
char* adb_getenv(const char* name) {
    _ensure_env_setup();

    // Case-insensitive search by searching for lowercase name in a map of
    // lowercase names.
    const auto it = g_environ_utf8.find(ToLower(std::string(name)));
    if (it == g_environ_utf8.end()) {
        return nullptr;
    }

    return it->second;
}

// Version of getcwd() that returns the current working directory in UTF-8.
char* adb_getcwd(char* buf, int size) {
    wchar_t* wbuf = _wgetcwd(nullptr, 0);
    if (wbuf == nullptr) {
        return nullptr;
    }

    std::string buf_utf8;
    const bool narrow_result = android::base::WideToUTF8(wbuf, &buf_utf8);
    free(wbuf);
    wbuf = nullptr;

    if (!narrow_result) {
        return nullptr;
    }

    // If size was specified, make sure all the chars will fit.
    if (size != 0) {
        if (size < static_cast<int>(buf_utf8.length() + 1)) {
            errno = ERANGE;
            return nullptr;
        }
    }

    // If buf was not specified, allocate storage.
    if (buf == nullptr) {
        if (size == 0) {
            size = buf_utf8.length() + 1;
        }
        buf = reinterpret_cast<char*>(malloc(size));
        if (buf == nullptr) {
            return nullptr;
        }
    }

    // Destination buffer was allocated with enough space, or we've already
    // checked an existing buffer size for enough space.
    strcpy(buf, buf_utf8.c_str());

    return buf;
}
