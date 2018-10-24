/*
 * Copyright (C) 2007 The Android Open Source Project
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

/* this file contains system-dependent definitions used by ADB
 * they're related to threads, sockets and file descriptors
 */
#ifndef _ADB_SYSDEPS_H
#define _ADB_SYSDEPS_H

#ifdef __CYGWIN__
#  undef _WIN32
#endif

#include <errno.h>

#include <string>
#include <vector>

// Include this before open/close/unlink are defined as macros below.
#include <android-base/errors.h>
#include <android-base/macros.h>
#include <android-base/unique_fd.h>
#include <android-base/utf8.h>

#include "sysdeps/errno.h"
#include "sysdeps/network.h"
#include "sysdeps/stat.h"

#ifdef _WIN32

// Clang-only nullability specifiers
#define _Nonnull
#define _Nullable

#include <ctype.h>
#include <direct.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <io.h>
#include <process.h>
#include <stdint.h>
#include <sys/stat.h>
#include <utime.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <memory>   // unique_ptr
#include <string>

#include "fdevent.h"

#define OS_PATH_SEPARATORS "\\/"
#define OS_PATH_SEPARATOR '\\'
#define OS_PATH_SEPARATOR_STR "\\"
#define ENV_PATH_SEPARATOR_STR ";"

static __inline__ bool adb_is_separator(char c) {
    return c == '\\' || c == '/';
}

extern int adb_thread_setname(const std::string& name);

static __inline__ void  close_on_exec(int  fd)
{
    /* nothing really */
}

extern int  adb_unlink(const char*  path);
#undef  unlink
#define unlink  ___xxx_unlink

extern int adb_mkdir(const std::string& path, int mode);
#undef   mkdir
#define  mkdir  ___xxx_mkdir

// See the comments for the !defined(_WIN32) versions of adb_*().
extern int adb_open(const char* path, int options);
extern int adb_creat(const char* path, int mode);
extern int adb_read(int fd, void* buf, int len);
extern int adb_write(int fd, const void* buf, int len);
extern int64_t adb_lseek(int fd, int64_t pos, int where);
extern int adb_shutdown(int fd, int direction = SHUT_RDWR);
extern int adb_close(int fd);
extern int adb_register_socket(SOCKET s);

// See the comments for the !defined(_WIN32) version of unix_close().
static __inline__ int  unix_close(int fd)
{
    return close(fd);
}
#undef   close
#define  close   ____xxx_close

// Like unix_read(), but may return EINTR.
extern int  unix_read_interruptible(int  fd, void*  buf, size_t  len);

// See the comments for the !defined(_WIN32) version of unix_read().
static __inline__ int unix_read(int fd, void* buf, size_t len) {
    return TEMP_FAILURE_RETRY(unix_read_interruptible(fd, buf, len));
}

#undef   read
#define  read  ___xxx_read

// See the comments for the !defined(_WIN32) version of unix_write().
static __inline__  int  unix_write(int  fd, const void*  buf, size_t  len)
{
    return write(fd, buf, len);
}
#undef   write
#define  write  ___xxx_write

// See the comments for the !defined(_WIN32) version of unix_lseek().
static __inline__ int unix_lseek(int fd, int pos, int where) {
    return lseek(fd, pos, where);
}
#undef lseek
#define lseek ___xxx_lseek

// See the comments for the !defined(_WIN32) version of adb_open_mode().
static __inline__ int  adb_open_mode(const char* path, int options, int mode)
{
    return adb_open(path, options);
}

// See the comments for the !defined(_WIN32) version of unix_open().
extern int unix_open(const char* path, int options, ...);
#define  open    ___xxx_unix_open

// Checks if |fd| corresponds to a console.
// Standard Windows isatty() returns 1 for both console FDs and character
// devices like NUL. unix_isatty() performs some extra checking to only match
// console FDs.
// |fd| must be a real file descriptor, meaning STDxx_FILENO or unix_open() FDs
// will work but adb_open() FDs will not. Additionally the OS handle associated
// with |fd| must have GENERIC_READ access (which console FDs have by default).
// Returns 1 if |fd| is a console FD, 0 otherwise. The value of errno after
// calling this function is unreliable and should not be used.
int unix_isatty(int fd);
#define  isatty  ___xxx_isatty

int network_inaddr_any_server(int port, int type, std::string* error);

inline int network_local_client(const char* name, int namespace_id, int type, std::string* error) {
    abort();
}

inline int network_local_server(const char* name, int namespace_id, int type, std::string* error) {
    abort();
}

int network_connect(const std::string& host, int port, int type, int timeout,
                    std::string* error);

extern int  adb_socket_accept(int  serverfd, struct sockaddr*  addr, socklen_t  *addrlen);

#undef   accept
#define  accept  ___xxx_accept

// Returns the local port number of a bound socket, or -1 on failure.
int adb_socket_get_local_port(int fd);

extern int  adb_setsockopt(int  fd, int  level, int  optname, const void*  optval, socklen_t  optlen);

#undef   setsockopt
#define  setsockopt  ___xxx_setsockopt

extern int  adb_socketpair( int  sv[2] );

struct adb_pollfd {
    int fd;
    short events;
    short revents;
};
extern int adb_poll(adb_pollfd* fds, size_t nfds, int timeout);
#define poll ___xxx_poll

static __inline__ int adb_is_absolute_host_path(const char* path) {
    return isalpha(path[0]) && path[1] == ':' && path[2] == '\\';
}

// UTF-8 versions of POSIX APIs.
extern DIR* adb_opendir(const char* dirname);
extern struct dirent* adb_readdir(DIR* dir);
extern int adb_closedir(DIR* dir);

extern int adb_utime(const char *, struct utimbuf *);
extern int adb_chmod(const char *, int);

extern int adb_vfprintf(FILE* stream, const char* format, va_list ap)
        __attribute__((__format__(__printf__, 2, 0)));
extern int adb_vprintf(const char* format, va_list ap) __attribute__((__format__(__printf__, 1, 0)));
extern int adb_fprintf(FILE* stream, const char* format, ...)
        __attribute__((__format__(__printf__, 2, 3)));
extern int adb_printf(const char* format, ...) __attribute__((__format__(__printf__, 1, 2)));

extern int adb_fputs(const char* buf, FILE* stream);
extern int adb_fputc(int ch, FILE* stream);
extern int adb_putchar(int ch);
extern int adb_puts(const char* buf);
extern size_t adb_fwrite(const void* ptr, size_t size, size_t nmemb,
                         FILE* stream);

extern FILE* adb_fopen(const char* f, const char* m);

extern char* adb_getenv(const char* name);

extern char* adb_getcwd(char* buf, int size);

// Remap calls to POSIX APIs to our UTF-8 versions.
#define opendir adb_opendir
#define readdir adb_readdir
#define closedir adb_closedir
#define rewinddir rewinddir_utf8_not_yet_implemented
#define telldir telldir_utf8_not_yet_implemented
// Some compiler's C++ headers have members named seekdir, so we can't do the
// macro technique and instead cause a link error if seekdir is called.
inline void seekdir(DIR*, long) {
    extern int seekdir_utf8_not_yet_implemented;
    seekdir_utf8_not_yet_implemented = 1;
}

#define utime adb_utime
#define chmod adb_chmod

#define vfprintf adb_vfprintf
#define vprintf adb_vprintf
#define fprintf adb_fprintf
#define printf adb_printf
#define fputs adb_fputs
#define fputc adb_fputc
// putc may be a macro, so if so, undefine it, so that we can redefine it.
#undef putc
#define putc(c, s) adb_fputc(c, s)
#define putchar adb_putchar
#define puts adb_puts
#define fwrite adb_fwrite

#define fopen adb_fopen
#define freopen freopen_utf8_not_yet_implemented

#define getenv adb_getenv
#define putenv putenv_utf8_not_yet_implemented
#define setenv setenv_utf8_not_yet_implemented
#define unsetenv unsetenv_utf8_not_yet_implemented

#define getcwd adb_getcwd

// Helper class to convert UTF-16 argv from wmain() to UTF-8 args that can be
// passed to main().
class NarrowArgs {
public:
    NarrowArgs(int argc, wchar_t** argv);
    ~NarrowArgs();

    inline char** data() {
        return narrow_args;
    }

private:
    char** narrow_args;
};

// Windows HANDLE values only use 32-bits of the type, even on 64-bit machines,
// so they can fit in an int. To convert back, we just need to sign-extend.
// https://msdn.microsoft.com/en-us/library/windows/desktop/aa384203%28v=vs.85%29.aspx
// Note that this does not make a HANDLE value work with APIs like open(), nor
// does this make a value from open() passable to APIs taking a HANDLE. This
// just lets you take a HANDLE, pass it around as an int, and then use it again
// as a HANDLE.
inline int cast_handle_to_int(const HANDLE h) {
    // truncate
    return static_cast<int>(reinterpret_cast<INT_PTR>(h));
}

inline HANDLE cast_int_to_handle(const int fd) {
    // sign-extend
    return reinterpret_cast<HANDLE>(static_cast<INT_PTR>(fd));
}

// Deleter for unique_handle. Adapted from many sources, including:
// http://stackoverflow.com/questions/14841396/stdunique-ptr-deleters-and-the-win32-api
// https://visualstudiomagazine.com/articles/2013/09/01/get-a-handle-on-the-windows-api.aspx
class handle_deleter {
public:
    typedef HANDLE pointer;

    void operator()(HANDLE h);
};

// Like std::unique_ptr, but for Windows HANDLE objects that should be
// CloseHandle()'d. Operator bool() only checks if the handle != nullptr,
// but does not check if the handle != INVALID_HANDLE_VALUE.
typedef std::unique_ptr<HANDLE, handle_deleter> unique_handle;

namespace internal {

size_t ParseCompleteUTF8(const char* first, const char* last, std::vector<char>* remaining_bytes);

}

#else /* !_WIN32 a.k.a. Unix */

#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <string>

#include <cutils/sockets.h>

#define OS_PATH_SEPARATORS "/"
#define OS_PATH_SEPARATOR '/'
#define OS_PATH_SEPARATOR_STR "/"
#define ENV_PATH_SEPARATOR_STR ":"

static __inline__ bool adb_is_separator(char c) {
    return c == '/';
}

static __inline__ void  close_on_exec(int  fd)
{
    fcntl( fd, F_SETFD, FD_CLOEXEC );
}

// Open a file and return a file descriptor that may be used with unix_read(),
// unix_write(), unix_close(), but not adb_read(), adb_write(), adb_close().
//
// On Unix, this is based on open(), so the file descriptor is a real OS file
// descriptor, but the Windows implementation (in sysdeps_win32.cpp) returns a
// file descriptor that can only be used with C Runtime APIs (which are wrapped
// by unix_read(), unix_write(), unix_close()). Also, the C Runtime has
// configurable CR/LF translation which defaults to text mode, but is settable
// with _setmode().
static __inline__ int  unix_open(const char*  path, int options,...)
{
    if ((options & O_CREAT) == 0)
    {
        return  TEMP_FAILURE_RETRY( open(path, options) );
    }
    else
    {
        int      mode;
        va_list  args;
        va_start( args, options );
        mode = va_arg( args, int );
        va_end( args );
        return TEMP_FAILURE_RETRY( open( path, options, mode ) );
    }
}

// Similar to the two-argument adb_open(), but takes a mode parameter for file
// creation. See adb_open() for more info.
static __inline__ int  adb_open_mode( const char*  pathname, int  options, int  mode )
{
    return TEMP_FAILURE_RETRY( open( pathname, options, mode ) );
}


// Open a file and return a file descriptor that may be used with adb_read(),
// adb_write(), adb_close(), but not unix_read(), unix_write(), unix_close().
//
// On Unix, this is based on open(), but the Windows implementation (in
// sysdeps_win32.cpp) uses Windows native file I/O and bypasses the C Runtime
// and its CR/LF translation. The returned file descriptor should be used with
// adb_read(), adb_write(), adb_close(), etc.
static __inline__ int  adb_open( const char*  pathname, int  options )
{
    int  fd = TEMP_FAILURE_RETRY( open( pathname, options ) );
    if (fd < 0)
        return -1;
    close_on_exec( fd );
    return fd;
}
#undef   open
#define  open    ___xxx_open

static __inline__ int adb_shutdown(int fd, int direction = SHUT_RDWR) {
    return shutdown(fd, direction);
}

#undef   shutdown
#define  shutdown   ____xxx_shutdown

// Closes a file descriptor that came from adb_open() or adb_open_mode(), but
// not designed to take a file descriptor from unix_open(). See the comments
// for adb_open() for more info.
__inline__ int adb_close(int fd) {
    return close(fd);
}
#undef   close
#define  close   ____xxx_close

// On Windows, ADB has an indirection layer for file descriptors. If we get a
// Win32 SOCKET object from an external library, we have to map it in to that
// indirection layer, which this does.
__inline__ int  adb_register_socket(int s) {
    return s;
}

static __inline__  int  adb_read(int  fd, void*  buf, size_t  len)
{
    return TEMP_FAILURE_RETRY( read( fd, buf, len ) );
}

// Like unix_read(), but does not handle EINTR.
static __inline__ int unix_read_interruptible(int fd, void* buf, size_t len) {
    return read(fd, buf, len);
}

#undef   read
#define  read  ___xxx_read

static __inline__  int  adb_write(int  fd, const void*  buf, size_t  len)
{
    return TEMP_FAILURE_RETRY( write( fd, buf, len ) );
}
#undef   write
#define  write  ___xxx_write

static __inline__ int64_t adb_lseek(int fd, int64_t pos, int where) {
#if defined(__APPLE__)
    return lseek(fd, pos, where);
#else
    return lseek64(fd, pos, where);
#endif
}
#undef lseek
#define lseek ___xxx_lseek

static __inline__  int    adb_unlink(const char*  path)
{
    return  unlink(path);
}
#undef  unlink
#define unlink  ___xxx_unlink

static __inline__  int  adb_creat(const char*  path, int  mode)
{
    int  fd = TEMP_FAILURE_RETRY( creat( path, mode ) );

    if ( fd < 0 )
        return -1;

    close_on_exec(fd);
    return fd;
}
#undef   creat
#define  creat  ___xxx_creat

static __inline__ int unix_isatty(int fd) {
    return isatty(fd);
}
#define  isatty  ___xxx_isatty

// Helper for network_* functions.
inline int _fd_set_error_str(int fd, std::string* error) {
  if (fd == -1) {
    *error = strerror(errno);
  }
  return fd;
}

inline int network_inaddr_any_server(int port, int type, std::string* error) {
  return _fd_set_error_str(socket_inaddr_any_server(port, type), error);
}

inline int network_local_client(const char* name, int namespace_id, int type, std::string* error) {
    return _fd_set_error_str(socket_local_client(name, namespace_id, type), error);
}

inline int network_local_server(const char* name, int namespace_id, int type, std::string* error) {
    return _fd_set_error_str(socket_local_server(name, namespace_id, type), error);
}

int network_connect(const std::string& host, int port, int type, int timeout, std::string* error);

static __inline__ int  adb_socket_accept(int  serverfd, struct sockaddr*  addr, socklen_t  *addrlen)
{
    int fd;

    fd = TEMP_FAILURE_RETRY( accept( serverfd, addr, addrlen ) );
    if (fd >= 0)
        close_on_exec(fd);

    return fd;
}

#undef   accept
#define  accept  ___xxx_accept

inline int adb_socket_get_local_port(int fd) {
    return socket_get_local_port(fd);
}

// Operate on a file descriptor returned from unix_open() or a well-known file
// descriptor such as STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO.
//
// On Unix, unix_read(), unix_write(), unix_close() map to adb_read(),
// adb_write(), adb_close() (which all map to Unix system calls), but the
// Windows implementations (in the ifdef above and in sysdeps_win32.cpp) call
// into the C Runtime and its configurable CR/LF translation (which is settable
// via _setmode()).
#define  unix_read   adb_read
#define  unix_write  adb_write
#define unix_lseek adb_lseek
#define  unix_close  adb_close

static __inline__ int adb_thread_setname(const std::string& name) {
#ifdef __APPLE__
    return pthread_setname_np(name.c_str());
#else
    // Both bionic and glibc's pthread_setname_np fails rather than truncating long strings.
    // glibc doesn't have strlcpy, so we have to fake it.
    char buf[16];  // MAX_TASK_COMM_LEN, but that's not exported by the kernel headers.
    strncpy(buf, name.c_str(), sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    return pthread_setname_np(pthread_self(), buf);
#endif
}

static __inline__ int  adb_setsockopt( int  fd, int  level, int  optname, const void*  optval, socklen_t  optlen )
{
    return setsockopt( fd, level, optname, optval, optlen );
}

#undef   setsockopt
#define  setsockopt  ___xxx_setsockopt

static __inline__ int  unix_socketpair( int  d, int  type, int  protocol, int sv[2] )
{
    return socketpair( d, type, protocol, sv );
}

static __inline__ int  adb_socketpair( int  sv[2] )
{
    int  rc;

    rc = unix_socketpair( AF_UNIX, SOCK_STREAM, 0, sv );
    if (rc < 0)
        return -1;

    close_on_exec( sv[0] );
    close_on_exec( sv[1] );
    return 0;
}

#undef   socketpair
#define  socketpair   ___xxx_socketpair

typedef struct pollfd adb_pollfd;
static __inline__ int adb_poll(adb_pollfd* fds, size_t nfds, int timeout) {
    return TEMP_FAILURE_RETRY(poll(fds, nfds, timeout));
}

#define poll ___xxx_poll

static __inline__ int  adb_mkdir(const std::string& path, int mode)
{
    return mkdir(path.c_str(), mode);
}

#undef   mkdir
#define  mkdir  ___xxx_mkdir

static __inline__ int adb_is_absolute_host_path(const char* path) {
    return path[0] == '/';
}

#endif /* !_WIN32 */

static inline void disable_tcp_nagle(int fd) {
    int off = 1;
    adb_setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &off, sizeof(off));
}

// Sets TCP socket |fd| to send a keepalive TCP message every |interval_sec| seconds. Set
// |interval_sec| to 0 to disable keepalives. If keepalives are enabled, the connection will be
// configured to drop after 10 missed keepalives. Returns true on success.
bool set_tcp_keepalive(int fd, int interval_sec);

#if defined(_WIN32)
// Win32 defines ERROR, which we don't need, but which conflicts with google3 logging.
#undef ERROR
#endif

#endif /* _ADB_SYSDEPS_H */
