/* implement the "debug-ports" and "track-debug-ports" device services */
#include "sysdeps.h"
#define  TRACE_TAG   TRACE_JDWP
#include "adb.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* here's how these things work.

   when adbd starts, it creates a unix server socket
   named @vm-debug-control (@ is a shortcut for "first byte is zero"
   to use the private namespace instead of the file system)

   when a new JDWP daemon thread starts in a new VM process, it creates
   a connection to @vm-debug-control to announce its availability.


     JDWP thread                             @vm-debug-control
         |                                         |
         |------------------------------->         |
         | hello I'm in process <pid>              |
         |                                         |
         |                                         |

    the connection is kept alive. it will be closed automatically if
    the JDWP process terminates (this allows adbd to detect dead
    processes).

    adbd thus maintains a list of "active" JDWP processes. it can send
    its content to clients through the "device:debug-ports" service,
    or even updates through the "device:track-debug-ports" service.

    when a debugger wants to connect, it simply runs the command
    equivalent to  "adb forward tcp:<hostport> jdwp:<pid>"

    "jdwp:<pid>" is a new forward destination format used to target
    a given JDWP process on the device. when sutch a request arrives,
    adbd does the following:

      - first, it calls socketpair() to create a pair of equivalent
        sockets.

      - it attaches the first socket in the pair to a local socket
        which is itself attached to the transport's remote socket:


      - it sends the file descriptor of the second socket directly
        to the JDWP process with the help of sendmsg()


     JDWP thread                             @vm-debug-control
         |                                         |
         |                  <----------------------|
         |           OK, try this file descriptor  |
         |                                         |
         |                                         |

   then, the JDWP thread uses this new socket descriptor as its
   pass-through connection to the debugger (and receives the
   JDWP-Handshake message, answers to it, etc...)

   this gives the following graphics:
                    ____________________________________
                   |                                    |
                   |          ADB Server (host)         |
                   |                                    |
        Debugger <---> LocalSocket <----> RemoteSocket  |
                   |                           ^^       |
                   |___________________________||_______|
                                               ||
                                     Transport ||
           (TCP for emulator - USB for device) ||
                                               ||
                    ___________________________||_______
                   |                           ||       |
                   |          ADBD  (device)   ||       |
                   |                           VV       |
         JDWP <======> LocalSocket <----> RemoteSocket  |
                   |                                    |
                   |____________________________________|

    due to the way adb works, this doesn't need a special socket
    type or fancy handling of socket termination if either the debugger
    or the JDWP process closes the connection.

    THIS IS THE SIMPLEST IMPLEMENTATION I COULD FIND, IF YOU HAPPEN
    TO HAVE A BETTER IDEA, LET ME KNOW - Digit

**********************************************************************/

/** JDWP PID List Support Code
 ** for each JDWP process, we record its pid and its connected socket
 **/

#define  MAX_OUT_FDS   4

#if !ADB_HOST

#include <sys/socket.h>
#include <sys/un.h>

typedef struct JdwpProcess  JdwpProcess;
struct JdwpProcess {
    JdwpProcess*  next;
    JdwpProcess*  prev;
    int           pid;
    int           socket;
    fdevent*      fde;

    char          in_buff[4];  /* input character to read PID */
    int           in_len;      /* number from JDWP process    */

    int           out_fds[MAX_OUT_FDS]; /* output array of file descriptors */
    int           out_count;            /* to send to the JDWP process      */
};

static JdwpProcess  _jdwp_list;

static int
jdwp_process_list( char*  buffer, int  bufferlen )
{
    char*         end  = buffer + bufferlen;
    char*         p    = buffer;
    JdwpProcess*  proc = _jdwp_list.next;

    for ( ; proc != &_jdwp_list; proc = proc->next ) {
        int  len;

        /* skip transient connections */
        if (proc->pid < 0)
            continue;

        len = snprintf(p, end-p, "%d\n", proc->pid);
        if (p + len >= end)
            break;
        p += len;
    }
    p[0] = 0;
    return (p - buffer);
}


static int
jdwp_process_list_msg( char*  buffer, int  bufferlen )
{
    char  head[5];
    int   len = jdwp_process_list( buffer+4, bufferlen-4 );
    snprintf(head, sizeof head, "%04x", len);
    memcpy(buffer, head, 4);
    return len + 4;
}


static void  jdwp_process_list_updated(void);

static void
jdwp_process_free( JdwpProcess*  proc )
{
    if (proc) {
        int  n;

        proc->prev->next = proc->next;
        proc->next->prev = proc->prev;

        if (proc->socket >= 0) {
            adb_shutdown(proc->socket);
            adb_close(proc->socket);
            proc->socket = -1;
        }

        if (proc->fde != NULL) {
            fdevent_destroy(proc->fde);
            proc->fde = NULL;
        }
        proc->pid = -1;

        for (n = 0; n < proc->out_count; n++) {
            adb_close(proc->out_fds[n]);
        }
        proc->out_count = 0;

        free(proc);

        jdwp_process_list_updated();
    }
}


static void  jdwp_process_event(int, unsigned, void*);  /* forward */


static JdwpProcess*
jdwp_process_alloc( int  socket )
{
    JdwpProcess*  proc = calloc(1,sizeof(*proc));

    if (proc == NULL) {
        D("not enough memory to create new JDWP process\n");
        return NULL;
    }

    proc->socket = socket;
    proc->pid    = -1;
    proc->next   = proc;
    proc->prev   = proc;

    proc->fde = fdevent_create( socket, jdwp_process_event, proc );
    if (proc->fde == NULL) {
        D("could not create fdevent for new JDWP process\n" );
        free(proc);
        return NULL;
    }

    proc->fde->state |= FDE_DONT_CLOSE;
    proc->in_len      = 0;
    proc->out_count   = 0;

    /* append to list */
    proc->next = &_jdwp_list;
    proc->prev = proc->next->prev;

    proc->prev->next = proc;
    proc->next->prev = proc;

    /* start by waiting for the PID */
    fdevent_add(proc->fde, FDE_READ);

    return proc;
}


static void
jdwp_process_event( int  socket, unsigned  events, void*  _proc )
{
    JdwpProcess*  proc = _proc;

    if (events & FDE_READ) {
        if (proc->pid < 0) {
            /* read the PID as a 4-hexchar string */
            char*  p    = proc->in_buff + proc->in_len;
            int    size = 4 - proc->in_len;
            char   temp[5];
            while (size > 0) {
                int  len = recv( socket, p, size, 0 );
                if (len < 0) {
                    if (errno == EINTR)
                        continue;
                    if (errno == EAGAIN)
                        return;
                    /* this can fail here if the JDWP process crashes very fast */
                    D("weird unknown JDWP process failure: %s\n",
                      strerror(errno));

                    goto CloseProcess;
                }
                if (len == 0) {  /* end of stream ? */
                    D("weird end-of-stream from unknown JDWP process\n");
                    goto CloseProcess;
                }
                p            += len;
                proc->in_len += len;
                size         -= len;
            }
            /* we have read 4 characters, now decode the pid */
            memcpy(temp, proc->in_buff, 4);
            temp[4] = 0;

            if (sscanf( temp, "%04x", &proc->pid ) != 1) {
                D("could not decode JDWP %p PID number: '%s'\n", proc, temp);
                goto CloseProcess;
            }

            /* all is well, keep reading to detect connection closure */
            D("Adding pid %d to jdwp process list\n", proc->pid);
            jdwp_process_list_updated();
        }
        else
        {
            /* the pid was read, if we get there it's probably because the connection
             * was closed (e.g. the JDWP process exited or crashed) */
            char  buf[32];

            for (;;) {
                int  len = recv(socket, buf, sizeof(buf), 0);

                if (len <= 0) {
                    if (len < 0 && errno == EINTR)
                        continue;
                    if (len < 0 && errno == EAGAIN)
                        return;
                    else {
                        D("terminating JDWP %d connection: %s\n", proc->pid,
                          strerror(errno));
                        break;
                    }
                }
                else {
                    D( "ignoring unexpected JDWP %d control socket activity (%d bytes)\n",
                       proc->pid, len );
                }
            }

        CloseProcess:
            if (proc->pid >= 0)
                D( "remove pid %d to jdwp process list\n", proc->pid );
            jdwp_process_free(proc);
            return;
        }
    }

    if (events & FDE_WRITE) {
        D("trying to write to JDWP pid controli (count=%d first=%d) %d\n",
          proc->pid, proc->out_count, proc->out_fds[0]);
        if (proc->out_count > 0) {
            int  fd = proc->out_fds[0];
            int  n, ret;
            struct cmsghdr*  cmsg;
            struct msghdr    msg;
            struct iovec     iov;
            char             dummy = '!';
            char             buffer[sizeof(struct cmsghdr) + sizeof(int)];
            int flags;

            iov.iov_base       = &dummy;
            iov.iov_len        = 1;
            msg.msg_name       = NULL;
            msg.msg_namelen    = 0;
            msg.msg_iov        = &iov;
            msg.msg_iovlen     = 1;
            msg.msg_flags      = 0;
            msg.msg_control    = buffer;
            msg.msg_controllen = sizeof(buffer);

            cmsg = CMSG_FIRSTHDR(&msg);
            cmsg->cmsg_len   = msg.msg_controllen;
            cmsg->cmsg_level = SOL_SOCKET;
            cmsg->cmsg_type  = SCM_RIGHTS;
            ((int*)CMSG_DATA(cmsg))[0] = fd;

            flags = fcntl(proc->socket,F_GETFL,0);

            if (flags == -1) {
                D("failed to get cntl flags for socket %d: %s\n",
                  proc->pid, strerror(errno));
                goto CloseProcess;

            }

            if (fcntl(proc->socket, F_SETFL, flags & ~O_NONBLOCK) == -1) {
                D("failed to remove O_NONBLOCK flag for socket %d: %s\n",
                  proc->pid, strerror(errno));
                goto CloseProcess;
            }

            for (;;) {
                ret = sendmsg(proc->socket, &msg, 0);
                if (ret >= 0) {
                    adb_close(fd);
                    break;
                }
                if (errno == EINTR)
                    continue;
                D("sending new file descriptor to JDWP %d failed: %s\n",
                  proc->pid, strerror(errno));
                goto CloseProcess;
            }

            D("sent file descriptor %d to JDWP process %d\n",
              fd, proc->pid);

            for (n = 1; n < proc->out_count; n++)
                proc->out_fds[n-1] = proc->out_fds[n];

            if (fcntl(proc->socket, F_SETFL, flags) == -1) {
                D("failed to set O_NONBLOCK flag for socket %d: %s\n",
                  proc->pid, strerror(errno));
                goto CloseProcess;
            }

            if (--proc->out_count == 0)
                fdevent_del( proc->fde, FDE_WRITE );
        }
    }
}


int
create_jdwp_connection_fd(int  pid)
{
    JdwpProcess*  proc = _jdwp_list.next;

    D("looking for pid %d in JDWP process list\n", pid);
    for ( ; proc != &_jdwp_list; proc = proc->next ) {
        if (proc->pid == pid) {
            goto FoundIt;
        }
    }
    D("search failed !!\n");
    return -1;

FoundIt:
    {
        int  fds[2];

        if (proc->out_count >= MAX_OUT_FDS) {
            D("%s: too many pending JDWP connection for pid %d\n",
              __FUNCTION__, pid);
            return -1;
        }

        if (adb_socketpair(fds) < 0) {
            D("%s: socket pair creation failed: %s\n",
              __FUNCTION__, strerror(errno));
            return -1;
        }

        proc->out_fds[ proc->out_count ] = fds[1];
        if (++proc->out_count == 1)
            fdevent_add( proc->fde, FDE_WRITE );

        return fds[0];
    }
}

/**  VM DEBUG CONTROL SOCKET
 **
 **  we do implement a custom asocket to receive the data
 **/

/* name of the debug control Unix socket */
#define  JDWP_CONTROL_NAME      "\0jdwp-control"
#define  JDWP_CONTROL_NAME_LEN  (sizeof(JDWP_CONTROL_NAME)-1)

typedef struct {
    int       listen_socket;
    fdevent*  fde;

} JdwpControl;


static void
jdwp_control_event(int  s, unsigned events, void*  user);


static int
jdwp_control_init( JdwpControl*  control,
                   const char*   sockname,
                   int           socknamelen )
{
    struct sockaddr_un   addr;
    socklen_t            addrlen;
    int                  s;
    int                  maxpath = sizeof(addr.sun_path);
    int                  pathlen = socknamelen;

    if (pathlen >= maxpath) {
        D( "vm debug control socket name too long (%d extra chars)\n",
           pathlen+1-maxpath );
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, sockname, socknamelen);

    s = socket( AF_UNIX, SOCK_STREAM, 0 );
    if (s < 0) {
        D( "could not create vm debug control socket. %d: %s\n",
           errno, strerror(errno));
        return -1;
    }

    addrlen = (pathlen + sizeof(addr.sun_family));

    if (bind(s, (struct sockaddr*)&addr, addrlen) < 0) {
        D( "could not bind vm debug control socket: %d: %s\n",
           errno, strerror(errno) );
        adb_close(s);
        return -1;
    }

    if ( listen(s, 4) < 0 ) {
        D("listen failed in jdwp control socket: %d: %s\n",
          errno, strerror(errno));
        adb_close(s);
        return -1;
    }

    control->listen_socket = s;

    control->fde = fdevent_create(s, jdwp_control_event, control);
    if (control->fde == NULL) {
        D( "could not create fdevent for jdwp control socket\n" );
        adb_close(s);
        return -1;
    }

    /* only wait for incoming connections */
    fdevent_add(control->fde, FDE_READ);
    close_on_exec(s);

    D("jdwp control socket started (%d)\n", control->listen_socket);
    return 0;
}


static void
jdwp_control_event( int  s, unsigned  events, void*  _control )
{
    JdwpControl*  control = (JdwpControl*) _control;

    if (events & FDE_READ) {
        struct sockaddr   addr;
        socklen_t         addrlen = sizeof(addr);
        int               s = -1;
        JdwpProcess*      proc;

        do {
            s = adb_socket_accept( control->listen_socket, &addr, &addrlen );
            if (s < 0) {
                if (errno == EINTR)
                    continue;
                if (errno == ECONNABORTED) {
                    /* oops, the JDWP process died really quick */
                    D("oops, the JDWP process died really quick\n");
                    return;
                }
                /* the socket is probably closed ? */
                D( "weird accept() failed on jdwp control socket: %s\n",
                   strerror(errno) );
                return;
            }
        }
        while (s < 0);

        proc = jdwp_process_alloc( s );
        if (proc == NULL)
            return;
    }
}


static JdwpControl   _jdwp_control;

/** "jdwp" local service implementation
 ** this simply returns the list of known JDWP process pids
 **/

typedef struct {
    asocket  socket;
    int      pass;
} JdwpSocket;

static void
jdwp_socket_close( asocket*  s )
{
    asocket*  peer = s->peer;

    remove_socket(s);

    if (peer) {
        peer->peer = NULL;
        peer->close(peer);
    }
    free(s);
}

static int
jdwp_socket_enqueue( asocket*  s, apacket*  p )
{
    /* you can't write to this asocket */
    put_apacket(p);
    s->peer->close(s->peer);
    return -1;
}


static void
jdwp_socket_ready( asocket*  s )
{
    JdwpSocket*  jdwp = (JdwpSocket*)s;
    asocket*     peer = jdwp->socket.peer;

   /* on the first call, send the list of pids,
    * on the second one, close the connection
    */
    if (jdwp->pass == 0) {
        apacket*  p = get_apacket();
        p->len = jdwp_process_list((char*)p->data, MAX_PAYLOAD);
        peer->enqueue(peer, p);
        jdwp->pass = 1;
    }
    else {
        peer->close(peer);
    }
}

asocket*
create_jdwp_service_socket( void )
{
    JdwpSocket*  s = calloc(sizeof(*s),1);

    if (s == NULL)
        return NULL;

    install_local_socket(&s->socket);

    s->socket.ready   = jdwp_socket_ready;
    s->socket.enqueue = jdwp_socket_enqueue;
    s->socket.close   = jdwp_socket_close;
    s->pass           = 0;

    return &s->socket;
}

/** "track-jdwp" local service implementation
 ** this periodically sends the list of known JDWP process pids
 ** to the client...
 **/

typedef struct JdwpTracker  JdwpTracker;

struct JdwpTracker {
    asocket       socket;
    JdwpTracker*  next;
    JdwpTracker*  prev;
    int           need_update;
};

static JdwpTracker   _jdwp_trackers_list;


static void
jdwp_process_list_updated(void)
{
    char             buffer[1024];
    int              len;
    JdwpTracker*  t = _jdwp_trackers_list.next;

    len = jdwp_process_list_msg(buffer, sizeof(buffer));

    for ( ; t != &_jdwp_trackers_list; t = t->next ) {
        apacket*  p    = get_apacket();
        asocket*  peer = t->socket.peer;
        memcpy(p->data, buffer, len);
        p->len = len;
        peer->enqueue( peer, p );
    }
}

static void
jdwp_tracker_close( asocket*  s )
{
    JdwpTracker*  tracker = (JdwpTracker*) s;
    asocket*      peer    = s->peer;

    if (peer) {
        peer->peer = NULL;
        peer->close(peer);
    }

    remove_socket(s);

    tracker->prev->next = tracker->next;
    tracker->next->prev = tracker->prev;

    free(s);
}

static void
jdwp_tracker_ready( asocket*  s )
{
    JdwpTracker*  t = (JdwpTracker*) s;

    if (t->need_update) {
        apacket*  p = get_apacket();
        t->need_update = 0;
        p->len = jdwp_process_list_msg((char*)p->data, sizeof(p->data));
        s->peer->enqueue(s->peer, p);
    }
}

static int
jdwp_tracker_enqueue( asocket*  s, apacket*  p )
{
    /* you can't write to this socket */
    put_apacket(p);
    s->peer->close(s->peer);
    return -1;
}


asocket*
create_jdwp_tracker_service_socket( void )
{
    JdwpTracker*  t = calloc(sizeof(*t),1);

    if (t == NULL)
        return NULL;

    t->next = &_jdwp_trackers_list;
    t->prev = t->next->prev;

    t->next->prev = t;
    t->prev->next = t;

    install_local_socket(&t->socket);

    t->socket.ready   = jdwp_tracker_ready;
    t->socket.enqueue = jdwp_tracker_enqueue;
    t->socket.close   = jdwp_tracker_close;
    t->need_update    = 1;

    return &t->socket;
}


int
init_jdwp(void)
{
    _jdwp_list.next = &_jdwp_list;
    _jdwp_list.prev = &_jdwp_list;

    _jdwp_trackers_list.next = &_jdwp_trackers_list;
    _jdwp_trackers_list.prev = &_jdwp_trackers_list;

    return jdwp_control_init( &_jdwp_control,
                              JDWP_CONTROL_NAME,
                              JDWP_CONTROL_NAME_LEN );
}

#endif /* !ADB_HOST */

