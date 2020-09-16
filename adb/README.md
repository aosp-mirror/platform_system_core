# ADB Internals

If you are new to adb source code, you should start by reading [OVERVIEW.TXT](OVERVIEW.TXT) which describes the three components of adb pipeline.

This document is here to boost what can be achieved within a "window of naive interest". You will not find function or class documentation here but rather the "big picture" which should allow you to build a mental map to help navigate the code.

## Three components of adb pipeline

As outlined in the overview, this codebase generates three components (Client, Server (a.k.a Host), and Daemon (a.k.a adbd)). The central part is the Server which runs on the Host computer. On one side the Server exposes a "Smart Socket" to Clients such as adb or DDMLIB. On the other side, the Server continuously monitors for connecting Daemons (as USB devices or TCP emulator). Communication with a device is done with a Transport.

```
+----------+              +------------------------+
|   ADB    +----------+   |      ADB SERVER        |                   +----------+
|  CLIENT  |          |   |                        |              (USB)|   ADBD   |
+----------+          |   |                     Transport+-------------+ (DEVICE) |
                      |   |                        |                   +----------+
+-----------          |   |                        |
|   ADB    |          v   +                        |                   +----------+
|  CLIENT  +--------->SmartSocket                  |              (USB)|   ADBD   |
+----------+          ^   | (TCP/IP)            Transport+-------------+ (DEVICE) |
                      |   |                        |                   +----------+
+----------+          |   |                        |
|  DDMLIB  |          |   |                     Transport+--+          +----------+
|  CLIENT  +----------+   |                        |        |  (TCP/IP)|   ADBD   |
+----------+              +------------------------+        +----------|(EMULATOR)|
                                                                       +----------+
```

The Client and the Server are contained in the same executable and both run on the Host machine. Code sections specific to the Host is enclosed within `ADB_HOST` guard. adbd runs on the Android Device. Daemon specific code is enclosed in `!ADB_HOST` but also sometimes with-in `__ANDROID__` guard.


## "SMART SOCKET" and TRANSPORT

A smart socket is a simple TCP socket with a smart protocol built on top of it. This is what Clients connect onto from the Host side. The Client must always initiate communication via a human readable request but the response format varies. The smart protocol is documented in [SERVICES.TXT](SERVICES.TXT).

On the other side, the Server communicate with a device via a Transport. adb initially targeted devices connecting over USB, which is restricted to a fixed number of data streams. Therefore, adb multiplexes multiple byte streams over a single pipe via Transport. When devices connecting over other mechanisms (e.g. emulators over TCP) were introduced, the existing transport protocol was maintained.

## THREADING MODEL and FDEVENT system

At the heart of both the Server and Daemon is a main thread running an fdevent loop, which is an platform-independent abstraction over poll/epoll/WSAPoll monitoring file descriptors events. Requests and services are usually server from the main thread but some service requests result in new threads being spawned.

To allow for operations to run on the Main thread, fdevent features a RunQueue combined with an interrupt fd to force polling to return.

```
+------------+    +-------------------------^
|  RUNQUEUE  |    |                         |
+------------+    |  POLLING (Main thread)  |
| Function<> |    |                         |
+------------+    |                         |
| Function<> |    ^-^-------^-------^------^^
+------------+      |       |       |       |
|    ...     |      |       |       |       |
+------------+      |       |       |       |
|            |      |       |       |       |
|============|      |       |       |       |
|Interrupt fd+------+  +----+  +----+  +----+
+------------+         fd      Socket  Pipe
```

## ASOCKET, APACKET, and AMESSAGE

The asocket, apacket, and amessage constructs exist only to wrap data while it transits on a Transport. An asocket handles a stream of apackets. An apacket consists in a amessage header featuring a command (`A_SYNC`, `A_OPEN`, `A_CLSE`, `A_WRTE`, `A_OKAY`, ...) followed by a payload (find more documentation in [protocol.txt](protocol.txt). There is no `A_READ` command because an asocket is unidirectional. To model a bi-directional stream, asocket have a peer which go in the opposite direction.

An asocket features a buffer where the elemental unit is an apacket. Is traffic is inbound, the buffer stores apacket until they are consumed. If the traffic is oubound, the buffer store apackets until they are sent down the wire (with `A_WRTE` commands).

```
+---------------------ASocket------------------------+
 |                                                   |
 | +----------------APacket Queue------------------+ |
 | |                                               | |
 | |            APacket     APacket     APacket    | |
 | |          +--------+  +--------+  +--------+   | |
 | |          |AMessage|  |AMessage|  |AMessage|   | |
 | |          +--------+  +--------+  +--------+   | |
 | |          |        |  |        |  |        |   | |
 | |  .....   |        |  |        |  |        |   | |
 | |          |  Data  |  |  Data  |  |  Data  |   | |
 | |          |        |  |        |  |        |   | |
 | |          |        |  |        |  |        |   | |
 | |          +--------+  +--------+  +--------+   | |
 | |                                               | |
 | +-----------------------------------------------+ |
 +---------------------------------------------------+
```

This system allows to multiplex data streams on an unique byte stream.  Without entering too much into details, the amessage fields arg1 and arg2 are used alike in the TCP protocol where local and remote ports identify an unique stream. Note that unlike TCP which feature an "unacknowledged-send window", an apacket is sent only after the previous one has been confirmed to be received.

The two types of asocket (Remote and Local) differentiate between outbound and inbound traffic.

## adbd <-> APPPLICATION communication

This pipeline is detailed in [services.cpp](services.cpp). The JDWP extension implemented by Dalvik/ART are documented in:
- platform/dalvik/+/master/docs/debugmon.html
- platform/dalvik/+/master/docs/debugger.html
