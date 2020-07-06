#!/usr/bin/env python3
#
# Copyright (C) 2015 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Tests for the adb program itself.

This differs from things in test_device.py in that there is no API for these
things. Most of these tests involve specific error messages or the help text.
"""

import contextlib
import os
import random
import select
import socket
import string
import struct
import subprocess
import sys
import threading
import time
import unittest
import warnings
from importlib import util

def find_open_port():
    # Find an open port.
    with socket.socket() as s:
        s.bind(("localhost", 0))
        return s.getsockname()[1]

@contextlib.contextmanager
def fake_adbd(protocol=socket.AF_INET, port=0):
    """Creates a fake ADB daemon that just replies with a CNXN packet."""

    serversock = socket.socket(protocol, socket.SOCK_STREAM)
    serversock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if protocol == socket.AF_INET:
        serversock.bind(("127.0.0.1", port))
    else:
        serversock.bind(("::1", port))
    serversock.listen(1)

    # A pipe that is used to signal the thread that it should terminate.
    readsock, writesock = socket.socketpair()

    def _adb_packet(command: bytes, arg0: int, arg1: int, data: bytes) -> bytes:
        bin_command = struct.unpack("I", command)[0]
        buf = struct.pack("IIIIII", bin_command, arg0, arg1, len(data), 0,
                          bin_command ^ 0xffffffff)
        buf += data
        return buf

    def _handle(sock):
        with contextlib.closing(sock) as serversock:
            rlist = [readsock, serversock]
            cnxn_sent = {}
            while True:
                read_ready, _, _ = select.select(rlist, [], [])
                for ready in read_ready:
                    if ready == readsock:
                        # Closure pipe
                        for f in rlist:
                            f.close()
                        return
                    elif ready == serversock:
                        # Server socket
                        conn, _ = ready.accept()
                        rlist.append(conn)
                    else:
                        # Client socket
                        data = ready.recv(1024)
                        if not data or data.startswith(b"OPEN"):
                            if ready in cnxn_sent:
                                del cnxn_sent[ready]
                            ready.shutdown(socket.SHUT_RDWR)
                            ready.close()
                            rlist.remove(ready)
                            continue
                        if ready in cnxn_sent:
                            continue
                        cnxn_sent[ready] = True
                        ready.sendall(_adb_packet(b"CNXN", 0x01000001, 1024 * 1024,
                                                  b"device::ro.product.name=fakeadb"))

    port = serversock.getsockname()[1]
    server_thread = threading.Thread(target=_handle, args=(serversock,))
    server_thread.start()

    try:
        yield port, writesock
    finally:
        writesock.close()
        server_thread.join()


@contextlib.contextmanager
def adb_connect(unittest, serial):
    """Context manager for an ADB connection.

    This automatically disconnects when done with the connection.
    """

    output = subprocess.check_output(["adb", "connect", serial])
    unittest.assertEqual(output.strip(),
                        "connected to {}".format(serial).encode("utf8"))

    try:
        yield
    finally:
        # Perform best-effort disconnection. Discard the output.
        subprocess.Popen(["adb", "disconnect", serial],
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE).communicate()


@contextlib.contextmanager
def adb_server():
    """Context manager for an ADB server.

    This creates an ADB server and returns the port it's listening on.
    """

    port = find_open_port()
    read_pipe, write_pipe = os.pipe()

    if sys.platform == "win32":
        import msvcrt
        write_handle = msvcrt.get_osfhandle(write_pipe)
        os.set_handle_inheritable(write_handle, True)
        reply_fd = str(write_handle)
    else:
        os.set_inheritable(write_pipe, True)
        reply_fd = str(write_pipe)

    proc = subprocess.Popen(["adb", "-L", "tcp:localhost:{}".format(port),
                             "fork-server", "server",
                             "--reply-fd", reply_fd], close_fds=False)
    try:
        os.close(write_pipe)
        greeting = os.read(read_pipe, 1024)
        assert greeting == b"OK\n", repr(greeting)
        yield port
    finally:
        proc.terminate()
        proc.wait()


class CommandlineTest(unittest.TestCase):
    """Tests for the ADB commandline."""

    def test_help(self):
        """Make sure we get _something_ out of help."""
        out = subprocess.check_output(
            ["adb", "help"], stderr=subprocess.STDOUT)
        self.assertGreater(len(out), 0)

    def test_version(self):
        """Get a version number out of the output of adb."""
        lines = subprocess.check_output(["adb", "version"]).splitlines()
        version_line = lines[0]
        self.assertRegex(
            version_line, rb"^Android Debug Bridge version \d+\.\d+\.\d+$")
        if len(lines) == 2:
            # Newer versions of ADB have a second line of output for the
            # version that includes a specific revision (git SHA).
            revision_line = lines[1]
            self.assertRegex(
                revision_line, rb"^Revision [0-9a-f]{12}-android$")

    def test_tcpip_error_messages(self):
        """Make sure 'adb tcpip' parsing is sane."""
        proc = subprocess.Popen(["adb", "tcpip"],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        out, _ = proc.communicate()
        self.assertEqual(1, proc.returncode)
        self.assertIn(b"requires an argument", out)

        proc = subprocess.Popen(["adb", "tcpip", "foo"],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        out, _ = proc.communicate()
        self.assertEqual(1, proc.returncode)
        self.assertIn(b"invalid port", out)


class ServerTest(unittest.TestCase):
    """Tests for the ADB server."""

    @staticmethod
    def _read_pipe_and_set_event(pipe, event):
        """Reads a pipe until it is closed, then sets the event."""
        pipe.read()
        event.set()

    def test_handle_inheritance(self):
        """Test that launch_server() does not inherit handles.

        launch_server() should not let the adb server inherit
        stdin/stdout/stderr handles, which can cause callers of adb.exe to hang.
        This test also runs fine on unix even though the impetus is an issue
        unique to Windows.
        """
        # This test takes 5 seconds to run on Windows: if there is no adb server
        # running on the the port used below, adb kill-server tries to make a
        # TCP connection to a closed port and that takes 1 second on Windows;
        # adb start-server does the same TCP connection which takes another
        # second, and it waits 3 seconds after starting the server.

        # Start adb client with redirected stdin/stdout/stderr to check if it
        # passes those redirections to the adb server that it starts. To do
        # this, run an instance of the adb server on a non-default port so we
        # don't conflict with a pre-existing adb server that may already be
        # setup with adb TCP/emulator connections. If there is a pre-existing
        # adb server, this also tests whether multiple instances of the adb
        # server conflict on adb.log.

        port = find_open_port()

        try:
            # We get warnings for unclosed files for the subprocess's pipes,
            # and it's somewhat cumbersome to close them, so just ignore this.
            warnings.simplefilter("ignore", ResourceWarning)

            # Run the adb client and have it start the adb server.
            proc = subprocess.Popen(["adb", "-P", str(port), "start-server"],
                                    stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)

            # Start threads that set events when stdout/stderr are closed.
            stdout_event = threading.Event()
            stdout_thread = threading.Thread(
                target=ServerTest._read_pipe_and_set_event,
                args=(proc.stdout, stdout_event))
            stdout_thread.start()

            stderr_event = threading.Event()
            stderr_thread = threading.Thread(
                target=ServerTest._read_pipe_and_set_event,
                args=(proc.stderr, stderr_event))
            stderr_thread.start()

            # Wait for the adb client to finish. Once that has occurred, if
            # stdin/stderr/stdout are still open, it must be open in the adb
            # server.
            proc.wait()

            # Try to write to stdin which we expect is closed. If it isn't
            # closed, we should get an IOError. If we don't get an IOError,
            # stdin must still be open in the adb server. The adb client is
            # probably letting the adb server inherit stdin which would be
            # wrong.
            with self.assertRaises(IOError):
                proc.stdin.write(b"x")
                proc.stdin.flush()

            # Wait a few seconds for stdout/stderr to be closed (in the success
            # case, this won't wait at all). If there is a timeout, that means
            # stdout/stderr were not closed and and they must be open in the adb
            # server, suggesting that the adb client is letting the adb server
            # inherit stdout/stderr which would be wrong.
            self.assertTrue(stdout_event.wait(5), "adb stdout not closed")
            self.assertTrue(stderr_event.wait(5), "adb stderr not closed")
            stdout_thread.join()
            stderr_thread.join()
        finally:
            # If we started a server, kill it.
            subprocess.check_output(["adb", "-P", str(port), "kill-server"],
                                    stderr=subprocess.STDOUT)

    @unittest.skipUnless(
        os.name == "posix",
        "adb doesn't yet support IPv6 on Windows",
    )
    def test_starts_on_ipv6_localhost(self):
        """
        Tests that the server can start up on ::1 and that it's accessible
        """

        server_port = find_open_port()
        try:
            subprocess.check_output(
                ["adb", "-L", "tcp:[::1]:{}".format(server_port), "server"],
                stderr=subprocess.STDOUT,
            )
            with fake_adbd() as (port, _):
                with adb_connect(self, serial="localhost:{}".format(port)):
                    pass
        finally:
            # If we started a server, kill it.
            subprocess.check_output(
                ["adb", "-P", str(server_port), "kill-server"],
                stderr=subprocess.STDOUT,
            )




class EmulatorTest(unittest.TestCase):
    """Tests for the emulator connection."""

    def _reset_socket_on_close(self, sock):
        """Use SO_LINGER to cause TCP RST segment to be sent on socket close."""
        # The linger structure is two shorts on Windows, but two ints on Unix.
        linger_format = "hh" if os.name == "nt" else "ii"
        l_onoff = 1
        l_linger = 0

        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                        struct.pack(linger_format, l_onoff, l_linger))
        # Verify that we set the linger structure properly by retrieving it.
        linger = sock.getsockopt(socket.SOL_SOCKET, socket.SO_LINGER, 16)
        self.assertEqual((l_onoff, l_linger),
                         struct.unpack_from(linger_format, linger))

    def test_emu_kill(self):
        """Ensure that adb emu kill works.

        Bug: https://code.google.com/p/android/issues/detail?id=21021
        """
        with contextlib.closing(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as listener:
            # Use SO_REUSEADDR so subsequent runs of the test can grab the port
            # even if it is in TIME_WAIT.
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(4)
            port = listener.getsockname()[1]

            # Now that listening has started, start adb emu kill, telling it to
            # connect to our mock emulator.
            proc = subprocess.Popen(
                ["adb", "-s", "emulator-" + str(port), "emu", "kill"],
                stderr=subprocess.STDOUT)

            accepted_connection, addr = listener.accept()
            with contextlib.closing(accepted_connection) as conn:
                # If WSAECONNABORTED (10053) is raised by any socket calls,
                # then adb probably isn't reading the data that we sent it.
                conn.sendall(("Android Console: type 'help' for a list "
                             "of commands\r\n").encode("utf8"))
                conn.sendall(b"OK\r\n")

                with contextlib.closing(conn.makefile()) as connf:
                    line = connf.readline()
                    if line.startswith("auth"):
                        # Ignore the first auth line.
                        line = connf.readline()
                    self.assertEqual("kill\n", line)
                    self.assertEqual("quit\n", connf.readline())

                conn.sendall(b"OK: killing emulator, bye bye\r\n")

                # Use SO_LINGER to send TCP RST segment to test whether adb
                # ignores WSAECONNRESET on Windows. This happens with the
                # real emulator because it just calls exit() without closing
                # the socket or calling shutdown(SD_SEND). At process
                # termination, Windows sends a TCP RST segment for every
                # open socket that shutdown(SD_SEND) wasn't used on.
                self._reset_socket_on_close(conn)

            # Wait for adb to finish, so we can check return code.
            proc.communicate()

            # If this fails, adb probably isn't ignoring WSAECONNRESET when
            # reading the response from the adb emu kill command (on Windows).
            self.assertEqual(0, proc.returncode)

    def test_emulator_connect(self):
        """Ensure that the emulator can connect.

        Bug: http://b/78991667
        """
        with adb_server() as server_port:
            with fake_adbd() as (port, _):
                serial = "emulator-{}".format(port - 1)
                # Ensure that the emulator is not there.
                try:
                    subprocess.check_output(["adb", "-P", str(server_port),
                                             "-s", serial, "get-state"],
                                            stderr=subprocess.STDOUT)
                    self.fail("Device should not be available")
                except subprocess.CalledProcessError as err:
                    self.assertEqual(
                        err.output.strip(),
                        "error: device '{}' not found".format(serial).encode("utf8"))

                # Let the ADB server know that the emulator has started.
                with contextlib.closing(
                        socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                    sock.connect(("localhost", server_port))
                    command = "host:emulator:{}".format(port).encode("utf8")
                    sock.sendall(b"%04x%s" % (len(command), command))

                # Ensure the emulator is there.
                subprocess.check_call(["adb", "-P", str(server_port),
                                       "-s", serial, "wait-for-device"])
                output = subprocess.check_output(["adb", "-P", str(server_port),
                                                  "-s", serial, "get-state"])
                self.assertEqual(output.strip(), b"device")


class ConnectionTest(unittest.TestCase):
    """Tests for adb connect."""

    def test_connect_ipv4_ipv6(self):
        """Ensure that `adb connect localhost:1234` will try both IPv4 and IPv6.

        Bug: http://b/30313466
        """
        for protocol in (socket.AF_INET, socket.AF_INET6):
            try:
                with fake_adbd(protocol=protocol) as (port, _):
                    serial = "localhost:{}".format(port)
                    with adb_connect(self, serial):
                        pass
            except socket.error:
                print("IPv6 not available, skipping")
                continue

    def test_already_connected(self):
        """Ensure that an already-connected device stays connected."""

        with fake_adbd() as (port, _):
            serial = "localhost:{}".format(port)
            with adb_connect(self, serial):
                # b/31250450: this always returns 0 but probably shouldn't.
                output = subprocess.check_output(["adb", "connect", serial])
                self.assertEqual(
                    output.strip(),
                    "already connected to {}".format(serial).encode("utf8"))

    @unittest.skip("Currently failing b/123247844")
    def test_reconnect(self):
        """Ensure that a disconnected device reconnects."""

        with fake_adbd() as (port, _):
            serial = "localhost:{}".format(port)
            with adb_connect(self, serial):
                # Wait a bit to give adb some time to connect.
                time.sleep(0.25)

                output = subprocess.check_output(["adb", "-s", serial,
                                                  "get-state"])
                self.assertEqual(output.strip(), b"device")

                # This will fail.
                proc = subprocess.Popen(["adb", "-s", serial, "shell", "true"],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT)
                output, _ = proc.communicate()
                self.assertEqual(output.strip(), b"error: closed")

                subprocess.check_call(["adb", "-s", serial, "wait-for-device"])

                output = subprocess.check_output(["adb", "-s", serial,
                                                  "get-state"])
                self.assertEqual(output.strip(), b"device")

                # Once we explicitly kick a device, it won't attempt to
                # reconnect.
                output = subprocess.check_output(["adb", "disconnect", serial])
                self.assertEqual(
                    output.strip(),
                    "disconnected {}".format(serial).encode("utf8"))
                try:
                    subprocess.check_output(["adb", "-s", serial, "get-state"],
                                            stderr=subprocess.STDOUT)
                    self.fail("Device should not be available")
                except subprocess.CalledProcessError as err:
                    self.assertEqual(
                        err.output.strip(),
                        "error: device '{}' not found".format(serial).encode("utf8"))


class DisconnectionTest(unittest.TestCase):
    """Tests for adb disconnect."""

    def test_disconnect(self):
        """Ensure that `adb disconnect` takes effect immediately."""

        def _devices(port):
            output = subprocess.check_output(["adb", "-P", str(port), "devices"])
            return [x.split("\t") for x in output.decode("utf8").strip().splitlines()[1:]]

        with adb_server() as server_port:
            with fake_adbd() as (port, sock):
                device_name = "localhost:{}".format(port)
                output = subprocess.check_output(["adb", "-P", str(server_port),
                                                  "connect", device_name])
                self.assertEqual(output.strip(),
                                  "connected to {}".format(device_name).encode("utf8"))


                self.assertEqual(_devices(server_port), [[device_name, "device"]])

                # Send a deliberately malformed packet to make the device go offline.
                packet = struct.pack("IIIIII", 0, 0, 0, 0, 0, 0)
                sock.sendall(packet)

                # Wait a bit.
                time.sleep(0.1)

                self.assertEqual(_devices(server_port), [[device_name, "offline"]])

                # Disconnect the device.
                output = subprocess.check_output(["adb", "-P", str(server_port),
                                                  "disconnect", device_name])

                # Wait a bit.
                time.sleep(0.1)

                self.assertEqual(_devices(server_port), [])


@unittest.skipUnless(sys.platform == "win32", "requires Windows")
class PowerTest(unittest.TestCase):
    def test_resume_usb_kick(self):
        """Resuming from sleep/hibernate should kick USB devices."""
        try:
            usb_serial = subprocess.check_output(["adb", "-d", "get-serialno"]).strip()
        except subprocess.CalledProcessError:
            # If there are multiple USB devices, we don't have a way to check whether the selected
            # device is USB.
            raise unittest.SkipTest('requires single USB device')

        try:
            serial = subprocess.check_output(["adb", "get-serialno"]).strip()
        except subprocess.CalledProcessError:
            # Did you forget to select a device with $ANDROID_SERIAL?
            raise unittest.SkipTest('requires $ANDROID_SERIAL set to a USB device')

        # Test only works with USB devices because adb _power_notification_thread does not kick
        # non-USB devices on resume event.
        if serial != usb_serial:
            raise unittest.SkipTest('requires USB device')

        # Run an adb shell command in the background that takes a while to complete.
        proc = subprocess.Popen(['adb', 'shell', 'sleep', '5'])

        # Wait for startup of adb server's _power_notification_thread.
        time.sleep(0.1)

        # Simulate resuming from sleep/hibernation by sending Windows message.
        import ctypes
        from ctypes import wintypes
        HWND_BROADCAST = 0xffff
        WM_POWERBROADCAST = 0x218
        PBT_APMRESUMEAUTOMATIC = 0x12

        PostMessageW = ctypes.windll.user32.PostMessageW
        PostMessageW.restype = wintypes.BOOL
        PostMessageW.argtypes = (wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)
        result = PostMessageW(HWND_BROADCAST, WM_POWERBROADCAST, PBT_APMRESUMEAUTOMATIC, 0)
        if not result:
            raise ctypes.WinError()

        # Wait for connection to adb shell to be broken by _power_notification_thread detecting the
        # Windows message.
        start = time.time()
        proc.wait()
        end = time.time()

        # If the power event was detected, the adb shell command should be broken very quickly.
        self.assertLess(end - start, 2)

"""Use 'adb mdns check' to see if mdns discovery is available."""
def is_adb_mdns_available():
    with adb_server() as server_port:
        output = subprocess.check_output(["adb", "-P", str(server_port),
                                          "mdns", "check"]).strip()
        return output.startswith(b"mdns daemon version")

"""Check if we have zeroconf python library installed"""
def is_zeroconf_installed():
    zeroconf_spec = util.find_spec("zeroconf")
    return zeroconf_spec is not None

@contextlib.contextmanager
def zeroconf_context(ipversion):
    from zeroconf import Zeroconf
    """Context manager for a zeroconf instance

    This creates a zeroconf instance and returns it.
    """

    try:
        zeroconf = Zeroconf(ip_version=ipversion)
        yield zeroconf
    finally:
        zeroconf.close()

@contextlib.contextmanager
def zeroconf_register_service(zeroconf_ctx, info):
    """Context manager for a zeroconf service

    Registers a service and unregisters it on cleanup. Returns the ServiceInfo
    supplied.
    """

    try:
        zeroconf_ctx.register_service(info)
        yield info
    finally:
        zeroconf_ctx.unregister_service(info)

@contextlib.contextmanager
def zeroconf_register_services(zeroconf_ctx, infos):
    """Context manager for multiple zeroconf services

    Registers all services given and unregisters all on cleanup. Returns the ServiceInfo
    list supplied.
    """

    try:
        for info in infos:
            zeroconf_ctx.register_service(info)
        yield infos
    finally:
        for info in infos:
            zeroconf_ctx.unregister_service(info)

"""Should match the service names listed in adb_mdns.h"""
class MdnsTest:
    """Tests for adb mdns."""
    @staticmethod
    def _mdns_services(port):
        output = subprocess.check_output(["adb", "-P", str(port), "mdns", "services"])
        return [x.split("\t") for x in output.decode("utf8").strip().splitlines()[1:]]

    @staticmethod
    def _devices(port):
        output = subprocess.check_output(["adb", "-P", str(port), "devices"])
        return [x.split("\t") for x in output.decode("utf8").strip().splitlines()[1:]]


    class Base(unittest.TestCase):
        @contextlib.contextmanager
        def _adb_mdns_connect(self, server_port, mdns_instance, serial, should_connect):
            """Context manager for an ADB connection.

            This automatically disconnects when done with the connection.
            """

            output = subprocess.check_output(["adb", "-P", str(server_port), "connect", mdns_instance])
            if should_connect:
                self.assertEqual(output.strip(), "connected to {}".format(serial).encode("utf8"))
            else:
                self.assertTrue(output.startswith("failed to resolve host: '{}'"
                    .format(mdns_instance).encode("utf8")))

            try:
                yield
            finally:
                # Perform best-effort disconnection. Discard the output.
                subprocess.Popen(["adb", "disconnect", serial],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE).communicate()


        @unittest.skipIf(not is_zeroconf_installed(), "zeroconf library not installed")
        def test_mdns_services_register_unregister(self):
            """Ensure that `adb mdns services` correctly adds and removes a service
            """
            from zeroconf import IPVersion, ServiceInfo

            with adb_server() as server_port:
                output = subprocess.check_output(["adb", "-P", str(server_port),
                                                  "mdns", "services"]).strip()
                self.assertTrue(output.startswith(b"List of discovered mdns services"))

                """TODO(joshuaduong): Add ipv6 tests once we have it working in adb"""
                """Register/Unregister a service"""
                with zeroconf_context(IPVersion.V4Only) as zc:
                    serv_instance = "my_fake_test_service"
                    serv_type = "_" + self.service_name + "._tcp."
                    serv_ipaddr = socket.inet_aton("1.2.3.4")
                    serv_port = 12345
                    service_info = ServiceInfo(
                            serv_type + "local.",
                            name=serv_instance + "." + serv_type + "local.",
                            addresses=[serv_ipaddr],
                            port=serv_port)
                    with zeroconf_register_service(zc, service_info) as info:
                        """Give adb some time to register the service"""
                        time.sleep(1)
                        self.assertTrue(any((serv_instance in line and serv_type in line)
                            for line in MdnsTest._mdns_services(server_port)))

                    """Give adb some time to unregister the service"""
                    time.sleep(1)
                    self.assertFalse(any((serv_instance in line and serv_type in line)
                        for line in MdnsTest._mdns_services(server_port)))

        @unittest.skipIf(not is_zeroconf_installed(), "zeroconf library not installed")
        def test_mdns_services_register_unregister_multiple(self):
            """Ensure that `adb mdns services` correctly adds and removes multiple services
            """
            from zeroconf import IPVersion, ServiceInfo

            with adb_server() as server_port:
                output = subprocess.check_output(["adb", "-P", str(server_port),
                                                  "mdns", "services"]).strip()
                self.assertTrue(output.startswith(b"List of discovered mdns services"))

                """TODO(joshuaduong): Add ipv6 tests once we have it working in adb"""
                """Register/Unregister a service"""
                with zeroconf_context(IPVersion.V4Only) as zc:
                    srvs = {
                        'mdns_name': ["testservice0", "testservice1", "testservice2"],
                        'mdns_type': "_" + self.service_name + "._tcp.",
                        'ipaddr': [
                            socket.inet_aton("192.168.0.1"),
                            socket.inet_aton("10.0.0.255"),
                            socket.inet_aton("172.16.1.100")],
                        'port': [10000, 20000, 65535]}
                    srv_infos = []
                    for i in range(len(srvs['mdns_name'])):
                        srv_infos.append(ServiceInfo(
                                srvs['mdns_type'] + "local.",
                                name=srvs['mdns_name'][i] + "." + srvs['mdns_type'] + "local.",
                                addresses=[srvs['ipaddr'][i]],
                                port=srvs['port'][i]))

                    """ Register all devices, then unregister"""
                    with zeroconf_register_services(zc, srv_infos) as infos:
                        """Give adb some time to register the service"""
                        time.sleep(1)
                        for i in range(len(srvs['mdns_name'])):
                            self.assertTrue(any((srvs['mdns_name'][i] in line and srvs['mdns_type'] in line)
                                for line in MdnsTest._mdns_services(server_port)))

                    """Give adb some time to unregister the service"""
                    time.sleep(1)
                    for i in range(len(srvs['mdns_name'])):
                        self.assertFalse(any((srvs['mdns_name'][i] in line and srvs['mdns_type'] in line)
                            for line in MdnsTest._mdns_services(server_port)))

        @unittest.skipIf(not is_zeroconf_installed(), "zeroconf library not installed")
        def test_mdns_connect(self):
            """Ensure that `adb connect` by mdns instance name works (for non-pairing services)
            """
            from zeroconf import IPVersion, ServiceInfo

            with adb_server() as server_port:
                with zeroconf_context(IPVersion.V4Only) as zc:
                    serv_instance = "fakeadbd-" + ''.join(
                            random.choice(string.ascii_letters) for i in range(4))
                    serv_type = "_" + self.service_name + "._tcp."
                    serv_ipaddr = socket.inet_aton("127.0.0.1")
                    should_connect = self.service_name != "adb-tls-pairing"
                    with fake_adbd() as (port, _):
                        service_info = ServiceInfo(
                                serv_type + "local.",
                                name=serv_instance + "." + serv_type + "local.",
                                addresses=[serv_ipaddr],
                                port=port)
                        with zeroconf_register_service(zc, service_info) as info:
                            """Give adb some time to register the service"""
                            time.sleep(1)
                            self.assertTrue(any((serv_instance in line and serv_type in line)
                                for line in MdnsTest._mdns_services(server_port)))
                            full_name = '.'.join([serv_instance, serv_type])
                            with self._adb_mdns_connect(server_port, serv_instance, full_name,
                                    should_connect):
                                if should_connect:
                                    self.assertEqual(MdnsTest._devices(server_port),
                                            [[full_name, "device"]])

                        """Give adb some time to unregister the service"""
                        time.sleep(1)
                        self.assertFalse(any((serv_instance in line and serv_type in line)
                            for line in MdnsTest._mdns_services(server_port)))


@unittest.skipIf(not is_adb_mdns_available(), "mdns feature not available")
class MdnsTestAdb(MdnsTest.Base):
    service_name = "adb"


@unittest.skipIf(not is_adb_mdns_available(), "mdns feature not available")
class MdnsTestAdbTlsConnect(MdnsTest.Base):
    service_name = "adb-tls-connect"


@unittest.skipIf(not is_adb_mdns_available(), "mdns feature not available")
class MdnsTestAdbTlsPairing(MdnsTest.Base):
    service_name = "adb-tls-pairing"


def main():
    """Main entrypoint."""
    random.seed(0)
    unittest.main(verbosity=3)


if __name__ == "__main__":
    main()
