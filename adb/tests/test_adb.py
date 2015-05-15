#!/usr/bin/env python2
"""Simple conformance test for adb.

This script will use the available adb in path and run simple
tests that attempt to touch all accessible attached devices.
"""
import hashlib
import os
import pipes
import random
import re
import shlex
import subprocess
import sys
import tempfile
import unittest


def trace(cmd):
    """Print debug message if tracing enabled."""
    if False:
        print >> sys.stderr, cmd


def call(cmd_str):
    """Run process and return output tuple (stdout, stderr, ret code)."""
    trace(cmd_str)
    process = subprocess.Popen(shlex.split(cmd_str),
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    return stdout, stderr, process.returncode


def call_combined(cmd_str):
    """Run process and return output tuple (stdout+stderr, ret code)."""
    trace(cmd_str)
    process = subprocess.Popen(shlex.split(cmd_str),
                               stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT)
    stdout, _ = process.communicate()
    return stdout, process.returncode


def call_checked(cmd_str):
    """Run process and get stdout+stderr, raise an exception on trouble."""
    trace(cmd_str)
    return subprocess.check_output(shlex.split(cmd_str),
                                   stderr=subprocess.STDOUT)


def call_checked_list(cmd_str):
    return call_checked(cmd_str).split('\n')


def call_checked_list_skip(cmd_str):
    out_list = call_checked_list(cmd_str)

    def is_init_line(line):
        if (len(line) >= 3) and (line[0] == "*") and (line[-2] == "*"):
            return True
        else:
            return False

    return [line for line in out_list if not is_init_line(line)]


def get_device_list():
    output = call_checked_list_skip("adb devices")
    dev_list = []
    for line in output[1:]:
        if line.strip() == "":
            continue
        device, _ = line.split()
        dev_list.append(device)
    return dev_list


def get_attached_device_count():
    return len(get_device_list())


def compute_md5(string):
    hsh = hashlib.md5()
    hsh.update(string)
    return hsh.hexdigest()


class HostFile(object):
    def __init__(self, handle, md5):
        self.handle = handle
        self.md5 = md5
        self.full_path = handle.name
        self.base_name = os.path.basename(self.full_path)


class DeviceFile(object):
    def __init__(self, md5, full_path):
        self.md5 = md5
        self.full_path = full_path
        self.base_name = os.path.basename(self.full_path)


def make_random_host_files(in_dir, num_files, rand_size=True):
    files = {}
    min_size = 1 * (1 << 10)
    max_size = 16 * (1 << 10)
    fixed_size = min_size

    for _ in range(num_files):
        file_handle = tempfile.NamedTemporaryFile(dir=in_dir)

        if rand_size:
            size = random.randrange(min_size, max_size, 1024)
        else:
            size = fixed_size
        rand_str = os.urandom(size)
        file_handle.write(rand_str)
        file_handle.flush()

        md5 = compute_md5(rand_str)
        files[file_handle.name] = HostFile(file_handle, md5)
    return files


def make_random_device_files(adb, in_dir, num_files, rand_size=True):
    files = {}
    min_size = 1 * (1 << 10)
    max_size = 16 * (1 << 10)
    fixed_size = min_size

    for i in range(num_files):
        if rand_size:
            size = random.randrange(min_size, max_size, 1024)
        else:
            size = fixed_size

        base_name = "device_tmpfile" + str(i)
        full_path = in_dir + "/" + base_name

        adb.shell("dd if=/dev/urandom of={} bs={} count=1".format(full_path,
                                                                  size))
        dev_md5, _ = adb.shell("md5sum {}".format(full_path)).split()

        files[full_path] = DeviceFile(dev_md5, full_path)
    return files


class AdbWrapper(object):
    """Convenience wrapper object for the adb command."""
    def __init__(self, device=None, out_dir=None):
        self.device = device
        self.out_dir = out_dir
        self.adb_cmd = "adb "
        if self.device:
            self.adb_cmd += "-s {} ".format(device)
        if self.out_dir:
            self.adb_cmd += "-p {} ".format(out_dir)

    def shell(self, cmd):
        return call_checked(self.adb_cmd + "shell " + cmd)

    def shell_nocheck(self, cmd):
        return call_combined(self.adb_cmd + "shell " + cmd)

    def install(self, filename):
        return call_checked(self.adb_cmd + "install {}".format(pipes.quote(filename)))

    def push(self, local, remote):
        return call_checked(self.adb_cmd + "push {} {}".format(local, remote))

    def pull(self, remote, local):
        return call_checked(self.adb_cmd + "pull {} {}".format(remote, local))

    def sync(self, directory=""):
        return call_checked(self.adb_cmd + "sync {}".format(directory))

    def forward(self, local, remote):
        return call_checked(self.adb_cmd + "forward {} {}".format(local,
                                                                  remote))

    def tcpip(self, port):
        return call_checked(self.adb_cmd + "tcpip {}".format(port))

    def usb(self):
        return call_checked(self.adb_cmd + "usb")

    def root(self):
        return call_checked(self.adb_cmd + "root")

    def unroot(self):
        return call_checked(self.adb_cmd + "unroot")

    def forward_remove(self, local):
        return call_checked(self.adb_cmd + "forward --remove {}".format(local))

    def forward_remove_all(self):
        return call_checked(self.adb_cmd + "forward --remove-all")

    def connect(self, host):
        return call_checked(self.adb_cmd + "connect {}".format(host))

    def disconnect(self, host):
        return call_checked(self.adb_cmd + "disconnect {}".format(host))

    def reverse(self, remote, local):
        return call_checked(self.adb_cmd + "reverse {} {}".format(remote,
                                                                  local))

    def reverse_remove_all(self):
        return call_checked(self.adb_cmd + "reverse --remove-all")

    def reverse_remove(self, remote):
        return call_checked(
            self.adb_cmd + "reverse --remove {}".format(remote))

    def wait(self):
        return call_checked(self.adb_cmd + "wait-for-device")


class AdbBasic(unittest.TestCase):
    def test_shell(self):
        """Check that we can at least cat a file."""
        adb = AdbWrapper()
        out = adb.shell("cat /proc/uptime")
        self.assertEqual(len(out.split()), 2)
        self.assertGreater(float(out.split()[0]), 0.0)
        self.assertGreater(float(out.split()[1]), 0.0)

    def test_help(self):
        """Make sure we get _something_ out of help."""
        out = call_checked("adb help")
        self.assertTrue(len(out) > 0)

    def test_version(self):
        """Get a version number out of the output of adb."""
        out = call_checked("adb version").split()
        version_num = False
        for item in out:
            if re.match(r"[\d+\.]*\d", item):
                version_num = True
        self.assertTrue(version_num)

    def _test_root(self):
        adb = AdbWrapper()
        adb.root()
        adb.wait()
        self.assertEqual("root", adb.shell("id -un").strip())

    def _test_unroot(self):
        adb = AdbWrapper()
        adb.unroot()
        adb.wait()
        self.assertEqual("shell", adb.shell("id -un").strip())

    def test_root_unroot(self):
        """Make sure that adb root and adb unroot work, using id(1)."""
        adb = AdbWrapper()
        original_user = adb.shell("id -un").strip()
        try:
            if original_user == "root":
                self._test_unroot()
                self._test_root()
            elif original_user == "shell":
                self._test_root()
                self._test_unroot()
        finally:
            if original_user == "root":
                adb.root()
            else:
                adb.unroot()
            adb.wait()

    def test_argument_escaping(self):
        """Make sure that argument escaping is somewhat sane."""
        adb = AdbWrapper()

        # http://b/19734868
        # Note that this actually matches ssh(1)'s behavior --- it's
        # converted to "sh -c echo hello; echo world" which sh interprets
        # as "sh -c echo" (with an argument to that shell of "hello"),
        # and then "echo world" back in the first shell.
        result = adb.shell("sh -c 'echo hello; echo world'").splitlines()
        self.assertEqual(["", "world"], result)
        # If you really wanted "hello" and "world", here's what you'd do:
        result = adb.shell("echo hello\;echo world").splitlines()
        self.assertEqual(["hello", "world"], result)

        # http://b/15479704
        self.assertEqual('t', adb.shell("'true && echo t'").strip())
        self.assertEqual('t', adb.shell("sh -c 'true && echo t'").strip())

        # http://b/20564385
        self.assertEqual('t', adb.shell("FOO=a BAR=b echo t").strip())
        self.assertEqual('123Linux', adb.shell("echo -n 123\;uname").strip())

    def test_install_argument_escaping(self):
        """Make sure that install argument escaping works."""
        adb = AdbWrapper()

        # http://b/20323053
        tf = tempfile.NamedTemporaryFile("w", suffix="-text;ls;1.apk")
        self.assertIn("-text;ls;1.apk", adb.install(tf.name))

        # http://b/3090932
        tf = tempfile.NamedTemporaryFile("w", suffix="-Live Hold'em.apk")
        self.assertIn("-Live Hold'em.apk", adb.install(tf.name))


class AdbFile(unittest.TestCase):
    SCRATCH_DIR = "/data/local/tmp"
    DEVICE_TEMP_FILE = SCRATCH_DIR + "/adb_test_file"
    DEVICE_TEMP_DIR = SCRATCH_DIR + "/adb_test_dir"

    def test_push(self):
        """Push a randomly generated file to specified device."""
        kbytes = 512
        adb = AdbWrapper()
        with tempfile.NamedTemporaryFile(mode="w") as tmp:
            rand_str = os.urandom(1024 * kbytes)
            tmp.write(rand_str)
            tmp.flush()

            host_md5 = compute_md5(rand_str)
            adb.shell_nocheck("rm -r {}".format(AdbFile.DEVICE_TEMP_FILE))
            try:
                adb.push(local=tmp.name, remote=AdbFile.DEVICE_TEMP_FILE)
                dev_md5, _ = adb.shell(
                    "md5sum {}".format(AdbFile.DEVICE_TEMP_FILE)).split()
                self.assertEqual(host_md5, dev_md5)
            finally:
                adb.shell_nocheck("rm {}".format(AdbFile.DEVICE_TEMP_FILE))

    # TODO: write push directory test.

    def test_pull(self):
        """Pull a randomly generated file from specified device."""
        kbytes = 512
        adb = AdbWrapper()
        adb.shell_nocheck("rm -r {}".format(AdbFile.DEVICE_TEMP_FILE))
        try:
            adb.shell("dd if=/dev/urandom of={} bs=1024 count={}".format(
                AdbFile.DEVICE_TEMP_FILE, kbytes))
            dev_md5, _ = adb.shell(
                "md5sum {}".format(AdbFile.DEVICE_TEMP_FILE)).split()

            with tempfile.NamedTemporaryFile(mode="w") as tmp_write:
                adb.pull(remote=AdbFile.DEVICE_TEMP_FILE, local=tmp_write.name)
                with open(tmp_write.name) as tmp_read:
                    host_contents = tmp_read.read()
                    host_md5 = compute_md5(host_contents)
                self.assertEqual(dev_md5, host_md5)
        finally:
            adb.shell_nocheck("rm {}".format(AdbFile.DEVICE_TEMP_FILE))

    def test_pull_dir(self):
        """Pull a randomly generated directory of files from the device."""
        adb = AdbWrapper()
        temp_files = {}
        host_dir = None
        try:
            # create temporary host directory
            host_dir = tempfile.mkdtemp()

            # create temporary dir on device
            adb.shell_nocheck("rm -r {}".format(AdbFile.DEVICE_TEMP_DIR))
            adb.shell("mkdir -p {}".format(AdbFile.DEVICE_TEMP_DIR))

            # populate device dir with random files
            temp_files = make_random_device_files(
                adb, in_dir=AdbFile.DEVICE_TEMP_DIR, num_files=32)

            adb.pull(remote=AdbFile.DEVICE_TEMP_DIR, local=host_dir)

            for device_full_path in temp_files:
                host_path = os.path.join(
                    host_dir, temp_files[device_full_path].base_name)
                with open(host_path) as host_file:
                    host_md5 = compute_md5(host_file.read())
                    self.assertEqual(host_md5,
                                     temp_files[device_full_path].md5)
        finally:
            for dev_file in temp_files.values():
                host_path = os.path.join(host_dir, dev_file.base_name)
                os.remove(host_path)
            adb.shell_nocheck("rm -r {}".format(AdbFile.DEVICE_TEMP_DIR))
            if host_dir:
                os.removedirs(host_dir)

    def test_sync(self):
        """Sync a randomly generated directory of files to specified device."""
        try:
            adb = AdbWrapper()
            temp_files = {}

            # create temporary host directory
            base_dir = tempfile.mkdtemp()

            # create mirror device directory hierarchy within base_dir
            full_dir_path = base_dir + AdbFile.DEVICE_TEMP_DIR
            os.makedirs(full_dir_path)

            # create 32 random files within the host mirror
            temp_files = make_random_host_files(in_dir=full_dir_path,
                                                num_files=32)

            # clean up any trash on the device
            adb = AdbWrapper(out_dir=base_dir)
            adb.shell_nocheck("rm -r {}".format(AdbFile.DEVICE_TEMP_DIR))

            # issue the sync
            adb.sync("data")

            # confirm that every file on the device mirrors that on the host
            for host_full_path in temp_files.keys():
                device_full_path = os.path.join(
                    AdbFile.DEVICE_TEMP_DIR,
                    temp_files[host_full_path].base_name)
                dev_md5, _ = adb.shell(
                    "md5sum {}".format(device_full_path)).split()
                self.assertEqual(temp_files[host_full_path].md5, dev_md5)

        finally:
            adb.shell_nocheck("rm -r {}".format(AdbFile.DEVICE_TEMP_DIR))
            if temp_files:
                for tf in temp_files.values():
                    tf.handle.close()
            if base_dir:
                os.removedirs(base_dir + AdbFile.DEVICE_TEMP_DIR)


if __name__ == '__main__':
    random.seed(0)
    dev_count = get_attached_device_count()
    if dev_count:
        suite = unittest.TestLoader().loadTestsFromName(__name__)
        unittest.TextTestRunner(verbosity=3).run(suite)
    else:
        print "Test suite must be run with attached devices"
