libnativeloader
===============================================================================

Overview
-------------------------------------------------------------------------------
libnativeloader is responsible for loading native shared libraries (`*.so`
files) inside the Android Runtime (ART). The native shared libraries could be
app-provided JNI libraries or public native libraries like `libc.so` provided
by the platform.

The most typical use case of this library is calling `System.loadLibrary(name)`.
When the method is called, the ART runtime delegates the call to this library
along with the reference to the classloader where the call was made.  Then this
library finds the linker namespace (named `classloader-namespace`) that is
associated with the given classloader, and tries to load the requested library
from the namespace. The actual searching, loading, and linking of the library
is performed by the dynamic linker.

The linker namespace is created when an APK is loaded into the process, and is
associated with the classloader that loaded the APK. The linker namespace is
configured so that only the JNI libraries embedded in the APK is accessible
from the namespace, thus preventing an APK from loading JNI libraries of other
APKs.

The linker namespace is also configured differently depending on other
characteristics of the APK such as whether or not the APK is bundled with the
platform. In case of the unbundled, i.e., downloaded or updated APK, only the
public native libraries that is listed in `/system/etc/public.libraries.txt`
are available from the platform, whereas in case of the bundled, all libraries
under `/system/lib` are available (i.e. shared). In case when the unbundled
app is from `/vendor` or `/product` partition, the app is additionally provided
with the [VNDK-SP](https://source.android.com/devices/architecture/vndk#sp-hal)
libraries. As the platform is getting modularized with
[APEX](https://android.googlesource.com/platform/system/apex/+/refs/heads/master/docs/README.md),
some libraries are no longer provided from platform, but from the APEXes which
have their own linker namespaces. For example, ICU libraries `libicuuc.so` and
`libicui18n.so` are from the runtime APEX.

The list of public native libraries is not static. The default set of libraries
are defined in AOSP, but partners can extend it to include their own libraries.
Currently, following extensions are available:

- `/vendor/etc/public.libraries.txt`: libraries in `/vendor/lib` that are
specific to the underlying SoC, e.g. GPU, DSP, etc.
- `/{system|product}/etc/public.libraries-<companyname>.txt`: libraries in
`/{system|product}/lib` that a device manufacturer has newly added. The
libraries should be named as `lib<name>.<companyname>.so` as in
`libFoo.acme.so`.

Note that, due to the naming constraint requiring `.<companyname>.so` suffix, it
is prohibited for a device manufacturer to expose an AOSP-defined private
library, e.g. libgui.so, libart.so, etc., to APKs.

Lastly, libnativeloader is responsible for abstracting the two types of the
dynamic linker interface: `libdl.so` and `libnativebridge.so`. The former is
for non-translated, e.g. ARM-on-ARM, libraries, while the latter is for
loading libraries in a translated environment such as ARM-on-x86.

Implementation
-------------------------------------------------------------------------------
Implementation wise, libnativeloader consists of four parts:

- `native_loader.cpp`
- `library_namespaces.cpp`
- `native_loader_namespace.cpp`
- `public_libraries.cpp`

`native_loader.cpp` implements the public interface of this library. It is just
a thin wrapper around `library_namespaces.cpp` and `native_loader_namespace.cpp`.

`library_namespaces.cpp` implements the singleton class `LibraryNamespaces` which
is a manager-like entity that is responsible for creating and configuring
linker namespaces and finding an already created linker namespace for a given
classloader.

`native_loader_namespace.cpp` implements the class `NativeLoaderNamespace` that
models a linker namespace. Its main job is to abstract the two types of the
dynamic linker interface so that other parts of this library do not have to know
the differences of the interfaces.

`public_libraries.cpp` is responsible for reading `*.txt` files for the public
native libraries from the various partitions. It can be considered as a part of
`LibraryNamespaces` but is separated from it to hide the details of the parsing
routines.
