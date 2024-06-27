
# wolfSSL JSSE Provider and JNI Wrapper

This package provides Java support for the
[wolfSSL embedded SSL/TLS library](https://www.wolfssl.com/products/wolfssl/),
giving applications support for SSL/TLS up to the current
[TLS 1.3](https://www.wolfssl.com/tls13) protocol level.
It contains both a wolfSSL **JSSE** (Java Secure Socket Extension) provider,
called **wolfJSSE**, and a thin JNI-based interface that wraps the native C
library.

wolfSSL also provides a **JCE** (Java Cryptography Extension) provider that
wraps native wolfCrypt. This can be found in a separate repository, located
[here](https://github.com/wolfSSL/wolfcrypt-jni).

## Why use wolfJSSE?

This interface gives Java applications access to all the benefits of using
wolfSSL, including current SSL/TLS standards up to
[TLS 1.3](https://www.wolfssl.com/tls13),
[FIPS 140-2 and 140-3](https://www.wolfssl.com/license/fips/) support,
performance optimizations, hardware cryptography support,
[commercial support](https://www.wolfssl.com/products/support-and-maintenance/),
and more!

## User Manual

The wolfSSL JNI/JSSE Manual is available on the wolfSSL website:
[wolfSSL JNI Manual](https://www.wolfssl.com/documentation/manuals/wolfssljni/).

For additional build instructions and more detailed comments, please reference
the manual.

## Building

wolfJSSE currently supports compilation on the following platforms:
- Linux/Unix
- Mac OSX
- [Windows (Visual Studio)](./IDE/WIN/README.md)
- Android Studio
- Android AOSP

To build wolfJSSE on Windows using Visual Studio, please reference the
Windows [README.md](./IDE/WIN/README.md).

## Building Native wolfSSL (Dependency)

To compile the wolfSSL JNI wrapper and JSSE provider, first the native (C)
wolfSSL library must be compiled and installed.

To build wolfJSSE in Linux/Unix environments, first download, compile, and
install wolfSSL. wolfSSL can be downloaded from the wolfSSL
[download page](https://www.wolfssl.com/download/) or cloned from
[GitHub](https://github.com/wolfssl/wolfssl).

```
$ unzip wolfssl-X.X.X.zip
$ cd wolfssl-X.X.X
$ ./configure --enable-jni
$ make check
$ sudo make install
```

If building a wolfSSL FIPS or FIPS Ready release bundle, additional
configure options may be required. Reference the wolfSSL Manual and build
documentation for exact build instructions.

## Building with ant

wolfSSL JNI/JSSE's ant build is the most stable and well-tested. Newer support
for building with Maven has also been added. See section below for instructions
on building with Maven.

***Note 1)***
The `java.sh` script uses a common location for the Java install location. If
your Java install location is different, this could lead to an error when
running `java.sh`. In this case, you should modify `java.sh` to match your
environment.

Build targets for ant are :
* **ant build (ant)**     (only builds the jar necessary for an app to use)
* **ant test**      (builds the jar and tests then runs the tests, requires JUNIT setup)
* **ant examples**  (builds the jar and example cases)
* **ant clean**     (cleans all Java artifacts)
* **ant cleanjni**  (cleans native artifacts)

To build wolfJSSE:

```
$ cd wolfssljni
$ ./java.sh
$ ant
$ export JUNIT_HOME=/path/to/junit/jars
$ ant test
```

To compile and run the examples, use the `ant examples` target:

```
$ ant examples
```

Then, run the examples from the root directory using the provided wrapper
scripts:

```
$ ./examples/provider/ServerJSSE.sh
$ ./examples/provider/ClientJSSE.sh
```

## Building with Maven

wolfJSSE supports building and packaging with Maven, for those projects that
are already set up to use and consume Maven packages.

wolfJSSE's Maven build configuration is defined in the included `pom.xml`.

First, compile the native JNI shared library (libwolfssljni.so/dylib) same
as above. This will create the native JNI shared library under the `./lib`
directory:

```
$ ./java.sh
```

Compile the Java sources, where Maven will place the compiled `.class` files
under the `./target/classes` directory:

```
$ mvn compile
```

Compile and run JUnit tests using:

```
$ mvn test
```

Package up the wolfSSL JNI/JSSE JAR file using the following command. This will
run the JUnit tests then create a `.jar` file located under the `./target`
directory, similar to `target/wolfssl-jsse-X.X.X-SNAPSHOT.jar`:

```
$ mvn package
```

To build the Javadoc API reference for wolfSSL JNI/JSSE run the following. This
will generate Javadoc HTML under the `./docs/apidocs` directory:

```
$ mvn javadoc:javadoc
```

To install the wolfSSL JNI/JSSE JAR file, run the following. This will install
the JAR into the local Maven repository:

```
$ mvn install
```

The local Maven repository installation location will be similar to:

```
~/.m2/repository/com/wolfssl/wolfssl-jsse/X.X.X-SNAPSHOT/wolfssl-jsse-X.X.X-SNAPSHOT.jar
```

The wolfSSL JNI shared library (`libwolfssljni.so/dylib`) created with the
`java.sh` script will need to be "installed" by being placed on your native
library search path. For example, copied into `/usr/local/lib`, `/usr/lib`,
or other location. Alternatively, append the `./libs` directory to your native
library search path by exporting `LD_LIBRARY_PATH` (Linux) or
`DYLD_LIBRARY_PATH` (OSX):

```
$ export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/path/to/wolfssljni/lib
```

After wolfSSL JNI/JSSE has been installed into the local Maven repository,
an application can include this as a dependency in the application's
`pom.xml` file, similar to:

```
<project ...>
    ...
    <dependencies>
        <dependency>
            <groupId>com.wolfssl</groupId>
            <artifactId>wolfssl-jsse</artifactId>
            <version>1.13.0-SNAPSHOT</version>
        </dependency>
    </dependencies>
    ...
</project>
```

## Examples

Examples of using wolfssljni can be found in the `./examples` subdirectory.
See [examples/README.md](./examples/README.md) for more details.

Examples of using the wolfJSSE provider can be found in the `./examples/provider`
subdirectory. See [examples/provider/README.md](./examples/provider/README.md)
for more details.

Example certificates and keys are included in this bundle. These should only
be used for testing and prototyping. Example certificates included here are
duplicates of the ones that ship with standard wolfSSL. If needed, certificates
can be easily updated from an existing wolfSSL directory by using the script
**examples/certs/update-certs.sh**. This should be run from the examples/certs
directory and given one argument which is the path to a wolfSSL certs directory.

## Debugging

wolfSSL JNI/JSSE supports several System properties for enabling debug
logging. The table below describes the currently-supported debug properties
and what each enables.

| System Property | Default | To Enable | Description |
| --- | --- | --- | --- |
| wolfssl.debug | "false" | "true" | Enables native wolfSSL debug logging |
| wolfjsse.debug | "false" | "true | Enables wolfJSSE debug logging |
| wolfsslengine.debug | "false" | "true" | Enables SSLEngine debug logging |
| wolfsslengine.io.debug | "false" | "true" | Enables SSLEngine I/O bytes log |

Native wolfSSL logging (`wolfssl.debug`) will only output messages if
native wolfSSL has been configured with `--enable-debug`.

These System properties can be defined at runtime, ie:

```
java -Dwolfjsse.debug=true App
```

Or these system properties can also be set programmatically at runtime, ie:

```
System.setProperty("wolfjsse.debug", "true");
System.setProperty("wolfsslengine.debug", "true);
```

JDK debug logging can be enabled using the `-Djavax.net.debug=all` option.

## Building for Android

wolfSSL JNI and JSSE can be built and used on the Android platform, either
at the application-level or installed inside a modified version of the
Android AOSP at the system-level.

### Android Application Level Usage

An example Android Studio application is included in this package, to show
users how they could include the wolfSSL native and wolfSSL JNI/JSSE sources
in an Android Studio application. For more details, see the Android Studio
project and README.md located in the [./IDE/Android](./IDE/Android) directory.

Using wolfJSSE at the application level will allow developers to register
wolfJSSE as a Security provider at the application scope. The application can
use the Java Security API for SSL/TLS operations which will then use the
underlying wolfJSSE provider (and subsequently native wolfSSL).

Applications can register the wolfJSSE provider using:

```
import com.wolfssl.provider.jsse.WolfSSLProvider;
...
Security.addProvider(new WolfSSLProvider());
```

To instead insert the WolfSSLProvider as the top priority provider, or at
a specified index (note: indexing starts at 1):

```
import com.wolfssl.provider.jsse.WolfSSLProvider;
...
Security.insertProviderAt(new WolfSSLProvider(), 1);
```

There are also additional Android examples using wolfSSL JNI in the
[wolfssl-examples](https://github.com/wolfssl/wolfssl-examples/tree/master/android) repository.

### Android AOSP System Level Installation

wolfJSSE can be installed inside an Android AOSP build and registered at the
OS/system level. This will allow wolfJSSE to be registered as the highest
priority JSSE provider on Android, thus allowing any application using the
Java Security API to automatically use wolfJSSE and wolfSSL.

For details on how to install wolfJSSE in Android AOSP, see the README located
in the [./platform/android_aosp](./platform/android_aosp) directory.

Additional instructions can be found on the wolfSSL.com website:
[Installing a JSSE Provider in Android OSP](https://www.wolfssl.com/docs/installing-a-jsse-provider-in-android-osp/).

## Behavior and Functionality Notes

### JSSE Class Implementation Support

wolfJSSE extends or implements the following JSSE classes:
- javax.net.ssl.SSLContextSpi
    - SSL, TLS, DEFAULT, TLSv1, TLSv1.1, TLSv1.2, TLSv1.3
- javax.net.ssl.KeyManagerFactorySpi
    - PKIX, X509, SunX509
- javax.net.ssl.TrustManagerFactorySpi
    - PKIX, X509, SunX509
- javax.net.ssl.SSLEngine
- javax.net.ssl.SSLSession / ExtendedSSLSession
- javax.net.ssl.X509KeyManager / X509ExtendedKeyManager
- javax.net.ssl.X509TrustManager / X509ExtendedTrustManager
- javax.net.ssl.SSLServerSocket
- javax.net.ssl.SSLServerSocketFactory
- javax.net.ssl.SSLSocket
- javax.net.ssl.SSLSocketFactory
- javax.net.ssl.SSLSessionContext
- java.security.cert.X509Certificate
- javax.security.cert.X509Certificate

### Secure Renegotiation Support

wolfSSL JNI and JSSE provider wrap native wolfSSL APIs to enable and conduct
secure renegotiation. For secure renegotiation functionality to be available
in wolfSSL JNI, and enabled for use in wolfJSSE, native wolfSSL must be
compiled with secure renegotiation support:

```
$ ./configure --enable-secure-renegotiation
```

Or by defining `-DHAVE_SECURE_RENEGOTIATION`.

### Native File Descriptor Events

wolfSSL JNI/JSSE internally makes several calls that operate on native
file descriptors inside Java Socket objects. These native file descriptors
are watched for read and write events with either `select()` or `poll()`.

By default `poll()` will be used, unless `WOLFJNI_USE_IO_SELECT` is defined
or added to CFLAGS when compiling the native JNI sources (see `java.sh`).
Windows builds will also default to using `select()` since `poll()` is not
available there.

wolfSSL JNI/JSSE does not select/poll on a large number of file descriptors
(typically just one). Although if used in applications that make lots of
connections, when using `select()` the `FD_ISSET` and other related macros
result in undefined behavior when the file descriptor number is larger than
`FD_SETSIZE` (defaults to 1024 on most systems). For this reason, `poll()` is
used as the default descriptor monitoring function.

## Release Notes

Release notes can be found in [ChangeLog.md](./ChangeLog.md).

## Support

For support inquiries and feedback please contact support@wolfssl.com.

