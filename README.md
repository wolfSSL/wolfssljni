
# wolfSSL JSSE Provider and JNI Wrapper

This package provides both a wolfSSL Java JSSE provider (**wolfJSSE**), and a
thin JNI-based interface to the native
[wolfSSL embedded SSL/TLS library](https://www.wolfssl.com/products/wolfssl/).
These provide Java applications with SSL/TLS support up to the current
[TLS 1.3](https://www.wolfssl.com/tls13) protocol standard.

## Why use wolfJSSE?

This interface gives Java applications access to all the benefits of using
wolfSSL, including current SSL/TLS standards up to
[TLS 1.3](https://www.wolfssl.com/tls13),
[FIPS 140-2 and 140-3](https://www.wolfssl.com/license/fips/) support,
performance optimizations, hardware cryptography support,
[commercial support](https://www.wolfssl.com/products/support-and-maintenance/),
and more!

## User Manual

The wolfSSL JNI/JSSE Manual is available on wolfssl.com:
[wolfSSL JNI Manual](https://www.wolfssl.com/documentation/wolfSSL-JNI-Manual.pdf).

For additional build instructions and more detailed comments, please check
the manual.

## Building

***Note 1)***
The java.sh script uses a common location for the Java install location. If
your Java install location is different, this could lead to an error when
running java.sh. In this case, you should modify java.sh to match your
environment.

Build targets for ant are :
* **ant build**     (only builds the jar necessary for an app to use)
* **ant test**      (builds the jar and tests then runs the tests, requires JUNIT setup)
* **ant examples**  (builds the jar and example cases)
* **ant clean**     (cleans all Java artifacts)
* **ant cleanjni**  (cleans native artifacts)

wolfJSSE currently supports compilation on Linux/Unix and Android.

To build wolfJSSE on Linux, first download, compile, and install wolfSSL.
wolfSSL can be downloaded from the wolfSSL download page or cloned from
GitHub.

```
$ unzip wolfssl-X.X.X.zip
$ cd wolfssl-X.X.X
$ ./configure --enable-jni
$ make check
$ sudo make install
```

Then, to build wolfJSSE:

```
$ cd wolfssljni
$ ./java.sh
$ ant
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

## Examples

Examples of using wolfssljni can be found in the `./examples` subdirectory.
See [examples/README.md](./examples/README.md) for more details.

Examples of using wolfJSSE can be found in the `./examples/provider`
subdirectory. See [examples/provider/README.md](./examples/provider/README.md)
for more details.

## Debugging

wolfJSSE debug logging can be enabled by using `-Dwolfjsse.debug=true` at
runtime.

wolfSSL native debug logging can be enabled by using `-Dwolfssl.debug=true` at
runtime, if native wolfSSL has been compiled with `--enable-debug`.

JDK debug logging can be enabled using the `-Djavax.net.debug=all` option.

## Building for Android

wolfSSL JNI and JSSE can be built and used on the Android platform, either
at the application-level or installed inside a modified version of the
Android AOSP at the system-level.

### Android Application Level Usage

An example Android Studio application is included in this package, to show
users how they could include the wolfSSL native and wolfSSL JNI/JSSE sources
in an Androi Studio application. For more details, see the Android Studio
project and README.md located in the [./IDE/Android](./IDE/Android) directory.

Using wolfJSSE at the application level will allow developers to register
wolfJSSE as a Security provider at the application scope. The application can
they use the Java Security API for SSL/TLS operations which will then use the
underlying wolfJSSE provider (and subsequently native wolfSSL).

Applications can add the wolfJSSE provider using:

```
import com.wolfssl.provider.jsse.WolfSSLProvider;
...
Security.addProvider(new WolfSSLProvider());
```

To instead insert the WolfSSLProvider as the top priority provider:

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

## Release Notes

### wolfSSL JNI Release X.X.X (TBD)

Release X.X.X has bug fixes and new features including:

* Removal of HC-128 stream cipher support. Native wolfSSL removed HC-128
support in [PR #4767](https://github.com/wolfSSL/wolfssl/pull/4767)

The wolfSSL JNI Manual is available at:
http://www.wolfssl.com/documentation/wolfSSL-JNI-Manual.pdf. For build
instructions and more detailed comments, please check the manual.

### wolfSSL JNI Release 1.8.0 (11/12/2021)

Release 1.8.0 has bug fixes and new features including:

* wolfCrypt FIPS 140-3 and FIPS Ready compatibility
* Add Socket method wrappers, fixes behavior when inner Socket used with JSSE
* Add wrappers to get FIPS verifyCore hash (FIPS error cb or directly)
* Fix potential NullPointerException with several clone() methods
* Refactor of SSLSessionContext implementation
* Fix behavior of WolfSSLSocket.getSoTimeout() when external Socket is wrapped
* Fix timeout used in socketSelect to correctly handle fractional sec timeouts
* Fix memory leak when custom X509TrustManager is used with wolfJSSE
* Add support for multiple X509TrustManager objects across multiple sessions
* Call WolfSSL.cleanup() in finalizer to release library resources earlier
* Release native WOLFSSL memory sooner, when WolfSSLSocket is closed
* Better management and freeing of native WolfSSLCertificate memory
* Release native logging callback when library is freed
* Release native wolfCrypt FIPS callback when library is freed
* Release CTX-level Java verify callback when CTX is freed
* Release CTX-level Java CRL callback when CTX is freed
* Better global reference cleanup in error conditions
* Fix unused variable warnings in non-FIPS builds
* Use one static WolfSSL object across all WolfSSLProvider objects
* Release local JNI array inside WolfSSLSession.read() on function exit
* Add multi-threaded JSSE provider client and server examples
* Update Android AOSP install script to create missing blank files if needed
* Update Android AOSP build fies to define `SIZEOF_LONG` and `SIZEOF_LONG_LONG`
* Update IDE/Android example Android Studio project
* Fix default cipher suite list order used in JSSE WolfSSLContext objects
* Fix FIPS Ready compatibility with `WC_RNG_SEED_CB`
* Update Android AOSP Android.mk to compile wolfCrypt kdf.c

The wolfSSL JNI Manual is available at:
http://www.wolfssl.com/documentation/wolfSSL-JNI-Manual.pdf. For build
instructions and more detailed comments, please check the manual.

### wolfSSL JNI Release 1.7.0 (01/15/2021)

Release 1.7.0 has bug fixes and new features including:

* Fixes for Infer analysis warnings
* Throw exception in DEFAULT\_Context creation if engineInit() fails
* Defer creating DEFAULT WolfSSLContext until first use
* Check if Socket is open before doing TLS shutdown in WolfSSLSocket.close()
* Only load X509TrustStore issuers when needed by native wolfSSL verification
* Fix compiler warnings when used with older versions of native wolfSSL
* Verify and load intermediate CA certs in WolfSSLTrustX509.certManagerVerify()
* Add support for setSoTimeout() in WolfSSLSocket
* Fix suites length check in WolfSSLEngineHelper.setLocalCiphers()
* Check for connection closed before completing handshake in SSLSocket.read/write

The wolfSSL JNI Manual is available at:
http://www.wolfssl.com/documentation/wolfSSL-JNI-Manual.pdf. For build
instructions and more detailed comments, please check the manual.


### wolfSSL JNI Release 1.6.0 (08/26/2020)

Release 1.6.0 has bug fixes and new features including:

* Support for custom TrustManager checkClientTrusted(), checkServerTrusted()
* wolfJSSE TrustManager registered as PKIX provider
* Improved support for auto-loading system CA certificates
* Improved Android TrustManager support
* Use AndroidCAStore KeyStore when available on Android
* Support for X509Certificate.getSubjectAlternativeNames()
* Fix for native memory leak in JSSE WolfSSLTrustX509
* Optimization of WolfSSLTrustX509 to hold less memory at idle
* Addition of missing finalize() methods in some JSSE classes
* Casts to uintptr\_t instead of intptr\_t at native JNI level
* Conversion to use GetByteArrayElements for potential memory use savings
* Consistently use wolfCrypt XMALLOC/XFREE for native memory allocation
* Use javah in build.xml for older ant/Java versions without nativeheaderdir
* Add JSSE debug logging for native wolfSSL with wolfssl.debug system parameter
* Add more JSSE-level debug messages for easier troubleshooting
* Add internal implementation of SSLParameters, WolfSSLParameters
* Add client-side SNI support
* Fix warnings when DH is disabled (--disable-dh)
* Add Java thread ID to JSSE debug log messages for easier multithreaded debug
* Improve handshake synchronization in WolfSSLSocket for multi-threaded apps
* Add support for jsse.enableSNIExtension system property
* Add client-side session ticket support
* Add support for jdk.tls.client.enableSessionTicketExtension system property
* Enable session ticket and session cert support by default on Android AOSP
* Fixes compatibility with OkHttp on Android
* Add support for non-blocking socket operations in WolfSSLSession/Socket
* Moves I/O mutex locking to native level for more efficient locking

The wolfSSL JNI Manual is available at:
http://www.wolfssl.com/documentation/wolfSSL-JNI-Manual.pdf. For build
instructions and more detailed comments, please check the manual.


### wolfSSL JNI Release 1.5.0 (01/17/2020)

Release 1.5.0 has bug fixes and new features including:

* New JSSE provider (wolfJSSE) including TLS 1.3 support!
* Add JSSE debug logging with wolfjsse.debug system parameter
* Add JSSE install script and helper files for Android AOSP
* Add JSSE example apps (examples/provider)
* Add JNI wrappers to detect if native features/protocols are compiled in
* Add JNI wrapper for PKCS#8 offset getter
* Add JNI wrapper for wolfSSL\_get\_ciphers\_iana()
* Update build.xml to use nativeheaderdir instead of javah target
* Update tests to use junit-4.13 / hamcrest-all-1.3
* Update to build, now ant build does not build and run tests / examples

The wolfSSL JNI Manual is available at:
http://www.wolfssl.com/documentation/wolfSSL-JNI-Manual.pdf. For build
instructions and more detailed comments, please check the manual.


### wolfSSL JNI Release 1.4.0 (11/16/2018)

Release 1.4.0 has bug fixes and new features including:

* Better support for conditional native wolfSSL feature dependencies
* Adds methods for checking if native features are enabled
* Optional method for loading native JNI library from a specific path
* TLS 1.0 functions are compiled out unless WOLFSSL\_ALLOW\_TLSV10 is defined
* Wrapper for native wolfCrypt ECC shared secret public key callback
* Allow other HmacSHA hash types to be used in Atomic User callback examples
* Error string buffer size set to use WOLFSSL\_MAX\_ERROR\_SZ
* Fix for RSA doSign() output length
* Fix for I/O, Atomic User, and Public Key callback registration in examples
* Updated example key and certificate files

The wolfSSL JNI Manual is available at:
http://www.wolfssl.com/documentation/wolfSSL-JNI-Manual.pdf. For build
instructions and more detailed comments, please check the manual.


### wolfSSL JNI Release 1.3.0 (12/04/2015)

Release 1.3.0 has bug fixes and new features including:

* Updated support to wolfSSL 3.7.0
* Added finalizers for WolfSSLContext and WolfSSLSession classes
* Fix for SSLv3 now disabled by default in wolfSSL proper
* SSLv3 now marked as @Deprecated
* PSK (pre-shared key) support for client and server
* Better error checking and exception handling
* New WolfSSLJNIException class
* WolfSSLSession now cached in native WOLFSSL struct for callbacks
* Easier inclusion of junit4 in build.xml

The wolfSSL JNI Manual is available at:
http://www.wolfssl.com/documentation/wolfSSL-JNI-Manual.pdf. For build
instructions and more detailed comments, please check the manual.


### wolfSSL JNI Release 1.2.0 (06/02/2015)

Release 1.2.0 has bug fixes and new features including:

* Updated support for wolfSSL 3.4.6 and CyaSSL to wolfSSL name change
* Benchmark functionality in example client
* Updated example certificates
* Better detection of Java home on Mac and Linux

The wolfSSL JNI Manual is available at:
http://www.wolfssl.com/documentation/wolfSSL-JNI-Manual.pdf. For build
instructions and more detailed comments, please check the manual.


### wolfSSL JNI Release 1.1.0 (10/25/2013)

Release 1.1.0 has bug fixes and new features including:

* Updated support for CyaSSL 2.9.4
* Updated example certificates and CRLs
* Now expects user to have JUnit JARs pre-installed on dev platform
* Updated unit tests, JUnit4 style
* Android support
* CRL monitor now optional in server mode

The wolfSSL JNI Manual is available at:
http://www.wolfssl.com/documentation/wolfSSL-JNI-Manual.pdf. For build
instructions and more detailed comments, please check the manual.


### wolfSSL JNI Release 1.0.0 (10/25/2013)

Release 1.0.0 is the first public release of wolfSSL JNI, the Java wrapper for
the CyaSSL embedded SSL library.

The wolfSSL JNI Manual is available at:
http://www.wolfssl.com/documentation/wolfSSL-JNI-Manual.pdf. For build
instructions and more detailed comments, please check the manual.

## Support

For support inquiries and feedback please contact support@wolfssl.com.

