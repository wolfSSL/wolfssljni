### wolfSSL JNI Release 1.16.0 (12/31/2025)

Release 1.16.0 has bug fixes and new features including:

**JSSE System/Security Property Support:**
* Add `wolfjsse.autoSNI` Security property support to control auto setting SNI (PR 249)
* Add partial support for `jdk.tls.client.SignatureSchemes` and `jdk.tls.server.SignatureSchemes` (PR 299)

**JSSE Changes:**
* Automatically set SNI for HttpsURLConnection connections (PR 249)
* Add support for DTLS 1.3 (`DTLSv1.3`) in `SSLContext` / `SSLEngine` (PR 254)
* Fix SNI storing/restoring at wolfJSSE level on session resumption (PR 255)
* Improve `SSLEngine` send/received performance 20-30% (PR 257)
* Implement SNI matcher logic for server-side `WolfSSLSocket` use (PR 259)
* Cache system and security properties on `WolfSSLEngineHelper` creation vs each handshake (PR 273)
* Reduce synchronization scope in `WolfSSLAuthStore` for lower contention (PR 274)
* Cache KeyStore entries in `X509ExtendedKeyManager` to reduce contention for heavy concurrent use (PR 272)
* Fix potential use-after-free issues with `WolfSSLSocket` (PR 275)
* Fix NullPointerException on double `close()` in `WolfSSLSocket` (PR 277)
* Implement `toString()` inside `WolfSSLPrincipal` (PR 281)
* Fix certificate chain order returned from `WolfSSLX509StoreCtx.getCerts()` to match JSSE expectations (PR 282, 289)
* Protect native sessions from being freed while I/O operations are in progress (PR 278)
* Add support for honoring client cipher suite preference ordering (PR 287)
* Fix potential memory leak in `SSLEngine` during JNI callback cleanup (PR 289)
* Implement `X509Certificate.getExtendedKeyUsage()` in `WolfSSLX509Certificate` (PR 289)
* Fix cert chain validation to handle cross-signed certs and chain paths (PR 292, 294)
* Add Java ServiceLoader support for wolfJSSE provider for Java Module System (JPMS) compatibility (PR 296)
* Implement `X509Certificate` `getSubjectX500Principal()` and `getIssuerX500Principal()` (PR 298)
* Fall back to `java.home` property use when `JAVA_HOME` env var not set (PR 302)
* Add `hashCode()` implementation to `SSLSession` (PR 303)
* Allow `SSLSessionContext` access before `SSLContext` init (PR 304)
* Add Android non-standard `checkServerTrusted()` in `X509TrustManager` (PR 288)
* Fix ALPN to support non-ASCII protocol names (PR 305)

**JNI Changes:**
* Rename wolfCrypt JNI helper classes to avoid namespace conflicts with wolfcrypt-jni (PR 252)
* Wrap Atomic Record VerifyDecrypt callback (PR 252)
* Ensure peer ALPN protocol list is null terminated (PR 258)
* Enhance error handling and return code checks in `WolfSSLSession.read()` (PR 260)
* Improve ByteBuffer handling in `WolfSSLSession.read()` (PR 262)
* Dynamically get algorithm and key ASN NID enum values from wolfSSL (PR 263)
* Add pool of ByteBuffers to `WolfSSLSession`, improves performance and avoids unaligned memory access (PR 268)
* Add `getSessionTicket()` and `setSessionTicket()` to `WolfSSLSession` (PR 270)
* Correct call to `CallObjectMethod()` in `WolfSSLSession` ByteBuffer read (PR 286)
* Wrap `wolfSSL_i2d_SSL_SESSION()` and `wolfSSL_d2i_SSL_SESSION()` allowing for session persistence (PR 290)
* Add DTLS Connection ID (CID) support, wrapping native wolfSSL APIs (PR 297)

**Debugging Changes:**
* Switch to use Java logging (`java.util.logging`) framework for debug logs (PR 261)
* Switch logging callback for wolfSSL debug messages to use stderr (PR 269)
* Switch debug log timestamp to use Java `Instant.ofEpochMilli()`, remove dependency on `java.sql.Timestamp` (PR 301)

**Example Changes:**
* Add DTLS 1.3 example client and server applications (PR 264)

**Testing Changes:**
* Add GitHub Actions PRB test with `ubuntu-24.04-arm` runner for testing `--enable-armasm` builds (PR 267)
* Add GitHub Actions PRB test for AddressSanitizer (`-fsanitize=address`) builds (PR 276)
* Add GitHub Actions PRB tests for coding style (line length, comment style) (PR 285)
* Add GitHub Actions PRB test for Clang scan-build static analysis (PR 285)
* Add GitHub Actions PRB test for Visual Studio builds on Windows (PR 295)
* Add GitHub Actions PRB test to build against last 5 stable wolfSSL releases (PR 306)
* Add GitHub Actions PRB test to run unit tests on Android emulator (PR 307)
* Use local server threads in some `WolfSSLSession` tests to avoid network access (PR 300)

**Misc Changes:**
* Clean up IDE warnings in Cursor and VSCode (PR 266)
* Add `CLAUDE.md` for consumption by Claude Code (PR 265)
* Add `-fPIC` to CFLAGS in `java.sh` for Aarch64 hosts (PR 267)
* Modify `java.sh` to allow passing install directory (`./java.sh <install_dir>`) (PR 285)

The wolfSSL JNI Manual is available at:
https://www.wolfssl.com/documentation/manuals/wolfssljni. For build
instructions and more detailed comments, please check the manual.

### wolfSSL JNI Release 1.15.0 (01/24/2025)

Release 1.15.0 has bug fixes and new features including:

**JSSE System/Security Property Support:**
* Addition of JNI-level debug system property (`wolfssljni.debug=true`) (PR 235)

**JSSE Changes:**
* Fix to close Socket when SSLSocket startHandshake() fails (PR 234)
* Fixes for potential NullPointerException in SSLSocket Input/OutputStream (PR 233)
* Add ability for `SSLSession.getRequestedServerNames()` to return SNI request on server side (PR 240)
* Add check for legacy DHE keys, for cipher suites using keys less than 1024 bits (PR 243)
* Optimize `byte[]` creation in `SSLEngine` when receiving app data (PR 244, 250)
* Add ability for `SSLSocket.close()` to interrupt `read()/write()` operations waiting in `select()/poll()` (PR 246)

**JNI Changes:**
* Always call `wolfSSL_get1_session()` inside `WolfSSLSession.getSession()` (PR 236)
* Call `wc_RunAllCast_fips()` with wolfCrypt FIPS builds if available (PR 247)
* Add ability to pass `CFLAGS` to `java.sh` (ie: `CFLAGS="-DTEST_DEFINE" ./java.sh`) (PR 248)
* Remove incorrect `ATOMIC_USER` preprocessor gate around native `wolfSSL_GetSide()` (PR 246)

**Example Changes:**
* Updated Android Studio example project, define `WOLFSSL_CERT_REQ` (PR 234)
* Update Android Studio CMakeLists.txt with `WOLFSSL_CUSTOM_CONFIG` definition (PR 239)

**Testing Changes:**
* Add GitHub Actions PRB test for Maven (Linux, macOS) builds (PR 232)
* Add tests of `SSLSession` state at various points throughout the handshake (PR 233)
* Add GitHub Actions PRB test for `--enable-jni CFLAGS="-DNO_SESSION_CACHE_REF"` build (PR 236)
* Add GitHub Actions PRB test for `-DWOLFJNI_USE_IO_SELECT` (PR 246)

The wolfSSL JNI Manual is available at:
https://www.wolfssl.com/documentation/manuals/wolfssljni. For build
instructions and more detailed comments, please check the manual.

### wolfSSL JNI Release 1.14.0 (11/7/2024)

Release 1.14.0 has bug fixes and new features including:

**New JSSE Functionality:**
* Add wolfJCE WKS KeyStore type support (PR 178)
* Add support for native `poll()` and set as default over `select()` (PR 201)
* Add `getSSLParameters()` to SSLServerSocket implementation (PR 214)
* Add `rsa_pss` support and tests to wolfJSSE (PR 218)
* Add LDAPS endpoint identification to X509ExtendedTrustManager (PR 227)

**JSSE System/Security Property Support:**
* Add option to print debug logs in JSON format (`wolfjsse.debugFormat=JSON`) (PR 187)
* Add Security property to disable Java client session cache (`wolfjsse.clientSessionCache.disabled=true`) (PR 225)

**JSSE Changes:**
* Fix for native memory leak when calling `wolfSSL_get_peer_certificate()` (PR 188)
* Optimization to allow for easier garbage collection (PR 189)
* Fix for SSLEngine session storage and unwrap() FINISHED state (PR 193)
* Fix to not close SSLSocket when SSLServerSocket is closed (PR 194)
* Fix for getting end of stream when calling InputStream.read() (PR 195)
* Fix for throwing exceptions on KeyManagerFactory/TrustManagerFactory use before init (PR 196)
* Fix for SSLEngine HandshakeStatus when receiving TLS 1.3 session tickets after handshake (PR 197)
* Throw SSLException to indicate lack of renegotiation support in `SSLEngine.beginHandshake()` (PR 197)
* Fix to mark inbound and outbound closed in SSLEngine when fatal alerts are received (PR 197)
* Return `X509Certificate[]` from `SSLSession.getPeerCertificates()` (PR 199)
* Remove unneeded `SSLServerSocket.close()` method (PR 200)
* Fix `SSLSession.getLocalPrincipal()` to assume user cert is first in chain (PR 204)
* Ensure that socket is closed if implicit handshake in `SSLSocket.getSession()` fails (PR 205)
* If SSLSocket handshake is unsuccessful, close Socket before throwing an exception (PR 205)
* Close SSLEngine inbound on ALPN protocol name error (PR 208)
* Adjust client-side session resumption to check cipher suite and protocol (PR 209)
* Pass lower level exception messages up during X509TrustManager verification (PR 211)
* Refactor code calls not available in Android API 24 (PR 216)
* Fix to return end of stream in `InputStream.read()` on socket error (PR 217)
* Fix to update the TLS protocol in SSLSession after handshake completes (PR 219)
* Fix potential deadlock on close() between SSLSocket and Input/OutputStream (PR 220)
* Fixes for issues found with SpotBugs (PR 221)
* Clean up ant build warnings on Corretto 20.0.1 (PR 223)
* Error out on invalid port during creation of SSLEngine (PR 224)
* Correct SSLSocket exception types and fix setting of native file descriptor (PR 228)
* Fix deadlock issues between `SSLSocket close()` and `OutputStream.write()` (PR 230)

**New JNI Wrapped APIs and Functionality:**
* `wolfSSL_SessionIsSetup()` (PR 191)
* `wolfSSL_SESSION_dup()` (PR 206)

**JNI Changes:**
* Fix for JNI example use of TLS 1.3 secret callback strings (PR 192)

**Example Changes:**
* Add Host into HTTP GET in example ClientJSSE when used with `-g` (PR 213)
* Add example JNI-only threaded client/server applications (PR 212)
* Add basic RMI example client and server (PR 226)

**Debugging Changes:**
* Fix typo in SSLEngine debug logs (PR 203)

**Testing Changes:**
* Run Facebook Infer on all PRs with GitHub Actions (PR 190)
* Run TLS 1.0 and 1.1 tests if enabled in native wolfSSL even if disabled in `java.security` (PR 198)
* Add GitHub Actions PRB test for Android gradle build (PR 222)

The wolfSSL JNI Manual is available at:
https://www.wolfssl.com/documentation/manuals/wolfssljni. For build
instructions and more detailed comments, please check the manual.

### wolfSSL JNI Release 1.13.0 (4/9/2024)

Release 1.13.0 has bug fixes and new features including:

**New JSSE Functionality:**
* Add `SSLSocket.getApplicationProtocol()`, returns negotiated ALPN protocol (PR 150)
* Add native `WOLFSSL_TRUST_PEER_CERT` support in `WolfSSLTrustX509` (PR 154)
* Add implementation of `javax.net.ssl.X509ExtendedTrustManager` (PR 159)
* Add `getSSLParameters()` to `SSLEngine` and `SSLSocket` (PR 159)
* Add `getHandshakeSession()` to `SSLSocket` (PR 159)
* Convert `SSLSession` to `ExtendedSSLSession`, add `getRequestedServerNames()` (PR 159)
* Add ALPN API support to `SSLSocket` and `SSLEngine` with tests (PR 163)
* Add implementation of `X509ExtendedKeyManager` (PR 167)

**JSSE System/Security Property Support:**
* Add partial support for `jdk.tls.disabledAlgorithms` Security property (PR 136)
* Add support for `wolfjsse.enabledCipherSuites` Security property (PR 136)
* Add support for `wolfjsse.enabledSignatureAlgorithms` Security property (PR 136)
* Add support for `wolfjsse.enabledSupportedCurves` Security property (PR 143)

**JSSE Changes:**
* Get updated status before returning from SSLEngine.getHandshakeStatus() (PR 122)
* Add synchronization to SSLEngine read/write buffers (PR 124)
* Return null array from X509TrustManager.getAcceptedIssuers() if not yet initialized (PR 128)
* Improve `SSLEngine.unwrap()` for better efficiency (PR 137)
* Add native wolfSSL crypto callback (CryptoCb) support with WolfSSLProvider (PR 138)
* Add synchronization around `WolfSSLAuthStore` lock (PR 139)
* Fixes and improvements to `SSLSocket`/`SSLEngine` session resumption (PR 139, 144)
* Fix for `X509TrustManager` to not add root CA twice in returned chains (PR 140)
* Add synchronization around native pointer use and active states (PR 142)
* Fix for `SSLSocket` to fall back to I/O callbacks if setting internal fd fails (PR 145)
* Fix `SSLSocket` TLS 1.3 session cache and threading issues (PR 149)
* Throw `SocketException` if native socket `select()` fails (PR 151)
* Only call `InetAddress.getHostName()` when `jdk.tls.trustNameService` is true (PR 134)
* Fix for `SSLSession.getPeerCertificate()` and cached certs during resumption (PR 162)
* Save session at correct time for resumption in SSLEngine (PR 165)
* Check TLS 1.3 session for ticket before saving to Java client cache (PR 175)
* Fixes for `SSLEngine.setWantClientAuth()` (PR 172)
* Release native verify callback when `SSLEngine` is closed (PR 180)
* Avoid extra Java array allocation in `SSLSocket` InputStream/OutputStream (PR 183)

**New JNI Wrapped APIs and Functionality:**
* `wolfSSL_CTX_SetTmpDH()` and `wolfSSL_CTX_SetTmpDH_file()` (PR 136)
* `wolfSSL_CTX_SetMinDh/Rsa/EccKey_Sz()` (PR 136)
* `wolfSSL_set1_sigalgs_list()` (PR 136)
* `wolfSSL_CTX_UseSupportedCurve()` (PR 158)
* `wolfSSL_X509_check_host()` and `wolfSSL_SNI_GetRequest()` (PR 159)
* `wolfSSL_CTX_set_groups()` and `wolfTLSv1_3_client/server_method()` (PR 164)
* `SSL_CTX_set1_sigalgs_list()` (PR 169)
* `wolfSSL_set_tls13_secret_cb()`, add ability to set Java callback (PR 181)
* Add X.509v3 certificate generation support in `WolfSSLCertificate` and examples (PR 141)
* Add Certificate Signing Request (CSR) support and examples (PR 146)

**JNI Changes:**
* Call `wolfSSL_get1_session()` when saving session for resumption (PR 139)
* Call `select()` again on error with `EINTR` (PR 171)

**New Platform Support:**
* Add Windows support with Visual Studio, see IDE/WIN/README.md (PR 125)

**Build System Changes:**
* Add `JAVA_HOME` support in `java.sh` for use with custom Java install (PR 121)
* New argument to `java.sh` for custom wolfSSL library name to be used (PR 126)
* Add lib64 directory to library search path in `java.sh` (PR 130)
* Standardize JNI library name on OSX to .dylib (PR 152)
* Add Maven build support (PR 153)
* Update Android Studio example project (PR 185)

**Example Changes:**
* Update instructions for running examples (PR 133)
* Fix example JSSE client `-d` option, add `-g` to send HTTP GET (PR 155)
* Fix example JSSE client for resumption when sending HTTP GET (PR 157)
* Add TLS 1.3 version support to example `Client.java` and `Server.java` (PR 169)
* Expand JNI `Client.java` with support for doing session resumption with tickets (PR 169)

**Debugging Changes:**
* Add WolfSSLDebug.logHex() for printing byte arrays as hex (PR 129)
* Add synchronization and Thread ID to debug log messages (PR 129)
* Add new debug System property `wolfsslengine.io.debug` for I/O debug logs (PR 137)
* Add timestamp to debug logs (PR 148)
* Fix for enabling JSSE debug logs after WolfSSLProvider has been registered (PR 166)
* Make native wolfSSL debug log format consistent with wolfJSSE logs (PR 166)

**Testing Changes:**
* Add Facebook Infer test script, make fixes (PR 127, 182)
* Add extended threading test of `SSLEngine` (PR 124)
* Testing with and fixes from SonarQube static analyzer (PR 131)
* Add extended threading test of `SSLSocket` (PR 149)
* Testing with and fixes for running SunJSSE tests on wolfJSSE (PR 170, 174)
* Add GitHub Actions tests for Oracle/Zulu/Coretto/Temurin/Microsoft JDKs on Linux and OS X (PR 176)

**Documentation Changes:**
* Clean up Javadoc warnings with Java 17 (PR 147)

The wolfSSL JNI Manual is available at:
https://www.wolfssl.com/documentation/manuals/wolfssljni. For build
instructions and more detailed comments, please check the manual.

### wolfSSL JNI Release 1.12.0 (03/31/2023)

Release 1.12.0 has bug fixes and new features including:

**JNI and JSSE Changes:**
* Additional synchronization support in WolfSSLCertificate (PR 118)
* Prevent WolfSSLCertificate from freeing `WOLFSSL_X509` if not owned (PR 118)
* Fix `X509KeyManager.getCertificateChain()` to return `null` when alias is `null` (PR 119)

**Documentation Changes:**
* Add Android Studio instructions for how to update source symlinks on Windows (PR 117)

The wolfSSL JNI Manual is available at:
https://www.wolfssl.com/documentation/manuals/wolfssljni. For build
instructions and more detailed comments, please check the manual.

### wolfSSL JNI Release 1.11.0 (12/2/2022)

Release 1.11.0 has bug fixes and new features including:

**JNI and JSSE Changes:**
* Add support for system properties: keyStore, keyStoreType, keyStorePassword (PR 74)
* Add support for secure renegotiation if available in native wolfSSL (PR 75)
* Fix compilation against newer wolfSSL versions that have dtls.c (PR 107)
* Fixes and cleanup to SSLEngine implementation (PR 108)
* Fixes for SSLEngine synchronization issues (PR 108)
* Add non-standard X509TrustManager.checkServerTrusted() for use on Android (PR 109)
* Add RPM packaging support (PR 110)
* Fix SSLSocketFactory.createSocket() to allow for null host (PR 111)
* Remove @Override on SSLEngine.getHandshakeSession() for older Java versions (PR 114)

The wolfSSL JNI Manual is available at:
https://www.wolfssl.com/documentation/manuals/wolfssljni. For build
instructions and more detailed comments, please check the manual.

### wolfSSL JNI Release 1.10.0 (8/11/2022)

Release 1.10.0 has bug fixes and new features including:

**JNI and JSSE Changes:**
* Add SSLEngine.getApplicationProtocol(), fixes Undertow compatibility (PR 84)
* Wrap wolfSSL\_UseALPN() at JNI level (PR 84)
* Fix compile error for wolfSSL < 4.2.0 and wolfSSL\_set\_alpn\_protos() (PR 84)
* Fix NullPointerException when no selected ALPN is available (PR 84)
* Fix JNI build when wolfSSL compiled with --disable-filesystem (PR 104)
* Fix SSLEngine compatibility with data larger than TLS record size (PR 105)
* Refactor SSLEngine handshake status to be more inline with SunJSSE (PR 105)
* Add verbose SSLEngine logging with "wolfsslengine.debug" property (PR 105)

**Documentation Changes**
* Fix missing Javadoc warnings in ALPN code

**Example Changes:**
* Update Android Studio IDE project to use Android 11 (SDK 30)

The wolfSSL JNI Manual is available at:
http://www.wolfssl.com/documentation/wolfSSL-JNI-Manual.pdf. For build
instructions and more detailed comments, please check the manual.

### wolfSSL JNI Release 1.9.0 (5/5/2022)

Release 1.9.0 has bug fixes and new features including:

**JNI and JSSE Changes:**
* Add synchronization to class cleanup/free routines (PR 78)
* Fix JNI native casting to use utintptr\_t instead of intptr\_t (PR 79)
* Add support for newer Java versions (ex: Java 17) (PR 90)
* Remove HC-128 support (PR 94). Native wolfSSL removed with
[PR #4767](https://github.com/wolfSSL/wolfssl/pull/4767)
* Remove RABBIT support (PR 96). Native wolfSSL removed with
[PR #4774](https://github.com/wolfSSL/wolfssl/pull/4767)
* Remove IDEA support (PR 97). Native wolfSSL removed in
[PR #4806](https://github.com/wolfSSL/wolfssl/pull/4806).
* Fix typecasting issues and cleanup for native argument checking (PR 98, 99)
* Add Socket timeout support for native SSL\_connect/write() (PR 95)
* SSLSocket.getSession() now tries to do TLS handshake if not completed (PR 76)
* Fix shutdown/close\_notify alert handling in WolfSSLEngine (PR 83)
* Fix WolfSSLSocket to test if close() called before object init (PR 88)
* Add support for loading default system CA certs on Java 9+ (PR 89)
* Fix timeout behavior with WolfSSLSession.connect() (PR 100)

**Example Changes:**
* Print wolfJSSE provider info in JSSE ProviderTest (PR 77)
* Add option to ClientJSSE to do one session resumption (PR 80)
* Update example certificates and keys (PR 81)

**Documentation Changes:**
* Add missing Javadocs, fix warnings on newer Java versions (PR 92)

**Testing Changes:**
* Update junit dependency to 4.13.2 (PR 91)

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

