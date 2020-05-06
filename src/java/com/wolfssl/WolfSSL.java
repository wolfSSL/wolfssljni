/* WolfSSL.java
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

package com.wolfssl;

import java.net.InetSocketAddress;
import java.net.Socket;

/**
 * Base class which wraps the native WolfSSL embedded SSL library.
 * This class contains library init and cleanup methods, general callback
 * methods, as well as error codes and general wolfSSL codes.
 *
 * @author  wolfSSL
 * @version 1.1, September 2013
 */
public class WolfSSL {

    /* ----------------------- wolfSSL codes ---------------------------- */

    public final static int SSL_ERROR_NONE      =  0;
    public final static int SSL_FAILURE         =  0;
    public final static int SSL_SUCCESS         =  1;
    public final static int SSL_SHUTDOWN_NOT_DONE = 2;

    public final static int SSL_BAD_CERTTYPE    = -8;
    public final static int SSL_BAD_STAT        = -7;
    public final static int SSL_BAD_PATH        = -6;
    public final static int SSL_BAD_FILETYPE    = -5;
    public final static int SSL_BAD_FILE        = -4;
    public final static int SSL_NOT_IMPLEMENTED = -3;
    public final static int SSL_UNKNOWN         = -2;
    public final static int SSL_FATAL_ERROR     = -1;

    public final static int SSL_FILETYPE_ASN1    = 2;
    public final static int SSL_FILETYPE_PEM     = 1;
    /** ASN1 */
    public final static int SSL_FILETYPE_DEFAULT = 2;
    /** NTRU raw key blog */
    public final static int SSL_FILETYPE_RAW     = 3;

    /**
     * Verification mode for peer certificates.
     * <p>
     * <b>Client mode:</b> the client will not verify the certificate
     * received from the server and the handshake will continue as normal.
     * <br>
     * <b>Server mode:</b> the server will not send a certificate request
     * to the client. As such, client verification will not be enabled.
     *
     * @see WolfSSLContext#setVerify(long, int, WolfSSLVerifyCallback)
     */
    public final static int SSL_VERIFY_NONE = 0;

    /**
     * Verification mode for peer certificates.
     * <p>
     * <b>Client mode:</b> the client will verify the certificate received
     * from the server during the handshake. This is turned on by default
     * in wolfSSL, therefore, using this option has no effect.
     * <br>
     * <b>Server mode:</b> the server will send a certificate request to the
     * client and verify the client certificate which is received.
     *
     * @see WolfSSLContext#setVerify(long, int, WolfSSLVerifyCallback)
     */
    public final static int SSL_VERIFY_PEER = 1;

    /**
     * Verification mode for peer certificates.
     * <p>
     * <b>Client mode:</b> no effect when used on the client side.
     * <br>
     * <b>Server mode:</b> the verification will fail on the server side
     * if the client fails to send a certificate when requested to do so
     * (when using SSL_VERIFY_PEER on the SSL server).
     *
     * @see WolfSSLContext#setVerify(long, int, WolfSSLVerifyCallback)
     */
    public final static int SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 2;
    public final static int SSL_VERIFY_CLIENT_ONCE          = 4;

    public final static int SSL_SESS_CACHE_OFF                = 30;
    public final static int SSL_SESS_CACHE_CLIENT             = 31;
    public final static int SSL_SESS_CACHE_SERVER             = 32;
    public final static int SSL_SESS_CACHE_BOTH               = 33;
    public final static int SSL_SESS_CACHE_NO_AUTO_CLEAR      = 34;
    public final static int SSL_SESS_CACHE_NO_INTERNAL_LOOKUP = 35;

    public final static int SSL_ERROR_WANT_READ        =  2;
    public final static int SSL_ERROR_WANT_WRITE       =  3;
    public final static int SSL_ERROR_WANT_CONNECT     =  7;
    public final static int SSL_ERROR_WANT_ACCEPT      =  8;
    public final static int SSL_ERROR_SYSCALL          =  5;
    public final static int SSL_ERROR_WANT_X509_LOOKUP = 83;
    public final static int SSL_ERROR_ZERO_RETURN      =  6;
    public final static int SSL_ERROR_SSL              = 85;

    /* extra definitions from ssl.h */
    public final static int WOLFSSL_CRL_CHECKALL      = 1;
    public final static int WOLFSSL_OCSP_URL_OVERRIDE = 1;
    public final static int WOLFSSL_OCSP_NO_NONCE     = 2;

    /* I/O callback default errors, pulled from wolfssl/ssl.h IOerrors */
    public final static int WOLFSSL_CBIO_ERR_GENERAL    = -1;
    public final static int WOLFSSL_CBIO_ERR_WANT_READ  = -2;
    public final static int WOLFSSL_CBIO_ERR_WANT_WRITE = -2;
    public final static int WOLFSSL_CBIO_ERR_CONN_RST   = -3;
    public final static int WOLFSSL_CBIO_ERR_ISR        = -4;
    public final static int WOLFSSL_CBIO_ERR_CONN_CLOSE = -5;
    public final static int WOLFSSL_CBIO_ERR_TIMEOUT    = -6;

    /* Atomic User Needs, from ssl.h */
    public final static int WOLFSSL_SERVER_END  = 0;
    public final static int WOLFSSL_CLIENT_END  = 1;
    public final static int WOLFSSL_BLOCK_TYPE  = 2;
    public final static int WOLFSSL_STREAM_TYPE = 3;
    public final static int WOLFSSL_AEAD_TYPE   = 4;
    public final static int WOLFSSL_TLS_HMAC_INNER_SZ = 13;

    /* GetBulkCipher enum, pulled in from ssl.h for Atomic Record layer */
    public static int wolfssl_cipher_null;
    public static int wolfssl_rc4;
    public static int wolfssl_rc2;
    public static int wolfssl_des;
    public static int wolfssl_triple_des;
    public static int wolfssl_des40;
    public static int wolfssl_idea;
    public static int wolfssl_aes;
    public static int wolfssl_aes_gcm;
    public static int wolfssl_aes_ccm;
    public static int wolfssl_hc128;
    public static int wolfssl_rabbit;

    /* wolfSSL error codes, pulled in from wolfssl/error.h wolfSSL_ErrorCodes */
    public final static int GEN_COOKIE_E    =   -277;

    public final static int SSL_SENT_SHUTDOWN                   = 1;
    public final static int SSL_RECEIVED_SHUTDOWN               = 2;
    public final static int SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER = 4;
    public final static int SSL_OP_NO_SSLv2                     = 8;
    public final static int SSL_OP_NO_SSLv3                     = 0x00001000;
    public final static int SSL_OP_NO_TLSv1                     = 0x00002000;
    public final static int SSL_OP_NO_TLSv1_1                   = 0x04000000;
    public final static int SSL_OP_NO_TLSv1_2                   = 0x08000000;
    public final static int SSL_OP_NO_COMPRESSION               = 0x10000000;
    public final static int SSL_OP_NO_TLSv1_3                   = 0x20000000;

    public final static int SSL_HANDSHAKE_FAILURE                 = 101;
    public final static int SSL_R_TLSV1_ALERT_UNKNOWN_CA          = 102;
    public final static int SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN = 103;
    public final static int SSL_R_SSLV3_ALERT_BAD_CERTIFICATE     = 104;

    /** Monitor this CRL directory flag */
    public final static int WOLFSSL_CRL_MONITOR   = 0x01;

    /** Start CRL monitoring flag */
    public final static int WOLFSSL_CRL_START_MON = 0x02;

    /** Bad mutex */
    public final static int BAD_MUTEX_ERROR      = -256;

    /** Bad path for opendir */
    public final static int BAD_PATH_ERROR       = -258;

    /** CRL Monitor already running */
    public final static int MONITOR_RUNNING_E    = -263;

    /** Thread create error */
    public final static int THREAD_CREATE_E      = -264;

    /** Cache header match error */
    public final static int CACHE_MATCH_ERROR    = -280;

    /* ---------------------- wolfCrypt codes ---------------------------- */

    /** Out of memory error */
    public final static int MEMORY_E        = -125;

    /** Output buffer too small or input too large */
    public final static int BUFFER_E        = -132;

    /** ASN input error, not enough data */
    public final static int ASN_INPUT_E     = -154;

    /** Bad function argument provided */
    public final static int BAD_FUNC_ARG    = -173;

    /** Feature not compiled in */
    public final static int NOT_COMPILED_IN = -174;

    /** No password provided by user */
    public final static int NO_PASSWORD     = -176;

    /* hmac codes, from wolfssl/wolfcrypt/hmac.h */
    public final static int MD5   = 0;
    public final static int SHA   = 1;
    public final static int SHA256 = 2;
    public final static int SHA512 = 4;
    public final static int SHA384 = 5;

    /* key types */
    public final static int DSAk     = 515;
    public final static int RSAk     = 645;
    public final static int NTRUk    = 274;
    public final static int ECDSAk   = 518;
    public final static int ED25519k = 256;

    /* ------------------------ constructors ---------------------------- */

    /**
     * Initializes the wolfSSL library for use.
     *
     * @throws com.wolfssl.WolfSSLException if wolfSSL library fails to
     *                                      initialize correctly
     */
    public WolfSSL() throws WolfSSLException {
        int ret = init();
        if (ret != SSL_SUCCESS) {
            throw new WolfSSLException("Failed to initialize wolfSSL library: "
                    + ret);
        }

        /* initialize enum values */
        wolfssl_aes         = getBulkCipherAlgorithmEnumAES();
        wolfssl_cipher_null = getBulkCipherAlgorithmEnumNULL();
        wolfssl_rc4         = getBulkCipherAlgorithmEnumRC4();
        wolfssl_rc2         = getBulkCipherAlgorithmEnumRC2();
        wolfssl_des         = getBulkCipherAlgorithmEnumDES();
        wolfssl_triple_des  = getBulkCipherAlgorithmEnumDES();
        wolfssl_des40       = getBulkCipherAlgorithmEnumDES40();
        wolfssl_idea        = getBulkCipherAlgorithmEnumIDEA();
        wolfssl_aes_gcm     = getBulkCipherAlgorithmEnumAESGCM();
        wolfssl_aes_ccm     = getBulkCipherAlgorithmEnumAESCCM();
        wolfssl_hc128       = getBulkCipherAlgorithmEnumHC128();
        wolfssl_rabbit      = getBulkCipherAlgorithmEnumRABBIT();
    }

    /* ------------------- private/protected methods -------------------- */

    private native int init();

    public static native void nativeFree(long ptr);

    static native int getBulkCipherAlgorithmEnumNULL();
    static native int getBulkCipherAlgorithmEnumRC4();
    static native int getBulkCipherAlgorithmEnumRC2();
    static native int getBulkCipherAlgorithmEnumDES();
    static native int getBulkCipherAlgorithmEnum3DES();
    static native int getBulkCipherAlgorithmEnumDES40();
    static native int getBulkCipherAlgorithmEnumIDEA();
    static native int getBulkCipherAlgorithmEnumAES();
    static native int getBulkCipherAlgorithmEnumAESGCM();
    static native int getBulkCipherAlgorithmEnumAESCCM();
    static native int getBulkCipherAlgorithmEnumCHACHA();
    static native int getBulkCipherAlgorithmEnumCAMELLIA();
    static native int getBulkCipherAlgorithmEnumHC128();
    static native int getBulkCipherAlgorithmEnumRABBIT();

    static native String getEnabledCipherSuites();
    static native String getEnabledCipherSuitesIana();

    /* ------------------------- Java methods --------------------------- */

    /**
     * Loads JNI library; must be called prior to any other calls in this class.
     *
     * The native library is expected to be be called "wolfssljni", and must be
     * on the system library search path.
     *
     * @throws UnsatisfiedLinkError if the library is not found.
     */
    public static void loadLibrary() throws UnsatisfiedLinkError {
        System.loadLibrary("wolfssljni");
    }

    /**
     * Load JNI library with a specific name; must be called prior to any
     * other calls in this package.
     *
     * The native library needs to be located on the system library search
     * path.
     *
     * @param  libName name of native JNI library
     * @throws UnsatisfiedLinkError if the library is not found.
     */
    public static void loadLibrary(String libName) throws UnsatisfiedLinkError {
        System.loadLibrary(libName);
    }

    /**
     * Loads dynamic JNI library from a specific path; must be called prior to
     * any other calls in this package.
     *
     * This function gives the application more control over the exact native
     * library being loaded, as both WolfSSL.loadLibrary() and
     * WolfSSL.loadLibrary(String libName) search for a library on the system
     * library search path. This function allows the appliation to specify
     * a specific absolute path to the native library file to load, thus
     * guaranteeing the exact library loaded and helping to prevent against
     * malicious attackers from attempting to override the library being
     * loaded.
     *
     * @param  libPath complete path name to the native dynamic JNI library
     * @throws UnsatisfiedLinkError if the library is not found.
     */
    public static void loadLibraryAbsolute(String libPath)
        throws UnsatisfiedLinkError {
        System.load(libPath);
    }

    /* --------------- native feature detection functions --------------- */

    /**
     * Tests if TLS 1.0 has been compiled into the native wolfSSL library.
     * TLS 1.0 is disabled by default in native wolfSSL, unless the user
     * has configured wolfSSL with "--enable-tls10".
     *
     * @return 1 if enabled, otherwise 0 if not compiled in.
     */
    public static native boolean TLSv1Enabled();

    /**
     * Tests if TLS 1.1 has been compiled into the native wolfSSL library.
     *
     * @return 1 if enabled, otherwise 0 if not compiled in.
     */
    public static native boolean TLSv11Enabled();

    /**
     * Tests if TLS 1.2 has been compiled into the native wolfSSL library.
     *
     * @return 1 if enabled, otherwise 0 if not compiled in.
     */
    public static native boolean TLSv12Enabled();

    /**
     * Tests if TLS 1.3 has been compiled into the native wolfSSL library.
     *
     * @return 1 if enabled, otherwise 0 if not compiled in.
     */
    public static native boolean TLSv13Enabled();

    /**
     * Tests if ECC support has been compiled into the native wolfSSL library.
     *
     * @return 1 if enabled, otherwise 0 if not compiled in.
     */
    public static native boolean EccEnabled();

    /**
     * Tests if RSA support has been compiled into the native wolfSSL library.
     *
     * @return 1 if enabled, otherwise 0 if not compiled in.
     */
    public static native boolean RsaEnabled();

    /* ---------------- native SSL/TLS version functions ---------------- */

    /**
     * Indicates that the application is a server and will only support the
     * SSL 3.0 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     * @deprecated SSL 3.0 is now considered insecure.
     */
    @Deprecated
    public final static native long SSLv3_ServerMethod();

    /**
     * Indicates that the application is a client and will only support the
     * SSL 3.0 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     * @deprecated SSL 3.0 is now considered insecure.
     */
    @Deprecated
    public final static native long SSLv3_ClientMethod();

    /**
     * Indicates that the application will only support the TLS 1.0 protocol.
     * Application is side-independent at this time, and client/server side
     * will be determined at connect/accept stage.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public final static native long TLSv1_Method();

    /**
     * Indicates that the application is a server and will only support the
     * TLS 1.0 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public final static native long TLSv1_ServerMethod();

    /**
     * Indicates that the application is a client and will only support the
     * TLS 1.0 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public final static native long TLSv1_ClientMethod();

    /**
     * Indicates that the application will only support the TLS 1.1 protocol.
     * Application is side-independent at this time, and client/server side
     * will be determined at connect/accept stage.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public final static native long TLSv1_1_Method();

    /**
     * Indicates that the application is a server and will only support the
     * TLS 1.1 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public final static native long TLSv1_1_ServerMethod();

    /**
     * Indicates that the application is a client and will only support the
     * TLS 1.1 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public final static native long TLSv1_1_ClientMethod();

    /**
     * Indicates that the application will only support the TLS 1.2 protocol.
     * Application is side-independent at this time, and client/server side
     * will be determined at connect/accept stage.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public final static native long TLSv1_2_Method();

    /**
     * Indicates that the application is a server and will only support the
     * TLS 1.2 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public final static native long TLSv1_2_ServerMethod();

    /**
     * Indicates that the application is a client and will only support the
     * TLS 1.2 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public final static native long TLSv1_2_ClientMethod();

    /**
     * Indicates that the application will only support the TLS 1.3 protocol.
     * Application is side-independent at this time, and client/server side
     * will be determined at connect/accept stage.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public final static native long TLSv1_3_Method();

    /**
     * Indicates that the application will only support the DTLS 1.0 protocol.
     * Application is side-independent at this time, and client/server side
     * will be determined at connect/accept stage.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public final static native long DTLSv1_Method();

    /**
     * Indicates that the application is a server and will only support the
     * DTLS 1.0 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public final static native long DTLSv1_ServerMethod();

    /**
     * Indicates that the application is a client and will only support the
     * DTLS 1.0 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public final static native long DTLSv1_ClientMethod();

    /**
     * Indicates that the application will only support the DTLS 1.2 protocol.
     * Application is side-independent at this time, and client/server side
     * will be determined at connect/accept stage.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public final static native long DTLSv1_2_Method();

    /**
     * Indicates that the application is a server and will only support the
     * DTLS 1.2 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public final static native long DTLSv1_2_ServerMethod();

    /**
     * Indicates that the application is a client and will only support the
     * DTLS 1.2 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public final static native long DTLSv1_2_ClientMethod();

    /**
     * Indicates that the application will use the highest possible SSL/TLS
     * version from SSL 3.0 up to TLS 1.2, but is side-independent at creation
     * time. Client/server side will be determined at connect/accept stage.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public final static native long SSLv23_Method();

    /**
     * Indicates that the application is a server and will use the highest
     * possible SSL/TLS version from SSL 3.0 up to TLS 1.2.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public final static native long SSLv23_ServerMethod();

    /**
     * Indicates that the application is a client and will use the highest
     * possible SSL/TLS version from SSL 3.0 up to TLS 1.2.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public final static native long SSLv23_ClientMethod();

    /**
     * Converts an error code returned by getError() into a more human-
     * readable error string.
     * The maximum length of the returned string is 80 characters by
     * default, as defined by MAX_ERROR_SZ in the native wolfSSL
     * error.h header file.
     *
     * @param errNumber     error code returned by <code>getError()</code>
     * @return              output String containing human-readable error
     *                      string matching <code>errNumber</code>
     *                      on success. On failure, this method returns a
     *                      String with the appropriate failure reason.
     * @see                 WolfSSLSession#getError(long, int)
     */
    public final static native String getErrorString(long errNumber);

    /**
     * Un-initializes the wolfSSL library from further use.
     * Doesn't have to be called, though it will free any resources used by
     * the library.
     *
     * @return <code>SSL_SUCCESS</code> upon success, <code>BAD_MUTEX_ERROR
     *         </code> on mutex error.
     */
    public final static native int cleanup();

    /**
     * Turns on debug logging at runtime.
     * To enable logging at build time, use <b>--enable-debug</b> or define
     * <b>DEBUG_WOLFSSL</b>. Debugging must be enabled at build time in order
     * for the method to have any effect.
     *
     * @return  <code>SSL_SUCCESS</code> upon success. <code>NOT_COMPILED_IN
     *          </code> if logging isnt' enabled for this wolfSSL build.
     * @see     #debuggingOFF()
     * @see     #setLoggingCb(WolfSSLLoggingCallback)
     */
    public final static native int debuggingON();

    /**
     * Turns off runtime debug log messages.
     * If they're already off, no action is taken.
     *
     * @see #debuggingON()
     * @see #setLoggingCb(WolfSSLLoggingCallback)
     */
    public final static native void debuggingOFF();

    /**
     * Registers the callback to be used for Logging debug and trace
     * messages.
     *
     * @param cb    Callback to be used for logging debug messages
     * @return      <b><code>SSL_ERROR_NONE</code></b> upon success,
     *              <b><code>BAD_FUNC_ARG</code></b> if input is null,
     *              <b><code>NOT_COMPILED_IN</code></b> if wolfSSL was not
     *              compiled with debugging support enabled.
     * @see         #debuggingON()
     * @see         #debuggingOFF()
     */
    public final static native int setLoggingCb(WolfSSLLoggingCallback cb);

    /**
     * Persists session cache to memory buffer.
     * This method can be used to persist the current session cache to a
     * memory buffer for storage. The cache can be loaded back into wolfSSL
     * using the corresponding <code>memrestoreSessionCache()</code> method.
     *
     * @param mem   buffer to store session cache in
     * @param sz    size of the input buffer, <b>mem</b>
     * @return      <b><code>SSL_SUCCESS</code></b> on success,
     *              <b><code>SSL_FAILURE</code></b> on general failure,
     *              <b><code>BUFFER_E</code></b> if the memory buffer is too
     *              small to store the session cache in,
     *              <b><code>BAD_MUTEX_ERROR</code></b> if the session cache
     *              mutex lock failed,
     *              <b><code>BAD_FUNC_ARG</code></b> if invalid parameters are
     *              used.
     * @see         #memrestoreSessionCache(byte[], int)
     * @see         #getSessionCacheMemsize()
     * @see         WolfSSLContext#memsaveCertCache(long, byte[], int, int[])
     * @see         WolfSSLContext#memrestoreCertCache(long, byte[], int)
     * @see         WolfSSLContext#getCertCacheMemsize(long)
     */
    public static native int memsaveSessionCache(byte[] mem, int sz);

    /**
     * Restores the persistant session cache from memory buffer.
     * This function restores a session cache that was previously saved to
     * a memory buffer.
     *
     * @param mem   buffer containing persistant session cache to be restored
     * @param sz    size of the input buffer, <b>mem</b>
     * @return      <b><code>SSL_SUCCESS</code></b> upon success,
     *              <b><code>SSL_FAILURE</code></b> upon general failure,
     *              <b><code>BUFFER_E</code></b> if the memory buffer is too
     *              small, <b><code>CACHE_MATCH_ERROR</code></b> if the
     *              session cache header match failed and there were
     *              differences in how the cache and the current library
     *              are configured, <b><code>BAD_MUTEX_ERROR</code></b>
     *              if the session cache mutex lock failed,
     *              <b><code>BAD_FUNC_ARG</code></b> if invalid parameters are
     *              used.
     * @see         #memsaveSessionCache(byte[], int)
     * @see         #getSessionCacheMemsize()
     * @see         WolfSSLContext#memsaveCertCache(long, byte[], int, int[])
     * @see         WolfSSLContext#memrestoreCertCache(long, byte[], int)
     * @see         WolfSSLContext#getCertCacheMemsize(long)
     */
    public static native int memrestoreSessionCache(byte[] mem, int sz);

    /**
     * Gets how big the session cache save buffer needs to be.
     * Use this method to determine how large the buffer needs to be to
     * store the persistant session cache into memory.
     *
     * @return      size, in bytes, of how large the output buffer should be
     *              to store the session cache into memory.
     * @see         #memsaveSessionCache(byte[], int)
     * @see         #memrestoreSessionCache(byte[], int)
     * @see         WolfSSLContext#memsaveCertCache(long, byte[], int, int[])
     * @see         WolfSSLContext#memrestoreCertCache(long, byte[], int)
     * @see         WolfSSLContext#getCertCacheMemsize(long)
     */
    public static native int getSessionCacheMemsize();

    /**
     * Strips off PKCS#8 header from byte array.
     * This function starts reading the input array for a PKCS#8 header,
     * beginning at input offset, idx. If found, it returns the offset of
     * the inner traditional data.
     *
     * @param in  input buffer containing PKCS#8 formatted key
     * @param idx index/offset into input array to begin reading
     * @param sz  size of input array
     * @return    offset where the traditional key begins, or negative on
     *            failure.
     */
    public static native int getPkcs8TraditionalOffset(byte[] in, long idx,
        long sz);

    /**
     * Returns the DER-encoded form of the certificate pointed to by
     * x509.
     *
     * @param x509      pointer (long) to a native WOLFSSL_X509 object. This
     *                  objects represents an X.509 certificate.
     * @return          DER-encoded certificate or
     *                  <code>null</code> if the input buffer is null.
     *
     */
    public static native byte[] x509_getDer(long x509);

    /**
     * Returns the wolfSSL max HMAC digest size.
     * Specifically, returns the value of the native wolfSSL
     * MAX_DIGEST_SIZE define.
     *
     * @return  value of native MAX_DIGEST_SIZE define
     */
    public static native int getHmacMaxSize();

    public static String[] getCiphers() {

        String cipherSuites = getEnabledCipherSuites();
        if (cipherSuites == null)
            return null;

        String[] suiteArray = cipherSuites.split(":");

        return suiteArray;
    }

    /**
     * Gets a list of all cipher suites supported and uses the format TLS_*
     * @return list of all cipher suites supported
     */
    public static String[] getCiphersIana() {
        String cipherSuites = getEnabledCipherSuitesIana();
        if (cipherSuites == null)
            return null;

        String[] suiteArray = cipherSuites.split(":");

        return suiteArray;
    }

    /* ------------------------- isEnabled methods -------------------------- */

    /**
     * Checks if CRL support is enabled in wolfSSL native library.
     *
     * @return 1 if enabled, 0 if not compiled in
     */
    public static native int isEnabledCRL();

    /**
     * Checks if CRL Monitor support is enabled in wolfSSL native library.
     *
     * @return 1 if enabled, 0 if not compiled in
     */
    public static native int isEnabledCRLMonitor();

    /**
     * Checks if OCSP support is enabled in wolfSSL native library.
     *
     * @return 1 if enabled, 0 if not compiled in
     */
    public static native int isEnabledOCSP();

    /**
     * Checks if PSK support is enabled in wolfSSL native library.
     *
     * @return 1 if enabled, 0 if not compiled in
     */
    public static native int isEnabledPSK();

    /**
     * Checks if DTLS support is enabled in wolfSSL native library.
     *
     * @return 1 if enabled, 0 if not compiled in
     */
    public static native int isEnabledDTLS();

    /**
     * Checks if Atomic User support is enabled in wolfSSL native library.
     *
     * @return 1 if enabled, 0 if not compiled in
     */
    public static native int isEnabledAtomicUser();

    /**
     * Checks if Public Key Callback support is enabled in wolfSSL
     * native library.
     *
     * @return 1 if enabled, 0 if not compiled in
     */
    public static native int isEnabledPKCallbacks();

    /**
     * Checks which protocols where built into wolfSSL
     *
     * @return an array of Strings for supported protocols
     */
    public static native String[] getProtocols();

    /**
     * Checks which protocols where built into wolfSSL with Mask
     *
     * @param mask flags prohibiting TLS version (i.e. SSL_OP_NO_xxx)
     * @return an array of Strings for supported protocols
     */
    public static native String[] getProtocolsMask(long mask);

} /* end WolfSSL */

