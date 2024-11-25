/* WolfSSLSessionTest.java
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

package com.wolfssl.test;

import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.io.IOException;
import java.net.Socket;
import java.net.ServerSocket;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.net.ConnectException;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.CountDownLatch;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLDebug;
import com.wolfssl.WolfSSLContext;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLJNIException;
import com.wolfssl.WolfSSLPskClientCallback;
import com.wolfssl.WolfSSLPskServerCallback;
import com.wolfssl.WolfSSLTls13SecretCallback;
import com.wolfssl.WolfSSLSession;

public class WolfSSLSessionTest {

    private final static int TEST_FAIL    = -1;
    private final static int TEST_SUCCESS =  0;

    private static String cliCert = "./examples/certs/client-cert.pem";
    private static String cliKey  = "./examples/certs/client-key.pem";
    private static String srvCert = "./examples/certs/server-cert.pem";
    private static String srvKey  = "./examples/certs/server-key.pem";
    private static String caCert  = "./examples/certs/ca-cert.pem";
    private static String bogusFile = "/dev/null";

    private final static String exampleHost = "www.example.com";
    private final static int examplePort = 443;

    private static WolfSSLContext ctx = null;

    @BeforeClass
    public static void loadLibrary()
        throws WolfSSLException{

        System.out.println("WolfSSLSession Class");

        try {
            WolfSSL.loadLibrary();
        } catch (UnsatisfiedLinkError ule) {
            fail("failed to load native JNI library");
        }

        /* Create one WolfSSLContext */
        ctx = new WolfSSLContext(WolfSSL.SSLv23_ClientMethod());

        /* Set cert/key paths */
        cliCert = WolfSSLTestCommon.getPath(cliCert);
        cliKey  = WolfSSLTestCommon.getPath(cliKey);
        srvCert = WolfSSLTestCommon.getPath(srvCert);
        srvKey  = WolfSSLTestCommon.getPath(srvKey);
        caCert  = WolfSSLTestCommon.getPath(caCert);
    }

    @Test
    public void test_WolfSSLSession_new()
        throws WolfSSLJNIException {

        WolfSSLSession sess = null;

        System.out.print("\tWolfSSLSession()");

        try {
            sess = new WolfSSLSession(ctx);

        } catch (WolfSSLException we) {
            System.out.println("\t... failed");
            fail("failed to create WolfSSLSession object");

        } finally {
            if (sess != null) {
                sess.freeSSL();
            }
        }

        System.out.println("\t\t... passed");
    }

    @Test
    public void test_WolfSSLSession_useCertificateFile()
        throws WolfSSLJNIException, WolfSSLException {

        System.out.print("\tuseCertificateFile()");

        WolfSSLSession ssl = new WolfSSLSession(ctx);

        test_ucf("useCertificateFile", null, null, 9999, WolfSSL.SSL_FAILURE,
                 "useCertificateFile(null, null, 9999)");

        test_ucf("useCertificateFile", ssl, bogusFile,
                 WolfSSL.SSL_FILETYPE_PEM, WolfSSL.SSL_FAILURE,
                 "useCertificateFile(ssl, bogusFile, SSL_FILETYPE_PEM)");

        test_ucf("useCertificateFile", ssl, cliCert, 9999,
                 WolfSSL.SSL_FAILURE,
                 "useCertificateFile(ssl, cliCert, 9999)");

        test_ucf("useCertificateFile", ssl, cliCert,
                 WolfSSL.SSL_FILETYPE_PEM,
                 WolfSSL.SSL_SUCCESS,
                 "useCertificateFile(ssl, cliCert, SSL_FILETYPE_PEM)");

        if (ssl != null) {
            ssl.freeSSL();
        }

        System.out.println("\t\t... passed");
    }

    @Test
    public void test_WolfSSLSession_useCertificateChainFile()
        throws WolfSSLJNIException, WolfSSLException {

        System.out.print("\tuseCertificateChainFile()");

        WolfSSLSession ssl = new WolfSSLSession(ctx);

        test_ucf("useCertificateChainFile", null, null, 0,
                 WolfSSL.SSL_FAILURE,
                 "useCertificateChainFile(null, null)");

        test_ucf("useCertificateChainFile", ssl, bogusFile, 0,
                 WolfSSL.SSL_FAILURE,
                 "useCertificateChainFile(ssl, bogusFile)");

        test_ucf("useCertificateChainFile", ssl, cliCert, 0,
                 WolfSSL.SSL_SUCCESS,
                 "useCertificateChainFile(ssl, cliCert)");

        if (ssl != null) {
            ssl.freeSSL();
        }

        System.out.println("\t... passed");
    }

    /* helper for testing WolfSSLSession.useCertificateFile() */
    private void test_ucf(String func, WolfSSLSession ssl, String filePath,
        int type, int cond, String name) {

        int result = WolfSSL.SSL_FAILURE;

        try {

            if (func.equals("useCertificateFile")) {
                result = ssl.useCertificateFile(filePath, type);
            } else if (func.equals("useCertificateChainFile")) {
                result = ssl.useCertificateChainFile(filePath);
            } else {
                fail(name + " failed");
            }

            if ((result != cond) && (result != WolfSSL.NOT_COMPILED_IN))
            {
                if (func.equals("useCertificateFile")) {
                    System.out.println("\t\t... failed");
                } else {
                    System.out.println("\t... failed");
                }
                fail(name + " failed");
            }

        } catch (NullPointerException e) {

            /* correctly handle NULL pointer */
            if (ssl == null) {
                return;
            }
        }

        return;
    }

    @Test
    public void test_WolfSSLSession_usePrivateKeyFile()
        throws WolfSSLJNIException, WolfSSLException {

        System.out.print("\tusePrivateKeyFile()");

        WolfSSLSession ssl = new WolfSSLSession(ctx);

        test_upkf(null, null, 9999, WolfSSL.SSL_FAILURE,
                 "usePrivateKeyFile(null, null, 9999)");

        test_upkf(ssl, bogusFile, WolfSSL.SSL_FILETYPE_PEM,
                  WolfSSL.SSL_FAILURE,
                 "usePrivateKeyFile(ssl, bogusFile, SSL_FILETYPE_PEM)");

        test_upkf(ssl, cliKey, 9999, WolfSSL.SSL_FAILURE,
                 "usePrivateKeyFile(ssl, cliKey, 9999)");

        test_upkf(ssl, cliKey, WolfSSL.SSL_FILETYPE_PEM, WolfSSL.SSL_SUCCESS,
                 "usePrivateKeyFile(ssl, cliKey, SSL_FILETYPE_PEM)");

        if (ssl != null) {
            ssl.freeSSL();
        }

        System.out.println("\t\t... passed");
    }

    /* helper for testing WolfSSLSession.usePrivateKeyFile() */
    private void test_upkf(WolfSSLSession ssl, String filePath, int type,
        int cond, String name) {

        int result;

        try {

            result = ssl.usePrivateKeyFile(filePath, type);
            if ((result != cond) && (result != WolfSSL.NOT_COMPILED_IN))
            {
                System.out.println("\t\t... failed");
                fail(name + " failed");
            }

        } catch (NullPointerException e) {

            /* correctly handle NULL pointer */
            if (ssl == null) {
                return;
            }
        }

        return;
    }

    class TestPskClientCb implements WolfSSLPskClientCallback
    {
        public long pskClientCallback(WolfSSLSession ssl, String hint,
                StringBuffer identity, long idMaxLen, byte[] key,
                long keyMaxLen) {

            /* set the client identity */
            if (identity.length() != 0)
                return 0;
            identity.append("Client_identity");

            /* set the client key, max key size is key.length */
            key[0] = 26;
            key[1] = 43;
            key[2] = 60;
            key[3] = 77;

            /* return size of key */
            return 4;
        }
    }

    @Test
    public void test_WolfSSLSession_setPskClientCb()
        throws WolfSSLJNIException {

        WolfSSLSession ssl = null;

        System.out.print("\tsetPskClientCb()");

        try {
            TestPskClientCb pskClientCb = new TestPskClientCb();
            ssl = new WolfSSLSession(ctx);
            ssl.setPskClientCb(pskClientCb);

        } catch (Exception e) {
            if (e.getMessage().equals("wolfSSL not compiled with PSK " +
                "support")) {
                /* Not compiled in, skip */
                System.out.println("\t\t... skipped");
                return;
            }
            else {
                System.out.println("\t\t... failed");
                fail("Failed setPskClientCb test");
                e.printStackTrace();
            }

        } finally {
            if (ssl != null) {
                ssl.freeSSL();
            }
        }

        System.out.println("\t\t... passed");
    }

    class TestPskServerCb implements WolfSSLPskServerCallback
    {
        public long pskServerCallback(WolfSSLSession ssl, String identity,
                byte[] key, long keyMaxLen) {

            /* check the client identity */
            if (!identity.equals("Client_identity"))
                return 0;

            /* set the server key, max key size is key.length */
            key[0] = 26;
            key[1] = 43;
            key[2] = 60;
            key[3] = 77;

            /* return size of key */
            return 4;
        }
    }

    @Test
    public void test_WolfSSLSession_setPskServerCb()
        throws WolfSSLJNIException {

        WolfSSLSession ssl = null;

        System.out.print("\tsetPskServerCb()");

        try {
            TestPskServerCb pskServerCb = new TestPskServerCb();
            ssl = new WolfSSLSession(ctx);
            ssl.setPskServerCb(pskServerCb);

        } catch (Exception e) {
            if (e.getMessage().equals("wolfSSL not compiled with PSK " +
                "support")) {
                /* Not compiled in, skip */
                System.out.println("\t\t... skipped");
                return;
            }
            else {
                System.out.println("\t\t... failed");
                fail("Failed setPskServerCb test");
                e.printStackTrace();
            }

        } finally {
            if (ssl != null) {
                ssl.freeSSL();
            }
        }

        System.out.println("\t\t... passed");
    }

    @Test
    public void test_WolfSSLSession_useGetPskIdentityHint()
        throws WolfSSLJNIException, WolfSSLException {

        int ret = 0;
        String hint = null;
        WolfSSLSession ssl = null;

        System.out.print("\tuse/getPskIdentityHint()");

        ssl = new WolfSSLSession(ctx);

        try {
            /* Set PSK identity hint */
            ret = ssl.usePskIdentityHint("wolfssl hint");
            if (ret != WolfSSL.SSL_SUCCESS &&
                ret != WolfSSL.NOT_COMPILED_IN) {
                System.out.println("\t... failed");
                fail("usePskIdentityHint failed");
            }

            /* Get PSK identity hint */
            hint = ssl.getPskIdentityHint();
            if (hint != null && !hint.equals("wolfssl hint")) {
                System.out.println("\t... failed");
                fail("getPskIdentityHint failed");
            }

        } catch (IllegalStateException e) {
            System.out.println("\t... failed");
            e.printStackTrace();
            fail("Failed use/getPskIdentityHint test");

        } finally {
            if (ssl != null) {
                ssl.freeSSL();
            }
        }

        System.out.println("\t... passed");
    }

    @Test
    public void test_WolfSSLSession_useSessionTicket()
        throws WolfSSLJNIException, WolfSSLException {

        int ret = 0;
        WolfSSLSession ssl = null;

        System.out.print("\tuseSessionTicket()");

        try {
            ssl = new WolfSSLSession(ctx);

            ret = ssl.useSessionTicket();
            if (ret != WolfSSL.SSL_SUCCESS &&
                ret != WolfSSL.NOT_COMPILED_IN) {
                System.out.println("\t\t... failed");
                fail("useSessionTicket failed");
            }

        } catch (IllegalStateException e) {
            System.out.println("\t\t... failed");
            e.printStackTrace();

        } finally {
            if (ssl != null) {
                ssl.freeSSL();
            }
        }

        System.out.println("\t\t... passed");
    }

    @Test
    public void test_WolfSSLSession_getPskIdentity()
        throws WolfSSLJNIException, WolfSSLException {

        String identity = null;
        WolfSSLSession ssl = null;

        System.out.print("\tgetPskIdentity()");

        try {
            ssl = new WolfSSLSession(ctx);
            identity = ssl.getPskIdentity();

        } catch (IllegalStateException e) {
            System.out.println("\t\t... failed");
            fail("Failed getPskIdentity test");
            e.printStackTrace();

        } finally {
            if (ssl != null) {
                ssl.freeSSL();
            }
        }

        System.out.println("\t\t... passed");
    }

    @Test
    public void test_WolfSSLSession_timeout()
        throws WolfSSLJNIException, WolfSSLException {

        WolfSSLSession ssl = null;

        System.out.print("\ttimeout()");

        ssl = new WolfSSLSession(ctx);

        try {
            ssl.setTimeout(5);
            if (ssl.getTimeout() != 5) {
                System.out.println("\t\t\t... failed");
                fail("Failed timeout test");
            }

        } finally {
            if (ssl != null) {
                ssl.freeSSL();
            }
        }

        System.out.println("\t\t\t... passed");
    }

    @Test
    public void test_WolfSSLSession_status()
        throws WolfSSLJNIException, WolfSSLException {

        WolfSSLSession ssl = null;

        System.out.print("\tstatus()");

        ssl = new WolfSSLSession(ctx);

        try {
            if (ssl.handshakeDone() == true) {
                System.out.println("\t\t\t... failed");
                fail("Failed status test");
            }

        } finally {
            if (ssl != null) {
                ssl.freeSSL();
            }
        }

        System.out.println("\t\t\t... passed");
    }

    @Test
    public void test_WolfSSLSession_useSNI()
        throws WolfSSLJNIException, WolfSSLException {

        int ret;
        String sniHostName = "www.example.com";
        WolfSSLSession ssl = null;

        System.out.print("\tuseSNI()");

        ssl = new WolfSSLSession(ctx);

        try {
            ret = ssl.useSNI((byte)0, sniHostName.getBytes());
            if (ret == WolfSSL.NOT_COMPILED_IN) {
                System.out.println("\t\t\t... skipped");
                return;
            } else if (ret != WolfSSL.SSL_SUCCESS) {
                System.out.println("\t\t\t... failed");
                fail("Failed useSNI test");
            }

        } finally {
            if (ssl != null) {
                ssl.freeSSL();
            }
        }

        System.out.println("\t\t\t... passed");
    }

    @Test
    public void test_WolfSSLSession_useALPN()
        throws WolfSSLException, WolfSSLJNIException {

        int ret;
        String[] alpnProtos = new String[] {
            "h2", "http/1.1"
        };
        String http11Alpn = "http/1.1";
        byte[] alpnProtoBytes = http11Alpn.getBytes();
        byte[] alpnProtoBytesPacked = new byte[1 + alpnProtoBytes.length];
        WolfSSLSession ssl = null;

        System.out.print("\tuseALPN()");

        ssl = new WolfSSLSession(ctx);

        try {
            /* Testing useALPN(String[], int) */
            ret = ssl.useALPN(alpnProtos,
                WolfSSL.WOLFSSL_ALPN_CONTINUE_ON_MISMATCH);

            if (ret == WolfSSL.SSL_SUCCESS) {
                ret = ssl.useALPN(alpnProtos,
                    WolfSSL.WOLFSSL_ALPN_FAILED_ON_MISMATCH);
            }

            if (ret == WolfSSL.SSL_SUCCESS) {
                ret = ssl.useALPN(null,
                    WolfSSL.WOLFSSL_ALPN_CONTINUE_ON_MISMATCH);
                if (ret < 0) {
                    /* error expected, null input */
                    ret = WolfSSL.SSL_SUCCESS;
                }
            }

            if (ret == WolfSSL.SSL_SUCCESS) {
                ret = ssl.useALPN(alpnProtos, 0);
                if (ret < 0) {
                    /* error expected, no options */
                    ret = WolfSSL.SSL_SUCCESS;
                }
            }

            if (ret == WolfSSL.SSL_SUCCESS) {
                ret = ssl.useALPN(alpnProtos, -123);
                if (ret < 0) {
                    /* error expected, invalid options */
                    ret = WolfSSL.SSL_SUCCESS;
                }
            }

            /* Testing useALPN(byte[]) */
            if (ret == WolfSSL.SSL_SUCCESS) {

                alpnProtoBytesPacked[0] = (byte)http11Alpn.length();
                System.arraycopy(alpnProtoBytes, 0, alpnProtoBytesPacked, 1,
                    alpnProtoBytes.length);

                ret = ssl.useALPN(alpnProtoBytesPacked);
            }

            if (ret == WolfSSL.SSL_SUCCESS) {
                ret = ssl.useALPN(null);
                if (ret < 0) {
                    /* error expected, null input */
                    ret = WolfSSL.SSL_SUCCESS;
                }
            }

            if (ret == WolfSSL.NOT_COMPILED_IN) {
                System.out.println("\t\t\t... skipped");
                return;

            } else if (ret != WolfSSL.SSL_SUCCESS) {
                System.out.println("\t\t\t... failed");
                fail("Failed useALPN test");
            }

        } finally {
            if (ssl != null) {
                ssl.freeSSL();
            }
        }

        System.out.println("\t\t\t... passed");
    }

    @Test
    public void test_WolfSSLSession_freeSSL()
        throws WolfSSLJNIException, WolfSSLException {

        WolfSSLSession ssl = null;

        System.out.print("\tfreeSSL()");

        ssl = new WolfSSLSession(ctx);

        try {
            ssl.freeSSL();

        } catch (WolfSSLJNIException e) {
            System.out.println("\t\t\t... failed");
            fail("Failed freeSSL test");
            e.printStackTrace();

        }

        System.out.println("\t\t\t... passed");
    }

    @Test
    public void test_WolfSSLSession_UseAfterFree()
        throws WolfSSLJNIException {

        int ret, err;
        WolfSSL sslLib = null;
        WolfSSLContext sslCtx = null;
        WolfSSLSession ssl = null;
        Socket sock = null;

        System.out.print("\tTesting use after free");

        try {

            /* setup library, context, session, socket */
            sslLib = new WolfSSL();
            sslCtx = new WolfSSLContext(WolfSSL.TLSv1_2_ClientMethod());
            sslCtx.setVerify(WolfSSL.SSL_VERIFY_NONE, null);
            ssl = new WolfSSLSession(sslCtx);

            sock = new Socket(exampleHost, examplePort);
            ret = ssl.setFd(sock);
            if (ret != WolfSSL.SSL_SUCCESS) {
                ssl.freeSSL();
                sslCtx.free();
                fail("Failed to set file descriptor");
            }

            /* successful connection test */
            do {
                ret = ssl.connect();
                err = ssl.getError(ret);
            } while (ret != WolfSSL.SSL_SUCCESS &&
                   (err == WolfSSL.SSL_ERROR_WANT_READ ||
                    err == WolfSSL.SSL_ERROR_WANT_WRITE));

            if (ret != WolfSSL.SSL_SUCCESS) {
                fail("Failed WolfSSL.connect() to " + exampleHost);
            }

        } catch (UnknownHostException | ConnectException e) {
            /* skip if no Internet connection */
            System.out.println("\t\t... skipped");
            return;

        } catch (Exception e) {
            System.out.println("\t\t... failed");
            fail("Failed UseAfterFree test");
            e.printStackTrace();
            return;

        } finally {
            if (ssl != null) {
                ssl.freeSSL();
            }
            if (sslCtx != null) {
                sslCtx.free();
            }
        }

        try {
            /* this should fail, use after free */
            ret = ssl.connect();

        } catch (IllegalStateException ise) {
            System.out.println("\t\t... passed");
            return;

        } catch (SocketTimeoutException | SocketException e) {
            System.out.println("\t\t... failed");
            fail("Failed UseAfterFree test");
            e.printStackTrace();
            return;
        }

        /* fail here means WolfSSLSession was used after free without
         * exception thrown */
        System.out.println("\t\t... failed");
        fail("WolfSSLSession was able to be used after freed");
    }

    @Test
    public void test_WolfSSLSession_getSessionID()
        throws WolfSSLJNIException {

        int ret, err;
        WolfSSL sslLib = null;
        WolfSSLContext sslCtx = null;
        WolfSSLSession ssl = null;
        Socket sock = null;
        byte[] sessionID = null;

        System.out.print("\tTesting getSessionID()");

        try {

            /* setup library, context, session, socket */
            sslLib = new WolfSSL();
            sslCtx = new WolfSSLContext(WolfSSL.TLSv1_2_ClientMethod());
            sslCtx.setVerify(WolfSSL.SSL_VERIFY_NONE, null);
            ssl = new WolfSSLSession(sslCtx);

            sessionID = ssl.getSessionID();
            if (sessionID == null || sessionID.length != 0) {
                /* sessionID array should not be null, but should be empty */
                fail("Session ID should be empty array before connection");
            }

            sock = new Socket(exampleHost, examplePort);
            ret = ssl.setFd(sock);
            if (ret != WolfSSL.SSL_SUCCESS) {
                fail("Failed to set file descriptor");
            }

            /* successful connection test */
            do {
                ret = ssl.connect();
                err = ssl.getError(ret);
            } while (ret != WolfSSL.SSL_SUCCESS &&
                   (err == WolfSSL.SSL_ERROR_WANT_READ ||
                    err == WolfSSL.SSL_ERROR_WANT_WRITE));

            if (ret != WolfSSL.SSL_SUCCESS) {
                fail("Failed WolfSSL.connect() to " + exampleHost);
            }

            sessionID = ssl.getSessionID();
            if (sessionID == null || sessionID.length == 0) {
                /* session ID should not be null or zero length */
                fail("Session ID should not be null or 0 length " +
                     "after connection");
            }

        } catch (UnknownHostException | ConnectException e) {
            /* skip if no Internet connection */
            System.out.println("\t\t... skipped");
            return;

        } catch (Exception e) {
            System.out.println("\t\t... failed");
            fail("Failed getSessionID test");
            e.printStackTrace();
            return;

        } finally {
            if (ssl != null) {
                ssl.freeSSL();
            }
            if (sslCtx != null) {
                sslCtx.free();
            }
        }

        System.out.println("\t\t... passed");
    }

    @Test
    public void test_WolfSSLSession_useSecureRenegotiation()
        throws WolfSSLJNIException {

        int ret, err;
        WolfSSL sslLib = null;
        WolfSSLContext sslCtx = null;
        WolfSSLSession ssl = null;
        Socket sock = null;
        byte[] sessionID = null;

        System.out.print("\tTesting useSecureRenegotiation()");

        try {

            /* setup library, context, session, socket */
            sslLib = new WolfSSL();
            sslCtx = new WolfSSLContext(WolfSSL.TLSv1_2_ClientMethod());
            sslCtx.setVerify(WolfSSL.SSL_VERIFY_NONE, null);
            ssl = new WolfSSLSession(sslCtx);

            /* test if enable call succeeds */
            ret = ssl.useSecureRenegotiation();
            if (ret != WolfSSL.SSL_SUCCESS && ret != WolfSSL.NOT_COMPILED_IN) {
                System.out.println("... failed");
                fail("Failed useSecureRenegotiation test");
                return;
            }

        } catch (Exception e) {
            System.out.println("... failed");
            fail("Failed useSecureRenegotiation test");
            e.printStackTrace();
            return;

        } finally {
            if (ssl != null) {
                ssl.freeSSL();
            }
            if (sslCtx != null) {
                sslCtx.free();
            }
        }

        System.out.println("... passed");
    }

    class TestTls13SecretCb implements WolfSSLTls13SecretCallback
    {
        public int tls13SecretCallback(WolfSSLSession ssl, int id,
            byte[] secret, Object ctx)
        {
            return 0;
        }
    }

    @Test
    public void test_WolfSSLSession_setTls13SecretCb()
        throws WolfSSLJNIException {

        int ret;
        WolfSSL sslLib = null;
        WolfSSLContext sslCtx = null;
        WolfSSLSession ssl = null;
        TestTls13SecretCb cb = null;

        System.out.print("\tTesting setTls13SecretCb()");

        if (!WolfSSL.secretCallbackEnabled()) {
            System.out.println("\t... skipped");
            return;
        }

        try {

            /* setup library, context, session, socket */
            sslLib = new WolfSSL();
            sslCtx = new WolfSSLContext(WolfSSL.TLSv1_3_ClientMethod());
            sslCtx.setVerify(WolfSSL.SSL_VERIFY_NONE, null);
            ssl = new WolfSSLSession(sslCtx);

            /* setting with null should pass */
            ssl.setTls13SecretCb(null, null);

            /* set with test callback */
            cb = new TestTls13SecretCb();
            ssl.setTls13SecretCb(cb, null);

        } catch (Exception e) {
            System.out.println("\t... failed");
            e.printStackTrace();
            fail("failed setTls13SecretCb() test");
            return;

        } finally {
            if (ssl != null) {
                ssl.freeSSL();
            }
            if (sslCtx != null) {
                sslCtx.free();
            }
        }

        System.out.println("\t... passed");
    }

    /**
     * Creates a WolfSSLContext using the certs and keys provided.
     *
     * @param certPath file path to local peer certificate chain, PEM format
     * @param keyPath file path to local peer private key file
     * @param keyFormat format of private key file, ie
     *        WolfSSL.SSL_FILETYPE_PEM
     * @param caCertPath file path to CA cert file used to verify peer, PEM
     *        formatted file
     * @param method protocol method to use for this context, ie
     *        WolfSSL.SSLv23_ClientMethod, WolfSSL.SSLv23_ServerMethod, etc
     */
    private WolfSSLContext createAndSetupWolfSSLContext(
        String certPath, String keyPath, int keyFormat,
        String caCertPath, long method) throws Exception {

        int ret;
        WolfSSLContext ctx = null;

        ctx = new WolfSSLContext(method);

        ret = ctx.useCertificateChainFile(certPath);
        if (ret != WolfSSL.SSL_SUCCESS) {
            ctx.free();
            throw new Exception("Failed to load certificate: " + certPath);
        }

        ret = ctx.usePrivateKeyFile(keyPath, keyFormat);
        if (ret != WolfSSL.SSL_SUCCESS) {
            ctx.free();
            throw new Exception("Failed to load private key: " + keyPath);
        }

        ret = ctx.loadVerifyLocations(caCertPath, null);
        if (ret != WolfSSL.SSL_SUCCESS) {
            ctx.free();
            throw new Exception("Failed to load CA certs: " + caCertPath);
        }

        return ctx;
    }

    @Test
    public void test_WolfSSLSession_connectionWithDebug() throws Exception {

        int ret = 0;
        int err = 0;
        Socket cliSock = null;
        WolfSSLSession cliSes = null;

        ByteArrayOutputStream outStream = null;
        PrintStream originalSysOut = System.out;

        /* Create client/server WolfSSLContext objects, Server context
         * must be final since used inside inner class. */
        final WolfSSLContext srvCtx;
        WolfSSLContext cliCtx;

        /* Latch used to wait for server to finish handshake before
         * test shuts down. Otherwise, we will sometimes miss debug
         * messages from the server side. */
        final CountDownLatch latch = new CountDownLatch(1);

        System.out.print("\tTesting wolfssljni.debug");

        /* Save original property value, then enable debug. Make sure
         * connection still works with debug enabled. */
        String originalProp = System.getProperty("wolfssljni.debug");
        System.setProperty("wolfssljni.debug", "true");

        /* Refresh debug flags, since WolfSSLDebug static class has already
         * been intiailzed before and static class variables have been set. */
        WolfSSLDebug.refreshDebugFlags();

        try {
            /* wolfSSL JNI debug logs are printed to stdout via
             * System.out.println(). Redirect stdout so we can check output, and
             * it doesn't clutter up ant test output. */
            outStream = new ByteArrayOutputStream();
            System.setOut(new PrintStream(outStream));

            /* Create ServerSocket first to get ephemeral port */
            final ServerSocket srvSocket = new ServerSocket(0);

            srvCtx = createAndSetupWolfSSLContext(srvCert, srvKey,
                WolfSSL.SSL_FILETYPE_PEM, cliCert,
                WolfSSL.SSLv23_ServerMethod());
            cliCtx = createAndSetupWolfSSLContext(cliCert, cliKey,
                WolfSSL.SSL_FILETYPE_PEM, caCert,
                WolfSSL.SSLv23_ClientMethod());

            /* Start server */
            try {
                ExecutorService es = Executors.newSingleThreadExecutor();
                Future<Void> serverFuture = es.submit(new Callable<Void>() {
                    @Override
                    public Void call() throws Exception {
                        int ret;
                        int err;
                        Socket server = null;
                        WolfSSLSession srvSes = null;

                        try {
                            server = srvSocket.accept();
                            srvSes = new WolfSSLSession(srvCtx);

                            ret = srvSes.setFd(server);
                            if (ret != WolfSSL.SSL_SUCCESS) {
                                throw new Exception(
                                    "WolfSSLSession.setFd() failed: " + ret);
                            }

                            do {
                                ret = srvSes.accept();
                                err = srvSes.getError(ret);
                            } while (ret != WolfSSL.SSL_SUCCESS &&
                                     (err == WolfSSL.SSL_ERROR_WANT_READ ||
                                      err == WolfSSL.SSL_ERROR_WANT_WRITE));

                            if (ret != WolfSSL.SSL_SUCCESS) {
                                throw new Exception(
                                    "WolfSSLSession.accept() failed: " + ret);
                            }

                            srvSes.shutdownSSL();
                            srvSes.freeSSL();
                            srvSes = null;

                        } finally {
                            if (srvSes != null) {
                                srvSes.freeSSL();
                            }
                            if (server != null) {
                                server.close();
                            }

                            latch.countDown();
                        }

                        return null;
                    }
                });

            } catch (Exception e) {
                System.out.println("\t... failed");
                e.printStackTrace();
                fail();
            }

            /* Client connection */
            try {
                cliSock = new Socket(InetAddress.getLocalHost(),
                    srvSocket.getLocalPort());

                cliSes = new WolfSSLSession(cliCtx);

                ret = cliSes.setFd(cliSock);
                if (ret != WolfSSL.SSL_SUCCESS) {
                    throw new Exception(
                        "WolfSSLSession.setFd() failed, ret = " + ret);
                }

                do {
                    ret = cliSes.connect();
                    err = cliSes.getError(ret);
                } while (ret != WolfSSL.SSL_SUCCESS &&
                       (err == WolfSSL.SSL_ERROR_WANT_READ ||
                        err == WolfSSL.SSL_ERROR_WANT_WRITE));

                if (ret != WolfSSL.SSL_SUCCESS) {
                    throw new Exception(
                        "WolfSSLSession.connect() failed: " + err);
                }

                cliSes.shutdownSSL();
                cliSes.freeSSL();
                cliSes = null;
                cliSock.close();
                cliSock = null;

            } catch (Exception e) {
                System.out.println("\t... failed");
                e.printStackTrace();
                fail();

            } finally {
                if (cliSes != null) {
                    cliSes.freeSSL();
                }
                if (cliSock != null) {
                    cliSock.close();
                }
            }

            /* Free resources */
            if (srvSocket != null) {
                srvSocket.close();
            }
            if (srvCtx != null) {
                srvCtx.free();
            }

        } finally {

            /* Wait for server to finish processing */
            latch.await(10, TimeUnit.SECONDS);

            /* Restore original property value */
            if (originalProp == null || originalProp.isEmpty()) {
                System.setProperty("wolfssljni.debug", "");
            }
            else {
                System.setProperty("wolfssljni.debug", originalProp);
            }
            WolfSSLDebug.refreshDebugFlags();

            /* Restore System.out direction */
            System.setOut(originalSysOut);

            /* Verify we have debug output and some expected strings */
            if (outStream == null) {
                System.out.println("\t... failed");
                fail("outStream is null but should not be");
            }

            String debugOutput = outStream.toString();
            if (debugOutput == null || debugOutput.isEmpty()) {
                System.out.println("\t... failed");
                fail("Debug output was null or empty, but expected");
            }
            if (!debugOutput.contains("connect() ret: 1")) {
                System.out.println("\t... failed");
                fail("Debug output did not contain connect() success:\n" +
                     debugOutput);
            }
            if (!debugOutput.contains("accept() ret: 1")) {
                System.out.println("\t... failed");
                fail("Debug output did not contain accept() success:\n" +
                     debugOutput);
            }
        }

        System.out.println("\t... passed");
    }

    @Test
    public void test_WolfSSLSession_getSetSession() throws Exception {

        int ret = 0;
        int err = 0;
        long sessionPtr = 0;
        long sesDup = 0;
        Socket cliSock = null;
        WolfSSLSession cliSes = null;

        /* Create client/server WolfSSLContext objects, Server context
         * must be final since used inside inner class. */
        final WolfSSLContext srvCtx;
        WolfSSLContext cliCtx;

        System.out.print("\tTesting get/setSession()");

        /* Create ServerSocket first to get ephemeral port */
        final ServerSocket srvSocket = new ServerSocket(0);

        srvCtx = createAndSetupWolfSSLContext(srvCert, srvKey,
            WolfSSL.SSL_FILETYPE_PEM, cliCert,
            WolfSSL.SSLv23_ServerMethod());
        cliCtx = createAndSetupWolfSSLContext(cliCert, cliKey,
            WolfSSL.SSL_FILETYPE_PEM, caCert,
            WolfSSL.SSLv23_ClientMethod());

        /* Start server, handles 1 resumption */
        try {
            ExecutorService es = Executors.newSingleThreadExecutor();
            Future<Void> serverFuture = es.submit(new Callable<Void>() {
                @Override
                public Void call() throws Exception {
                    int ret;
                    int err;
                    Socket server = null;
                    WolfSSLSession srvSes = null;

                    try {
                        /* Loop twice to allow handle one resumption */
                        for (int i = 0; i < 2; i++) {
                            server = srvSocket.accept();
                            srvSes = new WolfSSLSession(srvCtx);

                            ret = srvSes.setFd(server);
                            if (ret != WolfSSL.SSL_SUCCESS) {
                                throw new Exception(
                                    "WolfSSLSession.setFd() failed: " + ret);
                            }

                            do {
                                ret = srvSes.accept();
                                err = srvSes.getError(ret);
                            } while (ret != WolfSSL.SSL_SUCCESS &&
                                     (err == WolfSSL.SSL_ERROR_WANT_READ ||
                                      err == WolfSSL.SSL_ERROR_WANT_WRITE));

                            if (ret != WolfSSL.SSL_SUCCESS) {
                                throw new Exception(
                                    "WolfSSLSession.accept() failed: " + ret);
                            }

                            srvSes.shutdownSSL();
                            srvSes.freeSSL();
                            srvSes = null;
                        }

                    } finally {
                        if (srvSes != null) {
                            srvSes.freeSSL();
                        }
                        if (server != null) {
                            server.close();
                        }
                    }

                    return null;
                }
            });

        } catch (Exception e) {
            System.out.println("\t... failed");
            e.printStackTrace();
            fail();
        }

        try {
            /* -------------------------------------------------------------- */
            /* Client connection #1 */
            /* -------------------------------------------------------------- */
            cliSock = new Socket(InetAddress.getLocalHost(),
                srvSocket.getLocalPort());

            cliSes = new WolfSSLSession(cliCtx);

            ret = cliSes.setFd(cliSock);
            if (ret != WolfSSL.SSL_SUCCESS) {
                throw new Exception(
                    "WolfSSLSession.setFd() failed, ret = " + ret);
            }

            do {
                ret = cliSes.connect();
                err = cliSes.getError(ret);
            } while (ret != WolfSSL.SSL_SUCCESS &&
                   (err == WolfSSL.SSL_ERROR_WANT_READ ||
                    err == WolfSSL.SSL_ERROR_WANT_WRITE));

            if (ret != WolfSSL.SSL_SUCCESS) {
                throw new Exception(
                    "WolfSSLSession.connect() failed: " + err);
            }

            /* Get WOLFSSL_SESSION pointer */
            sessionPtr = cliSes.getSession();
            if (sessionPtr == 0) {
                throw new Exception(
                    "WolfSSLSession.getSession() failed, ptr == 0");
            }

            /* wolfSSL_SessionIsSetup() may not be available, don't treat
             * NOT_COMPILED_IN as an error */
            ret = WolfSSLSession.sessionIsSetup(sessionPtr);
            if ((ret != 1) && (ret != WolfSSL.NOT_COMPILED_IN)) {
                throw new Exception(
                    "WolfSSLSession.sessionIsSetup() did not return 1: " + ret);
            }

            /* Test duplicateSession(), wraps wolfSSL_SESSION_dup() */
            sesDup = WolfSSLSession.duplicateSession(sessionPtr);
            if (sesDup == 0) {
                throw new Exception(
                    "WolfSSLSession.duplicateSession() returned 0");
            }
            if (sesDup == sessionPtr) {
                throw new Exception(
                    "WolfSSLSession.duplicateSession() returned same pointer");
            }
            WolfSSLSession.freeSession(sesDup);
            sesDup = 0;

            cliSes.shutdownSSL();
            cliSes.freeSSL();
            cliSes = null;
            cliSock.close();
            cliSock = null;

            /* -------------------------------------------------------------- */
            /* Client connection #2, set session and try resumption */
            /* -------------------------------------------------------------- */
            cliSock = new Socket(InetAddress.getLocalHost(),
                srvSocket.getLocalPort());
            cliSes = new WolfSSLSession(cliCtx);

            ret = cliSes.setFd(cliSock);
            if (ret != WolfSSL.SSL_SUCCESS) {
                throw new Exception(
                    "WolfSSLSession.setFd() failed, ret = " + ret);
            }

            /* Set session pointer from original connection */
            ret = cliSes.setSession(sessionPtr);
            if (ret != WolfSSL.SSL_SUCCESS) {
                throw new Exception(
                    "WolfSSLSession.setSession() failed: " + ret);
            }

            do {
                ret = cliSes.connect();
                err = cliSes.getError(ret);
            } while (ret != WolfSSL.SSL_SUCCESS &&
                   (err == WolfSSL.SSL_ERROR_WANT_READ ||
                    err == WolfSSL.SSL_ERROR_WANT_WRITE));

            if (ret != WolfSSL.SSL_SUCCESS) {
                throw new Exception(
                    "WolfSSLSession.connect() failed: " + err);
            }

            /* Get WOLFSSL_SESSION pointer, free original one first */
            WolfSSLSession.freeSession(sessionPtr);
            sessionPtr = cliSes.getSession();
            if (sessionPtr == 0) {
                throw new Exception(
                    "WolfSSLSession.getSession() failed, ptr == 0");
            }

            /* Free WOLFSSL_SESSION pointer */
            WolfSSLSession.freeSession(sessionPtr);
            sessionPtr = 0;

            /* Session should be marked as resumed */
            if (cliSes.sessionReused() == 0) {
                throw new Exception(
                    "Second connection not resumed");
            }

            cliSes.shutdownSSL();
            cliSes.freeSSL();
            cliSes = null;
            cliSock.close();
            cliSock = null;

        } catch (Exception e) {
            System.out.println("\t... failed");
            e.printStackTrace();
            fail();

        } finally {
            if (sessionPtr != 0) {
                WolfSSLSession.freeSession(sessionPtr);
            }
            if (sesDup != 0) {
                WolfSSLSession.freeSession(sesDup);
            }
            if (cliSes != null) {
                cliSes.freeSSL();
            }
            if (cliSock != null) {
                cliSock.close();
            }
        }

        /* Free resources */
        if (srvSocket != null) {
            srvSocket.close();
        }
        if (srvCtx != null) {
            srvCtx.free();
        }

        System.out.println("\t... passed");
    }
}

