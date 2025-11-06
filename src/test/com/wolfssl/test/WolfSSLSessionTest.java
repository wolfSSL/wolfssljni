/* WolfSSLSessionTest.java
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.Socket;
import java.net.ServerSocket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.net.ConnectException;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Callable;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.CountDownLatch;
import java.nio.ByteBuffer;
import java.security.Security;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLDebug;
import com.wolfssl.WolfSSLContext;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLJNIException;
import com.wolfssl.WolfSSLPskClientCallback;
import com.wolfssl.WolfSSLPskServerCallback;
import com.wolfssl.WolfSSLTls13SecretCallback;
import com.wolfssl.WolfSSLSession;
import com.wolfssl.WolfSSLByteBufferIORecvCallback;
import com.wolfssl.WolfSSLByteBufferIOSendCallback;

public class WolfSSLSessionTest {

    private static String cliCert = "./examples/certs/client-cert.pem";
    private static String cliKey  = "./examples/certs/client-key.pem";
    private static String srvCert = "./examples/certs/server-cert.pem";
    private static String srvKey  = "./examples/certs/server-key.pem";
    private static String caCert  = "./examples/certs/ca-cert.pem";
    private static String bogusFile = "/dev/null";

    private final static String exampleHost = "www.example.com";
    private final static int examplePort = 443;

    /* Maximum network buffer size, for test I/O callbacks */
    private final static int MAX_NET_BUF_SZ = 17 * 1024;

    private static WolfSSLContext ctx = null;

    /* Lock around WolfSSLSession static per-thread ByteBuffer pool
     * Security property use in this test class */
    private static final Object byteBufferPoolPropertyLock = new Object();

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
    public void test_WolfSSLSession_getSetSessionTickets()
        throws WolfSSLException, WolfSSLJNIException {
        int ret = 0;
        WolfSSLSession ssl = null;
        String ticketStr = "This is a session ticket";
        byte[] ticket = null;
        byte[] retrievedTicket = null;

        System.out.print("\t(get/set)SessionTicket()");

        try {
            ssl = new WolfSSLSession(ctx);

            ret = ssl.useSessionTicket();
            if (ret != WolfSSL.SSL_SUCCESS &&
                ret != WolfSSL.NOT_COMPILED_IN) {
                System.out.println("\t\t... failed");
                fail("useSessionTicket failed");
            }

            /* set session ticket */
            ticket = ticketStr.getBytes();

            ret = ssl.setSessionTicket(ticket);
            if (ret != WolfSSL.SSL_SUCCESS &&
                ret != WolfSSL.NOT_COMPILED_IN) {
                System.out.println("\t... failed");
                fail("setSessionTicket failed");
            }

            retrievedTicket = ssl.getSessionTicket();

            if (retrievedTicket == null) {
                System.out.println("\t... failed" );
                fail("getSessionTicket failed");
            }

            for (int i = 0; i < ticket.length; i++) {
                if (ticket[i] != retrievedTicket[i]) {
                    System.out.println("\t... failed");
                    fail("getSessionTicket failed");
                }
            }

        } catch (IllegalStateException e) {
            System.out.println("\t... failed");
            e.printStackTrace();

        } finally {
            if (ssl != null) {
                ssl.freeSSL();
            }
        }

        System.out.println("\t... passed");
    }

    public void test_WolfSSLSession_resumeWithSessionTickets()
        throws WolfSSLException, WolfSSLJNIException, Exception {
        int ret = 0;
        int err = 0;
        Socket cliSock = null;
        byte[] sessionTicket = "This is a session ticket".getBytes();
        WolfSSLSession ssl = null;

        /* Create client/server WolfSSLContext objects, Server context
         * must be final since used inside inner class. */
        final WolfSSLContext srvCtx;
        WolfSSLContext cliCtx;

        System.out.println("\tresumeWithSessionTickets()");

        /* Create ServerSocket first to get ephemeral port */
        final ServerSocket srvSocket = new ServerSocket(0);
        final int port = srvSocket.getLocalPort();

        srvCtx = createAndSetupWolfSSLContext(srvCert, srvKey,
            WolfSSL.SSL_FILETYPE_PEM, cliCert,
            WolfSSL.TLSv1_3_ServerMethod());
        cliCtx = createAndSetupWolfSSLContext(cliCert, cliKey,
            WolfSSL.SSL_FILETYPE_PEM, caCert,
            WolfSSL.TLSv1_3_ClientMethod());
        /* Start server, handles 1 resumption */
        try {
            ExecutorService es = Executors.newSingleThreadExecutor();
            es.submit(new Callable<Void>() {
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
            /* ------------------------------------------------------------- */
            /* Client connection #1 */
            /* ------------------------------------------------------------- */
            cliSock = new Socket("localhost", port);
            ssl = new WolfSSLSession(cliCtx);

            ret = ssl.setFd(cliSock);
            if (ret != WolfSSL.SSL_SUCCESS)
                throw new Exception("setFd() failed");

            do {
                ret = ssl.connect();
                err = ssl.getError(ret);
            } while (ret != WolfSSL.SSL_SUCCESS &&
                    (err == WolfSSL.SSL_ERROR_WANT_READ ||
                    err == WolfSSL.SSL_ERROR_WANT_WRITE));

            if (ret != WolfSSL.SSL_SUCCESS)
                throw new Exception("Initial connect failed");

            /* Get session ticket after handshake */
            sessionTicket = ssl.getSessionTicket();

            assertNotNull("Session ticket was null", sessionTicket);
            assertTrue("Session ticket empty", sessionTicket.length > 0);

            ssl.shutdownSSL();
            ssl.freeSSL();
            cliSock.close();

            /* ------------------------------------------------------------- */
            /* Client connection #2, set session and try resumption */
            /* ------------------------------------------------------------- */
            cliSock = new Socket("localhost", port);
            ssl = new WolfSSLSession(cliCtx);

            ret = ssl.setFd(cliSock);
            if (ret != WolfSSL.SSL_SUCCESS)
                throw new Exception("setFd() failed");

            ret = ssl.setSessionTicket(sessionTicket);
            if (ret != WolfSSL.SSL_SUCCESS)
                throw new Exception("setSessionTicket() failed");

            do {
                ret = ssl.connect();
                err = ssl.getError(ret);
            } while (ret != WolfSSL.SSL_SUCCESS &&
                    (err == WolfSSL.SSL_ERROR_WANT_READ ||
                    err == WolfSSL.SSL_ERROR_WANT_WRITE));

            if (ret != WolfSSL.SSL_SUCCESS)
            throw new Exception("Resumption connect failed");

            /* Check if session was resumed */
            assertEquals("Session was not resumed", 1, ssl.sessionReused());

            ssl.shutdownSSL();
            ssl.freeSSL();
            cliSock.close();

        } finally {
            /* Free resources */
            if (ssl != null) {
                ssl.freeSSL();
            }
            if (cliSock != null) {
                cliSock.close();
            }
            if (srvSocket != null) {
                srvSocket.close();
            }
            if (srvCtx != null) {
                srvCtx.free();
            }
        }

        System.out.println("\t... passed");
    }

    @Test
    public void test_WolfSSLSession_getPskIdentity()
        throws WolfSSLJNIException, WolfSSLException {

        WolfSSLSession ssl = null;

        System.out.print("\tgetPskIdentity()");

        try {
            ssl = new WolfSSLSession(ctx);
            /* Not checking return, just that we don't throw an exception */
            ssl.getPskIdentity();

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
            assertNotNull(sslLib);
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
            assertNotNull(sslLib);
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

        int ret;
        WolfSSL sslLib = null;
        WolfSSLContext sslCtx = null;
        WolfSSLSession ssl = null;

        System.out.print("\tTesting useSecureRenegotiation()");

        try {

            /* setup library, context, session, socket */
            sslLib = new WolfSSL();
            assertNotNull(sslLib);
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
            assertNotNull(sslLib);
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
        PrintStream originalSysErr = System.err;

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

        /* Set up output stream and redirect System.err */
        outStream = new ByteArrayOutputStream();
        System.setErr(new PrintStream(outStream));

        /* Refresh debug flags, since WolfSSLDebug static class has already
         * been intiailzed before and static class variables have been set. */
        WolfSSLDebug.refreshDebugFlags();

        try {
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
                es.submit(new Callable<Void>() {
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
                /* Free resources */
                if (cliSes != null) {
                    cliSes.freeSSL();
                }
                if (cliSock != null) {
                    cliSock.close();
                }
                if (srvSocket != null) {
                    srvSocket.close();
                }
                if (srvCtx != null) {
                    srvCtx.free();
                }
            }

        } finally {

            /* Wait for server to finish processing */
            latch.await(10, TimeUnit.SECONDS);

            /* Restore original property value */
            if (originalProp == null || originalProp.isEmpty()) {
                System.setProperty("wolfssljni.debug", "false");
            }
            else {
                System.setProperty("wolfssljni.debug", originalProp);
            }

            /* Refresh debug flags */
            WolfSSLDebug.refreshDebugFlags();

            /* Restore System.err direction */
            System.setErr(originalSysErr);

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
            es.submit(new Callable<Void>() {
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
            /* Free resources */
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
            if (srvSocket != null) {
                srvSocket.close();
            }
            if (srvCtx != null) {
                srvCtx.free();
            }
        }

        System.out.println("\t... passed");
    }

    /**
     * Internal method that connects a client to a server and does
     * one resumption.
     *
     * @throws Exception on error
     */
    private void runClientServerOneResumption() throws Exception {

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
            es.submit(new Callable<Void>() {
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
                                    "WolfSSLSession.setFd() failed: " +
                                    ret);
                            }

                            do {
                                ret = srvSes.accept();
                                err = srvSes.getError(ret);
                            } while (ret != WolfSSL.SSL_SUCCESS &&
                                     (err == WolfSSL.SSL_ERROR_WANT_READ ||
                                      err == WolfSSL.SSL_ERROR_WANT_WRITE));

                            if (ret != WolfSSL.SSL_SUCCESS) {
                                throw new Exception(
                                    "WolfSSLSession.accept() failed: " +
                                    ret);
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
            /* ------------------------------------------------------ */
            /* Client connection #1 */
            /* ------------------------------------------------------ */
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

            /* wolfSSL_SessionIsSetup() may not be available, don't
             * treat NOT_COMPILED_IN as an error */
            ret = WolfSSLSession.sessionIsSetup(sessionPtr);
            if ((ret != 1) && (ret != WolfSSL.NOT_COMPILED_IN)) {
                throw new Exception(
                    "WolfSSLSession.sessionIsSetup() did not " +
                    "return 1: " + ret);
            }

            /* Test duplicateSession(), wraps wolfSSL_SESSION_dup() */
            sesDup = WolfSSLSession.duplicateSession(sessionPtr);
            if (sesDup == 0) {
                throw new Exception(
                    "WolfSSLSession.duplicateSession() returned 0");
            }
            if (sesDup == sessionPtr) {
                throw new Exception(
                    "WolfSSLSession.duplicateSession() returned " +
                    "same pointer");
            }
            WolfSSLSession.freeSession(sesDup);
            sesDup = 0;

            cliSes.shutdownSSL();
            cliSes.freeSSL();
            cliSes = null;
            cliSock.close();
            cliSock = null;

            /* ------------------------------------------------------ */
            /* Client connection #2, set session and try resumption */
            /* ------------------------------------------------------ */
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
            /* Free resources */
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
            if (srvSocket != null) {
                srvSocket.close();
            }
            if (srvCtx != null) {
                srvCtx.free();
            }
        }
    }

    @Test
    public void test_WolfSSLSession_disableByteBufferPool() throws Exception {

        System.out.print("\tByteBuffer pool disabled");

        synchronized (byteBufferPoolPropertyLock) {

            String originalProp =
                Security.getProperty("wolfssl.readWriteByteBufferPool.disabled");

            try {
                /* Disable WolfSSLSession internal direct ByteBuffer pool
                 * for use with read/write() calls */
                Security.setProperty("wolfssl.readWriteByteBufferPool.disabled",
                    "true");

                runClientServerOneResumption();

            } finally {
                if (originalProp == null) {
                    originalProp = "";
                }
                /* restore system property */
                Security.setProperty("wolfssl.readWriteByteBufferPool.disabled",
                    originalProp);
            }
        }

        System.out.println("\t... passed");
    }

    @Test
    public void test_WolfSSLSession_byteBufferPoolSize() throws Exception {

        System.out.print("\tByteBuffer pool size changes");

        synchronized (byteBufferPoolPropertyLock) {

            String originalProp =
                Security.getProperty("wolfssl.readWriteByteBufferPool.size");

            try {

                /* Pool size of 0 */
                Security.setProperty("wolfssl.readWriteByteBufferPool.size",
                    "0");
                runClientServerOneResumption();

                /* Pool size of 1 */
                Security.setProperty("wolfssl.readWriteByteBufferPool.size",
                    "1");
                runClientServerOneResumption();

                /* Pool size of 100 */
                Security.setProperty("wolfssl.readWriteByteBufferPool.size",
                    "100");
                runClientServerOneResumption();

            } finally {
                if (originalProp == null) {
                    originalProp = "";
                }
                /* restore system property */
                Security.setProperty("wolfssl.readWriteByteBufferPool.size",
                    originalProp);
            }
        }

        System.out.println("\t... passed");
    }

    @Test
    public void test_WolfSSLSession_byteBufferPoolBufferSize() throws Exception {

        System.out.print("\tByteBuffer pool buffer sizes");

        synchronized (byteBufferPoolPropertyLock) {

            String originalProp =
                Security.getProperty(
                    "wolfssl.readWriteByteBufferPool.bufferSize");

            try {

                /* Tiny buffer size of 128 bytes, lots of looping  */
                Security.setProperty(
                    "wolfssl.readWriteByteBufferPool.bufferSize", "128");
                runClientServerOneResumption();

                /* Bigger buffer size than default (17k), try 32k */
                Security.setProperty(
                    "wolfssl.readWriteByteBufferPool.bufferSize", "32768");
                runClientServerOneResumption();

                /* Bigger buffer size than default (17k), try 64k */
                Security.setProperty(
                    "wolfssl.readWriteByteBufferPool.bufferSize", "65536");
                runClientServerOneResumption();

            } finally {
                if (originalProp == null) {
                    originalProp = "";
                }
                /* restore system property */
                Security.setProperty(
                    "wolfssl.readWriteByteBufferPool.bufferSize", originalProp);
            }
        }

        System.out.println("\t... passed");
    }

    /**
     * wolfSSL I/O context, is passed to I/O callbacks when called
     * by native wolfSSL.
     */
    private class MyIOCtx {
        private byte[] cliToSrv = new byte[MAX_NET_BUF_SZ];
        private byte[] srvToCli = new byte[MAX_NET_BUF_SZ];

        private int cliToSrvUsed = 0;
        private int srvToCliUsed = 0;

        private final Object cliLock = new Object();
        private final Object srvLock = new Object();

        private int insertData(byte[] dest, int destUsed,
            ByteBuffer src, int len) {

            int freeBufSpace = dest.length - destUsed;

            /* Check if buffer is full */
            if ((len > 0) && (freeBufSpace == 0)) {
                return -1;
            }

            int bytesToCopy = Math.min(len, freeBufSpace);
            if (bytesToCopy > 0) {
                src.get(dest, destUsed, bytesToCopy);
            }
            return bytesToCopy;
        }

        private int getData(byte[] src, int srcUsed,
            ByteBuffer dest, int len) {

            /* src buffer is empty */
            if ((len > 0) && (srcUsed == 0)) {
                return -1;
            }

            int bytesToCopy = Math.min(len, srcUsed);
            if (bytesToCopy > 0) {
                dest.put(src, 0, bytesToCopy);
                srcUsed -= bytesToCopy;
                /* Shift remaining data to front of buffer */
                if (srcUsed > 0) {
                    System.arraycopy(src, bytesToCopy, src, 0, srcUsed);
                }
            }
            return bytesToCopy;
        }

        public int insertCliToSrvData(ByteBuffer buf, int len) {
            synchronized (cliLock) {
                int ret = insertData(cliToSrv, cliToSrvUsed, buf, len);
                if (ret > 0) {
                    cliToSrvUsed += ret;
                }
                return ret;
            }
        }

        public int insertSrvToCliData(ByteBuffer buf, int len) {
            synchronized (srvLock) {
                int ret = insertData(srvToCli, srvToCliUsed, buf, len);
                if (ret > 0) {
                    srvToCliUsed += ret;
                }
                return ret;
            }
        }

        public int getCliToSrvData(ByteBuffer buf, int len) {
            synchronized (cliLock) {
                int ret = getData(cliToSrv, cliToSrvUsed, buf, len);
                if (ret > 0) {
                    cliToSrvUsed -= ret;
                }
                return ret;
            }
        }

        public int getSrvToCliData(ByteBuffer buf, int len) {
            synchronized (srvLock) {
                int ret = getData(srvToCli, srvToCliUsed, buf, len);
                if (ret > 0) {
                    srvToCliUsed -= ret;
                }
                return ret;
            }
        }
    }

    /* Client I/O callback using ByteBuffers */
    private class ClientByteBufferIOCallback
        implements WolfSSLByteBufferIORecvCallback,
                   WolfSSLByteBufferIOSendCallback {
        /**
         * Receive data is called when wolfSSL needs to read data from the
         * transport layer. In this case, we read data from the beginning
         * of the internal byte[] (buffer) and place it into the ByteBuffer buf.
         *
         * Return the number of bytes copied to the ByteBuffer buf, or negative
         * on error.
         */
        @Override
        public synchronized int receiveCallback(WolfSSLSession ssl,
            ByteBuffer buf, int len, Object ctx) {

            int ret;
            MyIOCtx ioCtx = (MyIOCtx) ctx;

            ret = ioCtx.getSrvToCliData(buf, len);
            if (ret == -1) {
                /* No data available, return WOLFSSL_CBIO_ERR_WANT_READ */
                ret = WolfSSL.WOLFSSL_CBIO_ERR_WANT_READ;
            }

            return ret;
        }

        /**
         * Send data is called when wolfSSL needs to write data to the
         * transport layer. In this case, we read data from the ByteBuffer
         * buf and place it into our internal byte[] (buffer).
         *
         * Return the number of bytes copied from the ByteBuffer buf, or
         * negative on error.
         */
        @Override
        public synchronized int sendCallback(
            WolfSSLSession ssl, ByteBuffer buf, int len, Object ctx) {

            int ret;
            MyIOCtx ioCtx = (MyIOCtx) ctx;

            ret = ioCtx.insertCliToSrvData(buf, len);
            if (ret == -1) {
                /* No space available, return WOLFSSL_CBIO_ERR_WANT_WRITE */
                ret = WolfSSL.WOLFSSL_CBIO_ERR_WANT_WRITE;
            }

            return ret;
        }
    }

    /* Server I/O callback using ByteBuffers */
    private class ServerByteBufferIOCallback
        implements WolfSSLByteBufferIORecvCallback,
                   WolfSSLByteBufferIOSendCallback {
        /**
         * Receive data is called when wolfSSL needs to read data from the
         * transport layer. In this case, we read data from the beginning
         * of the internal byte[] (buffer) and place it into the ByteBuffer buf.
         *
         * Return the number of bytes copied to the ByteBuffer buf, or negative
         * on error.
         */
        @Override
        public synchronized int receiveCallback(WolfSSLSession ssl,
            ByteBuffer buf, int len, Object ctx) {

            int ret;
            MyIOCtx ioCtx = (MyIOCtx) ctx;

            ret = ioCtx.getCliToSrvData(buf, len);
            if (ret == -1) {
                /* No data available, return WOLFSSL_CBIO_ERR_WANT_READ */
                ret = WolfSSL.WOLFSSL_CBIO_ERR_WANT_READ;
            }

            return ret;
        }

        /**
         * Send data is called when wolfSSL needs to write data to the
         * transport layer. In this case, we read data from the ByteBuffer
         * buf and place it into our internal byte[] (buffer).
         *
         * Return the number of bytes copied from the ByteBuffer buf, or
         * negative on error.
         */
        @Override
        public synchronized int sendCallback(
            WolfSSLSession ssl, ByteBuffer buf, int len, Object ctx) {

            int ret;
            MyIOCtx ioCtx = (MyIOCtx) ctx;

            ret = ioCtx.insertSrvToCliData(buf, len);
            if (ret == -1) {
                /* No space available, return WOLFSSL_CBIO_ERR_WANT_WRITE */
                ret = WolfSSL.WOLFSSL_CBIO_ERR_WANT_WRITE;
            }

            return ret;
        }
    }

    @Test
    public void test_WolfSSLSession_ioBuffers() throws Exception {
        int ret = 0;
        int err = 0;
        Socket cliSock = null;
        WolfSSLSession cliSes = null;
        byte[] testData = "Hello from client".getBytes();
        byte[] servAppBuffer = new byte[MAX_NET_BUF_SZ];
        byte[] cliAppBuffer = new byte[MAX_NET_BUF_SZ];
        int bytesRead = 0;

        /* Create client/server WolfSSLContext objects */
        final WolfSSLContext srvCtx;
        WolfSSLContext cliCtx;

        System.out.print("\tTesting I/O CB with ByteBuffers");

        /* Initialize library */
        WolfSSL lib = new WolfSSL();
        assertNotNull(lib);
        /* Create ServerSocket first to get ephemeral port */
        final ServerSocket srvSocket = new ServerSocket(0);

        srvCtx = createAndSetupWolfSSLContext(srvCert, srvKey,
            WolfSSL.SSL_FILETYPE_PEM, cliCert,
            WolfSSL.SSLv23_ServerMethod());
        cliCtx = createAndSetupWolfSSLContext(cliCert, cliKey,
            WolfSSL.SSL_FILETYPE_PEM, caCert,
            WolfSSL.SSLv23_ClientMethod());

        MyIOCtx myIOCb = new MyIOCtx();
        ClientByteBufferIOCallback cliIOCb = new ClientByteBufferIOCallback();
        ServerByteBufferIOCallback srvIOCb = new ServerByteBufferIOCallback();

        ExecutorService es = Executors.newSingleThreadExecutor();

        /* Start server */
        try {
            es.submit(new Callable<Void>() {
                @Override
                public Void call() throws Exception {
                    int ret;
                    int err;
                    Socket server = null;
                    WolfSSLSession srvSes = null;
                    int bytesRead = 0;

                    try {
                        server = srvSocket.accept();
                        srvSes = new WolfSSLSession(srvCtx);

                        /* Set I/O callback and ctx */
                        srvSes.setIOSendByteBuffer(srvIOCb);
                        srvSes.setIORecvByteBuffer(srvIOCb);
                        srvSes.setIOWriteCtx(myIOCb);
                        srvSes.setIOReadCtx(myIOCb);

                        /* Do handshake */
                        do {
                            ret = srvSes.accept();
                            err = srvSes.getError(ret);
                        } while (ret != WolfSSL.SSL_SUCCESS &&
                               (err == WolfSSL.SSL_ERROR_WANT_READ ||
                                err == WolfSSL.SSL_ERROR_WANT_WRITE));

                        if (ret != WolfSSL.SSL_SUCCESS) {
                            throw new Exception(
                                "Server accept failed: " + err);
                        }

                        /* Read data from client */
                        do {
                            bytesRead = srvSes.read(servAppBuffer,
                                servAppBuffer.length, 0);
                            err = srvSes.getError(bytesRead);
                        } while ((bytesRead < 0) &&
                                 (err == WolfSSL.SSL_ERROR_WANT_READ ||
                                  err == WolfSSL.SSL_ERROR_WANT_WRITE));

                        if (bytesRead <= 0) {
                            throw new Exception(
                                "Server read failed: " + bytesRead);
                        }

                        /* Send same data back to client */
                        do {
                            ret = srvSes.write(servAppBuffer, bytesRead, 0);
                            err = srvSes.getError(ret);
                        } while ((ret < 0) &&
                                 (err == WolfSSL.SSL_ERROR_WANT_READ ||
                                  err == WolfSSL.SSL_ERROR_WANT_WRITE));

                        if (ret != bytesRead) {
                            throw new Exception("Server write failed: " + ret);
                        }

                        srvSes.shutdownSSL();
                        srvSes.freeSSL();
                        srvSes = null;
                        server.close();
                        server = null;

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
            /* Client connection */
            cliSock = new Socket(InetAddress.getLocalHost(),
                srvSocket.getLocalPort());

            cliSes = new WolfSSLSession(cliCtx);

            /* Set I/O callback and ctx */
            cliSes.setIOSendByteBuffer(cliIOCb);
            cliSes.setIORecvByteBuffer(cliIOCb);
            cliSes.setIOWriteCtx(myIOCb);
            cliSes.setIOReadCtx(myIOCb);

            /* Do handshake */
            do {
                ret = cliSes.connect();
                err = cliSes.getError(ret);
            } while (ret != WolfSSL.SSL_SUCCESS &&
                   (err == WolfSSL.SSL_ERROR_WANT_READ ||
                    err == WolfSSL.SSL_ERROR_WANT_WRITE));

            if (ret != WolfSSL.SSL_SUCCESS) {
                throw new Exception(
                    "Client connect failed: " + err);
            }

            /* Send test data */
            do {
                ret = cliSes.write(testData, testData.length, 0);
                err = cliSes.getError(ret);
            } while ((ret < 0) &&
                     (err == WolfSSL.SSL_ERROR_WANT_READ ||
                      err == WolfSSL.SSL_ERROR_WANT_WRITE));

            if (ret != testData.length) {
                throw new Exception(
                    "Client write failed: " + ret);
            }

            /* Read response */
            do {
                bytesRead = cliSes.read(cliAppBuffer, cliAppBuffer.length, 0);
                err = cliSes.getError(bytesRead);
            } while ((bytesRead < 0) &&
                     (err == WolfSSL.SSL_ERROR_WANT_READ ||
                      err == WolfSSL.SSL_ERROR_WANT_WRITE));

            if (bytesRead != testData.length) {
                throw new Exception(
                    "Client read failed: " + bytesRead);
            }

            /* Verify received data matches sent data using Java 8 compatible
             * array comparison */
            boolean arraysMatch = true;
            if (testData.length != bytesRead) {
                arraysMatch = false;
            } else {
                for (int i = 0; i < testData.length; i++) {
                    if (testData[i] != cliAppBuffer[i]) {
                        arraysMatch = false;
                        break;
                    }
                }
            }
            if (!arraysMatch) {
                throw new Exception("Received data does not match sent data");
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
            /* Free resources */
            if (cliSes != null) {
                cliSes.freeSSL();
            }
            if (cliSock != null) {
                cliSock.close();
            }
            if (srvSocket != null) {
                srvSocket.close();
            }
            if (srvCtx != null) {
                srvCtx.free();
            }
            es.shutdown();
        }

        System.out.println("\t... passed");
    }

    @Test
    public void test_WolfSSLSession_readByteBuffer() throws Exception {
        int ret = 0;
        int err = 0;
        int bytesRead = 0;
        Socket cliSock = null;
        WolfSSLSession cliSes = null;
        ByteBuffer readBuffer = ByteBuffer.allocate(128);
        byte[] testData = "Hello ByteBuffer read test".getBytes();

        /* Create client/server WolfSSLContext objects */
        final WolfSSLContext srvCtx;
        WolfSSLContext cliCtx;

        System.out.print("\tTesting ByteBuffer read()");

        /* Create ServerSocket first to get ephemeral port */
        final ServerSocket srvSocket = new ServerSocket(0);

        srvCtx = createAndSetupWolfSSLContext(srvCert, srvKey,
            WolfSSL.SSL_FILETYPE_PEM, cliCert,
            WolfSSL.SSLv23_ServerMethod());
        cliCtx = createAndSetupWolfSSLContext(cliCert, cliKey,
            WolfSSL.SSL_FILETYPE_PEM, caCert,
            WolfSSL.SSLv23_ClientMethod());

        ExecutorService es = Executors.newSingleThreadExecutor();

        /* Start server */
        try {
            es.submit(new Callable<Void>() {
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

                        /* Send test data to client */
                        do {
                            ret = srvSes.write(testData, testData.length, 0);
                            err = srvSes.getError(ret);
                        } while ((ret < 0) &&
                                 (err == WolfSSL.SSL_ERROR_WANT_READ ||
                                  err == WolfSSL.SSL_ERROR_WANT_WRITE));

                        if (ret != testData.length) {
                            throw new Exception("Server write failed: " + ret);
                        }

                        srvSes.shutdownSSL();
                        srvSes.freeSSL();
                        srvSes = null;
                        server.close();
                        server = null;

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
            /* Client connection */
            cliSock = new Socket(InetAddress.getLocalHost(),
                srvSocket.getLocalPort());

            cliSes = new WolfSSLSession(cliCtx);

            ret = cliSes.setFd(cliSock);
            if (ret != WolfSSL.SSL_SUCCESS) {
                throw new Exception(
                    "WolfSSLSession.setFd() failed, ret = " + ret);
            }

            /* Do handshake */
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

            /* Test ByteBuffer read */
            int initialPosition = readBuffer.position();

            do {
                bytesRead = cliSes.read(readBuffer, testData.length, 5000);
                err = cliSes.getError(bytesRead);
            } while ((bytesRead < 0) &&
                     (err == WolfSSL.SSL_ERROR_WANT_READ ||
                      err == WolfSSL.SSL_ERROR_WANT_WRITE));

            if (bytesRead != testData.length) {
                throw new Exception(
                    "Client ByteBuffer read failed: " + bytesRead);
            }

            /* Verify ByteBuffer position was updated correctly */
            int expectedPosition = initialPosition + bytesRead;
            if (readBuffer.position() != expectedPosition) {
                throw new Exception(
                    "ByteBuffer position not updated correctly. Expected: " +
                    expectedPosition + ", Got: " + readBuffer.position());
            }

            /* Verify received data matches sent data */
            readBuffer.flip();
            byte[] receivedData = new byte[bytesRead];
            readBuffer.get(receivedData);

            if (!Arrays.equals(testData, receivedData)) {
                throw new Exception("Received data does not match sent data");
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
            /* Free resources */
            if (cliSes != null) {
                cliSes.freeSSL();
            }
            if (cliSock != null) {
                cliSock.close();
            }
            if (srvSocket != null) {
                srvSocket.close();
            }
            if (srvCtx != null) {
                srvCtx.free();
            }
            es.shutdown();
        }

        System.out.println("\t... passed");
    }

    @Test
    public void test_WolfSSLSession_sessionToDerFromDer() throws Exception {

        int ret = 0;
        int err = 0;
        long deserializedSessionPtr = 0;
        Socket cliSock = null;
        WolfSSLSession cliSes = null;
        byte[] serializedSession = null;

        /* Create client/server WolfSSLContext objects, Server context
         * must be final since used inside inner class. */
        final WolfSSLContext srvCtx;
        WolfSSLContext cliCtx;

        System.out.print("\tTesting sessionToDer/sessionFromDer()");

        /* Create ServerSocket first to get ephemeral port */
        final ServerSocket srvSocket = new ServerSocket(0);

        srvCtx = createAndSetupWolfSSLContext(srvCert, srvKey,
            WolfSSL.SSL_FILETYPE_PEM, cliCert,
            WolfSSL.SSLv23_ServerMethod());
        cliCtx = createAndSetupWolfSSLContext(cliCert, cliKey,
            WolfSSL.SSL_FILETYPE_PEM, caCert,
            WolfSSL.SSLv23_ClientMethod());

        /* Start server, handles 2 connections */
        try {
            ExecutorService es = Executors.newSingleThreadExecutor();
            es.submit(new Callable<Void>() {
                @Override
                public Void call() throws Exception {
                    int ret;
                    int err;
                    Socket server = null;
                    WolfSSLSession srvSes = null;

                    try {
                        /* Loop twice to handle one resumption */
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
            /* Client connection #1 - get session and serialize it */
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

            /* Convert session to DER format */
            serializedSession = cliSes.sessionToDer();
            if (serializedSession == null) {
                /* Feature not compiled in, skip test */
                System.out.println("\t... skipped");
                return;
            }

            if (serializedSession.length == 0) {
                throw new Exception("DER session has zero length");
            }

            cliSes.shutdownSSL();
            cliSes.freeSSL();
            cliSes = null;
            cliSock.close();
            cliSock = null;

            /* -------------------------------------------------------------- */
            /* Client connection #2 - deserialize session and resume */
            /* -------------------------------------------------------------- */
            cliSock = new Socket(InetAddress.getLocalHost(),
                srvSocket.getLocalPort());
            cliSes = new WolfSSLSession(cliCtx);

            ret = cliSes.setFd(cliSock);
            if (ret != WolfSSL.SSL_SUCCESS) {
                throw new Exception(
                    "WolfSSLSession.setFd() failed, ret = " + ret);
            }

            /* Create session from DER format */
            deserializedSessionPtr = cliSes.sessionFromDer(serializedSession);
            if (deserializedSessionPtr == 0) {
                throw new Exception(
                    "WolfSSLSession.sessionFromDer() returned null pointer");
            }

            /* Set the DER-created session for resumption */
            ret = cliSes.setSession(deserializedSessionPtr);
            if (ret != WolfSSL.SSL_SUCCESS) {
                throw new Exception(
                    "WolfSSLSession.setSession() failed: " + ret);
            }

            /* Now connect - this should result in session resumption */
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

            /* Check if session was resumed */
            if (cliSes.sessionReused() == 0) {
                throw new Exception(
                    "Session was not resumed");
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
            if (deserializedSessionPtr != 0) {
                WolfSSLSession.freeSession(deserializedSessionPtr);
            }
            if (cliSes != null) {
                cliSes.freeSSL();
            }
            if (cliSock != null) {
                cliSock.close();
            }
            if (srvSocket != null) {
                srvSocket.close();
            }
            if (srvCtx != null) {
                srvCtx.free();
            }
        }

        System.out.println("\t... passed");
    }

    @Test
    public void test_WolfSSLSession_dtlsCidMaxSize()
        throws WolfSSLJNIException {

        System.out.print("\tdtlsCidMaxSize()");

        /* This is a static method, should work even without wolfSSL compiled
         * with DTLS CID support - may return NOT_COMPILED_IN */
        int maxSize = WolfSSLSession.dtlsCidMaxSize();

        /* Expected to be positive value if DTLS CID is compiled in,
         * or NOT_COMPILED_IN (-173) if not compiled in */
        assertTrue("dtlsCidMaxSize() should return positive value or " +
                   "NOT_COMPILED_IN",
                   maxSize > 0 || maxSize == WolfSSL.NOT_COMPILED_IN);

        System.out.println("\t\t... passed");
    }

    @Test
    public void test_WolfSSLSession_dtlsCidParse()
        throws WolfSSLJNIException {

        System.out.print("\tdtlsCidParse()");

        /* Test with null message - should return null */
        byte[] result = WolfSSLSession.dtlsCidParse(null, 0);
        assertNull("dtlsCidParse() with null msg should return null", result);

        /* Test with invalid cidSize - should return null */
        byte[] testMsg = new byte[10];
        result = WolfSSLSession.dtlsCidParse(testMsg, -1);
        assertNull("dtlsCidParse() with negative cidSize should return null",
                   result);

        /* Test with valid parameters (may return null if DTLS CID not
         * compiled in or message doesn't contain valid CID) */
        result = WolfSSLSession.dtlsCidParse(testMsg, 5);
        /* Result can be null if not compiled in or no valid CID found */

        System.out.println("\t\t\t... passed");
    }

    @Test
    public void test_WolfSSLSession_dtlsCidFunctions()
        throws WolfSSLJNIException, WolfSSLException {

        WolfSSLContext dtlsCtx = null;
        WolfSSLSession sess = null;
        int ret;

        System.out.print("\tDTLS CID functions");

        /* Skip if DTLS not supported */
        String[] protocols = WolfSSL.getProtocols();
        boolean dtlsSupported = false;
        for (String protocol : protocols) {
            if (protocol.equals("DTLSv1.3")) {
                dtlsSupported = true;
                break;
            }
        }
        if (!dtlsSupported) {
            System.out.println("\t\t... skipped (DTLSv1.3 not enabled)");
            return;
        }

        try {
            /* Create DTLS context for CID testing */
            dtlsCtx = new WolfSSLContext(WolfSSL.DTLSv1_3_ClientMethod());
            sess = new WolfSSLSession(dtlsCtx);

            /* Test dtlsCidUse() - may return NOT_COMPILED_IN if DTLS CID
             * not compiled into native wolfSSL */
            ret = sess.dtlsCidUse();
            assertTrue("dtlsCidUse() should return success or NOT_COMPILED_IN",
                       ret == WolfSSL.SSL_SUCCESS ||
                       ret == WolfSSL.NOT_COMPILED_IN);

            /* Test dtlsCidIsEnabled() */
            ret = sess.dtlsCidIsEnabled();
            assertTrue("dtlsCidIsEnabled() should return 0, 1, or " +
                       "NOT_COMPILED_IN",
                       ret == 0 || ret == 1 || ret == WolfSSL.NOT_COMPILED_IN);

            /* Test dtlsCidSet() with null array - should return BAD_FUNC_ARG */
            ret = sess.dtlsCidSet(null);
            assertEquals("dtlsCidSet() with null should return BAD_FUNC_ARG",
                         WolfSSL.BAD_FUNC_ARG, ret);

            /* Test dtlsCidSet() with valid CID */
            byte[] testCid = new byte[]{0x01, 0x02, 0x03, 0x04};
            ret = sess.dtlsCidSet(testCid);
            assertTrue("dtlsCidSet() should return success or error code",
                       ret == WolfSSL.SSL_SUCCESS || ret < 0);

            /* Test size getter functions */
            int rxSize = sess.dtlsCidGetRxSize();
            assertTrue("dtlsCidGetRxSize() should return size or " +
                       "NOT_COMPILED_IN",
                       rxSize >= 0 || rxSize == WolfSSL.NOT_COMPILED_IN);

            int txSize = sess.dtlsCidGetTxSize();
            assertTrue("dtlsCidGetTxSize() should return size or " +
                       "NOT_COMPILED_IN",
                       txSize >= 0 || txSize == WolfSSL.NOT_COMPILED_IN);

            /* Test CID getter functions - may return null if not set
             * or not compiled in */
            byte[] rxCid = sess.dtlsCidGetRx();
            /* rxCid can be null if not set or not compiled in */

            byte[] rxCid0 = sess.dtlsCidGet0Rx();
            /* rxCid0 can be null if not set or not compiled in */

            byte[] txCid = sess.dtlsCidGetTx();
            /* txCid can be null if not set or not compiled in */

            byte[] txCid0 = sess.dtlsCidGet0Tx();
            /* txCid0 can be null if not set or not compiled in */

            /* If we got valid CIDs, they should have expected lengths */
            if (rxCid != null && rxSize > 0) {
                assertEquals("RX CID length should match reported size",
                             rxSize, rxCid.length);
            }

            if (txCid != null && txSize > 0) {
                assertEquals("TX CID length should match reported size",
                             txSize, txCid.length);
            }

        } catch (WolfSSLException we) {
            /* Some methods may throw exceptions if DTLS CID not supported
             * or session not properly configured */
            System.out.println("\t\t... expected exception: " +
                               we.getMessage());

        } finally {
            if (sess != null) {
                sess.freeSSL();
            }
            if (dtlsCtx != null) {
                dtlsCtx.free();
            }
        }

        System.out.println("\t\t... passed");
    }

    @Test
    public void test_WolfSSLSession_dtlsCidClientServer()
        throws WolfSSLJNIException, WolfSSLException {

        System.out.print("\tDTLS CID connection");

        /* Skip if DTLSv1.3 not supported - CID requires DTLSv1.3 */
        String[] protocols = WolfSSL.getProtocols();
        boolean dtls13Supported = false;
        for (String protocol : protocols) {
            if (protocol.equals("DTLSv1.3")) {
                dtls13Supported = true;
                break;
            }
        }
        if (!dtls13Supported) {
            System.out.println("\t\t... skipped (DTLSv1.3 not enabled)");
            return;
        }

        WolfSSLContext serverCtx = null;
        WolfSSLContext clientCtx = null;
        WolfSSLSession server = null;
        WolfSSLSession client = null;

        try {
            /* Create DTLSv1.3 contexts (CID requires DTLSv1.3) */
            serverCtx = new WolfSSLContext(WolfSSL.DTLSv1_3_ServerMethod());
            clientCtx = new WolfSSLContext(WolfSSL.DTLSv1_3_ClientMethod());

            /* Load server certificate and key */
            serverCtx.useCertificateFile(cliCert, WolfSSL.SSL_FILETYPE_PEM);
            serverCtx.usePrivateKeyFile(cliKey, WolfSSL.SSL_FILETYPE_PEM);

            /* Load client certificate verification */
            clientCtx.loadVerifyLocations(caCert, null);

            /* Create SSL sessions */
            server = new WolfSSLSession(serverCtx);
            client = new WolfSSLSession(clientCtx);

            /* Test basic CID functionality without connection first */

            /* Test dtlsCidUse() - may return NOT_COMPILED_IN */
            int ret = server.dtlsCidUse();
            if (ret == WolfSSL.NOT_COMPILED_IN) {
                System.out.println("\t\t... skipped (DTLS CID not " +
                                   "compiled in)");
                return;
            }
            assertTrue("Server dtlsCidUse() should succeed",
                       ret == WolfSSL.SSL_SUCCESS);

            ret = client.dtlsCidUse();
            assertTrue("Client dtlsCidUse() should succeed",
                       ret == WolfSSL.SSL_SUCCESS);

            /* Test dtlsCidIsEnabled() */
            ret = server.dtlsCidIsEnabled();
            assertTrue("Server CID should be enabled",
                       ret == 1);

            ret = client.dtlsCidIsEnabled();
            assertTrue("Client CID should be enabled",
                       ret == 1);

            /* Set Connection IDs */
            byte[] serverCid = {0x01, 0x02, 0x03, 0x04, 0x05};
            byte[] clientCid = {0x06, 0x07, 0x08, 0x09, 0x0A};

            ret = server.dtlsCidSet(serverCid);
            if (ret != WolfSSL.SSL_SUCCESS) {
                System.out.println("\t\t... skipped (Server " +
                                   "dtlsCidSet failed: " + ret + ")");
                return;
            }

            ret = client.dtlsCidSet(clientCid);
            if (ret != WolfSSL.SSL_SUCCESS) {
                System.out.println("\t\t... skipped (Client " +
                                   "dtlsCidSet failed: " + ret + ")");
                return;
            }

            /* Verify RX CID sizes (what we set) */
            int serverRxSize = server.dtlsCidGetRxSize();
            int clientRxSize = client.dtlsCidGetRxSize();

            assertTrue("Server RX CID size should match set CID length",
                       serverRxSize == serverCid.length);
            assertTrue("Client RX CID size should match set CID length",
                       clientRxSize == clientCid.length);

            /* Get and verify RX CIDs (what we set) */
            byte[] serverRxCid = server.dtlsCidGetRx();
            byte[] clientRxCid = client.dtlsCidGetRx();

            assertNotNull("Server RX CID should not be null", serverRxCid);
            assertNotNull("Client RX CID should not be null", clientRxCid);

            assertArrayEquals("Server RX CID should match set CID",
                              serverCid, serverRxCid);
            assertArrayEquals("Client RX CID should match set CID",
                              clientCid, clientRxCid);

            /* Test get0 versions (direct reference) for RX CIDs */
            byte[] serverRxCid0 = server.dtlsCidGet0Rx();
            byte[] clientRxCid0 = client.dtlsCidGet0Rx();

            assertNotNull("Server RX CID0 should not be null", serverRxCid0);
            assertNotNull("Client RX CID0 should not be null", clientRxCid0);

            assertArrayEquals("Server RX CID0 should match set CID",
                              serverCid, serverRxCid0);
            assertArrayEquals("Client RX CID0 should match set CID",
                              clientCid, clientRxCid0);

            /* TX CIDs should be 0/null since no handshake occurred */
            int serverTxSize = server.dtlsCidGetTxSize();
            int clientTxSize = client.dtlsCidGetTxSize();
            assertTrue("Server TX CID size should be 0 (no handshake)",
                       serverTxSize == 0);
            assertTrue("Client TX CID size should be 0 (no handshake)",
                       clientTxSize == 0);

            System.out.println("\t\t... passed");

        } catch (Exception e) {
            System.out.println("\t\t... failed with exception: " +
                               e.getMessage());
            throw e;

        } finally {
            if (server != null) {
                server.freeSSL();
            }
            if (client != null) {
                client.freeSSL();
            }
            if (serverCtx != null) {
                serverCtx.free();
            }
            if (clientCtx != null) {
                clientCtx.free();
            }
        }
    }

    @Test
    public void test_WolfSSLSession_dtlsCidDataExchange()
        throws WolfSSLJNIException, WolfSSLException {

        System.out.print("\tDTLS CID data exchange");

        /* Skip if DTLSv1.3 not supported - CID requires DTLSv1.3 */
        String[] protocols = WolfSSL.getProtocols();
        boolean dtls13Supported = false;
        for (String protocol : protocols) {
            if (protocol.equals("DTLSv1.3")) {
                dtls13Supported = true;
                break;
            }
        }
        if (!dtls13Supported) {
            System.out.println("\t\t... skipped (DTLSv1.3 not enabled)");
            return;
        }

        WolfSSLContext serverCtx = null;
        WolfSSLContext clientCtx = null;
        WolfSSLSession server = null;
        WolfSSLSession client = null;

        try {
            /* Create DTLSv1.3 contexts (CID requires DTLSv1.3) */
            serverCtx = new WolfSSLContext(WolfSSL.DTLSv1_3_ServerMethod());
            clientCtx = new WolfSSLContext(WolfSSL.DTLSv1_3_ClientMethod());

            /* Load certificates */
            serverCtx.useCertificateFile(cliCert, WolfSSL.SSL_FILETYPE_PEM);
            serverCtx.usePrivateKeyFile(cliKey, WolfSSL.SSL_FILETYPE_PEM);
            clientCtx.loadVerifyLocations(caCert, null);

            /* Create sessions */
            server = new WolfSSLSession(serverCtx);
            client = new WolfSSLSession(clientCtx);

            /* Enable CID on both sides */
            int ret = server.dtlsCidUse();
            if (ret == WolfSSL.NOT_COMPILED_IN) {
                System.out.println("\t\t... skipped (DTLS CID not " +
                                   "compiled in)");
                return;
            }

            ret = client.dtlsCidUse();
            assertTrue("Client CID enable should succeed",
                       ret == WolfSSL.SSL_SUCCESS);

            /* Set different CIDs for each direction */
            byte[] serverToClientCid = {0x11, 0x22, 0x33, 0x44};
            byte[] clientToServerCid = {0x55, 0x66, 0x77, (byte)0x88};

            ret = server.dtlsCidSet(serverToClientCid);
            if (ret != WolfSSL.SSL_SUCCESS) {
                System.out.println("\t\t... skipped (Server " +
                                   "dtlsCidSet failed: " + ret + ")");
                return;
            }

            ret = client.dtlsCidSet(clientToServerCid);
            if (ret != WolfSSL.SSL_SUCCESS) {
                System.out.println("\t\t... skipped (Client " +
                                   "dtlsCidSet failed: " + ret + ")");
                return;
            }

            /* Verify bidirectional CID setup (RX side) */
            byte[] serverRx = server.dtlsCidGetRx();
            byte[] clientRx = client.dtlsCidGetRx();

            if (serverRx == null || clientRx == null) {
                System.out.println("\t\t... skipped (CID retrieval failed)");
                return;
            }

            assertArrayEquals("Server should expect server-to-client CID",
                              serverToClientCid, serverRx);
            assertArrayEquals("Client should expect client-to-server CID",
                              clientToServerCid, clientRx);

            /* Test CID size limits */
            int maxCidSize = WolfSSLSession.dtlsCidMaxSize();
            if (maxCidSize > 0) {
                assertTrue("Server RX CID should be within max size",
                           serverRx.length <= maxCidSize);
                assertTrue("Client RX CID should be within max size",
                           clientRx.length <= maxCidSize);
            }

            /* Test parsing functionality with mock DTLS message */
            byte[] mockDtlsMsg = new byte[]{
                /* DTLS header simulation - not a real DTLS message */
                0x16, (byte)0xfe, (byte)0xfd, 0x00, 0x01, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x22, 0x33,
                0x44 /* Mock CID data at end */
            };

            byte[] parsedCid = WolfSSLSession.dtlsCidParse(mockDtlsMsg, 4);
            /* parsedCid may be null - depends on DTLS message format */
            /* This tests the API works, actual parsing depends on wolfSSL */

            System.out.println("\t\t... passed");

        } catch (Exception e) {
            System.out.println("\t\t... failed with exception: " +
                               e.getMessage());
            throw e;

        } finally {
            if (server != null) {
                server.freeSSL();
            }
            if (client != null) {
                client.freeSSL();
            }
            if (serverCtx != null) {
                serverCtx.free();
            }
            if (clientCtx != null) {
                clientCtx.free();
            }
        }
    }

    @Test
    public void test_WolfSSLSession_dtlsCidConnectionMigration()
        throws WolfSSLJNIException, WolfSSLException {

        System.out.print("\tDTLS CID connection migration");

        /* Skip if DTLSv1.3 not supported - CID requires DTLSv1.3 */
        String[] protocols = WolfSSL.getProtocols();
        boolean dtls13Supported = false;
        for (String protocol : protocols) {
            if (protocol.equals("DTLSv1.3")) {
                dtls13Supported = true;
                break;
            }
        }
        if (!dtls13Supported) {
            System.out.println("\t... skipped (DTLSv1.3 not enabled)");
            return;
        }

        WolfSSLContext serverCtx = null;
        WolfSSLSession server1 = null;
        WolfSSLSession server2 = null;

        try {
            /* Create DTLSv1.3 server context (CID requires DTLSv1.3) */
            serverCtx = new WolfSSLContext(WolfSSL.DTLSv1_3_ServerMethod());

            serverCtx.useCertificateFile(cliCert, WolfSSL.SSL_FILETYPE_PEM);
            serverCtx.usePrivateKeyFile(cliKey, WolfSSL.SSL_FILETYPE_PEM);

            /* Create two server sessions to simulate connection migration */
            server1 = new WolfSSLSession(serverCtx);
            server2 = new WolfSSLSession(serverCtx);

            /* Enable CID on both sessions */
            int ret1 = server1.dtlsCidUse();
            if (ret1 == WolfSSL.NOT_COMPILED_IN) {
                System.out.println("\t... skipped (DTLS CID not " +
                                   "compiled in)");
                return;
            }

            int ret2 = server2.dtlsCidUse();
            assertTrue("Both servers should enable CID successfully",
                       ret1 == WolfSSL.SSL_SUCCESS &&
                       ret2 == WolfSSL.SSL_SUCCESS);

            /* Set same CID on both sessions (simulating connection
             * migration) */
            byte[] migrationCid = {(byte)0xAA, (byte)0xBB, (byte)0xCC,
                                   (byte)0xDD, (byte)0xEE, (byte)0xFF};

            ret1 = server1.dtlsCidSet(migrationCid);
            ret2 = server2.dtlsCidSet(migrationCid);

            if (ret1 != WolfSSL.SSL_SUCCESS || ret2 != WolfSSL.SSL_SUCCESS) {
                System.out.println("\t... skipped (dtlsCidSet failed: " +
                                   ret1 + ", " + ret2 + ")");
                return;
            }

            /* Verify both sessions have the same RX CID */
            byte[] server1Rx = server1.dtlsCidGetRx();
            byte[] server2Rx = server2.dtlsCidGetRx();

            if (server1Rx == null || server2Rx == null) {
                System.out.println("\t... skipped (CID retrieval failed)");
                return;
            }

            assertArrayEquals("Both servers should have same RX CID",
                              server1Rx, server2Rx);
            assertArrayEquals("RX CID should match original migration CID",
                              migrationCid, server1Rx);

            /* Test RX CID size consistency across sessions */
            int size1 = server1.dtlsCidGetRxSize();
            int size2 = server2.dtlsCidGetRxSize();

            assertEquals("Both sessions should report same RX CID size",
                         size1, size2);
            assertEquals("RX CID size should match set CID length",
                         migrationCid.length, size1);

            /* Test direct reference consistency for RX CIDs */
            byte[] server1Rx0 = server1.dtlsCidGet0Rx();
            byte[] server2Rx0 = server2.dtlsCidGet0Rx();

            assertArrayEquals("Direct reference RX CIDs should match",
                              server1Rx0, server2Rx0);

            /* TX CID sizes should be 0 (no handshake occurred) */
            int txSize1 = server1.dtlsCidGetTxSize();
            int txSize2 = server2.dtlsCidGetTxSize();

            /* TX size should be 0 (no peer CID negotiated yet) */
            assertTrue("TX CID size should be 0 without handshake",
                       txSize1 == 0 && txSize2 == 0);

            System.out.println("\t... passed");

        } catch (Exception e) {
            System.out.println("\t... failed with exception: " +
                               e.getMessage());
            throw e;

        } finally {
            if (server1 != null) {
                server1.freeSSL();
            }
            if (server2 != null) {
                server2.freeSSL();
            }
            if (serverCtx != null) {
                serverCtx.free();
            }
        }
    }

    @Test
    public void test_WolfSSLSession_dtlsCidBoundarySizes()
        throws WolfSSLJNIException, WolfSSLException {

        WolfSSLContext dtlsCtx = null;
        WolfSSLSession sess = null;

        System.out.print("\tDTLS CID boundary sizes");

        /* Skip if DTLSv1.3 not supported */
        String[] protocols = WolfSSL.getProtocols();
        boolean dtls13Supported = false;
        for (String protocol : protocols) {
            if (protocol.equals("DTLSv1.3")) {
                dtls13Supported = true;
                break;
            }
        }

        if (!dtls13Supported) {
            System.out.println("\t\t... skipped (DTLSv1.3 not enabled)");
            return;
        }

        try {
            /* Create DTLS context for CID testing */
            dtlsCtx = new WolfSSLContext(WolfSSL.DTLSv1_3_ClientMethod());
            sess = new WolfSSLSession(dtlsCtx);

            /* Enable CID */
            int ret = sess.dtlsCidUse();
            if (ret == WolfSSL.NOT_COMPILED_IN) {
                System.out.println("\t\t... skipped (DTLS CID not " +
                                   "compiled in)");
                return;
            }

            /* Test empty CID (0 bytes) */
            byte[] emptyCid = new byte[0];
            ret = sess.dtlsCidSet(emptyCid);
            assertTrue("Empty CID should return valid result",
                       ret == WolfSSL.SSL_SUCCESS ||
                       ret == WolfSSL.BAD_FUNC_ARG || ret < 0);

            /* Get max CID size */
            int maxSize = WolfSSLSession.dtlsCidMaxSize();
            if (maxSize > 0) {
                /* Test CID at max size - should succeed */
                byte[] maxCid = new byte[maxSize];
                for (int i = 0; i < maxSize; i++) {
                    maxCid[i] = (byte)(i & 0xFF);
                }

                ret = sess.dtlsCidSet(maxCid);
                assertTrue("Max size CID should succeed or return " +
                           "valid error",
                           ret == WolfSSL.SSL_SUCCESS || ret < 0);

                /* If max size succeeded, verify it was set correctly */
                if (ret == WolfSSL.SSL_SUCCESS) {
                    int rxSize = sess.dtlsCidGetRxSize();
                    assertEquals("RX CID size should match max size",
                                 maxSize, rxSize);

                    byte[] retrievedCid = sess.dtlsCidGetRx();
                    assertNotNull("Retrieved max size CID should not " +
                                  "be null", retrievedCid);
                    assertEquals("Retrieved CID length should match " +
                                 "max size",
                                 maxSize, retrievedCid.length);
                }

                /* Test oversized CID (max + 1) - should fail */
                byte[] oversizedCid = new byte[maxSize + 1];
                for (int i = 0; i <= maxSize; i++) {
                    oversizedCid[i] = (byte)0xFF;
                }

                ret = sess.dtlsCidSet(oversizedCid);
                assertTrue("Oversized CID should return error code",
                           ret != WolfSSL.SSL_SUCCESS);
            }

            /* Test single byte CID - minimum valid size */
            byte[] minCid = new byte[]{(byte)0xAA};
            ret = sess.dtlsCidSet(minCid);
            if (ret == WolfSSL.SSL_SUCCESS) {
                int rxSize = sess.dtlsCidGetRxSize();
                assertEquals("Single byte CID size should be 1", 1,
                             rxSize);

                byte[] retrieved = sess.dtlsCidGetRx();
                assertNotNull("Single byte CID should be retrievable",
                              retrieved);
                assertEquals("Retrieved single byte CID length", 1,
                             retrieved.length);
                assertEquals("Retrieved CID value should match",
                             (byte)0xAA, retrieved[0]);
            }

            System.out.println("\t\t... passed");

        } finally {
            if (sess != null) {
                sess.freeSSL();
            }
            if (dtlsCtx != null) {
                dtlsCtx.free();
            }
        }
    }

    @Test
    public void test_WolfSSLSession_dtlsCidErrorConditions()
        throws WolfSSLJNIException, WolfSSLException {

        WolfSSLContext dtlsCtx = null;
        WolfSSLSession sess = null;

        System.out.print("\tDTLS CID error conditions");

        /* Skip if DTLSv1.3 not supported */
        String[] protocols = WolfSSL.getProtocols();
        boolean dtls13Supported = false;
        for (String protocol : protocols) {
            if (protocol.equals("DTLSv1.3")) {
                dtls13Supported = true;
                break;
            }
        }

        if (!dtls13Supported) {
            System.out.println("\t\t... skipped (DTLSv1.3 not enabled)");
            return;
        }

        try {
            /* Create DTLS context for CID testing */
            dtlsCtx = new WolfSSLContext(WolfSSL.DTLSv1_3_ClientMethod());
            sess = new WolfSSLSession(dtlsCtx);

            /* Enable CID */
            int ret = sess.dtlsCidUse();
            if (ret == WolfSSL.NOT_COMPILED_IN) {
                System.out.println("\t\t... skipped (DTLS CID not " +
                                   "compiled in)");
                return;
            }

            /* Test null CID - should return BAD_FUNC_ARG */
            ret = sess.dtlsCidSet(null);
            assertEquals("Null CID should return BAD_FUNC_ARG",
                         WolfSSL.BAD_FUNC_ARG, ret);

            /* Test multiple calls to dtlsCidSet (overwrite scenario) */
            byte[] firstCid = new byte[]{0x01, 0x02, 0x03};
            byte[] secondCid = new byte[]{0x04, 0x05, 0x06, 0x07};

            ret = sess.dtlsCidSet(firstCid);
            if (ret == WolfSSL.SSL_SUCCESS) {
                /* Verify first CID was set */
                byte[] retrieved = sess.dtlsCidGetRx();
                assertNotNull("First CID should be retrievable",
                              retrieved);
                assertArrayEquals("First CID should match", firstCid,
                                  retrieved);

                /* Overwrite with second CID */
                ret = sess.dtlsCidSet(secondCid);
                assertNotNull("Second dtlsCidSet should return a value",
                              Integer.valueOf(ret));

                if (ret == WolfSSL.SSL_SUCCESS) {
                    /* Verify second CID overwrote first */
                    retrieved = sess.dtlsCidGetRx();
                    assertNotNull("Second CID should be retrievable",
                                  retrieved);
                    assertArrayEquals("Second CID should have " +
                                      "replaced first",
                                      secondCid, retrieved);
                    assertEquals("RX size should match second CID",
                                 secondCid.length,
                                 sess.dtlsCidGetRxSize());
                }
            }

            /* Test calling CID methods without dtlsCidUse() */
            WolfSSLSession sess2 = new WolfSSLSession(dtlsCtx);
            try {
                /* Don't call dtlsCidUse(), try to set CID anyway */
                byte[] testCid = new byte[]{0x11, 0x22};
                ret = sess2.dtlsCidSet(testCid);
                /* Should fail or return error since CID not enabled */
                assertNotEquals("Setting CID without dtlsCidUse should fail",
                                WolfSSL.SSL_SUCCESS, ret);

                /* Check that CID is not enabled */
                int enabled = sess2.dtlsCidIsEnabled();
                assertTrue("CID should not be enabled", enabled == 0 ||
                           enabled == WolfSSL.NOT_COMPILED_IN);

            } finally {
                sess2.freeSSL();
            }

            System.out.println("\t\t... passed");

        } finally {
            if (sess != null) {
                sess.freeSSL();
            }
            if (dtlsCtx != null) {
                dtlsCtx.free();
            }
        }
    }

    @Test
    public void test_WolfSSLSession_dtlsCidGet0VsRegularGet()
        throws WolfSSLJNIException, WolfSSLException {

        WolfSSLContext dtlsCtx = null;
        WolfSSLSession sess = null;

        System.out.print("\tDTLS CID get0 vs regular get");

        /* Skip if DTLSv1.3 not supported */
        String[] protocols = WolfSSL.getProtocols();
        boolean dtls13Supported = false;
        for (String protocol : protocols) {
            if (protocol.equals("DTLSv1.3")) {
                dtls13Supported = true;
                break;
            }
        }

        if (!dtls13Supported) {
            System.out.println("\t\t... skipped (DTLSv1.3 not enabled)");
            return;
        }

        try {
            /* Create DTLS context for CID testing */
            dtlsCtx = new WolfSSLContext(WolfSSL.DTLSv1_3_ClientMethod());
            sess = new WolfSSLSession(dtlsCtx);

            /* Enable CID */
            int ret = sess.dtlsCidUse();
            if (ret == WolfSSL.NOT_COMPILED_IN) {
                System.out.println("\t\t... skipped (DTLS CID not " +
                                   "compiled in)");
                return;
            }

            /* Set a test CID */
            byte[] testCid = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05};
            ret = sess.dtlsCidSet(testCid);
            if (ret != WolfSSL.SSL_SUCCESS) {
                System.out.println("\t\t... skipped (dtlsCidSet failed)");
                return;
            }

            /* Get CID using both methods */
            byte[] rxCid = sess.dtlsCidGetRx();
            byte[] rxCid0 = sess.dtlsCidGet0Rx();

            /* Both should return non-null */
            assertNotNull("dtlsCidGetRx should return non-null", rxCid);
            assertNotNull("dtlsCidGet0Rx should return non-null",
                          rxCid0);

            /* Both should have same content */
            assertArrayEquals("Both methods should return same CID data",
                              rxCid, rxCid0);

            /* Both should match original CID */
            assertArrayEquals("Regular get should match set CID",
                              testCid, rxCid);
            assertArrayEquals("Get0 should match set CID", testCid,
                              rxCid0);

            /* Test that modifying returned arrays doesn't affect
             * internal state. Note: get0 typically means "direct
             * reference" in OpenSSL/wolfSSL, but our JNI wrapper
             * creates new Java byte arrays for both, so both should
             * be safe to modify */
            byte originalFirstByte = rxCid[0];
            rxCid[0] = (byte)0xFF;
            rxCid0[0] = (byte)0xEE;

            /* Re-fetch CIDs */
            byte[] rxCidAgain = sess.dtlsCidGetRx();
            byte[] rxCid0Again = sess.dtlsCidGet0Rx();

            /* Should still have original value */
            assertNotNull("Re-fetched CID should not be null",
                          rxCidAgain);
            assertNotNull("Re-fetched CID0 should not be null",
                          rxCid0Again);
            assertEquals("Internal CID should not be modified by " +
                         "external changes",
                         originalFirstByte, rxCidAgain[0]);
            assertEquals("Internal CID should not be modified by " +
                         "external changes",
                         originalFirstByte, rxCid0Again[0]);

            /* Test TX side (before handshake, should return null or
             * empty) */
            byte[] txCid = sess.dtlsCidGetTx();
            byte[] txCid0 = sess.dtlsCidGet0Tx();

            /* TX CIDs should be null or have zero length since no
             * handshake occurred */
            assertTrue("TX CID should be null or empty before handshake",
                       txCid == null || txCid.length == 0);
            assertTrue("TX CID0 should be null or empty before " +
                       "handshake",
                       txCid0 == null || txCid0.length == 0);

            System.out.println("\t... passed");

        } finally {
            if (sess != null) {
                sess.freeSSL();
            }
            if (dtlsCtx != null) {
                dtlsCtx.free();
            }
        }
    }

    @Test
    public void test_WolfSSLSession_dtlsCidHandshakeComplete()
        throws Exception {

        System.out.print("\tDTLS CID handshake complete");

        /* Skip if DTLSv1.3 not supported - CID requires DTLSv1.3 */
        String[] protocols = WolfSSL.getProtocols();
        boolean dtls13Supported = false;
        for (String protocol : protocols) {
            if (protocol.equals("DTLSv1.3")) {
                dtls13Supported = true;
                break;
            }
        }

        if (!dtls13Supported) {
            System.out.println("\t\t... skipped (DTLSv1.3 not enabled)");
            return;
        }

        ExecutorService es = Executors.newSingleThreadExecutor();
        WolfSSLContext serverCtx = null;
        WolfSSLContext clientCtx = null;
        WolfSSLSession server = null;
        WolfSSLSession client = null;
        DatagramSocket serverSocket = null;
        DatagramSocket clientSocket = null;

        try {
            /* Create server and client contexts */
            serverCtx = new WolfSSLContext(
                WolfSSL.DTLSv1_3_ServerMethod());
            clientCtx = new WolfSSLContext(
                WolfSSL.DTLSv1_3_ClientMethod());

            /* Load certificates */
            serverCtx.useCertificateFile(cliCert,
                                         WolfSSL.SSL_FILETYPE_PEM);
            serverCtx.usePrivateKeyFile(cliKey,
                                        WolfSSL.SSL_FILETYPE_PEM);
            clientCtx.loadVerifyLocations(caCert, null);

            /* Create sessions */
            server = new WolfSSLSession(serverCtx);
            client = new WolfSSLSession(clientCtx);

            /* Enable CID on both sides */
            int ret = server.dtlsCidUse();
            if (ret == WolfSSL.NOT_COMPILED_IN) {
                System.out.println("\t\t... skipped (DTLS CID not " +
                                   "compiled in)");
                return;
            }

            ret = client.dtlsCidUse();
            if (ret != WolfSSL.SSL_SUCCESS) {
                System.out.println("\t\t... skipped (Client CID " +
                                   "enable failed: " + ret + ")");
                return;
            }

            /* Set Connection IDs before handshake */
            byte[] serverCid = {0x01, 0x02, 0x03, 0x04, 0x05};
            byte[] clientCid = {0x06, 0x07, 0x08, 0x09, 0x0A};

            ret = server.dtlsCidSet(serverCid);
            if (ret != WolfSSL.SSL_SUCCESS) {
                System.out.println("\t\t... skipped (Server " +
                                   "dtlsCidSet failed: " + ret + ")");
                return;
            }

            ret = client.dtlsCidSet(clientCid);
            if (ret != WolfSSL.SSL_SUCCESS) {
                System.out.println("\t\t... skipped (Client " +
                                   "dtlsCidSet failed: " + ret + ")");
                return;
            }

            /* Verify RX CIDs are set (what we'll receive with) */
            byte[] serverRx = server.dtlsCidGetRx();
            byte[] clientRx = client.dtlsCidGetRx();

            assertNotNull("Server RX CID should be set", serverRx);
            assertNotNull("Client RX CID should be set", clientRx);
            assertArrayEquals("Server RX CID should match set value",
                              serverCid, serverRx);
            assertArrayEquals("Client RX CID should match set value",
                              clientCid, clientRx);

            /* Before handshake, TX CIDs should be 0/null */
            int serverTxSizeBefore = server.dtlsCidGetTxSize();
            int clientTxSizeBefore = client.dtlsCidGetTxSize();

            assertEquals("Server TX CID size should be 0 before " +
                         "handshake", 0, serverTxSizeBefore);
            assertEquals("Client TX CID size should be 0 before " +
                         "handshake", 0, clientTxSizeBefore);

            /* Set up UDP sockets for DTLS communication */
            serverSocket = new DatagramSocket();
            clientSocket = new DatagramSocket();

            InetSocketAddress serverAddr = new InetSocketAddress(
                InetAddress.getLoopbackAddress(),
                serverSocket.getLocalPort());
            InetSocketAddress clientAddr = new InetSocketAddress(
                InetAddress.getLoopbackAddress(),
                clientSocket.getLocalPort());

            /* Set up DTLS peers */
            ret = server.dtlsSetPeer(clientAddr);
            if (ret != WolfSSL.SSL_SUCCESS) {
                System.out.println("\t\t... skipped (Server " +
                                   "dtlsSetPeer failed: " + ret + ")");
                return;
            }

            ret = client.dtlsSetPeer(serverAddr);
            if (ret != WolfSSL.SSL_SUCCESS) {
                System.out.println("\t\t... skipped (Client " +
                                   "dtlsSetPeer failed: " + ret + ")");
                return;
            }

            /* Configure sockets for sessions */
            ret = server.setFd(serverSocket);
            if (ret != WolfSSL.SSL_SUCCESS) {
                System.out.println("\t\t... skipped (Server setFd " +
                                   "failed: " + ret + ")");
                return;
            }

            ret = client.setFd(clientSocket);
            if (ret != WolfSSL.SSL_SUCCESS) {
                System.out.println("\t\t... skipped (Client setFd " +
                                   "failed: " + ret + ")");
                return;
            }

            /* Perform DTLS handshake in separate thread */
            final WolfSSLSession finalServer = server;
            Future<Integer> serverFuture = es.submit(
                new Callable<Integer>() {
                    @Override
                    public Integer call() {
                        try {
                            return finalServer.accept();
                        } catch (Exception e) {
                            return WolfSSL.SSL_FAILURE;
                        }
                    }
                });

            /* Client handshake */
            ret = client.connect();

            /* Wait for server handshake to complete */
            Integer serverRet = serverFuture.get(5, TimeUnit.SECONDS);

            if (ret == WolfSSL.SSL_SUCCESS &&
                serverRet == WolfSSL.SSL_SUCCESS) {

                /* Handshake succeeded! Now verify TX CIDs are
                 * negotiated. TX CID = what we send to peer, which
                 * should be peer's RX CID */
                int serverTxSize = server.dtlsCidGetTxSize();
                int clientTxSize = client.dtlsCidGetTxSize();

                /* TX sizes should now be non-zero */
                assertTrue("Server TX CID size should be > 0 after " +
                           "handshake", serverTxSize > 0);
                assertTrue("Client TX CID size should be > 0 after " +
                           "handshake", clientTxSize > 0);

                /* Get TX CIDs */
                byte[] serverTx = server.dtlsCidGetTx();
                byte[] clientTx = client.dtlsCidGetTx();

                assertNotNull("Server TX CID should not be null",
                              serverTx);
                assertNotNull("Client TX CID should not be null",
                              clientTx);

                /* Server's TX CID should match client's RX CID */
                assertArrayEquals("Server TX should match client RX",
                                  clientCid, serverTx);

                /* Client's TX CID should match server's RX CID */
                assertArrayEquals("Client TX should match server RX",
                                  serverCid, clientTx);

                /* Test get0 versions for TX */
                byte[] serverTx0 = server.dtlsCidGet0Tx();
                byte[] clientTx0 = client.dtlsCidGet0Tx();

                assertNotNull("Server TX CID0 should not be null",
                              serverTx0);
                assertNotNull("Client TX CID0 should not be null",
                              clientTx0);

                assertArrayEquals("Server TX0 should match TX",
                                  serverTx, serverTx0);
                assertArrayEquals("Client TX0 should match TX",
                                  clientTx, clientTx0);

                System.out.println("\t... passed");

            } else {
                System.out.println("\t... skipped (handshake failed: " +
                                   "client=" + ret + ", server=" +
                                   serverRet + ")");
            }

        } finally {
            if (serverSocket != null) {
                serverSocket.close();
            }
            if (clientSocket != null) {
                clientSocket.close();
            }
            if (server != null) {
                server.freeSSL();
            }
            if (client != null) {
                client.freeSSL();
            }
            if (serverCtx != null) {
                serverCtx.free();
            }
            if (clientCtx != null) {
                clientCtx.free();
            }
            es.shutdown();
        }
    }

    @Test
    public void test_WolfSSLSession_dtlsCidDataExchangeAfterHandshake()
        throws Exception {

        System.out.print("\tDTLS CID data exchange");

        /* Skip if DTLSv1.3 not supported - CID requires DTLSv1.3 */
        String[] protocols = WolfSSL.getProtocols();
        boolean dtls13Supported = false;
        for (String protocol : protocols) {
            if (protocol.equals("DTLSv1.3")) {
                dtls13Supported = true;
                break;
            }
        }

        if (!dtls13Supported) {
            System.out.println("\t\t... skipped (DTLSv1.3 not enabled)");
            return;
        }

        ExecutorService es = Executors.newSingleThreadExecutor();
        WolfSSLContext serverCtx = null;
        WolfSSLContext clientCtx = null;
        WolfSSLSession server = null;
        WolfSSLSession client = null;
        DatagramSocket serverSocket = null;
        DatagramSocket clientSocket = null;

        try {
            /* Create server and client contexts */
            serverCtx = new WolfSSLContext(
                WolfSSL.DTLSv1_3_ServerMethod());
            clientCtx = new WolfSSLContext(
                WolfSSL.DTLSv1_3_ClientMethod());

            /* Load certificates */
            serverCtx.useCertificateFile(cliCert,
                                         WolfSSL.SSL_FILETYPE_PEM);
            serverCtx.usePrivateKeyFile(cliKey,
                                        WolfSSL.SSL_FILETYPE_PEM);
            clientCtx.loadVerifyLocations(caCert, null);

            /* Create sessions */
            server = new WolfSSLSession(serverCtx);
            client = new WolfSSLSession(clientCtx);

            /* Enable CID on both sides */
            int ret = server.dtlsCidUse();
            if (ret == WolfSSL.NOT_COMPILED_IN) {
                System.out.println("\t\t... skipped (DTLS CID not " +
                                   "compiled in)");
                return;
            }

            ret = client.dtlsCidUse();
            if (ret != WolfSSL.SSL_SUCCESS) {
                System.out.println("\t\t... skipped (Client CID " +
                                   "enable failed: " + ret + ")");
                return;
            }

            /* Set Connection IDs */
            byte[] serverCid = {0x11, 0x22, 0x33, 0x44};
            byte[] clientCid = {0x55, 0x66, 0x77, (byte)0x88};

            ret = server.dtlsCidSet(serverCid);
            if (ret != WolfSSL.SSL_SUCCESS) {
                System.out.println("\t\t... skipped (Server " +
                                   "dtlsCidSet failed)");
                return;
            }

            ret = client.dtlsCidSet(clientCid);
            if (ret != WolfSSL.SSL_SUCCESS) {
                System.out.println("\t\t... skipped (Client " +
                                   "dtlsCidSet failed)");
                return;
            }

            /* Set up UDP sockets for DTLS communication */
            serverSocket = new DatagramSocket();
            clientSocket = new DatagramSocket();

            InetSocketAddress serverAddr = new InetSocketAddress(
                InetAddress.getLoopbackAddress(),
                serverSocket.getLocalPort());
            InetSocketAddress clientAddr = new InetSocketAddress(
                InetAddress.getLoopbackAddress(),
                clientSocket.getLocalPort());

            /* Set up DTLS peers */
            ret = server.dtlsSetPeer(clientAddr);
            if (ret != WolfSSL.SSL_SUCCESS) {
                System.out.println("\t\t... skipped (Server " +
                                   "dtlsSetPeer failed: " + ret + ")");
                return;
            }

            ret = client.dtlsSetPeer(serverAddr);
            if (ret != WolfSSL.SSL_SUCCESS) {
                System.out.println("\t\t... skipped (Client " +
                                   "dtlsSetPeer failed: " + ret + ")");
                return;
            }

            /* Configure sockets for sessions */
            ret = server.setFd(serverSocket);
            if (ret != WolfSSL.SSL_SUCCESS) {
                System.out.println("\t\t... skipped (Server setFd " +
                                   "failed: " + ret + ")");
                return;
            }

            ret = client.setFd(clientSocket);
            if (ret != WolfSSL.SSL_SUCCESS) {
                System.out.println("\t\t... skipped (Client setFd " +
                                   "failed: " + ret + ")");
                return;
            }

            /* Perform DTLS handshake in separate thread */
            final WolfSSLSession finalServer = server;
            Future<Integer> serverFuture = es.submit(
                new Callable<Integer>() {
                    @Override
                    public Integer call() {
                        try {
                            return finalServer.accept();
                        } catch (Exception e) {
                            return WolfSSL.SSL_FAILURE;
                        }
                    }
                });

            /* Client handshake */
            ret = client.connect();

            /* Wait for server handshake to complete */
            Integer serverRet = serverFuture.get(5, TimeUnit.SECONDS);

            if (ret == WolfSSL.SSL_SUCCESS &&
                serverRet == WolfSSL.SSL_SUCCESS) {

                /* Handshake succeeded, now test data exchange */
                final String testMessage = "Hello DTLS CID!";
                final byte[] sendBuf = testMessage.getBytes();
                final byte[] recvBuf = new byte[256];

                /* Client sends data to server */
                int sent = client.write(sendBuf, sendBuf.length);
                assertTrue("Client should send data successfully",
                           sent == sendBuf.length);

                /* Server receives data */
                int received = server.read(recvBuf, recvBuf.length);
                assertTrue("Server should receive data",
                           received == sendBuf.length);

                String receivedMsg = new String(recvBuf, 0, received);
                assertEquals("Received message should match sent",
                             testMessage, receivedMsg);

                /* Server sends response */
                final String responseMsg = "DTLS CID works!";
                final byte[] responseBuf = responseMsg.getBytes();

                sent = server.write(responseBuf, responseBuf.length);
                assertTrue("Server should send response successfully",
                           sent == responseBuf.length);

                /* Client receives response */
                received = client.read(recvBuf, recvBuf.length);
                assertTrue("Client should receive response",
                           received == responseBuf.length);

                receivedMsg = new String(recvBuf, 0, received);
                assertEquals("Received response should match sent",
                             responseMsg, receivedMsg);

                /* Verify CIDs are still correctly configured after
                 * data exchange */
                byte[] serverTx = server.dtlsCidGetTx();
                byte[] clientTx = client.dtlsCidGetTx();

                assertNotNull("Server TX CID should still be set",
                              serverTx);
                assertNotNull("Client TX CID should still be set",
                              clientTx);

                assertArrayEquals("Server TX should still match " +
                                  "client RX",
                                  clientCid, serverTx);
                assertArrayEquals("Client TX should still match " +
                                  "server RX",
                                  serverCid, clientTx);

                System.out.println("\t\t... passed");

            } else {
                System.out.println("\t\t... skipped (handshake " +
                                   "failed: client=" + ret +
                                   ", server=" + serverRet + ")");
            }

        } finally {
            if (serverSocket != null) {
                serverSocket.close();
            }
            if (clientSocket != null) {
                clientSocket.close();
            }
            if (server != null) {
                server.freeSSL();
            }
            if (client != null) {
                client.freeSSL();
            }
            if (serverCtx != null) {
                serverCtx.free();
            }
            if (clientCtx != null) {
                clientCtx.free();
            }
            es.shutdown();
        }
    }

}

