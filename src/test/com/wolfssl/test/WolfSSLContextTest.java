/* WolfSSLContextTest.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import static org.junit.Assert.*;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.ServerSocket;
import java.nio.ByteBuffer;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLContext;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLIORecvCallback;
import com.wolfssl.WolfSSLIOSendCallback;
import com.wolfssl.WolfSSLJNIException;
import com.wolfssl.WolfSSLVerifyCallback;
import com.wolfssl.WolfSSLMissingCRLCallback;
import com.wolfssl.WolfSSLPskClientCallback;
import com.wolfssl.WolfSSLPskServerCallback;
import com.wolfssl.WolfSSLSession;
import com.wolfssl.WolfSSLRsaSignCallback;
import com.wolfssl.WolfSSLRsaVerifyCallback;
import com.wolfssl.WolfSSLRsaPssSignCallback;
import com.wolfssl.WolfSSLRsaPssVerifyCallback;
import com.wolfssl.WolfCryptRSA;

public class WolfSSLContextTest {

    public final static int TEST_FAIL    = -1;
    public final static int TEST_SUCCESS =  0;

    public static String cliCert    = "examples/certs/client-cert.pem";
    public static String cliKey     = "examples/certs/client-key.pem";
    public static String svrCert    = "examples/certs/server-cert.pem";
    public static String svrKey     = "examples/certs/server-key.pem";
    public static String svrCertEcc = "examples/certs/server-ecc.pem";
    public static String caCert     = "examples/certs/ca-cert.pem";
    public static String dhParams   = "examples/certs/dh2048.pem";
    public final static String bogusFile = "/dev/null";

    @Rule
    public TestRule testWatcher = TimedTestWatcher.create();

    WolfSSLContext ctx;

    /* Hold a strong reference to a WolfSSL instance for the lifetime of
     * this test class so wolfSSL_Init() runs before any test executes.
     * Required when surefire/Maven runs this class outside of
     * WolfSSLTestSuite, whose @BeforeClass would otherwise create one. */
    private static WolfSSL sslLib = null;

    @BeforeClass
    public static void loadLibrary() throws WolfSSLException {
        System.out.println("WolfSSLContext Class");

        try {
            WolfSSL.loadLibrary();
        } catch (UnsatisfiedLinkError ule) {
            fail("failed to load native JNI library");
        }
        sslLib = new WolfSSL();

        cliCert = WolfSSLTestCommon.getPath(cliCert);
        cliKey = WolfSSLTestCommon.getPath(cliKey);
        svrCert = WolfSSLTestCommon.getPath(svrCert);
        svrKey = WolfSSLTestCommon.getPath(svrKey);
        svrCertEcc = WolfSSLTestCommon.getPath(svrCertEcc);
        caCert = WolfSSLTestCommon.getPath(caCert);
        dhParams = WolfSSLTestCommon.getPath(dhParams);
    }

    @Before
    public void createCtx() throws WolfSSLException {
        long method = WolfSSL.SSLv23_ServerMethod();
        Assume.assumeTrue("SSLv23 server method not available",
            method != 0 && method != WolfSSL.NOT_COMPILED_IN);
        ctx = new WolfSSLContext(method);
    }

    @After
    public void freeCtx() {
        if (ctx != null) {
            ctx.free();
            ctx = null;
        }
    }

    @Test
    public void test_WolfSSLContext_new() {
        /* Freshly-created ctx from @Before covers the success path. Verify
         * that constructor throws when passed an invalid method (0). */
        try {
            new WolfSSLContext(0);
            fail("new WolfSSLContext(0) should have thrown");
        } catch (WolfSSLException expected) {
            /* expected */
        }
    }

    @Test
    public void test_WolfSSLContext_useCertificateFile() {
        test_ucf(null, null, 9999, WolfSSL.SSL_FAILURE,
                 "useCertificateFile(null, null, 9999)");

        if (WolfSSL.FileSystemEnabled() == true) {
            test_ucf(ctx, bogusFile, WolfSSL.SSL_FILETYPE_PEM,
                     WolfSSL.SSL_FAILURE,
                     "useCertificateFile(ctx, bogusFile, SSL_FILETYPE_PEM)");

            test_ucf(ctx, cliCert, 9999, WolfSSL.SSL_FAILURE,
                     "useCertificateFile(ctx, cliCert, 9999)");

            test_ucf(ctx, cliCert, WolfSSL.SSL_FILETYPE_PEM,
                     WolfSSL.SSL_SUCCESS,
                     "useCertificateFile(ctx, cliCert, SSL_FILETYPE_PEM)");
        }
    }

    /* helper for testing WolfSSLContext.useCertificateFile() */
    private void test_ucf(WolfSSLContext sslCtx, String filePath, int type,
                        int cond, String name) {

        int result;

        try {
            result = sslCtx.useCertificateFile(filePath, type);
            if (result != cond) {
                fail(name + " failed");
            }
        } catch (NullPointerException e) {
            /* Native code throws NPE for null inputs (null ctx or null
             * path) instead of returning SSL_FAILURE. Accept NPE only
             * when the test was already expecting a failure. */
            if (cond != WolfSSL.SSL_FAILURE) {
                fail(name + " threw unexpected NullPointerException");
            }
        }
    }

    @Test
    public void test_WolfSSLContext_usePrivateKeyFile() {
        test_upkf(null, null, 9999, WolfSSL.SSL_FAILURE,
                 "usePrivateKeyFile(null, null, 9999)");

        if (WolfSSL.FileSystemEnabled() == true) {
            test_upkf(ctx, bogusFile, WolfSSL.SSL_FILETYPE_PEM,
                      WolfSSL.SSL_FAILURE,
                     "usePrivateKeyFile(ctx, bogusFile, SSL_FILETYPE_PEM)");

            test_upkf(ctx, cliKey, 9999, WolfSSL.SSL_FAILURE,
                     "usePrivateKeyFile(ctx, cliKey, 9999)");

            test_upkf(ctx, cliKey, WolfSSL.SSL_FILETYPE_PEM,
                     WolfSSL.SSL_SUCCESS,
                     "usePrivateKeyFile(ctx, cliKey, SSL_FILETYPE_PEM)");
        }
    }

    /* helper for testing WolfSSLContext.usePrivateKeyFile() */
    private void test_upkf(WolfSSLContext sslCtx, String filePath, int type,
                        int cond, String name) {

        int result;

        try {
            result = sslCtx.usePrivateKeyFile(filePath, type);
            if (result != cond) {
                fail(name + " failed");
            }
        } catch (NullPointerException e) {
            /* Native code throws NPE for null inputs (null ctx or null
             * path) instead of returning SSL_FAILURE. Accept NPE only
             * when the test was already expecting a failure. */
            if (cond != WolfSSL.SSL_FAILURE) {
                fail(name + " threw unexpected NullPointerException");
            }
        }
    }

    @Test
    public void test_WolfSSLContext_loadVerifyLocations() {
        test_lvl(null, null, null, WolfSSL.SSL_FAILURE,
                "loadVerifyLocations(null, null, null)");

        if (WolfSSL.FileSystemEnabled() == true ) {
            test_lvl(ctx, null, null, WolfSSL.SSL_FAILURE,
                    "loadVerifyLocations(ctx, null, null)");

            test_lvl(null, caCert, null, WolfSSL.SSL_FAILURE,
                    "loadVerifyLocations(null, caCert, null)");

            test_lvl(ctx, caCert, null, WolfSSL.SSL_SUCCESS,
                    "loadVerifyLocations(ctx, caCert, 0)");
        }
    }

    /* helper for testing WolfSSLContext.loadVerifyLocations() */
    private void test_lvl(WolfSSLContext sslCtx, String filePath,
                         String dirPath, int cond, String name) {

        int result;

        try {
            result = sslCtx.loadVerifyLocations(filePath, dirPath);
            if (result != cond) {
                fail(name + " failed");
            }
        } catch (NullPointerException e) {
            /* Native code throws NPE for null inputs (null ctx or null
             * path) instead of returning SSL_FAILURE. Accept NPE only
             * when the test was already expecting a failure. */
            if (cond != WolfSSL.SSL_FAILURE) {
                fail(name + " threw unexpected NullPointerException");
            }
        }
    }

    @Test
    public void test_WolfSSLContext_memsaveCertCache()
        throws WolfSSLException, WolfSSLJNIException {

        int ret;
        int sz;
        int[] used = new int[1];
        byte[] mem = null;
        WolfSSLContext ctx2 = null;

        if (WolfSSL.FileSystemEnabled() == false) {
            return;
        }

        ret = ctx.loadVerifyLocations(caCert, null);
        assertEquals(WolfSSL.SSL_SUCCESS, ret);

        sz = ctx.getCertCacheMemsize();
        if (sz == WolfSSL.NOT_COMPILED_IN) {
            /* skip when PERSIST_CERT_CACHE is not compiled in */
            return;
        }
        assertTrue(sz > 0);

        /* undersized buffer returns BUFFER_E and leaves used untouched */
        used[0] = -1;
        ret = ctx.memsaveCertCache(new byte[1], 1, used);
        assertEquals(WolfSSL.BUFFER_E, ret);
        assertEquals(-1, used[0]);

        /* null used array is rejected */
        ret = ctx.memsaveCertCache(new byte[sz], sz, null);
        assertEquals(WolfSSL.BAD_FUNC_ARG, ret);

        /* correctly sized buffer saves cert cache */
        mem = new byte[sz];
        used[0] = 0;
        ret = ctx.memsaveCertCache(mem, sz, used);
        assertEquals(WolfSSL.SSL_SUCCESS, ret);
        assertTrue(used[0] > 0 && used[0] <= sz);

        /* saved cache restores into a new context */
        ctx2 = new WolfSSLContext(WolfSSL.SSLv23_ServerMethod());
        try {
            ret = ctx2.memrestoreCertCache(mem, used[0]);
            assertEquals(WolfSSL.SSL_SUCCESS, ret);

            /* Ensure we reject bad sizes */
            assertEquals(WolfSSL.BAD_FUNC_ARG,
                ctx2.memrestoreCertCache(mem, mem.length + 1));
            assertEquals(WolfSSL.BAD_FUNC_ARG,
                ctx2.memrestoreCertCache(mem, 0));
            assertEquals(WolfSSL.BAD_FUNC_ARG,
                ctx2.memrestoreCertCache(mem, -1));
        } finally {
            ctx2.free();
        }
    }

    /* in-memory byte queue connecting context level I/O callbacks */
    class TestIOQueue {
        private byte[] data = new byte[0];

        synchronized void add(byte[] buf, int sz) {
            byte[] tmp = new byte[data.length + sz];
            System.arraycopy(data, 0, tmp, 0, data.length);
            System.arraycopy(buf, 0, tmp, data.length, sz);
            data = tmp;
        }

        synchronized int take(byte[] buf, int sz) {
            byte[] tmp = null;
            int n = Math.min(sz, data.length);
            if (n == 0) {
                return 0;
            }
            System.arraycopy(data, 0, buf, 0, n);
            tmp = new byte[data.length - n];
            System.arraycopy(data, n, tmp, 0, tmp.length);
            data = tmp;
            return n;
        }
    }

    class TestCtxIOCallback implements WolfSSLIORecvCallback,
        WolfSSLIOSendCallback {

        private final TestIOQueue in;
        private final TestIOQueue out;

        TestCtxIOCallback(TestIOQueue in, TestIOQueue out) {
            this.in = in;
            this.out = out;
        }

        public int receiveCallback(WolfSSLSession ssl, byte[] buf, int sz,
            Object ctx) {
            int n = in.take(buf, sz);
            if (n == 0) {
                return WolfSSL.WOLFSSL_CBIO_ERR_WANT_READ;
            }
            return n;
        }

        public int sendCallback(WolfSSLSession ssl, byte[] buf, int sz,
            Object ctx) {
            out.add(buf, sz);
            return sz;
        }
    }

    @Test
    public void test_WolfSSLContext_ioRecvSendCallbacks() throws Exception {

        int cliRet = WolfSSL.SSL_FAILURE;
        int srvRet = WolfSSL.SSL_FAILURE;
        int cliErr = 0;
        int srvErr = 0;
        int i;
        WolfSSLContext srvCtx = null;
        WolfSSLContext cliCtx = null;
        WolfSSLSession server = null;
        WolfSSLSession client = null;
        TestIOQueue cliToSrv = new TestIOQueue();
        TestIOQueue srvToCli = new TestIOQueue();
        TestCtxIOCallback srvCb = new TestCtxIOCallback(cliToSrv, srvToCli);
        TestCtxIOCallback cliCb = new TestCtxIOCallback(srvToCli, cliToSrv);

        if (WolfSSL.FileSystemEnabled() == false) {
            return;
        }

        try {
            srvCtx = new WolfSSLContext(WolfSSL.SSLv23_ServerMethod());
            cliCtx = new WolfSSLContext(WolfSSL.SSLv23_ClientMethod());

            assertEquals(WolfSSL.SSL_SUCCESS, srvCtx.useCertificateFile(
                svrCert, WolfSSL.SSL_FILETYPE_PEM));
            assertEquals(WolfSSL.SSL_SUCCESS, srvCtx.usePrivateKeyFile(
                svrKey, WolfSSL.SSL_FILETYPE_PEM));
            assertEquals(WolfSSL.SSL_SUCCESS,
                cliCtx.loadVerifyLocations(caCert, null));

            /* register context level I/O callbacks before creating sessions
             * so new sessions inherit them */
            srvCtx.setIORecv(srvCb);
            srvCtx.setIOSend(srvCb);
            cliCtx.setIORecv(cliCb);
            cliCtx.setIOSend(cliCb);

            server = new WolfSSLSession(srvCtx);
            client = new WolfSSLSession(cliCtx);

            /* single threaded handshake, alternate client and server until
             * both complete */
            for (i = 0; i < 100; i++) {
                if (cliRet != WolfSSL.SSL_SUCCESS) {
                    cliRet = client.connect();
                    cliErr = client.getError(cliRet);
                    if (cliRet != WolfSSL.SSL_SUCCESS &&
                        cliErr != WolfSSL.SSL_ERROR_WANT_READ &&
                        cliErr != WolfSSL.SSL_ERROR_WANT_WRITE) {
                        break;
                    }
                }
                if (srvRet != WolfSSL.SSL_SUCCESS) {
                    srvRet = server.accept();
                    srvErr = server.getError(srvRet);
                    if (srvRet != WolfSSL.SSL_SUCCESS &&
                        srvErr != WolfSSL.SSL_ERROR_WANT_READ &&
                        srvErr != WolfSSL.SSL_ERROR_WANT_WRITE) {
                        break;
                    }
                }
                if (cliRet == WolfSSL.SSL_SUCCESS &&
                    srvRet == WolfSSL.SSL_SUCCESS) {
                    break;
                }
            }

            assertEquals("client connect over context I/O callbacks, " +
                "error: " + cliErr, WolfSSL.SSL_SUCCESS, cliRet);
            assertEquals("server accept over context I/O callbacks, " +
                "error: " + srvErr, WolfSSL.SSL_SUCCESS, srvRet);

            /* exchange application data through the callbacks */
            byte[] msg = "hello callbacks".getBytes();
            byte[] rcvd = new byte[msg.length];
            assertEquals(msg.length, client.write(msg, msg.length));
            assertEquals(msg.length, server.read(rcvd, rcvd.length));
            assertArrayEquals(msg, rcvd);

        } finally {
            if (server != null) {
                server.freeSSL();
            }
            if (client != null) {
                client.freeSSL();
            }
            if (srvCtx != null) {
                srvCtx.free();
            }
            if (cliCtx != null) {
                cliCtx.free();
            }
        }
    }

    class TestPskClientCb implements WolfSSLPskClientCallback
    {
        public long pskClientCallback(WolfSSLSession ssl, String hint,
                StringBuffer identity, long idMaxLen, byte[] key,
                long keyMaxLen) {

            /* set the client identity */
            if (identity.length() != 0) {
                return 0;
            }
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
    public void test_WolfSSLContext_setPskClientCb() {
        try {
            TestPskClientCb pskClientCb = new TestPskClientCb();
            ctx.setPskClientCb(pskClientCb);

        } catch (Exception e) {
            String msg = e.getMessage();
            if ("wolfSSL not compiled with PSK support".equals(msg)) {
                Assume.assumeNoException("PSK not compiled in", e);
            }

            e.printStackTrace();
            fail("setPskClientCb threw unexpected: " + msg);
        }
    }

    class TestPskServerCb implements WolfSSLPskServerCallback
    {
        public long pskServerCallback(WolfSSLSession ssl, String identity,
                byte[] key, long keyMaxLen) {

            /* check the client identity */
            if (!identity.equals("Client_identity")) {
                return 0;
            }

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
    public void test_WolfSSLContext_setPskServerCb() {
        try {
            TestPskServerCb pskServerCb = new TestPskServerCb();
            ctx.setPskServerCb(pskServerCb);

        } catch (Exception e) {
            String msg = e.getMessage();
            if ("wolfSSL not compiled with PSK support".equals(msg)) {
                Assume.assumeNoException("PSK not compiled in", e);
            }

            e.printStackTrace();
            fail("setPskServerCb threw unexpected: " + msg);
        }
    }

    @Test
    public void test_WolfSSLContext_usePskIdentityHint() {
        try {
            int ret = ctx.usePskIdentityHint("wolfssl hint");
            if (ret != WolfSSL.SSL_SUCCESS &&
                ret != WolfSSL.NOT_COMPILED_IN) {
                fail("usePskIdentityHint failed");
            }

        } catch (IllegalStateException e) {
            e.printStackTrace();
            fail("usePskIdentityHint threw: " + e.getMessage());
        }
    }

    @Test
    public void test_WolfSSLContext_useSecureRenegotiation() {
        try {
            int ret = ctx.useSecureRenegotiation();
            if (ret != WolfSSL.SSL_SUCCESS &&
                ret != WolfSSL.NOT_COMPILED_IN) {
                fail("useSecureRenegotiation failed");
            }

        } catch (IllegalStateException e) {
            e.printStackTrace();
            fail("useSecureRenegotiation threw: " + e.getMessage());
        }
    }

    @Test
    public void test_WolfSSLContext_useSupportedCurves() {

        int ret;
        String[] singleEccSecp256r1 = new String[] { "secp256r1" };
        String[] commonEccCurves =  new String[] {
            "secp256r1", "secp384r1", "secp521r1"
        };
        String[] containsUnknownCurve = new String[] {
            "bogus_curve_name", "secp256r1"
        };
        String[] x25519Curve = new String[] { "x25519" };
        String[] x448Curve = new String[] { "x448" };

        try {
            ret = ctx.useSupportedCurves(singleEccSecp256r1);
            if (ret != WolfSSL.SSL_SUCCESS &&
                ret != WolfSSL.NOT_COMPILED_IN) {
                fail("useSupportedCurves(singleEccSecp256r1) failed");
            }
            ret = ctx.useSupportedCurves(commonEccCurves);
            if (ret != WolfSSL.SSL_SUCCESS &&
                ret != WolfSSL.NOT_COMPILED_IN) {
                fail("useSupportedCurves(commonEccCurves) failed");
            }
            /* An unknown curve name must surface as an error, even when a
             * later entry in the list succeeds. Valid entries are still
             * appended (best-effort), but the first error is returned. */
            ret = ctx.useSupportedCurves(containsUnknownCurve);
            if (ret == WolfSSL.SSL_SUCCESS) {
                fail("useSupportedCurves(containsUnknownCurve) should " +
                     "not return SSL_SUCCESS");
            }
            if (WolfSSL.Curve25519Enabled()) {
                ret = ctx.useSupportedCurves(x25519Curve);
                if (ret != WolfSSL.SSL_SUCCESS &&
                    ret != WolfSSL.NOT_COMPILED_IN) {
                    fail("useSupportedCurves(x25519Curve) failed");
                }
            }
            if (WolfSSL.Curve448Enabled()) {
                ret = ctx.useSupportedCurves(x448Curve);
                if (ret != WolfSSL.SSL_SUCCESS &&
                    ret != WolfSSL.NOT_COMPILED_IN) {
                    fail("useSupportedCurves(x448Curve) failed");
                }
            }
        } catch (IllegalStateException e) {
            e.printStackTrace();
            fail("useSupportedCurves failed");
        }
    }

    @Test
    public void test_WolfSSLContext_setGroups() {

        int ret;
        int[] singleItem = { WolfSSL.WOLFSSL_ECC_SECP256R1 };
        int[] twoItems = {
            WolfSSL.WOLFSSL_ECC_SECP256R1,
            WolfSSL.WOLFSSL_ECC_SECP256R1
        };
        int[] tooLong = new int[50];
        int[] badGroups = { 0xDEAD, 0xBEEF };

        try {
            ret = ctx.setGroups(null);
            if (ret != WolfSSL.NOT_COMPILED_IN &&
                ret == WolfSSL.SSL_SUCCESS) {
                fail("setGroups() should fail with null arg");
            }
            if (WolfSSL.EccEnabled()) {
                ret = ctx.setGroups(singleItem);
                if (ret != WolfSSL.NOT_COMPILED_IN &&
                    ret != WolfSSL.SSL_SUCCESS) {
                    fail("setGroups() failed with WOLFSSL_ECC_SECP256R1");
                }
                if (ret == WolfSSL.NOT_COMPILED_IN &&
                    WolfSSL.TLSv13Enabled() &&
                    ctx.useSupportedCurves(new String[] { "secp256r1" })
                        == WolfSSL.SSL_SUCCESS) {
                    fail("setGroups() returned NOT_COMPILED_IN on a " +
                        "TLS 1.3 build with supported-curves available");
                }
                ret = ctx.setGroups(twoItems);
                if (ret != WolfSSL.NOT_COMPILED_IN &&
                    ret != WolfSSL.SSL_SUCCESS) {
                    fail("setGroups() failed with two entries");
                }
            }
            ret = ctx.setGroups(tooLong);
            if (ret != WolfSSL.NOT_COMPILED_IN &&
                ret != WolfSSL.BAD_FUNC_ARG) {
                fail("setGroups() should fail with too long array");
            }
            ret = ctx.setGroups(badGroups);
            if (ret != WolfSSL.NOT_COMPILED_IN &&
                ret != WolfSSL.BAD_FUNC_ARG) {
                fail("setGroups() should fail with bad/invalid values");
            }
        } catch (IllegalStateException e) {
            e.printStackTrace();
            fail("setGroups() failed");
        }
    }

    @Test
    public void test_WolfSSLContext_set1SigAlgsList() {

        int ret;

        try {
            /* Expected failure, null list */
            ret = ctx.set1SigAlgsList(null);
            if (ret != WolfSSL.NOT_COMPILED_IN &&
                ret != WolfSSL.SSL_FAILURE) {
                fail("set1SigAlgsList() should fail with null list");
            }

            /* Expected failure, empty list */
            ret = ctx.set1SigAlgsList("");
            if (ret != WolfSSL.NOT_COMPILED_IN &&
                ret != WolfSSL.SSL_FAILURE) {
                fail("set1SigAlgsList() should fail with empty list");
            }

            if (WolfSSL.RsaEnabled()) {
                ret = ctx.set1SigAlgsList("RSA");
                if (ret != WolfSSL.NOT_COMPILED_IN &&
                    ret != WolfSSL.SSL_FAILURE) {
                    fail("set1SigAlgsList() should fail without hash");
                }

                if (WolfSSL.Sha256Enabled()) {
                    ret = ctx.set1SigAlgsList("RSA+SHA256");
                    if (ret != WolfSSL.NOT_COMPILED_IN &&
                        ret != WolfSSL.SSL_SUCCESS) {
                        fail("set1SigAlgsList() should pass with given list");
                    }

                    ret = ctx.set1SigAlgsList("RSA:RSA+SHA256");
                    if (ret != WolfSSL.NOT_COMPILED_IN &&
                        ret != WolfSSL.SSL_FAILURE) {
                        fail("set1SigAlgsList() should fail without hash");
                    }

                    if (WolfSSL.Sha512Enabled()) {
                        ret = ctx.set1SigAlgsList("RSA+SHA256:RSA+SHA512");
                        if (ret != WolfSSL.NOT_COMPILED_IN &&
                            ret != WolfSSL.SSL_SUCCESS) {
                            fail("set1SigAlgsList() should pass");
                        }
                    }
                }
            }

            if (WolfSSL.EccEnabled()) {
                ret = ctx.set1SigAlgsList("ECDSA");
                if (ret != WolfSSL.NOT_COMPILED_IN &&
                    ret != WolfSSL.SSL_FAILURE) {
                    fail("set1SigAlgsList() should fail without hash");
                }

                if (WolfSSL.Sha256Enabled()) {
                    ret = ctx.set1SigAlgsList("ECDSA+SHA256");
                    if (ret != WolfSSL.NOT_COMPILED_IN &&
                        ret != WolfSSL.SSL_SUCCESS) {
                        fail("set1SigAlgsList() should pass with given list");
                    }

                    ret = ctx.set1SigAlgsList("ECDSA:ECDSA+SHA256");
                    if (ret != WolfSSL.NOT_COMPILED_IN &&
                        ret != WolfSSL.SSL_FAILURE) {
                        fail("set1SigAlgsList() should fail without hash");
                    }

                    if (WolfSSL.Sha512Enabled()) {
                        ret = ctx.set1SigAlgsList("ECDSA+SHA256:ECDSA+SHA512");
                        if (ret != WolfSSL.NOT_COMPILED_IN &&
                            ret != WolfSSL.SSL_SUCCESS) {
                            fail("set1SigAlgsList() should pass");
                        }
                    }
                }
            }
        } catch (IllegalStateException e) {
            e.printStackTrace();
            fail("set1SigAlgsList() failed");
        }
    }

    @Test
    public void test_WolfSSLContext_setMinRSAKeySize() {

        int ret = 0;

        try {
            /* negative size key length should fail */
            ret = ctx.setMinRSAKeySize(-1);
            if (ret != WolfSSL.BAD_FUNC_ARG) {
                fail("setMinRSAKeySize should fail with negative key size");
            }

            /* value that wraps across the 16-bit boundary should fail,
             * 66560 wraps to 1024. */
            ret = ctx.setMinRSAKeySize(66560);
            if (ret != WolfSSL.BAD_FUNC_ARG) {
                fail("setMinRSAKeySize should fail for out-of-range value");
            }

            /* key length not % 8 should fail */
            ret = ctx.setMinRSAKeySize(1023);
            if (ret != WolfSSL.BAD_FUNC_ARG) {
                fail("setMinRSAKeySize should fail with non % 8 size");
            }

            /* valid key length should succeed */
            ret = ctx.setMinRSAKeySize(1024);
            if (ret != WolfSSL.SSL_SUCCESS) {
                fail("setMinRSAKeySize did not pass as expected");
            }

            /* loading of key larger than set size should pass */
            ret = ctx.useCertificateFile(cliCert, WolfSSL.SSL_FILETYPE_PEM);
            if (ret != WolfSSL.SSL_SUCCESS) {
                fail("setMinRSAKeySize did not pass as expected (1024 limit)");
            }

            /* set min key size to something very large for next test. Below
             * we test ctx.useCertificateFile(), but that API will only fail
             * based on key size limitations when peer verification is
             * enabled, set SSL_VERIFY_PEER here. */
            ctx.setVerify(WolfSSL.SSL_VERIFY_PEER, null);
            ret = ctx.setMinRSAKeySize(8192);
            if (ret != WolfSSL.SSL_SUCCESS) {
                fail("setMinRSAKeySize did not pass as expected for 8192");
            }

            /* loading of key smaller than set size should fail */
            ret = ctx.useCertificateFile(cliCert, WolfSSL.SSL_FILETYPE_PEM);
            if (ret == WolfSSL.SSL_SUCCESS) {
                fail("setMinRSAKeySize did not fail as expected with limit");
            }

        } catch (IllegalStateException e) {
            e.printStackTrace();
            fail("setMinRSAKeySize threw: " + e.getMessage());
        }
    }

    @Test
    public void test_WolfSSLContext_setMinECCKeySize() {

        int ret = 0;

        try {
            /* negative size key length should fail */
            ret = ctx.setMinECCKeySize(-1);
            if (ret != WolfSSL.BAD_FUNC_ARG) {
                fail("setMinECCKeySize should fail with negative key size");
            }

            /* value that wraps across the 16-bit boundary should fail,
             * 66048 narrows to 512. */
            ret = ctx.setMinECCKeySize(66048);
            if (ret != WolfSSL.BAD_FUNC_ARG) {
                fail("setMinECCKeySize should fail for out-of-range value");
            }

            /* valid key length should succeed */
            ret = ctx.setMinECCKeySize(128);
            if (ret != WolfSSL.SSL_SUCCESS) {
                fail("setMinECCKeySize did not pass as expected");
            }

            /* loading of key larger than set size should pass */
            ret = ctx.useCertificateFile(svrCertEcc, WolfSSL.SSL_FILETYPE_PEM);
            if (ret != WolfSSL.SSL_SUCCESS) {
                fail("setMinECCKeySize did not pass as expected (128 limit)");
            }

            /* Below we test ctx.useCertificateFile(), but that API will only
             * fail based on key size limitations when peer verification is
             * enabled, set SSL_VERIFY_PEER here. */
            ctx.setVerify(WolfSSL.SSL_VERIFY_PEER, null);

            /* set min key size to something very large for next test */
            ret = ctx.setMinECCKeySize(512);
            if (ret != WolfSSL.SSL_SUCCESS) {
                fail("setMinECCKeySize did not pass as expected for 521");
            }

            /* loading of key smaller than set size should fail */
            ret = ctx.useCertificateFile(svrCertEcc, WolfSSL.SSL_FILETYPE_PEM);
            if (ret == WolfSSL.SSL_SUCCESS) {
                fail("setMinECCKeySize did not fail as expected with limit");
            }

        } catch (IllegalStateException e) {
            e.printStackTrace();
            fail("setMinECCKeySize threw: " + e.getMessage());
        }
    }

    @Test
    public void test_WolfSSLContext_setMinDHKeySize() {

        int ret = 0;

        /* If DH is not compiled into native wolfSSL (ex: FIPS NO_DH),
         * setMinDHKeySize() returns NOT_COMPILED_IN in that case */
        if (!WolfSSL.DhEnabled()) {
            assertEquals(WolfSSL.NOT_COMPILED_IN, ctx.setMinDHKeySize(1024));
            return;
        }

        try {
            /* key length > 16000 should fail */
            ret = ctx.setMinDHKeySize(17000);
            if (ret != WolfSSL.BAD_FUNC_ARG) {
                fail("setMinDHKeySize should fail with key size too large");
            }

            /* value that wraps across the 16-bit boundary should fail,
             * 66560 narrows to 1024. */
            ret = ctx.setMinDHKeySize(66560);
            if (ret != WolfSSL.BAD_FUNC_ARG) {
                fail("setMinDHKeySize should fail for out-of-range value");
            }

            /* key length not % 8 should fail */
            ret = ctx.setMinDHKeySize(1023);
            if (ret != WolfSSL.BAD_FUNC_ARG) {
                fail("setMinDHKeySize should fail with non % 8 size");
            }

            /* valid key length should succeed */
            ret = ctx.setMinDHKeySize(1024);
            if (ret != WolfSSL.SSL_SUCCESS) {
                fail("setMinDHKeySize did not pass as expected");
            }

            Assume.assumeTrue(WolfSSL.FileSystemEnabled());

            /* loading params larger than min size should pass (2048>1024) */
            ret = ctx.setTmpDHFile(dhParams, WolfSSL.SSL_FILETYPE_PEM);
            if (ret != WolfSSL.SSL_SUCCESS) {
                fail("setTmpDHFile did not pass as expected (1024 limit)");
            }

            /* set min key size too large to accept dh2048 params */
            ret = ctx.setMinDHKeySize(8192);
            if (ret != WolfSSL.SSL_SUCCESS) {
                fail("setMinDHKeySize did not pass as expected for 8192");
            }

            /* loading of params smaller than set size should fail */
            ret = ctx.setTmpDHFile(dhParams, WolfSSL.SSL_FILETYPE_PEM);
            if (ret == WolfSSL.SSL_SUCCESS) {
                fail("setMinDHKeySize did not fail as expected with limit");
            }

        } catch (IllegalStateException | WolfSSLJNIException e) {
            e.printStackTrace();
            fail("setMinDHKeySize threw: " + e.getMessage());
        }
    }

    /* Custom verify callback class so each test instance is its own Java
     * object (and therefore its own JNI global ref). */
    private static class CountingVerifyCb implements WolfSSLVerifyCallback {
        public int calls = 0;
        public int verifyCallback(int preverify_ok, long x509StorePtr) {
            calls++;
            return preverify_ok;
        }
    }

    /* Exercises setVerify ref lifecycle with multiple WolfSSLContext instances
     * each holding their own callback. Goes through the install, replace,
     * unregister, and re-install paths, frees one context while the other is
     * still live, and forces GC to surface any dangling-ref issues under
     * -Xcheck:jni or Android checked JNI.
     *
     * The Java callback objects are referenced at the end of the test
     * to keep them strongly reachable for the duration of the test. */
    @Test
    public void test_WolfSSLContext_setVerifyMultipleContexts()
        throws WolfSSLException {

        /* Each context owns the WOLFSSL_METHOD it is constructed with and
         * frees it during free(), so allocate a method per context. */
        long methodA = WolfSSL.SSLv23_ServerMethod();
        long methodB = WolfSSL.SSLv23_ServerMethod();
        Assume.assumeTrue("SSLv23 server method not available",
            methodA != 0 && methodA != WolfSSL.NOT_COMPILED_IN &&
            methodB != 0 && methodB != WolfSSL.NOT_COMPILED_IN);

        WolfSSLContext ctxA = new WolfSSLContext(methodA);
        WolfSSLContext ctxB = new WolfSSLContext(methodB);
        CountingVerifyCb cbA = new CountingVerifyCb();
        CountingVerifyCb cbB = new CountingVerifyCb();

        try {
            /* Register distinct callbacks on each ctx. */
            ctxA.setVerify(WolfSSL.SSL_VERIFY_PEER, cbA);
            ctxB.setVerify(WolfSSL.SSL_VERIFY_PEER, cbB);

            /* Replace ctxA's callback with a fresh one, exercises the
             * prior-ref-release path on the same ctx. */
            CountingVerifyCb cbA2 = new CountingVerifyCb();
            ctxA.setVerify(WolfSSL.SSL_VERIFY_PEER, cbA2);

            /* Unregister ctxB's callback (null path). */
            ctxB.setVerify(WolfSSL.SSL_VERIFY_PEER, null);

            /* Re-register on ctxB after a null pass. */
            ctxB.setVerify(WolfSSL.SSL_VERIFY_PEER, cbB);

            /* Free ctxA first while ctxB's callback is still live. */
            ctxA.free();
            ctxA = null;

            /* ctxB should still be functional (no exception thrown). */
            ctxB.setVerify(WolfSSL.SSL_VERIFY_PEER, null);

            /* Touch the cb references at the end to defeat any compiler level
             * liveness shortening that would let GC collect them mid-test. */
            assertNotNull(cbA);
            assertNotNull(cbA2);
            assertNotNull(cbB);
        } finally {
            if (ctxA != null) {
                ctxA.free();
            }
            if (ctxB != null) {
                ctxB.free();
            }
        }
    }

    /* Custom missing CRL callback class so each test instance is its own
     * Java object (and own JNI global ref). */
    private static class CountingMissingCRLCb
        implements WolfSSLMissingCRLCallback {
        public int calls = 0;
        public void missingCRLCallback(String url) {
            calls++;
        }
    }

    /* Exercises setCRLCb ref lifecycle for both WolfSSLContext.setCRLCb() and
     * WolfSSLSession.setCRLCb(). The two globals (g_crlCtxCbIfaceObj and
     * g_crlCbIfaceObj) are protected by a single process-global mutex
     * (g_crlCbMutex). This test does install / replace / unregister /
     * re-install / free paths and forces GC.
     *
     * Java callback objects are referenced at the end of the test to keep
     * them strongly reachable for the duration of the test. */
    @Test
    public void test_WolfSSLContext_setCRLCbMultipleContexts()
        throws Exception {

        /* WolfSSLSession construction requires a CTX with cert and key loaded,
         * so this test is gated on RSA and filesystem support. */
        Assume.assumeTrue(WolfSSL.RsaEnabled() && WolfSSL.FileSystemEnabled());
        Assume.assumeTrue(WolfSSL.TLSv12Enabled());

        WolfSSLContext ctxA = createCtx(cliCert, cliKey, caCert,
            WolfSSL.TLSv1_2_ClientMethod());
        WolfSSLContext ctxB = createCtx(cliCert, cliKey, caCert,
            WolfSSL.TLSv1_2_ClientMethod());
        WolfSSLSession sesA = null;
        WolfSSLSession sesB = null;
        CountingMissingCRLCb cbA = new CountingMissingCRLCb();
        CountingMissingCRLCb cbB = new CountingMissingCRLCb();
        CountingMissingCRLCb cbA2 = new CountingMissingCRLCb();
        CountingMissingCRLCb sesCbA = new CountingMissingCRLCb();
        CountingMissingCRLCb sesCbB = new CountingMissingCRLCb();

        try {
            /* Check for HAVE_CRL by attempting a CTX-level register. Skip the
             * test if CRL is not compiled in. */
            int probe = ctxA.setCRLCb(cbA);
            Assume.assumeTrue("CRL not compiled in",
                probe != WolfSSL.NOT_COMPILED_IN);

            ctxB.setCRLCb(cbB);

            /* Replace ctxA callback with a fresh one, exercises the
             * prior-ref-release path on the same ctx. */
            ctxA.setCRLCb(cbA2);

            /* Unregister ctxB callback (null path, should also unregister
             * the native wolfSSL CRL cb). */
            ctxB.setCRLCb(null);

            /* Re-register on ctxB after a null pass. */
            ctxB.setCRLCb(cbB);

            /* Session-level setCRLCb, same pattern on a session created
             * from each context. */
            sesA = new WolfSSLSession(ctxA);
            sesB = new WolfSSLSession(ctxB);
            sesA.setCRLCb(sesCbA);
            sesB.setCRLCb(sesCbB);
            sesA.setCRLCb(null);
            sesA.setCRLCb(sesCbA);

            /* Force a GC pass to show any dangling refs in checked-JNI
             * environments before tearing down. */
            System.gc();
            try {
                Thread.sleep(10);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            }

            /* Free sesA session, then ctxA, while ctxB and sesB still hold
             * live callbacks. */
            sesA.freeSSL();
            sesA = null;
            ctxA.free();
            ctxA = null;

            /* ctxB should still be functional (no exception thrown). */
            ctxB.setCRLCb(null);
            sesB.setCRLCb(null);

            /* Touch the cb references at the end to defeat any compiler
             * level liveness shortening that would let GC collect them
             * mid-test. */
            assertNotNull(cbA);
            assertNotNull(cbA2);
            assertNotNull(cbB);
            assertNotNull(sesCbA);
            assertNotNull(sesCbB);

            /* No handshake is done in this test, so no missing-CRL callback
             * should have fired. A non-zero count would mean native callback
             * got wired to the wrong jobject or leaked across contexts. */
            assertEquals("cbA missingCRLCallback fired unexpectedly",
                0, cbA.calls);
            assertEquals("cbA2 missingCRLCallback fired unexpectedly",
                0, cbA2.calls);
            assertEquals("cbB missingCRLCallback fired unexpectedly",
                0, cbB.calls);
            assertEquals("sesCbA missingCRLCallback fired unexpectedly",
                0, sesCbA.calls);
            assertEquals("sesCbB missingCRLCallback fired unexpectedly",
                0, sesCbB.calls);

        } finally {
            if (sesA != null) {
                sesA.freeSSL();
            }
            if (sesB != null) {
                sesB.freeSSL();
            }
            if (ctxA != null) {
                ctxA.free();
            }
            if (ctxB != null) {
                ctxB.free();
            }
        }
    }

    /* Do a real handshake on each of two client contexts and assert that each
     * context's verify callback fires only for its own handshake. */
    @Test
    public void test_WolfSSLContext_setVerifyHandshakeRouting()
        throws Exception {

        Assume.assumeTrue(WolfSSL.RsaEnabled() && WolfSSL.FileSystemEnabled());
        Assume.assumeTrue(WolfSSL.TLSv12Enabled());

        WolfSSLContext srvCtx = null;
        WolfSSLContext cliCtxA = null;
        WolfSSLContext cliCtxB = null;
        ServerSocket srvSocket = null;
        ExecutorService es = null;
        Future<Void> srvFuture = null;

        try {
            srvCtx = createCtx(svrCert, svrKey, caCert,
                WolfSSL.TLSv1_2_ServerMethod());
            cliCtxA = createCtx(cliCert, cliKey, caCert,
                WolfSSL.TLSv1_2_ClientMethod());
            cliCtxB = createCtx(cliCert, cliKey, caCert,
                WolfSSL.TLSv1_2_ClientMethod());

            final CountingVerifyCb cbA = new CountingVerifyCb();
            final CountingVerifyCb cbB = new CountingVerifyCb();
            cliCtxA.setVerify(WolfSSL.SSL_VERIFY_PEER, cbA);
            cliCtxB.setVerify(WolfSSL.SSL_VERIFY_PEER, cbB);

            srvSocket = new ServerSocket(0);
            srvSocket.setSoTimeout(10000);
            final int port = srvSocket.getLocalPort();
            final ServerSocket fSrvSock = srvSocket;
            final WolfSSLContext fSrvCtx = srvCtx;

            /* Server thread accepts two sequential connections. */
            es = Executors.newSingleThreadExecutor();
            srvFuture = es.submit(new Callable<Void>() {
                @Override
                public Void call() throws Exception {
                    for (int i = 0; i < 2; i++) {
                        Socket srv = fSrvSock.accept();
                        WolfSSLSession ses = new WolfSSLSession(fSrvCtx);
                        try {
                            int r = ses.setFd(srv);
                            if (r != WolfSSL.SSL_SUCCESS) {
                                throw new Exception("srv setFd: " + r);
                            }
                            int err;
                            do {
                                r = ses.accept();
                                err = ses.getError(r);
                            } while (r != WolfSSL.SSL_SUCCESS &&
                                (err == WolfSSL.SSL_ERROR_WANT_READ ||
                                 err == WolfSSL.SSL_ERROR_WANT_WRITE));
                            if (r != WolfSSL.SSL_SUCCESS) {
                                throw new Exception("srv accept: " + r);
                            }
                            ses.shutdownSSL();
                        } finally {
                            ses.freeSSL();
                            srv.close();
                        }
                    }
                    return null;
                }
            });

            /* Client A handshake: should fire cbA only. */
            doClientHandshake(cliCtxA, port);
            assertTrue("cbA not called for ctxA handshake", cbA.calls > 0);
            assertEquals("cbB unexpectedly called for ctxA handshake",
                0, cbB.calls);

            int cbACallsAfterFirst = cbA.calls;

            /* Client B handshake: should fire cbB only. */
            doClientHandshake(cliCtxB, port);
            assertTrue("cbB not called for ctxB handshake", cbB.calls > 0);
            assertEquals("cbA called for ctxB handshake",
                cbACallsAfterFirst, cbA.calls);

            srvFuture.get(5, TimeUnit.SECONDS);
        } finally {
            /* Close the server socket first so any pending accept() unblocks.
             * Then cancel the future and force the executor to terminate. */
            if (srvSocket != null && !srvSocket.isClosed()) {
                srvSocket.close();
            }
            if (srvFuture != null) {
                srvFuture.cancel(true);
            }
            if (es != null) {
                es.shutdownNow();
                try {
                    es.awaitTermination(5, TimeUnit.SECONDS);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
            }
            if (cliCtxA != null) {
                cliCtxA.free();
            }
            if (cliCtxB != null) {
                cliCtxB.free();
            }
            if (srvCtx != null) {
                srvCtx.free();
            }
        }
    }

    /* Helper method to open a TCP socket to localhost:port and complete a TLS
     * handshake using the given client context. */
    private void doClientHandshake(WolfSSLContext cliCtx, int port)
        throws Exception {

        final int socketTimeoutMs = 5000;
        Socket sock = new Socket();
        sock.connect(new InetSocketAddress("localhost", port), socketTimeoutMs);
        sock.setSoTimeout(socketTimeoutMs);
        WolfSSLSession ses = new WolfSSLSession(cliCtx);
        try {
            int r = ses.setFd(sock);
            if (r != WolfSSL.SSL_SUCCESS) {
                throw new Exception("cli setFd: " + r);
            }
            int err;
            do {
                r = ses.connect();
                err = ses.getError(r);
            } while (r != WolfSSL.SSL_SUCCESS &&
                (err == WolfSSL.SSL_ERROR_WANT_READ ||
                 err == WolfSSL.SSL_ERROR_WANT_WRITE));
            if (r != WolfSSL.SSL_SUCCESS) {
                throw new Exception("cli connect: " + r);
            }
            ses.shutdownSSL();
        } finally {
            ses.freeSSL();
            sock.close();
        }
    }

    /* Context object shared between RSA sign/verify callbacks, tracks whether
     * callback was invoked during handshake */
    class TestRsaCbCtx
    {
        public boolean called = false;
    }

    class TestRsaSignCb implements WolfSSLRsaSignCallback
    {
        public int rsaSignCallback(WolfSSLSession ssl, ByteBuffer in, long inSz,
            ByteBuffer out, int[] outSz, ByteBuffer keyDer, long keySz,
            Object ctx) {

            TestRsaCbCtx myCtx = (TestRsaCbCtx)ctx;
            myCtx.called = true;

            WolfCryptRSA rsa = new WolfCryptRSA();
            return rsa.doSign(in, inSz, out, outSz, keyDer, keySz);
        }
    }

    class TestRsaVerifyCb implements WolfSSLRsaVerifyCallback
    {
        public int rsaVerifyCallback(WolfSSLSession ssl, ByteBuffer sig,
            long sigSz, ByteBuffer out, long outSz, ByteBuffer keyDer,
            long keySz, Object ctx) {

            TestRsaCbCtx myCtx = (TestRsaCbCtx)ctx;
            myCtx.called = true;

            WolfCryptRSA rsa = new WolfCryptRSA();
            return rsa.doVerify(sig, sigSz, out, outSz, keyDer, keySz);
        }
    }

    class TestRsaPssSignCb implements WolfSSLRsaPssSignCallback
    {
        public int rsaPssSignCallback(WolfSSLSession ssl, ByteBuffer in,
            long inSz, ByteBuffer out, int[] outSz, int hash, int mgf,
            ByteBuffer keyDer, long keySz, Object ctx) {

            TestRsaCbCtx myCtx = (TestRsaCbCtx)ctx;
            myCtx.called = true;

            WolfCryptRSA rsa = new WolfCryptRSA();
            return rsa.doPssSign(in, inSz, out, outSz, hash, mgf, keyDer,
                keySz);
        }
    }

    class TestRsaPssVerifyCb implements WolfSSLRsaPssVerifyCallback
    {
        public int rsaPssVerifyCallback(WolfSSLSession ssl, ByteBuffer sig,
            long sigSz, ByteBuffer out, long outSz, int hash, int mgf,
            ByteBuffer keyDer, long keySz, Object ctx) {

            TestRsaCbCtx myCtx = (TestRsaCbCtx)ctx;
            myCtx.called = true;

            WolfCryptRSA rsa = new WolfCryptRSA();
            return rsa.doPssVerify(sig, sigSz, out, outSz, hash, mgf, keyDer,
                keySz);
        }
    }

    /**
     * Helper to create and configure a WolfSSLContext with cert, key, and CA
     * for handshake tests.
     */
    private WolfSSLContext createCtx(String certPath, String keyPath,
        String caPath, long method) throws Exception {

        int ret;
        WolfSSLContext c = new WolfSSLContext(method);

        ret = c.useCertificateChainFile(certPath);
        if (ret != WolfSSL.SSL_SUCCESS) {
            c.free();
            throw new Exception("Failed to load cert: " + certPath);
        }

        ret = c.usePrivateKeyFile(keyPath, WolfSSL.SSL_FILETYPE_PEM);
        if (ret != WolfSSL.SSL_SUCCESS) {
            c.free();
            throw new Exception("Failed to load key: " + keyPath);
        }

        ret = c.loadVerifyLocations(caPath, null);
        if (ret != WolfSSL.SSL_SUCCESS) {
            c.free();
            throw new Exception("Failed to load CA: " + caPath);
        }

        return c;
    }

    @Test
    public void test_WolfSSLContext_rsaCbHandshake() {
        Assume.assumeTrue(WolfSSL.RsaEnabled() && WolfSSL.FileSystemEnabled());

        /* TLS 1.2 handshake with RSA PK callbacks */
        rsaCbHandshakeTls12();

        /* TLS 1.3 handshake with RSA-PSS PK callbacks */
        if (WolfSSL.TLSv13Enabled() && WolfSSL.RsaPssEnabled()) {
            rsaCbHandshakeTls13();
        }
    }

    private void rsaCbHandshakeTls12() {

        WolfSSLContext srvCtx = null;
        WolfSSLContext cliCtx = null;
        ServerSocket srvSocket = null;
        ExecutorService es = null;
        Socket cliSock = null;
        WolfSSLSession cliSes = null;

        try {
            srvCtx = createCtx(svrCert, svrKey, caCert,
                WolfSSL.TLSv1_2_ServerMethod());
            cliCtx = createCtx(cliCert, cliKey, caCert,
                WolfSSL.TLSv1_2_ClientMethod());

            /* Register server-side RSA sign + sign check */
            TestRsaSignCb signCb = new TestRsaSignCb();
            TestRsaVerifyCb signCheckCb = new TestRsaVerifyCb();
            srvCtx.setRsaSignCb(signCb);
            srvCtx.setRsaSignCheckCb(signCheckCb);

            /* Register client-side RSA verify */
            TestRsaVerifyCb verifyCb = new TestRsaVerifyCb();
            cliCtx.setRsaVerifyCb(verifyCb);

            /* Register RSA-PSS callbacks in case rsa_pss_sa_algo is used
             * as sig algo in TLS 1.2 */
            if (WolfSSL.RsaPssEnabled()) {
                TestRsaPssSignCb pssSignCb = new TestRsaPssSignCb();
                TestRsaPssVerifyCb pssSrvChk = new TestRsaPssVerifyCb();
                TestRsaPssVerifyCb pssCliChk = new TestRsaPssVerifyCb();
                srvCtx.setRsaPssSignCb(pssSignCb);
                srvCtx.setRsaPssSignCheckCb(pssSrvChk);
                cliCtx.setRsaPssSignCheckCb(pssCliChk);
            }

            /* Context objects to track invocation */
            final TestRsaCbCtx srvSignCtx = new TestRsaCbCtx();
            final TestRsaCbCtx srvVerifyCtx = new TestRsaCbCtx();
            final TestRsaCbCtx cliVerifyCtx = new TestRsaCbCtx();

            srvSocket = new ServerSocket(0);
            srvSocket.setSoTimeout(10000);
            final int port = srvSocket.getLocalPort();
            final ServerSocket fSrvSock = srvSocket;
            final WolfSSLContext fSrvCtx = srvCtx;

            final CountDownLatch ready = new CountDownLatch(1);

            es = Executors.newSingleThreadExecutor();
            Future<Void> srvFuture = es.submit(new Callable<Void>() {
                @Override
                public Void call() throws Exception {
                    int ret;
                    int err;
                    Socket srv = null;
                    WolfSSLSession srvSes = null;
                    try {
                        ready.countDown();
                        srv = fSrvSock.accept();
                        srvSes = new WolfSSLSession(fSrvCtx);
                        srvSes.setRsaSignCtx(srvSignCtx);
                        srvSes.setRsaVerifyCtx(srvVerifyCtx);
                        ret = srvSes.setFd(srv);
                        if (ret != WolfSSL.SSL_SUCCESS) {
                            throw new Exception("srv setFd fail: " + ret);
                        }
                        do {
                            ret = srvSes.accept();
                            err = srvSes.getError(ret);
                        } while (
                            ret != WolfSSL.SSL_SUCCESS &&
                            (err == WolfSSL.SSL_ERROR_WANT_READ ||
                             err == WolfSSL.SSL_ERROR_WANT_WRITE));
                        if (ret != WolfSSL.SSL_SUCCESS) {
                            throw new Exception("srv accept fail: " + ret);
                        }
                        srvSes.shutdownSSL();

                    } finally {
                        if (srvSes != null) {
                            srvSes.freeSSL();
                        }
                        if (srv != null) {
                            srv.close();
                        }
                        fSrvSock.close();
                    }
                    return null;
                }
            });

            if (!ready.await(2, TimeUnit.SECONDS)) {
                fail("Server did not become ready within timeout");
            }

            cliSock = new Socket("localhost", port);
            cliSes = new WolfSSLSession(cliCtx);
            cliSes.setRsaVerifyCtx(cliVerifyCtx);

            int ret = cliSes.setFd(cliSock);
            if (ret != WolfSSL.SSL_SUCCESS) {
                fail("cli setFd fail: " + ret);
            }

            int err;
            do {
                ret = cliSes.connect();
                err = cliSes.getError(ret);
            } while (ret != WolfSSL.SSL_SUCCESS &&
                (err == WolfSSL.SSL_ERROR_WANT_READ ||
                 err == WolfSSL.SSL_ERROR_WANT_WRITE));
            if (ret != WolfSSL.SSL_SUCCESS) {
                fail("TLS 1.2 RSA CB connect fail: " + ret);
            }

            cliSes.shutdownSSL();
            cliSes.freeSSL();
            cliSock.close();

            /* Check server thread for errors */
            es.shutdown();
            srvFuture.get(5, TimeUnit.SECONDS);

            /* Verify callbacks were invoked */
            assertTrue("RSA sign cb not called", srvSignCtx.called);
            assertTrue("RSA sign check cb not called", srvVerifyCtx.called);
            if (!WolfSSL.RsaPssEnabled()) {
                assertTrue("RSA verify (cli) cb not called",
                    cliVerifyCtx.called);
            }

        } catch (WolfSSLJNIException e) {
            /* PK callbacks may not be compiled in */
            if (e.getMessage() != null &&
                e.getMessage().contains("PK Callback")) {
                return;
            }
            fail("TLS 1.2 RSA CB handshake: " + e.getMessage());

        } catch (ExecutionException e) {
            fail("TLS 1.2 RSA CB server: " + e.getCause().getMessage());

        } catch (Exception e) {
            fail("TLS 1.2 RSA CB handshake: " + e.getMessage());

        } finally {
            if (cliSes != null) {
                try { cliSes.freeSSL(); }
                catch (Exception e) { /* ignore */ }
            }
            if (cliSock != null) {
                try { cliSock.close(); }
                catch (IOException e) { /* ignore */ }
            }
            if (srvSocket != null && !srvSocket.isClosed()) {
                try { srvSocket.close(); }
                catch (IOException e) { /* ignore */ }
            }
            if (cliCtx != null) cliCtx.free();
            if (srvCtx != null) srvCtx.free();
            if (es != null) {
                es.shutdownNow();
            }
        }
    }

    private void rsaCbHandshakeTls13() {

        WolfSSLContext srvCtx = null;
        WolfSSLContext cliCtx = null;
        ServerSocket srvSocket = null;
        ExecutorService es = null;
        Socket cliSock = null;
        WolfSSLSession cliSes = null;

        try {
            srvCtx = createCtx(svrCert, svrKey, caCert,
                WolfSSL.TLSv1_3_ServerMethod());
            cliCtx = createCtx(cliCert, cliKey, caCert,
                WolfSSL.TLSv1_3_ClientMethod());

            /* Server: RSA-PSS sign + sign check */
            TestRsaPssSignCb pssSignCb = new TestRsaPssSignCb();
            TestRsaPssVerifyCb pssSrvChkCb = new TestRsaPssVerifyCb();
            srvCtx.setRsaPssSignCb(pssSignCb);
            srvCtx.setRsaPssSignCheckCb(pssSrvChkCb);

            /* Context objects to track invocation */
            final TestRsaCbCtx srvSignCtx = new TestRsaCbCtx();
            final TestRsaCbCtx srvVerifyCtx = new TestRsaCbCtx();

            srvSocket = new ServerSocket(0);
            srvSocket.setSoTimeout(10000);
            final int port = srvSocket.getLocalPort();
            final ServerSocket fSrvSock = srvSocket;
            final WolfSSLContext fSrvCtx = srvCtx;

            final CountDownLatch ready = new CountDownLatch(1);

            es = Executors.newSingleThreadExecutor();
            Future<Void> srvFuture = es.submit(new Callable<Void>() {
                @Override
                public Void call() throws Exception {
                    int ret;
                    int err;
                    Socket srv = null;
                    WolfSSLSession srvSes = null;
                    try {
                        ready.countDown();
                        srv = fSrvSock.accept();
                        srvSes = new WolfSSLSession(fSrvCtx);
                        srvSes.setRsaSignCtx(srvSignCtx);
                        srvSes.setRsaVerifyCtx(srvVerifyCtx);
                        ret = srvSes.setFd(srv);
                        if (ret != WolfSSL.SSL_SUCCESS) {
                            throw new Exception("srv setFd fail: " + ret);
                        }
                        do {
                            ret = srvSes.accept();
                            err = srvSes.getError(ret);
                        } while (ret != WolfSSL.SSL_SUCCESS &&
                            (err == WolfSSL.SSL_ERROR_WANT_READ ||
                             err == WolfSSL.SSL_ERROR_WANT_WRITE));
                        if (ret != WolfSSL.SSL_SUCCESS) {
                            throw new Exception("srv accept fail: " + ret);
                        }
                        srvSes.shutdownSSL();

                    } finally {
                        if (srvSes != null) {
                            srvSes.freeSSL();
                        }
                        if (srv != null) {
                            srv.close();
                        }
                        fSrvSock.close();
                    }
                    return null;
                }
            });

            if (!ready.await(2, TimeUnit.SECONDS)) {
                fail("Server did not become ready within timeout");
            }

            cliSock = new Socket("localhost", port);
            cliSes = new WolfSSLSession(cliCtx);

            int ret = cliSes.setFd(cliSock);
            if (ret != WolfSSL.SSL_SUCCESS) {
                fail("cli setFd fail: " + ret);
            }

            int err;
            do {
                ret = cliSes.connect();
                err = cliSes.getError(ret);
            } while (ret != WolfSSL.SSL_SUCCESS &&
                (err == WolfSSL.SSL_ERROR_WANT_READ ||
                 err == WolfSSL.SSL_ERROR_WANT_WRITE));
            if (ret != WolfSSL.SSL_SUCCESS) {
                fail("TLS 1.3 PSS CB connect fail: " + ret);
            }

            cliSes.shutdownSSL();
            cliSes.freeSSL();
            cliSock.close();

            /* Check server thread for errors */
            es.shutdown();
            srvFuture.get(5, TimeUnit.SECONDS);

            /* Verify server-side callbacks were invoked. Client-side PSS peer
             * verify uses internal wolfSSL code (no setRsaPssVerifyCb in
             * JNI yet). */
            assertTrue("PSS sign cb not called", srvSignCtx.called);
            assertTrue("PSS sign check cb not called", srvVerifyCtx.called);

        } catch (WolfSSLJNIException e) {
            /* PK callbacks may not be compiled in */
            if (e.getMessage() != null &&
                e.getMessage().contains("PK Callback")) {
                return;
            }
            fail("TLS 1.3 PSS CB handshake: " + e.getMessage());

        } catch (ExecutionException e) {
            fail("TLS 1.3 PSS CB server: " + e.getCause().getMessage());

        } catch (Exception e) {
            fail("TLS 1.3 PSS CB handshake: " + e.getMessage());

        } finally {
            if (cliSes != null) {
                try { cliSes.freeSSL(); }
                catch (Exception e) { /* ignore */ }
            }
            if (cliSock != null) {
                try { cliSock.close(); }
                catch (IOException e) { /* ignore */ }
            }
            if (srvSocket != null && !srvSocket.isClosed()) {
                try { srvSocket.close(); }
                catch (IOException e) { /* ignore */ }
            }
            if (cliCtx != null) cliCtx.free();
            if (srvCtx != null) srvCtx.free();
            if (es != null) {
                es.shutdownNow();
            }
        }
    }

    @Test
    public void test_WolfSSLContext_free() {
        /* Free the ctx created in @Before, then null it so @After skips. */
        ctx.free();
        ctx = null;
    }
}
