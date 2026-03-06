/* WolfSSLParametersPskTest.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

package com.wolfssl.provider.jsse.test;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLSession;
import com.wolfssl.WolfSSLPskClientCallback;
import com.wolfssl.WolfSSLPskServerCallback;
import com.wolfssl.provider.jsse.WolfSSLProvider;
import com.wolfssl.provider.jsse.WolfSSLParameters;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;

import java.nio.ByteBuffer;
import java.security.Provider;
import java.security.Security;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.Timeout;

/**
 * Tests for PSK support via WolfSSLParameters.
 *
 * @author wolfSSL
 */
public class WolfSSLParametersPskTest {

    private static final String engineProvider = "wolfJSSE";
    private static String pskCipher = null;

    @Rule
    public Timeout globalTimeout =
        new Timeout(60, TimeUnit.SECONDS);

    private static WolfSSLPskClientCallback testClientCb =
        new WolfSSLPskClientCallback() {
            public long pskClientCallback(WolfSSLSession ssl, String hint,
                StringBuffer identity, long idMaxLen, byte[] key,
                long keyMaxLen) {

                String id = "Client_identity";
                if (id.length() > idMaxLen ||
                    keyMaxLen < 4) {
                    return 0;
                }
                identity.append(id);
                key[0] = 26;
                key[1] = 43;
                key[2] = 60;
                key[3] = 77;
                return 4;
            }
        };

    private static WolfSSLPskServerCallback testServerCb =
        new WolfSSLPskServerCallback() {
            public long pskServerCallback(WolfSSLSession ssl, String identity,
                byte[] key, long keyMaxLen) {

                if (!"Client_identity".equals(identity)) {
                    return 0;
                }
                if (keyMaxLen < 4) {
                    return 0;
                }
                key[0] = 26;
                key[1] = 43;
                key[2] = 60;
                key[3] = 77;
                return 4;
            }
        };

    @BeforeClass
    public static void testSetup() throws WolfSSLException {

        System.out.println("WolfSSLParametersPskTest Class");

        /* Install wolfJSSE provider */
        Security.insertProviderAt(new WolfSSLProvider(), 1);
        Provider p = Security.getProvider(engineProvider);
        assertNotNull(p);

        /* Skip all tests if PSK not compiled in */
        Assume.assumeTrue("PSK not enabled, skipping PSK tests",
            WolfSSL.isEnabledPSK() == 1);

        /* Find an available PSK cipher suite, preferring ephemeral
         * (ECDHE > DHE) over static PSK */
        try {
            String ecdhe = null;
            String dhe = null;
            String plain = null;
            String[] suites = null;

            SSLContext ctx = SSLContext.getInstance("TLSv1.2", engineProvider);
            ctx.init(null, null, null);
            suites = ctx.createSSLEngine().getSupportedCipherSuites();

            for (String s : suites) {
                if (s.startsWith("TLS_ECDHE_PSK_WITH_")) {
                    if (ecdhe == null || s.contains("GCM")) {
                        ecdhe = s;
                    }
                }
                else if (s.startsWith("TLS_DHE_PSK_WITH_")) {
                    if (dhe == null || s.contains("GCM")) {
                        dhe = s;
                    }
                }
                else if (s.startsWith("TLS_PSK_WITH_")) {
                    if (plain == null) {
                        plain = s;
                    }
                }
            }
            if (ecdhe != null) {
                pskCipher = ecdhe;
            }
            else if (dhe != null) {
                pskCipher = dhe;
            }
            else {
                pskCipher = plain;
            }

        } catch (Exception e) {
            /* ignore */
        }

        Assume.assumeTrue("No PSK cipher suite available", pskCipher != null);
    }

    @Test
    public void testExtendsSSLParameters() {
        System.out.print("\tExtends SSLParameters\t\t... ");

        WolfSSLParameters wp = new WolfSSLParameters();
        assertTrue(wp instanceof SSLParameters);

        System.out.println("passed");
    }

    @Test
    public void testGetSetPskClientCb() {
        System.out.print("\tGet/Set PSK client cb\t\t... ");

        WolfSSLParameters wp = new WolfSSLParameters();
        assertNull(wp.getPskClientCb());

        wp.setPskClientCb(testClientCb);
        assertEquals(testClientCb, wp.getPskClientCb());

        wp.setPskClientCb(null);
        assertNull(wp.getPskClientCb());

        System.out.println("passed");
    }

    @Test
    public void testGetSetPskServerCb() {
        System.out.print("\tGet/Set PSK server cb\t\t... ");

        WolfSSLParameters wp = new WolfSSLParameters();
        assertNull(wp.getPskServerCb());

        wp.setPskServerCb(testServerCb);
        assertEquals(testServerCb, wp.getPskServerCb());

        wp.setPskServerCb(null);
        assertNull(wp.getPskServerCb());

        System.out.println("passed");
    }

    @Test
    public void testGetSetPskIdentityHint() {
        System.out.print("\tGet/Set PSK identity hint\t... ");

        WolfSSLParameters wp = new WolfSSLParameters();
        assertNull(wp.getPskIdentityHint());

        wp.setPskIdentityHint("test_hint");
        assertEquals("test_hint", wp.getPskIdentityHint());

        wp.setPskIdentityHint(null);
        assertNull(wp.getPskIdentityHint());

        System.out.println("passed");
    }

    @Test
    public void testGetSetKeepArrays() {
        System.out.print("\tGet/Set keepArrays\t\t... ");

        WolfSSLParameters wp = new WolfSSLParameters();
        assertFalse(wp.getKeepArrays());

        wp.setKeepArrays(true);
        assertTrue(wp.getKeepArrays());

        wp.setKeepArrays(false);
        assertFalse(wp.getKeepArrays());

        System.out.println("passed");
    }

    @Test
    public void testUseCipherSuitesOrderDefault() {
        System.out.print("\tCipher suite order default\t... ");

        WolfSSLParameters wp = new WolfSSLParameters();
        assertTrue("useCipherSuitesOrder should default to true",
            wp.getUseCipherSuitesOrder());

        System.out.println("passed");
    }

    @Test
    public void testUseCipherSuitesOrderGetSet() {
        System.out.print("\tGet/Set useCipherSuitesOrder\t... ");

        WolfSSLParameters wp = new WolfSSLParameters();

        wp.setUseCipherSuitesOrder(false);
        assertFalse(wp.getUseCipherSuitesOrder());

        wp.setUseCipherSuitesOrder(true);
        assertTrue(wp.getUseCipherSuitesOrder());

        System.out.println("passed");
    }

    @Test
    public void testPskFieldsNotLeakedViaGetSSLParameters()
        throws Exception {

        System.out.print("\tPSK fields not in getSSLParams\t... ");

        SSLContext ctx = SSLContext.getInstance("TLSv1.2", engineProvider);
        ctx.init(null, null, null);
        SSLEngine engine = ctx.createSSLEngine();

        /* getSSLParameters() returns a standard SSLParameters, PSK fields
         * should not leak through */
        SSLParameters sp = engine.getSSLParameters();
        assertNotNull(sp);
        if (sp instanceof WolfSSLParameters) {
            WolfSSLParameters wp = (WolfSSLParameters)sp;
            assertNull(wp.getPskClientCb());
            assertNull(wp.getPskServerCb());
            assertNull(wp.getPskIdentityHint());
            assertFalse(wp.getKeepArrays());
        }

        System.out.println("passed");
    }

    @Test
    public void testPskClearedOnPlainSSLParamsImport()
        throws Exception {

        System.out.print("\tPSK cleared by plain SSLParams\t... ");

        SSLContext ctx = SSLContext.getInstance("TLSv1.2", engineProvider);
        ctx.init(null, null, null);

        SSLEngine serverEngine = ctx.createSSLEngine();
        serverEngine.setUseClientMode(false);

        /* Set WolfSSLParameters with PSK callbacks on server */
        WolfSSLParameters serverParams = new WolfSSLParameters();
        serverParams.setPskServerCb(testServerCb);
        serverParams.setPskIdentityHint("wolfssl hint");
        serverParams.setCipherSuites(new String[] {pskCipher});
        serverEngine.setSSLParameters(serverParams);

        /* Overwrite with plain SSLParameters, should clear PSK
         * callbacks but keep PSK cipher suite to force PSK path */
        SSLParameters plainParams = new SSLParameters();
        plainParams.setCipherSuites(new String[] {pskCipher});
        serverEngine.setSSLParameters(plainParams);

        SSLEngine clientEngine = ctx.createSSLEngine("localhost", 0);
        clientEngine.setUseClientMode(true);

        WolfSSLParameters clientParams = new WolfSSLParameters();
        clientParams.setPskClientCb(testClientCb);
        clientParams.setCipherSuites(new String[] {pskCipher});
        clientEngine.setSSLParameters(clientParams);

        /* Handshake should fail because server PSK callback was
         * cleared by the plain SSLParameters import */
        boolean handshakeSucceeded = false;
        try {
            doInMemoryHandshake(clientEngine, serverEngine);
            handshakeSucceeded = true;
        } catch (Exception e) {
            /* Expected: handshake fails without PSK callback */
        } catch (AssertionError e) {
            /* Expected: doInMemoryHandshake loop exhausted */
        }

        assertFalse("PSK handshake should fail after PSK callback cleared by " +
            "plain SSLParameters import", handshakeSucceeded);

        clientEngine.closeOutbound();
        serverEngine.closeOutbound();

        System.out.println("passed");
    }

    @Test
    public void testPskEngineHandshake() throws Exception {

        System.out.print("\tPSK SSLEngine handshake\t\t... ");

        SSLContext ctx = SSLContext.getInstance("TLSv1.2", engineProvider);
        ctx.init(null, null, null);

        SSLEngine serverEngine = ctx.createSSLEngine();
        serverEngine.setUseClientMode(false);

        WolfSSLParameters serverParams = new WolfSSLParameters();
        serverParams.setPskServerCb(testServerCb);
        serverParams.setPskIdentityHint("wolfssl hint");
        serverParams.setCipherSuites(
            new String[]{pskCipher});
        serverEngine.setSSLParameters(serverParams);

        SSLEngine clientEngine = ctx.createSSLEngine("localhost", 0);
        clientEngine.setUseClientMode(true);

        WolfSSLParameters clientParams = new WolfSSLParameters();
        clientParams.setPskClientCb(testClientCb);
        clientParams.setCipherSuites(
            new String[]{pskCipher});
        clientEngine.setSSLParameters(clientParams);

        /* Do in-memory handshake */
        doInMemoryHandshake(clientEngine, serverEngine);

        /* Verify handshake completed */
        assertEquals(HandshakeStatus.NOT_HANDSHAKING,
            clientEngine.getHandshakeStatus());
        assertEquals(HandshakeStatus.NOT_HANDSHAKING,
            serverEngine.getHandshakeStatus());

        clientEngine.closeOutbound();
        serverEngine.closeOutbound();

        System.out.println("passed");
    }

    @Test
    public void testPskEngineKeepArrays() throws Exception {

        System.out.print("\tPSK SSLEngine keepArrays\t... ");

        SSLContext ctx = SSLContext.getInstance("TLSv1.2", engineProvider);
        ctx.init(null, null, null);

        SSLEngine serverEngine = ctx.createSSLEngine();
        serverEngine.setUseClientMode(false);

        WolfSSLParameters serverParams = new WolfSSLParameters();
        serverParams.setPskServerCb(testServerCb);
        serverParams.setPskIdentityHint("wolfssl hint");
        serverParams.setKeepArrays(true);
        serverParams.setCipherSuites(
            new String[]{pskCipher});
        serverEngine.setSSLParameters(serverParams);

        SSLEngine clientEngine = ctx.createSSLEngine("localhost", 0);
        clientEngine.setUseClientMode(true);

        WolfSSLParameters clientParams = new WolfSSLParameters();
        clientParams.setPskClientCb(testClientCb);
        clientParams.setKeepArrays(true);
        clientParams.setCipherSuites(
            new String[]{pskCipher});
        clientEngine.setSSLParameters(clientParams);

        doInMemoryHandshake(clientEngine, serverEngine);

        assertEquals(HandshakeStatus.NOT_HANDSHAKING,
            clientEngine.getHandshakeStatus());

        clientEngine.closeOutbound();
        serverEngine.closeOutbound();

        System.out.println("passed");
    }

    @Test
    public void testPskSocketHandshake() throws Exception {

        System.out.print("\tPSK SSLSocket handshake\t\t... ");

        SSLContext ctx = SSLContext.getInstance("TLSv1.2", engineProvider);
        ctx.init(null, null, null);

        SSLServerSocket ss = (SSLServerSocket)ctx.getServerSocketFactory()
            .createServerSocket(0);
        int port = ss.getLocalPort();

        final CountDownLatch latch = new CountDownLatch(1);
        final Exception[] serverEx = new Exception[1];

        /* Server thread */
        Thread serverThread = new Thread(() -> {
            try {
                SSLSocket serverSock = (SSLSocket)ss.accept();

                WolfSSLParameters sp = new WolfSSLParameters();
                sp.setPskServerCb(testServerCb);
                sp.setPskIdentityHint("wolfssl hint");
                sp.setCipherSuites(
                    new String[]{pskCipher});
                serverSock.setSSLParameters(sp);

                serverSock.startHandshake();

                /* Read/write to confirm connection */
                InputStream in = serverSock.getInputStream();
                OutputStream out = serverSock.getOutputStream();
                byte[] buf = new byte[64];
                int n = in.read(buf);
                out.write(buf, 0, n);

                serverSock.close();

            } catch (Exception e) {
                serverEx[0] = e;
            } finally {
                latch.countDown();
            }
        });
        serverThread.start();

        try {
            SSLSocket clientSock = (SSLSocket)
                ctx.getSocketFactory().createSocket(
                    InetAddress.getLoopbackAddress(), port);

            WolfSSLParameters cp = new WolfSSLParameters();
            cp.setPskClientCb(testClientCb);
            cp.setCipherSuites(
                new String[]{pskCipher});
            clientSock.setSSLParameters(cp);

            clientSock.startHandshake();

            /* Send data and read echo */
            OutputStream out = clientSock.getOutputStream();
            InputStream in = clientSock.getInputStream();
            out.write("hello".getBytes());
            byte[] buf = new byte[64];
            int n = in.read(buf);
            assertEquals("hello", new String(buf, 0, n));

            clientSock.close();

        } finally {
            ss.close();
        }

        assertTrue("Server thread timed out",
            latch.await(10, TimeUnit.SECONDS));

        if (serverEx[0] != null) {
            fail("Server thread failed: " +
                serverEx[0].getMessage());
        }

        System.out.println("passed");
    }

    @Test
    public void testPskSocketKeepArrays() throws Exception {

        System.out.print("\tPSK SSLSocket keepArrays\t... ");

        SSLContext ctx = SSLContext.getInstance("TLSv1.2", engineProvider);
        ctx.init(null, null, null);

        SSLServerSocket ss = (SSLServerSocket)ctx.getServerSocketFactory()
            .createServerSocket(0);
        int port = ss.getLocalPort();

        final CountDownLatch latch = new CountDownLatch(1);
        final Exception[] serverEx = new Exception[1];

        Thread serverThread = new Thread(() -> {
            try {
                SSLSocket serverSock = (SSLSocket)ss.accept();

                WolfSSLParameters sp = new WolfSSLParameters();
                sp.setPskServerCb(testServerCb);
                sp.setPskIdentityHint("wolfssl hint");
                sp.setKeepArrays(true);
                sp.setCipherSuites(
                    new String[]{pskCipher});
                serverSock.setSSLParameters(sp);

                serverSock.startHandshake();

                InputStream in = serverSock.getInputStream();
                OutputStream out = serverSock.getOutputStream();
                byte[] buf = new byte[64];
                int n = in.read(buf);
                out.write(buf, 0, n);

                serverSock.close();

            } catch (Exception e) {
                serverEx[0] = e;
            } finally {
                latch.countDown();
            }
        });
        serverThread.start();

        try {
            SSLSocket clientSock = (SSLSocket)
                ctx.getSocketFactory().createSocket(
                    InetAddress.getLoopbackAddress(), port);

            WolfSSLParameters cp = new WolfSSLParameters();
            cp.setPskClientCb(testClientCb);
            cp.setKeepArrays(true);
            cp.setCipherSuites(
                new String[]{pskCipher});
            clientSock.setSSLParameters(cp);

            clientSock.startHandshake();

            OutputStream out = clientSock.getOutputStream();
            InputStream in = clientSock.getInputStream();
            out.write("hello".getBytes());
            byte[] buf = new byte[64];
            int n = in.read(buf);
            assertEquals("hello", new String(buf, 0, n));

            clientSock.close();

        } finally {
            ss.close();
        }

        assertTrue("Server thread timed out",
            latch.await(10, TimeUnit.SECONDS));

        if (serverEx[0] != null) {
            fail("Server thread failed: " + serverEx[0].getMessage());
        }

        System.out.println("passed");
    }

    /**
     * Perform SSLEngine handshake using in-memory buffers (no sockets). Data
     * produced by one engine is fed directly to the other.
     */
    private void doInMemoryHandshake(SSLEngine client, SSLEngine server)
        throws Exception {

        int netSize = Math.max(client.getSession().getPacketBufferSize(),
            server.getSession().getPacketBufferSize());
        int appSize = Math.max(
            client.getSession().getApplicationBufferSize(),
            server.getSession().getApplicationBufferSize());

        /* Network buffers: client writes to cToS, server reads from cToS.
         * Server writes to sToC, client reads from sToC. */
        ByteBuffer cToS = ByteBuffer.allocate(netSize);
        ByteBuffer sToC = ByteBuffer.allocate(netSize);
        ByteBuffer clientApp = ByteBuffer.allocate(appSize);
        ByteBuffer serverApp = ByteBuffer.allocate(appSize);
        ByteBuffer emptyApp = ByteBuffer.allocate(0);

        client.beginHandshake();
        server.beginHandshake();

        HandshakeStatus chs = client.getHandshakeStatus();
        HandshakeStatus shs = server.getHandshakeStatus();

        int maxLoops = 200;
        int loops = 0;

        while (loops < maxLoops) {
            boolean cDone =
                (chs == HandshakeStatus.NOT_HANDSHAKING ||
                 chs == HandshakeStatus.FINISHED);
            boolean sDone =
                (shs == HandshakeStatus.NOT_HANDSHAKING ||
                 shs == HandshakeStatus.FINISHED);
            if (cDone && sDone) {
                break;
            }

            /* Process client side */
            if (chs == HandshakeStatus.NEED_WRAP) {
                SSLEngineResult res = client.wrap(emptyApp, cToS);
                chs = res.getHandshakeStatus();
            }
            else if (chs == HandshakeStatus.NEED_UNWRAP) {
                sToC.flip();
                SSLEngineResult res = client.unwrap(sToC, clientApp);
                sToC.compact();
                chs = res.getHandshakeStatus();
            }
            else if (chs == HandshakeStatus.NEED_TASK) {
                Runnable task;
                while ((task =
                    client.getDelegatedTask()) != null) {
                    task.run();
                }
                chs = client.getHandshakeStatus();
            }

            /* Process server side */
            if (shs == HandshakeStatus.NEED_WRAP) {
                SSLEngineResult res = server.wrap(emptyApp, sToC);
                shs = res.getHandshakeStatus();
            }
            else if (shs == HandshakeStatus.NEED_UNWRAP) {
                cToS.flip();
                SSLEngineResult res = server.unwrap(cToS, serverApp);
                cToS.compact();
                shs = res.getHandshakeStatus();
            }
            else if (shs == HandshakeStatus.NEED_TASK) {
                Runnable task;
                while ((task =
                    server.getDelegatedTask()) != null) {
                    task.run();
                }
                shs = server.getHandshakeStatus();
            }
            loops++;
        }

        if (loops >= maxLoops) {
            fail("Handshake did not complete in " + maxLoops +
                " iterations, chs=" + chs + " shs=" + shs);
        }
    }
}
