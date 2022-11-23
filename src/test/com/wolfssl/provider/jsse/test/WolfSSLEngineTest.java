/* WolfSSLEngineTest.java
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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

package com.wolfssl.provider.jsse.test;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLException;
import com.wolfssl.provider.jsse.WolfSSLProvider;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Random;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author wolfSSL
 */
public class WolfSSLEngineTest {
    public final static char[] jksPass = "wolfSSL test".toCharArray();
    public final static String engineProvider = "wolfJSSE";
    private static boolean extraDebug = false;
    private static WolfSSLTestFactory tf;

    private SSLContext ctx = null;
    private static String allProtocols[] = {
        "TLSv1",
        "TLSv1.1",
        "TLSv1.2",
        "TLSv1.3",
        "TLS"
    };

    private static ArrayList<String> enabledProtocols =
        new ArrayList<String>();

    @BeforeClass
    public static void testProviderInstallationAtRuntime()
        throws NoSuchProviderException {

        SSLContext ctx;

        System.out.println("WolfSSLEngine Class");

        /* install wolfJSSE provider at runtime */
        Security.insertProviderAt(new WolfSSLProvider(), 1);

        Provider p = Security.getProvider("wolfJSSE");
        assertNotNull(p);

        /* populate enabledProtocols */
        for (int i = 0; i < allProtocols.length; i++) {
            try {
                ctx = SSLContext.getInstance(allProtocols[i], "wolfJSSE");
                enabledProtocols.add(allProtocols[i]);

            } catch (NoSuchAlgorithmException e) {
                /* protocol not enabled */
            }
        }

        try {
            tf = new WolfSSLTestFactory();
        } catch (WolfSSLException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }


    @Test
    public void testSSLEngine()
        throws NoSuchProviderException, NoSuchAlgorithmException {
        SSLEngine e;

        /* create new SSLEngine */
        System.out.print("\tTesting creation");

        for (int i = 0; i < enabledProtocols.size(); i++) {
            this.ctx = tf.createSSLContext(enabledProtocols.get(i),
                                           engineProvider);
            e = this.ctx.createSSLEngine();
            if (e == null) {
                error("\t\t... failed");
                fail("failed to create engine for " + enabledProtocols.get(i));
            }
        }
        pass("\t\t... passed");
    }

    @Test
    public void testSSLEngineSetCipher()
        throws NoSuchProviderException, NoSuchAlgorithmException {
        SSLEngine e;
        String sup[];
        boolean ok = false;

        System.out.print("\tTesting setting cipher");

        if (!WolfSSL.TLSv12Enabled()) {
            pass("\t\t... skipped");
            return;
        }

        this.ctx = tf.createSSLContext("TLSv1.2", engineProvider);
        e = this.ctx.createSSLEngine();
        if (e == null) {
            error("\t\t... failed");
            fail("failed to create engine");
            return;
        }

        sup = e.getSupportedProtocols();
        for (String x : sup) {
            if (x.equals("TLSv1.2")) {
                ok = true;
            }
        }
        if (!ok) {
            error("\t\t... failed");
            fail("failed to find TLSv1.2 in supported protocols");
        }

        sup = e.getEnabledProtocols();
        for (String x : sup) {
            if (x.equals("TLSv1.2")) {
                ok = true;
            }
        }
        if (!ok) {
            error("\t\t... failed");
            fail("failed to find TLSv1.2 in enabled protocols");
        }

        /* check supported cipher suites */
        sup = e.getSupportedCipherSuites();
        e.setEnabledCipherSuites(new String[] {sup[0]});
        if (e.getEnabledCipherSuites() == null ||
                !sup[0].equals(e.getEnabledCipherSuites()[0])) {
            error("\t\t... failed");
            fail("unexpected empty cipher list");
        }
        pass("\t\t... passed");
    }

    @Test
    public void testCipherConnection()
        throws NoSuchProviderException, NoSuchAlgorithmException {
        SSLEngine server;
        SSLEngine client;
        String    cipher = null;
        int ret, i;
        String[] ciphers;
        String   certType;
        Certificate[] certs;

        /* create new SSLEngine */
        System.out.print("\tTesting cipher connection");

        this.ctx = tf.createSSLContext("TLS", engineProvider);
        server = this.ctx.createSSLEngine();
        client = this.ctx.createSSLEngine("wolfSSL client test", 11111);

        ciphers = client.getSupportedCipherSuites();
        certs = server.getSession().getLocalCertificates();
        if (certs != null) {
            certType = ((X509Certificate)certs[0]).getSigAlgName();
            if (certType.contains("RSA")) {
                /* use a ECDHE-RSA suite if available */
                for (String x : ciphers) {
                    if (x.contains("ECDHE_RSA")) {
                        cipher = x;
                        break;
                    }
                }
            }
            if (certType.contains("ECDSA")) {
                /* use a ECDHE-RSA suite if available */
                for (String x : ciphers) {
                    if (x.contains("ECDHE_ECDSA")) {
                        cipher = x;
                        break;
                    }
                }
            }
        }

        server.setUseClientMode(false);
        server.setNeedClientAuth(false);
        client.setUseClientMode(true);
        ret = tf.testConnection(server, client, new String[] { cipher },
                new String[] { "TLSv1.2" }, "Test cipher suite");
        if (ret != 0) {
            error("\t... failed");
            fail("failed to create engine");
        }

        /* check if inbound is still open */
        if (server.isInboundDone() && client.isInboundDone()) {
            error("\t... failed");
            fail("inbound done too early");
        }

        /* check if outbound is still open */
        if (server.isOutboundDone() && client.isOutboundDone()) {
            error("\t... failed");
            fail("outbound done too early");
        }

        /* check get client */
        if (!client.getUseClientMode() || server.getUseClientMode()) {
            error("\t... failed");
            fail("invalid client mode");
        }
        pass("\t... passed");

        System.out.print("\tTesting close connection");
        try {
            /* test close connection */
            tf.CloseConnection(server, client, false);
        } catch (SSLException ex) {
            error("\t... failed");
            fail("failed to create engine");
        }

        /* check if inbound is still open */
        if (!server.isInboundDone() || !client.isInboundDone()) {
            error("\t... failed");
            fail("inbound is not done");
        }

        /* check if outbound is still open */
        if (!server.isOutboundDone() || !client.isOutboundDone()) {
            error("\t... failed");
            fail("outbound is not done");
        }

        /* close inbound should do nothing now */
        try {
            server.closeInbound();
        } catch (SSLException ex) {
            error("\t... failed");
            fail("close inbound failure");
        }

        pass("\t... passed");
    }

    @Test
    public void testBeginHandshake()
        throws NoSuchProviderException, NoSuchAlgorithmException {
        SSLEngine server;
        SSLEngine client;
        int ret;

        /* create new SSLEngine */
        System.out.print("\tTesting begin handshake");

        this.ctx = tf.createSSLContext("TLS", engineProvider);
        server = this.ctx.createSSLEngine();
        client = this.ctx.createSSLEngine("wolfSSL begin handshake test", 11111);

        server.setUseClientMode(false);
        server.setNeedClientAuth(false);
        client.setUseClientMode(true);

        try {
            server.beginHandshake();
            client.beginHandshake();
        } catch (SSLException e) {
            error("\t\t... failed");
            fail("failed to begin handshake");
        }

        ret = tf.testConnection(server, client, null, null, "Test in/out bound");
        if (ret != 0) {
            error("\t\t... failed");
            fail("failed to create engine");
        }
        pass("\t\t... passed");
    }

    @Test
    public void testConnectionOutIn()
        throws NoSuchProviderException, NoSuchAlgorithmException {
        SSLEngine server;
        SSLEngine client;
        int ret;

        /* create new SSLEngine */
        System.out.print("\tTesting out/in bound");

        this.ctx = tf.createSSLContext("TLS", engineProvider);
        server = this.ctx.createSSLEngine();
        client = this.ctx.createSSLEngine("wolfSSL in/out test", 11111);

        server.setUseClientMode(false);
        server.setNeedClientAuth(false);
        client.setUseClientMode(true);
        ret = tf.testConnection(server, client, null, null, "Test in/out bound");
        if (ret != 0) {
            error("\t\t... failed");
            fail("failed to create engine");
        }

        /* check if inbound is still open */
        if (server.isInboundDone() && client.isInboundDone()) {
            error("\t\t... failed");
            fail("inbound done too early");
        }

        /* check if outbound is still open */
        if (server.isOutboundDone() && client.isOutboundDone()) {
            error("\t\t... failed");
            fail("outbound done too early");
        }

        /* close inbound before peer responded to shutdown should fail */
        try {
            server.closeInbound();
            error("\t\t... failed");
            fail("was able to incorrectly close inbound");
        } catch (SSLException ex) {
            /* expected to fail here */
        }

        pass("\t\t... passed");
    }

    @Test
    public void testSetUseClientMode()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        int ret;
        SSLEngine client;
        SSLEngine server;

        System.out.print("\tTesting setUseClientMode()");

        /* expected to fail, not calling setUseClientMode() */
        this.ctx = tf.createSSLContext("TLS", engineProvider);
        server = this.ctx.createSSLEngine();
        client = this.ctx.createSSLEngine("wolfSSL test", 11111);
        server.setWantClientAuth(false);
        server.setNeedClientAuth(false);
        try {
            ret = tf.testConnection(server, client, null, null, "Testing");
            error("\t... failed");
            fail("did not fail without setUseClientMode()");
        } catch (IllegalStateException e) {
            /* expected */
        }

        /* expected to fail, only calling client.setUseClientMode() */
        server = this.ctx.createSSLEngine();
        client = this.ctx.createSSLEngine("wolfSSL test", 11111);
        server.setWantClientAuth(false);
        server.setNeedClientAuth(false);
        client.setUseClientMode(true);
        try {
            ret = tf.testConnection(server, client, null, null, "Testing");
            error("\t... failed");
            fail("did not fail without server.setUseClientMode()");
        } catch (IllegalStateException e) {
            /* expected */
        }

        /* expected to fail, only calling client.setUseClientMode() */
        server = this.ctx.createSSLEngine();
        client = this.ctx.createSSLEngine("wolfSSL test", 11111);
        server.setWantClientAuth(false);
        server.setNeedClientAuth(false);
        server.setUseClientMode(false);
        try {
            ret = tf.testConnection(server, client, null, null, "Testing");
            error("\t... failed");
            fail("did not fail without client.setUseClientMode()");
        } catch (IllegalStateException e) {
            /* expected */
        }

        /* expected to succeed, both setUseClientMode() set */
        server = this.ctx.createSSLEngine();
        client = this.ctx.createSSLEngine("wolfSSL test", 11111);
        server.setWantClientAuth(false);
        server.setNeedClientAuth(false);
        client.setUseClientMode(true);
        server.setUseClientMode(false);
        try {
            ret = tf.testConnection(server, client, null, null, "Testing");
        } catch (IllegalStateException e) {
            e.printStackTrace();
            error("\t... failed");
            fail("failed with setUseClientMode(), should succeed");
        }

        pass("\t... passed");
    }

    @Test
    public void testMutualAuth()
        throws NoSuchProviderException, NoSuchAlgorithmException {
        SSLEngine server;
        SSLEngine client;
        int ret;

        /* create new SSLEngine */
        System.out.print("\tTesting mutual auth");

        /* success case */
        this.ctx = tf.createSSLContext("TLS", engineProvider);
        server = this.ctx.createSSLEngine();
        client = this.ctx.createSSLEngine("wolfSSL auth test", 11111);

        server.setWantClientAuth(true);
        server.setNeedClientAuth(true);
        client.setUseClientMode(true);
        server.setUseClientMode(false);
        ret = tf.testConnection(server, client, null, null, "Test mutual auth");
        if (ret != 0) {
            error("\t\t... failed");
            fail("failed to create connection with engine");
        }

        /* want client auth should be overwritten by need client auth */
        if (!server.getNeedClientAuth() || server.getWantClientAuth()) {
            error("\t\t... failed");
            fail("failed with mutual auth getter check");
        }

        /* fail case */
        this.ctx = tf.createSSLContext("TLS", engineProvider,
                tf.createTrustManager("SunX509", tf.serverJKS, engineProvider),
                tf.createKeyManager("SunX509", tf.serverJKS, engineProvider));
        server = this.ctx.createSSLEngine();
        client = this.ctx.createSSLEngine("wolfSSL auth fail test", 11111);

        server.setWantClientAuth(true);
        server.setNeedClientAuth(true);
        client.setUseClientMode(true);
        server.setUseClientMode(false);
        ret = tf.testConnection(server, client, null, null, "Test in/out bound");
        if (ret == 0) {
            error("\t\t... failed");
            fail("failed to create engine");
        }

        pass("\t\t... passed");
    }

    @Test
    public void testReuseSession()
        throws NoSuchProviderException, NoSuchAlgorithmException {
        SSLEngine server;
        SSLEngine client;
        int ret;

        /* create new SSLEngine */
        System.out.print("\tTesting reuse of session");

        this.ctx = tf.createSSLContext("TLS", engineProvider);
        server = this.ctx.createSSLEngine();
        client = this.ctx.createSSLEngine("wolfSSL client test", 11111);

        server.setUseClientMode(false);
        server.setNeedClientAuth(false);
        client.setUseClientMode(true);
        ret = tf.testConnection(server, client, null, null, "Test reuse");
        if (ret != 0) {
            error("\t... failed");
            fail("failed to create engine");
        }

        try {
            /* test close connection */
            tf.CloseConnection(server, client, false);
        } catch (SSLException ex) {
            error("\t... failed");
            fail("failed to create engine");
        }

        server = this.ctx.createSSLEngine();
        client = this.ctx.createSSLEngine("wolfSSL client test", 11111);
        client.setEnableSessionCreation(false);
        server.setUseClientMode(false);
        server.setNeedClientAuth(false);
        client.setUseClientMode(true);
        ret = tf.testConnection(server, client, null, null, "Test reuse");
        if (ret != 0) {
            error("\t... failed");
            fail("failed to create engine");
        }
        try {
            /* test close connection */
            tf.CloseConnection(server, client, false);
        } catch (SSLException ex) {
            error("\t... failed");
            fail("failed to create engine");
        }

        if (client.getEnableSessionCreation() || !server.getEnableSessionCreation()) {
            error("\t... failed");
            fail("bad enabled session creation");
        }
        pass("\t... passed");
    }

    @Test
    public void testThreadedUse()
        throws NoSuchProviderException, NoSuchAlgorithmException {
        ServerEngine server;
        ClientEngine client;

        /* create new SSLEngine */
        System.out.print("\tTesting threaded use");

        this.ctx = tf.createSSLContext("TLS", engineProvider);
        server = new ServerEngine(this);
        client = new ClientEngine(this);

        client.setServer(server);
        server.setClient(client);

        server.start();
        client.start();

        try {
            server.join(1000);
            client.join(1000);
        } catch (InterruptedException ex) {
            System.out.println("interupt happened");
            Logger.getLogger(
                    WolfSSLEngineTest.class.getName()).log(
                        Level.SEVERE, null, ex);
        }

        if (!server.success || !client.success) {
            error("\t\t... failed");
            fail("failed to successfully connect");
        }
        pass("\t\t... passed");
    }

    /* status tests buffer overflow/underflow/closed test */


    private void pass(String msg) {
        WolfSSLTestFactory.pass(msg);
    }

    private void error(String msg) {
        WolfSSLTestFactory.fail(msg);
    }

    protected class ServerEngine extends Thread
    {
        private final SSLEngine server;
        private ClientEngine client;
        private HandshakeStatus status;
        protected boolean success;

        public ServerEngine(WolfSSLEngineTest in) {
            server = in.ctx.createSSLEngine();
            server.setUseClientMode(false);
            server.setNeedClientAuth(false);
            status = HandshakeStatus.NOT_HANDSHAKING;
            success = false;
        }

        @Override
        public void run() {
            ByteBuffer out =
                    ByteBuffer.allocateDirect(
                            server.getSession().getPacketBufferSize());;
            ByteBuffer in = ByteBuffer.wrap("Hello wolfSSL JSSE".getBytes());

            do {
                SSLEngineResult result;
                try {
                    Runnable run;
                    result = server.wrap(in, out);
                    while ((run = server.getDelegatedTask()) != null) {
                        run.run();
                    }
                    if (result.bytesProduced() > 0) {
                        out.flip();
                        do {
                            client.toClient(out);
                        } while (out.remaining() > 0);
                        out.compact();
                    }
                    status = result.getHandshakeStatus();
                } catch (SSLException ex) {
                    Logger.getLogger(WolfSSLEngineTest.class.getName()).log(
                                        Level.SEVERE, null, ex);
                    return;
                }
            } while (status != HandshakeStatus.NOT_HANDSHAKING);
            success = true;

        }


        protected void toServer(ByteBuffer in) throws SSLException {
            Runnable run;
            SSLEngineResult result;
            ByteBuffer out = ByteBuffer.allocateDirect(
                                server.getSession().getPacketBufferSize());;
            result = server.unwrap(in, out);
            while ((run = server.getDelegatedTask()) != null) {
                run.run();
            }
        }

        protected void setClient(ClientEngine in) {
            client = in;
        }
    }

    protected class ClientEngine extends Thread
    {
        private final SSLEngine client;
        private ServerEngine server;
        private HandshakeStatus status;
        protected boolean success;

        public ClientEngine(WolfSSLEngineTest in) {
            client = in.ctx.createSSLEngine("wolfSSL threaded client test",
                                            11111);
            client.setUseClientMode(true);
            status = HandshakeStatus.NOT_HANDSHAKING;
            success = false;
        }

        @Override
        public void run() {
            ByteBuffer out = ByteBuffer.allocateDirect(
                                client.getSession().getPacketBufferSize());;
            ByteBuffer in = ByteBuffer.wrap("Hello wolfSSL JSSE".getBytes());

            do {
                SSLEngineResult result;
                try {
                    Runnable run;
                    result = client.wrap(in, out);
                    while ((run = client.getDelegatedTask()) != null) {
                        run.run();
                    }
                    if (result.bytesProduced() > 0) {
                        out.flip();
                        do { /* send all data */
                            server.toServer(out);
                        } while (out.remaining() > 0);
                        out.compact();
                    }
                    status = result.getHandshakeStatus();
                } catch (SSLException ex) {
                    Logger.getLogger(WolfSSLEngineTest.class.getName()).log(
                                        Level.SEVERE, null, ex);
                    return;
                }
            } while (status != HandshakeStatus.NOT_HANDSHAKING);
            success = true;
        }

        protected void toClient(ByteBuffer in) throws SSLException {
            Runnable run;
            SSLEngineResult result;
            ByteBuffer out = ByteBuffer.allocateDirect(
                                client.getSession().getPacketBufferSize());
            result = client.unwrap(in, out);
            while ((run = client.getDelegatedTask()) != null) {
                run.run();
            }
        }

        protected void setServer(ServerEngine in) {
            server = in;
        }
    }

    @Test
    public void testGetApplicationBufferSize() {

        int appBufSz = 0;
        SSLEngine engine;
        SSLSession session;

        System.out.print("\tTesting getAppBufferSize");

        try {
            /* create SSLContext */
            this.ctx = tf.createSSLContext("TLS", engineProvider);

            engine = this.ctx.createSSLEngine("test", 11111);
            session = engine.getSession();
            appBufSz = session.getApplicationBufferSize();

            /* expected to be 16384 */
            if (appBufSz != 16384) {
                error("\t... failed");
                fail("got incorrect application buffer size");
            }
        } catch (Exception e) {
            e.printStackTrace();
            error("\t... failed");
            fail("unexpected Exception during getApplicationBufferSize test");
        }

        pass("\t... passed");
    }

    @Test
    public void testGetPacketBufferSize() {

        int packetBufSz = 0;
        SSLEngine engine;
        SSLSession session;

        System.out.print("\tTesting getPacketBufferSize");

        try {
            /* create SSLContext */
            this.ctx = tf.createSSLContext("TLS", engineProvider);

            engine = this.ctx.createSSLEngine("test", 11111);
            session = engine.getSession();
            packetBufSz = session.getPacketBufferSize();

            /* expected to be 18437 */
            if (packetBufSz != 18437) {
                error("\t... failed");
                fail("got incorrect packet buffer size");
            }
        } catch (Exception e) {
            e.printStackTrace();
            error("\t... failed");
            fail("unexpected Exception during getPacketBufferSize test");
        }

        pass("\t... passed");
    }

    @Test
    public void testSSLEngineBigInput() throws Exception {

        int appBufMax, netBufMax;
        int done = 0;
        ByteBuffer cIn;
        ByteBuffer cOut;
        ByteBuffer sIn;
        ByteBuffer sOut;
        ByteBuffer clientToServer;
        ByteBuffer serverToClient;

        /* big input buffer to test, 16k */
        byte[] bigInput = new byte[16384];

        SSLEngineResult cResult;
        SSLEngineResult sResult;

        System.out.print("\tTesting large data transfer");

        try {
            /* create SSLContext */
            this.ctx = tf.createSSLContext("TLS", engineProvider);

            /* create server SSLEngine */
            SSLEngine server = this.ctx.createSSLEngine();
            server.setUseClientMode(false);
            server.setNeedClientAuth(true);

            /* create client SSLEngine */
            SSLEngine client = this.ctx.createSSLEngine(
                                   "wolfSSL client test", 11111);
            client.setUseClientMode(true);

            SSLSession session = client.getSession();
            appBufMax = session.getApplicationBufferSize();
            netBufMax = session.getPacketBufferSize();

            cIn = ByteBuffer.allocate(appBufMax);
            sIn = ByteBuffer.allocate(netBufMax);
            clientToServer = ByteBuffer.allocate(netBufMax);
            serverToClient = ByteBuffer.allocate(netBufMax);

            /* generate random bytes for input buffer */
            Random rand = new Random();
            rand.nextBytes(bigInput);

            cOut = ByteBuffer.wrap(bigInput);
            sOut = ByteBuffer.wrap("Hello client, from server".getBytes());

            while (!(client.isOutboundDone() && client.isInboundDone()) &&
                   !(server.isOutboundDone() && server.isInboundDone())) {

                cResult = client.wrap(cOut, clientToServer);
                sResult = server.wrap(sOut, serverToClient);

                clientToServer.flip();
                serverToClient.flip();

                cResult = client.unwrap(serverToClient, cIn);
                sResult = server.unwrap(clientToServer, sIn);

                clientToServer.compact();
                serverToClient.compact();

                if (done == 0 &&
                    (cOut.limit() == sIn.position()) &&
                    (sOut.limit() == cIn.position())) {

                    /* check server out matches client in */
                    sOut.flip();
                    cIn.flip();

                    if (!sOut.equals(cIn)) {
                        error("\t... failed");
                        fail("server output does not match client input");
                    }
                    sOut.position(sOut.limit());
                    cIn.position(cIn.limit());
                    sOut.limit(sOut.capacity());
                    cIn.limit(cIn.capacity());

                    /* check client out matches server in */
                    cOut.flip();
                    sIn.flip();

                    if (!cOut.equals(sIn)) {
                        error("\t... failed");
                        fail("client output does not match server input");
                    }
                    cOut.position(cOut.limit());
                    sIn.position(sIn.limit());
                    cOut.limit(cOut.capacity());
                    sIn.limit(sIn.capacity());

                    /* close client outbound, mark done */
                    client.closeOutbound();
                    done = 1;
                }
            }
        } catch (Exception e) {
            error("\t... failed");
            e.printStackTrace();
            fail("failed large input test with Exception");
        }
        pass("\t... passed");
    }

    @Test
    public void testSSLEngineSplitInput() throws Exception {

        int appBufMax, netBufMax;
        int done = 0;
        ByteBuffer cIn;
        ByteBuffer cOut1;
        ByteBuffer cOut2;
        ByteBuffer[] cOutBuffs = new ByteBuffer[2];
        ByteBuffer[] sOutBuffs = new ByteBuffer[2];
        ByteBuffer sIn;
        ByteBuffer sOut1;
        ByteBuffer sOut2;
        ByteBuffer clientToServer;
        ByteBuffer serverToClient;

        byte[] input1Buf = "Hello client, ".getBytes();
        byte[] input2Buf = "from server".getBytes();

        SSLEngineResult cResult;
        SSLEngineResult sResult;

        System.out.print("\tTesting split input data");

        try {
            /* create SSLContext */
            this.ctx = tf.createSSLContext("TLS", engineProvider);

            /* create server SSLEngine */
            SSLEngine server = this.ctx.createSSLEngine();
            server.setUseClientMode(false);
            server.setNeedClientAuth(true);

            /* create client SSLEngine */
            SSLEngine client = this.ctx.createSSLEngine(
                                   "wolfSSL client test", 11111);
            client.setUseClientMode(true);

            SSLSession session = client.getSession();
            appBufMax = session.getApplicationBufferSize();
            netBufMax = session.getPacketBufferSize();

            cIn = ByteBuffer.allocate(appBufMax);
            sIn = ByteBuffer.allocate(netBufMax);
            clientToServer = ByteBuffer.allocate(netBufMax);
            serverToClient = ByteBuffer.allocate(netBufMax);

            /* Input data split across 2 ByteBuffers on both cli and svr */
            cOut1 = ByteBuffer.wrap("Hello server, ".getBytes());
            cOut2 = ByteBuffer.wrap("from client".getBytes());
            cOutBuffs[0] = cOut1;
            cOutBuffs[1] = cOut2;

            sOut1 = ByteBuffer.wrap("Hello client, ".getBytes());
            sOut2 = ByteBuffer.wrap("from server".getBytes());
            sOutBuffs[0] = sOut1;
            sOutBuffs[1] = sOut2;

            while (!(client.isOutboundDone() && client.isInboundDone()) &&
                   !(server.isOutboundDone() && server.isInboundDone())) {

                cResult = client.wrap(cOutBuffs, clientToServer);
                sResult = server.wrap(sOutBuffs, serverToClient);

                clientToServer.flip();
                serverToClient.flip();

                cResult = client.unwrap(serverToClient, cIn);
                sResult = server.unwrap(clientToServer, sIn);

                clientToServer.compact();
                serverToClient.compact();

                if (done == 0 &&
                    ((cOut1.limit() + cOut2.limit()) == sIn.position()) &&
                    ((sOut1.limit() + sOut2.limit()) == cIn.position())) {

                    /* check server out matches client in */
                    ByteBuffer cExpectedIn = ByteBuffer.wrap(
                            "Hello client, from server".getBytes());
                    cIn.flip();

                    if (!cIn.equals(cExpectedIn)) {
                        error("\t... failed");
                        fail("server output does not match expected");
                    }

                    /* check client out matches server in */
                    ByteBuffer sExpectedIn = ByteBuffer.wrap(
                            "Hello server, from client".getBytes());
                    sIn.flip();

                    if (!sIn.equals(sExpectedIn)) {
                        error("\t... failed");
                        fail("client output does not match expected");
                    }

                    /* close client outbound, mark done */
                    client.closeOutbound();
                    done = 1;
                }
            }
        } catch (Exception e) {
            error("\t... failed");
            e.printStackTrace();
            fail("failed split input test with Exception");
        }
        pass("\t... passed");
    }
}

