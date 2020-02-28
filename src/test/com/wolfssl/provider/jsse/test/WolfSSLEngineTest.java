/* WolfSSLEngineTest.java
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
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLContext;
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
        "TLSV1",
        "TLSV1.1",
        "TLSV1.2",
        "TLS"
    };

    private static ArrayList<String> enabledProtocols =
        new ArrayList<String>();

    @BeforeClass
    public static void testProviderInstallationAtRuntime()
        throws NoSuchProviderException {

        System.out.println("WolfSSLEngine Class");

        /* install wolfJSSE provider at runtime */
        Security.insertProviderAt(new WolfSSLProvider(), 1);

        Provider p = Security.getProvider("wolfJSSE");
        assertNotNull(p);

        try {
            tf = new WolfSSLTestFactory();
        } catch (WolfSSLException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }


    private int CloseConnection(SSLEngine server, SSLEngine client, boolean earlyClose) throws SSLException {
        ByteBuffer serToCli = ByteBuffer.allocateDirect(server.getSession().getPacketBufferSize());
        ByteBuffer cliToSer = ByteBuffer.allocateDirect(client.getSession().getPacketBufferSize());
        ByteBuffer empty = ByteBuffer.allocate(server.getSession().getPacketBufferSize());
        SSLEngineResult result;
        HandshakeStatus s;
        boolean passed;
        Runnable run;

        client.closeOutbound();

        result = client.wrap(empty, cliToSer);
        if (extraDebug) {
            System.out.println("[client wrap] consumed = " + result.bytesConsumed() +
                        " produced = " + result.bytesProduced() +
                        " status = " + result.getStatus().name());
        }
        while ((run = client.getDelegatedTask()) != null) {
            run.run();
        }
        s = client.getHandshakeStatus();
        if (extraDebug) {
            System.out.println("client status = " + s.toString());
        }
        if (result.bytesProduced() <= 0 || result.bytesConsumed() != 0) {
            throw new SSLException("Client wrap consumed/produced error");
        }
        if (!s.toString().equals("NEED_UNWRAP") ||
                !result.getStatus().name().equals("CLOSED") ) {
            throw new SSLException("Bad status");
        }
        cliToSer.flip();

        /* check that early close inbounds fail */
        if (earlyClose) {
            try {
                passed = false;
                server.closeInbound();
            }
            catch (SSLException e) {
                passed = true;
            }
            if (!passed) {
                throw new SSLException("Expected to fail on early close inbound");
            }

            try {
                passed = false;
                client.closeInbound();
            }
            catch (SSLException e) {
                passed = true;
            }
            if (!passed) {
                throw new SSLException("Expected to fail on early close inbound");
            }
            return 0;
        }

        result = server.unwrap(cliToSer, empty);
        if (extraDebug) {
            System.out.println("[server unwrap] consumed = " + result.bytesConsumed() +
                        " produced = " + result.bytesProduced() +
                        " status = " + result.getStatus().name());
        }
        if (result.getStatus().name().equals("CLOSED")) {
            /* odd case where server tries to send "empty" if not set close */
            server.closeOutbound();
        }
        while ((run = server.getDelegatedTask()) != null) {
            run.run();
        }
        s = server.getHandshakeStatus();
        if (result.bytesProduced() != 0 || result.bytesConsumed() <= 0) {
            throw new SSLException("Server unwrap consumed/produced error");
        }
        if (!s.toString().equals("NEED_WRAP") ||
                !result.getStatus().name().equals("CLOSED") ) {
            throw new SSLException("Bad status");
        }

        result = server.wrap(empty, serToCli);
        if (extraDebug) {
            System.out.println("[server wrap] consumed = " + result.bytesConsumed() +
                        " produced = " + result.bytesProduced() +
                        " status = " + result.getStatus().name());
        }
        while ((run = server.getDelegatedTask()) != null) {
            run.run();
        }
        s = server.getHandshakeStatus();
        if (result.bytesProduced() <= 0 || result.bytesConsumed() != 0) {
            throw new SSLException("Server wrap consumed/produced error");
        }
        if (extraDebug) {
            System.out.println("server status = " + s.toString());
        }
        if (!s.toString().equals("NOT_HANDSHAKING") ||
                !result.getStatus().name().equals("CLOSED")) {
            throw new SSLException("Bad status");
        }

        serToCli.flip();
        result = client.unwrap(serToCli, empty);
        if (extraDebug) {
            System.out.println("[client unwrap] consumed = " + result.bytesConsumed() +
                        " produced = " + result.bytesProduced() +
                        " status = " + result.getStatus().name());
        }
        while ((run = client.getDelegatedTask()) != null) {
            run.run();
        }
        s = client.getHandshakeStatus();
        if (result.bytesProduced() != 0 || result.bytesConsumed() <= 0) {
            throw new SSLException("Client unwrap consumed/produced error");
        }
        if (!s.toString().equals("NOT_HANDSHAKING") ||
                !result.getStatus().name().equals("CLOSED")) {
            throw new SSLException("Bad status");
        }
        if (extraDebug) {
            System.out.println("client status = " + s.toString());
        }

        server.closeInbound();
        client.closeInbound();
        return 0;
    }


    @Test
    public void testSSLEngine()
        throws NoSuchProviderException, NoSuchAlgorithmException {
        SSLEngine e;

        /* create new SSLEngine */
        System.out.print("\tTesting creation");

        this.ctx = tf.createSSLContext("TLSv1.2", engineProvider);
        e = this.ctx.createSSLEngine();
        if (e == null) {
            error("\t\t... failed");
            fail("failed to create engine");
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

//        /* use wolfJSSE client */
//        SSLContext c = SSLContext.getInstance("TLS", "wolfJSSE");
//        try {
//            c.init(createKeyManager("SunX509", clientJKS),
//                    createTrustManager("SunX509", clientJKS), null);
//        } catch (KeyManagementException ex) {
//            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
//        }
//        client = c.createSSLEngine("wolfSSL client test", 11111);
//        server = c.createSSLEngine();


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
            CloseConnection(server, client, false);
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

        /* use wolfJSSE client */
//        SSLContext c = SSLContext.getInstance("TLSv1.2", "wolfJSSE");
//        try {
//            c.init(createKeyManager("SunX509", clientJKS),
//                    createTrustManager("SunX509", clientJKS), null);
//        } catch (KeyManagementException ex) {
//            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
//        }
//        client = c.createSSLEngine("wolfSSL client test", 11111);
//        server = c.createSSLEngine();
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
            CloseConnection(server, client, false);
        } catch (SSLException ex) {
            error("\t... failed");
            fail("failed to create engine");
        }

        /* use wolfJSSE client */
//        c = SSLContext.getInstance("TLSv1.2", "wolfJSSE");
//        try {
//            c.init(createKeyManager("SunX509", clientJKS),
//                    createTrustManager("SunX509", clientJKS), null);
//        } catch (KeyManagementException ex) {
//            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
//        }
//        client = c.createSSLEngine("wolfSSL client test", 11111);
//        server = c.createSSLEngine();


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
            CloseConnection(server, client, false);
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

        /* use wolfJSSE client */
//        SSLContext c = SSLContext.getInstance("TLSv1.2", "wolfJSSE");
//        try {
//            c.init(createKeyManager("SunX509", clientJKS),
//                    createTrustManager("SunX509", clientJKS), null);
//        } catch (KeyManagementException ex) {
//            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
//        }
//        client = c.createSSLEngine("wolfSSL client test", 11111);
//        server = c.createSSLEngine();

        client.setServer(server);
        server.setClient(client);

        server.start();
        client.start();

        try {
            server.join(1000);
            client.join(1000);
        } catch (InterruptedException ex) {
            System.out.println("interupt happened");
            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
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
                    ByteBuffer.allocateDirect(server.getSession().getPacketBufferSize());;
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
                    Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
                    return;
                }
            } while (status != HandshakeStatus.NOT_HANDSHAKING);
            success = true;

        }


        protected void toServer(ByteBuffer in) throws SSLException {
            Runnable run;
            SSLEngineResult result;
            ByteBuffer out =
                    ByteBuffer.allocateDirect(server.getSession().getPacketBufferSize());;
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
            client = in.ctx.createSSLEngine("wolfSSL threaded client test", 11111);
            client.setUseClientMode(true);
            status = HandshakeStatus.NOT_HANDSHAKING;
            success = false;
        }

        @Override
        public void run() {
            ByteBuffer out =
                    ByteBuffer.allocateDirect(client.getSession().getPacketBufferSize());;
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
                    Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
                    return;
                }
            } while (status != HandshakeStatus.NOT_HANDSHAKING);
            success = true;
        }

        protected void toClient(ByteBuffer in) throws SSLException {
            Runnable run;
            SSLEngineResult result;
            ByteBuffer out =
                    ByteBuffer.allocateDirect(client.getSession().getPacketBufferSize());
            result = client.unwrap(in, out);
            while ((run = client.getDelegatedTask()) != null) {
                run.run();
            }
        }

        protected void setServer(ServerEngine in) {
            server = in;
        }
    }
}
