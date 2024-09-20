/* WolfSSLEngineTest.java
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

package com.wolfssl.provider.jsse.test;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLException;
import com.wolfssl.provider.jsse.WolfSSLProvider;
import java.io.FileInputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.channels.SocketChannel;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.security.KeyStore;
import java.util.Random;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.net.Socket;
import java.net.InetSocketAddress;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicIntegerArray;
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
        System.out.print("\tSSLEngine creation");

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

        System.out.print("\tSetting ciphersuite");

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
        System.out.print("\tBasic ciphersuiet connection");

        this.ctx = tf.createSSLContext("TLS", engineProvider);
        server = this.ctx.createSSLEngine();
        client = this.ctx.createSSLEngine("wolfSSL client test", 11111);

        ciphers = client.getSupportedCipherSuites();
        certs = server.getSession().getLocalCertificates();
        if (certs == null) {
            error("\t... failed");
            fail("no certs available from server SSLEngine.getSession()");
        }
        else {
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

        System.out.print("\tclose connection");
        try {
            /* test close connection */
            tf.CloseConnection(server, client, false);
        } catch (SSLException ex) {
            error("\t\t... failed");
            fail("failed to create engine");
        }

        /* check if inbound is still open */
        if (!server.isInboundDone() || !client.isInboundDone()) {
            error("\t\t... failed");
            fail("inbound is not done");
        }

        /* check if outbound is still open */
        if (!server.isOutboundDone() || !client.isOutboundDone()) {
            error("\t\t... failed");
            fail("outbound is not done");
        }

        /* close inbound should do nothing now */
        try {
            server.closeInbound();
        } catch (SSLException ex) {
            error("\t\t... failed");
            fail("close inbound failure");
        }

        pass("\t\t... passed");
    }

    @Test
    public void testBeginHandshake()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               SSLException {
        SSLEngine server;
        SSLEngine client;
        int ret;

        /* create new SSLEngine */
        System.out.print("\tbeginHandshake()");

        this.ctx = tf.createSSLContext("TLS", engineProvider);
        server = this.ctx.createSSLEngine();
        client = this.ctx.createSSLEngine("wolfSSL begin handshake test", 11111);

        /* Calling beginHandshake() before setUseClientMode() should throw
         * IllegalStateException */
        try {
            server.beginHandshake();
            error("\t\t... failed");
            fail("beginHandshake() before setUseClientMode() should throw " +
                 "IllegalStateException");
        } catch (IllegalStateException e) {
            /* expected */
        }
        try {
            client.beginHandshake();
            error("\t\t... failed");
            fail("beginHandshake() before setUseClientMode() should throw " +
                 "IllegalStateException");
        } catch (IllegalStateException e) {
            /* expected */
        }

        /* Set client/server mode, disable auth to simplify tests below */
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

        /* Calling beginHandshake() again should throw SSLException
         * since renegotiation is not yet supported in wolfJSSE */
        try {
            server.beginHandshake();
            error("\t\t... failed");
            fail("beginHandshake() called again should throw SSLException");
        } catch (SSLException e) {
            /* expected */
        }
        try {
            client.beginHandshake();
            error("\t\t... failed");
            fail("beginHandshake() called again should throw SSLException");
        } catch (SSLException e) {
            /* expected */
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
        System.out.print("\tisIn/OutboundDone()");

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

        System.out.print("\tsetUseClientMode()");

        /* expected to fail, not calling setUseClientMode() */
        this.ctx = tf.createSSLContext("TLS", engineProvider);
        server = this.ctx.createSSLEngine();
        client = this.ctx.createSSLEngine("wolfSSL test", 11111);
        server.setWantClientAuth(false);
        server.setNeedClientAuth(false);
        try {
            ret = tf.testConnection(server, client, null, null, "Testing");
            error("\t\t... failed");
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
            error("\t\t... failed");
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
            error("\t\t... failed");
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
            error("\t\t... failed");
            fail("failed with setUseClientMode(), should succeed");
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
        System.out.print("\tMutual authentication");

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

    /**
     * Helper class used with below setWant/NeedClientAuth() test methods.
     *
     * Note that setWantClientAuth() and setNeedClientAuth() are only
     * applicable when called on the server side. But including testing
     * then when called on the client side here as well, for sanity.
     */
    private static class PeerAuthConfig {
        boolean clientWantClientAuth;
        boolean clientNeedClientAuth;
        boolean serverWantClientAuth;
        boolean serverNeedClientAuth;
        boolean expectSuccess;

        public PeerAuthConfig(boolean cwca, boolean cnca, boolean swca,
            boolean snca, boolean ex) {
            this.clientWantClientAuth = cwca;
            this.clientNeedClientAuth = cnca;
            this.serverWantClientAuth = swca;
            this.serverNeedClientAuth = snca;
            this.expectSuccess = ex;
        }
    }

    @Test
    public void testSetWantNeedClientAuth_ClientServerDefaultKeyManager()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        int ret = 0;
        SSLContext cCtx = null;
        SSLContext sCtx = null;
        SSLEngine client = null;
        SSLEngine server = null;

        /* All combinations using DEFAULT X509TrustManager/X509KeyManager
         * from WolfSSLTestFactory. All expected to pass since each since has
         * certs/keys loaded no matter if verify is being done */
        PeerAuthConfig[] configsDefaultManagers = new PeerAuthConfig[] {
            new PeerAuthConfig(true, true, true, true, true),
            new PeerAuthConfig(true, true, true, false, true),
            new PeerAuthConfig(true, true, false, true, true),
            new PeerAuthConfig(true, true, false, false, true),
            new PeerAuthConfig(true, false, true, true, true),
            new PeerAuthConfig(true, false, true, false, true),
            new PeerAuthConfig(true, false, false, true, true),
            new PeerAuthConfig(true, false, false, false, true),
            new PeerAuthConfig(false, true, true, true, true),
            new PeerAuthConfig(false, true, true, false, true),
            new PeerAuthConfig(false, true, false, true, true),
            new PeerAuthConfig(false, true, false, false, true),
            new PeerAuthConfig(false, false, true, true, true),
            new PeerAuthConfig(false, false, true, false, true),
            new PeerAuthConfig(false, false, false, true, true),
            new PeerAuthConfig(false, false, false, false, true)
        };

        System.out.print("\tsetWantClientAuth(default KM)");

        for (PeerAuthConfig c : configsDefaultManagers) {

            sCtx = tf.createSSLContext("TLS", engineProvider);
            server = sCtx.createSSLEngine();
            server.setUseClientMode(false);
            server.setWantClientAuth(c.serverWantClientAuth);
            server.setNeedClientAuth(c.serverNeedClientAuth);

            cCtx = tf.createSSLContext("TLS", engineProvider);
            client = cCtx.createSSLEngine("wolfSSL test case", 11111);
            client.setUseClientMode(true);
            client.setWantClientAuth(c.clientWantClientAuth);
            client.setNeedClientAuth(c.clientNeedClientAuth);

            ret = tf.testConnection(server, client, null, null, "Test");
            if ((c.expectSuccess && ret != 0) ||
                (!c.expectSuccess && ret == 0)) {
                error("\t... failed");
                fail("SSLEngine want/needClientAuth failed: \n" +
                     "\n  cWantClientAuth = " + c.clientWantClientAuth +
                     "\n  cNeedClientAuth = " + c.clientNeedClientAuth +
                     "\n  sWantClientAuth = " + c.serverWantClientAuth +
                     "\n  sNeedClientAuth = " + c.serverNeedClientAuth +
                     "\n  expectSuccess = " + c.expectSuccess +
                     "\n  got ret = " + ret);
            }
        }

        pass("\t... passed");
    }

    @Test
    public void testSetWantNeedClientAuth_ClientNoKeyManager()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        int ret = 0;
        SSLContext cCtx = null;
        SSLContext sCtx = null;
        SSLEngine client = null;
        SSLEngine server = null;

        /* All combinations using 'null' as client KeyManager, so client
         * will not have cert or private key loaded, but server will */
        PeerAuthConfig[] configs = new PeerAuthConfig[] {
            new PeerAuthConfig(true, true, true, true, false),
            new PeerAuthConfig(true, true, true, false, true),
            new PeerAuthConfig(true, true, false, true, false),
            new PeerAuthConfig(true, true, false, false, true),
            new PeerAuthConfig(true, false, true, true, false),
            new PeerAuthConfig(true, false, true, false, true),
            new PeerAuthConfig(true, false, false, true, false),
            new PeerAuthConfig(true, false, false, false, true),
            new PeerAuthConfig(false, true, true, true, false),
            new PeerAuthConfig(false, true, true, false, true),
            new PeerAuthConfig(false, true, false, true, false),
            new PeerAuthConfig(false, true, false, false, true),
            new PeerAuthConfig(false, false, true, true, false),
            new PeerAuthConfig(false, false, true, false, true),
            new PeerAuthConfig(false, false, false, true, false),
            new PeerAuthConfig(false, false, false, false, true)
        };

        System.out.print("\tsetWantClientAuth(no client KM)");

        for (PeerAuthConfig c : configs) {

            sCtx = tf.createSSLContext("TLS", engineProvider);
            server = sCtx.createSSLEngine();
            server.setUseClientMode(false);
            server.setWantClientAuth(c.serverWantClientAuth);
            server.setNeedClientAuth(c.serverNeedClientAuth);

            cCtx = tf.createSSLContextNoDefaults("TLS", engineProvider,
                tf.createTrustManager("SunX509", tf.clientJKS, engineProvider),
                null);
            client = cCtx.createSSLEngine("wolfSSL test case", 11111);
            client.setUseClientMode(true);
            client.setWantClientAuth(c.clientWantClientAuth);
            client.setNeedClientAuth(c.clientNeedClientAuth);

            ret = tf.testConnection(server, client, null, null, "Test");
            if ((c.expectSuccess && ret != 0) ||
                (!c.expectSuccess && ret == 0)) {
                error("\t... failed");
                fail("SSLEngine want/needClientAuth failed: \n" +
                     "\n  cWantClientAuth = " + c.clientWantClientAuth +
                     "\n  cNeedClientAuth = " + c.clientNeedClientAuth +
                     "\n  sWantClientAuth = " + c.serverWantClientAuth +
                     "\n  sNeedClientAuth = " + c.serverNeedClientAuth +
                     "\n  expectSuccess = " + c.expectSuccess +
                     "\n  got ret = " + ret);
            }
        }

        pass("\t... passed");
    }

    @Test
    public void testSetWantNeedClientAuth_ServerNoKeyManager()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        int ret = 0;
        SSLContext cCtx = null;
        SSLContext sCtx = null;
        SSLEngine client = null;
        SSLEngine server = null;

        /* All combinations using 'null' as server KeyManager, so server
         * will not have cert or private key loaded, but client will.
         * All these should fail, since the server requires a private key
         * be loaded. */
        PeerAuthConfig[] configs = new PeerAuthConfig[] {
            new PeerAuthConfig(true, true, true, true, false),
            new PeerAuthConfig(true, true, true, false, false),
            new PeerAuthConfig(true, true, false, true, false),
            new PeerAuthConfig(true, true, false, false, false),
            new PeerAuthConfig(true, false, true, true, false),
            new PeerAuthConfig(true, false, true, false, false),
            new PeerAuthConfig(true, false, false, true, false),
            new PeerAuthConfig(true, false, false, false, false),
            new PeerAuthConfig(false, true, true, true, false),
            new PeerAuthConfig(false, true, true, false, false),
            new PeerAuthConfig(false, true, false, true, false),
            new PeerAuthConfig(false, true, false, false, false),
            new PeerAuthConfig(false, false, true, true, false),
            new PeerAuthConfig(false, false, true, false, false),
            new PeerAuthConfig(false, false, false, true, false),
            new PeerAuthConfig(false, false, false, false, false)
        };

        System.out.print("\tsetWantClientAuth(no server KM)");

        for (PeerAuthConfig c : configs) {

            sCtx = tf.createSSLContextNoDefaults("TLS", engineProvider,
                tf.createTrustManager("SunX509", tf.clientJKS, engineProvider),
                null);
            server = sCtx.createSSLEngine();
            server.setUseClientMode(false);
            server.setWantClientAuth(c.serverWantClientAuth);
            server.setNeedClientAuth(c.serverNeedClientAuth);

            cCtx = tf.createSSLContext("TLS", engineProvider);
            client = cCtx.createSSLEngine("wolfSSL test case", 11111);
            client.setUseClientMode(true);
            client.setWantClientAuth(c.clientWantClientAuth);
            client.setNeedClientAuth(c.clientNeedClientAuth);

            ret = tf.testConnection(server, client, null, null, "Test");
            if ((c.expectSuccess && ret != 0) ||
                (!c.expectSuccess && ret == 0)) {
                error("\t... failed");
                fail("SSLEngine want/needClientAuth failed: \n" +
                     "\n  cWantClientAuth = " + c.clientWantClientAuth +
                     "\n  cNeedClientAuth = " + c.clientNeedClientAuth +
                     "\n  sWantClientAuth = " + c.serverWantClientAuth +
                     "\n  sNeedClientAuth = " + c.serverNeedClientAuth +
                     "\n  expectSuccess = " + c.expectSuccess +
                     "\n  got ret = " + ret);
            }
        }

        pass("\t... passed");
    }

    @Test
    public void testSetWantNeedClientAuth_ClientServerExternalTrustAllCerts()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        int ret = 0;
        SSLContext cCtx = null;
        SSLContext sCtx = null;
        SSLEngine client = null;
        SSLEngine server = null;

        /* TrustManager that trusts all certificates */
        TrustManager[] trustAllCerts = {
            new X509ExtendedTrustManager() {
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
                public void checkClientTrusted(X509Certificate[] chain,
                    String authType) {
                }
                public void checkClientTrusted(X509Certificate[] chain,
                    String authType, Socket socket) {
                }
                public void checkClientTrusted(X509Certificate[] chain,
                    String authType, SSLEngine engine) {
                }
                public void checkServerTrusted(X509Certificate[] chain,
                    String authType) {
                }
                public void checkServerTrusted(X509Certificate[] chain,
                    String authType, Socket socket) {
                }
                public void checkServerTrusted(X509Certificate[] chain,
                    String authType, SSLEngine engine) {
                }
            }
        };

        /* All combinations using DEFAULT X509TrustManager/X509KeyManager
         * from WolfSSLTestFactory. All expected to pass since each since has
         * certs/keys loaded no matter if verify is being done */
        PeerAuthConfig[] configsDefaultManagers = new PeerAuthConfig[] {
            new PeerAuthConfig(true, true, true, true, true),
            new PeerAuthConfig(true, true, true, false, true),
            new PeerAuthConfig(true, true, false, true, true),
            new PeerAuthConfig(true, true, false, false, true),
            new PeerAuthConfig(true, false, true, true, true),
            new PeerAuthConfig(true, false, true, false, true),
            new PeerAuthConfig(true, false, false, true, true),
            new PeerAuthConfig(true, false, false, false, true),
            new PeerAuthConfig(false, true, true, true, true),
            new PeerAuthConfig(false, true, true, false, true),
            new PeerAuthConfig(false, true, false, true, true),
            new PeerAuthConfig(false, true, false, false, true),
            new PeerAuthConfig(false, false, true, true, true),
            new PeerAuthConfig(false, false, true, false, true),
            new PeerAuthConfig(false, false, false, true, true),
            new PeerAuthConfig(false, false, false, false, true)
        };

        System.out.print("\tsetWantClientAuth(ext KM all)");

        for (PeerAuthConfig c : configsDefaultManagers) {

            sCtx = tf.createSSLContextNoDefaults("TLS", engineProvider,
                trustAllCerts,
                tf.createKeyManager("SunX509", tf.clientJKS, engineProvider));
            server = sCtx.createSSLEngine();
            server.setUseClientMode(false);
            server.setWantClientAuth(c.serverWantClientAuth);
            server.setNeedClientAuth(c.serverNeedClientAuth);

            cCtx = tf.createSSLContextNoDefaults("TLS", engineProvider,
                trustAllCerts,
                tf.createKeyManager("SunX509", tf.clientJKS, engineProvider));
            client = cCtx.createSSLEngine("wolfSSL test case", 11111);
            client.setUseClientMode(true);
            client.setWantClientAuth(c.clientWantClientAuth);
            client.setNeedClientAuth(c.clientNeedClientAuth);

            ret = tf.testConnection(server, client, null, null, "Test");
            if ((c.expectSuccess && ret != 0) ||
                (!c.expectSuccess && ret == 0)) {
                error("\t... failed");
                fail("SSLEngine want/needClientAuth failed: \n" +
                     "\n  cWantClientAuth = " + c.clientWantClientAuth +
                     "\n  cNeedClientAuth = " + c.clientNeedClientAuth +
                     "\n  sWantClientAuth = " + c.serverWantClientAuth +
                     "\n  sNeedClientAuth = " + c.serverNeedClientAuth +
                     "\n  expectSuccess = " + c.expectSuccess +
                     "\n  got ret = " + ret);
            }
        }

        pass("\t... passed");
    }

    @Test
    public void testSetWantNeedClientAuth_ExternalTrustNoClientCerts()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        int ret = 0;
        SSLContext cCtx = null;
        SSLContext sCtx = null;
        SSLEngine client = null;
        SSLEngine server = null;

        /* TrustManager that trusts no certificates */
        TrustManager[] trustNoClientCerts = {
            new X509ExtendedTrustManager() {
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
                public void checkClientTrusted(X509Certificate[] chain,
                    String authType) throws CertificateException {
                    throw new CertificateException(
                        "fail on purpose / bad cert");
                }
                public void checkClientTrusted(X509Certificate[] chain,
                    String authType, Socket socket)
                    throws CertificateException {
                    throw new CertificateException(
                        "fail on purpose / bad cert");
                }
                public void checkClientTrusted(X509Certificate[] chain,
                    String authType, SSLEngine engine)
                    throws CertificateException {
                    throw new CertificateException(
                        "fail on purpose / bad cert");
                }
                public void checkServerTrusted(X509Certificate[] chain,
                    String authType) throws CertificateException {
                    /* Accept all server certs, not in scope of
                     * setWant/NeedClientAuth() */
                }
                public void checkServerTrusted(X509Certificate[] chain,
                    String authType, Socket socket)
                    throws CertificateException {
                    /* Accept all server certs, not in scope of
                     * setWant/NeedClientAuth() */
                }
                public void checkServerTrusted(X509Certificate[] chain,
                    String authType, SSLEngine engine)
                    throws CertificateException {
                    /* Accept all server certs, not in scope of
                     * setWant/NeedClientAuth() */
                }
            }
        };

        /* All combinations with external X509ExtendedTrustManager registered
         * which will trust NO client certs and ALL server certs */
        PeerAuthConfig[] configsDefaultManagers = new PeerAuthConfig[] {
            new PeerAuthConfig(true, true, true, true, false),
            new PeerAuthConfig(true, true, true, false, true),
            new PeerAuthConfig(true, true, false, true, false),
            new PeerAuthConfig(true, true, false, false, true),
            new PeerAuthConfig(true, false, true, true, false),
            new PeerAuthConfig(true, false, true, false, true),
            new PeerAuthConfig(true, false, false, true, false),
            new PeerAuthConfig(true, false, false, false, true),
            new PeerAuthConfig(false, true, true, true, false),
            new PeerAuthConfig(false, true, true, false, true),
            new PeerAuthConfig(false, true, false, true, false),
            new PeerAuthConfig(false, true, false, false, true),
            new PeerAuthConfig(false, false, true, true, false),
            new PeerAuthConfig(false, false, true, false, true),
            new PeerAuthConfig(false, false, false, true, false),
            new PeerAuthConfig(false, false, false, false, true)
        };

        System.out.print("\tsetWantClientAuth(ext KM no)");

        for (PeerAuthConfig c : configsDefaultManagers) {

            sCtx = tf.createSSLContextNoDefaults("TLS", engineProvider,
                trustNoClientCerts,
                tf.createKeyManager("SunX509", tf.clientJKS, engineProvider));
            server = sCtx.createSSLEngine();
            server.setUseClientMode(false);
            server.setWantClientAuth(c.serverWantClientAuth);
            server.setNeedClientAuth(c.serverNeedClientAuth);

            cCtx = tf.createSSLContextNoDefaults("TLS", engineProvider,
                trustNoClientCerts,
                tf.createKeyManager("SunX509", tf.clientJKS, engineProvider));
            client = cCtx.createSSLEngine("wolfSSL test case", 11111);
            client.setUseClientMode(true);
            client.setWantClientAuth(c.clientWantClientAuth);
            client.setNeedClientAuth(c.clientNeedClientAuth);

            ret = tf.testConnection(server, client, null, null, "Test");
            if ((c.expectSuccess && ret != 0) ||
                (!c.expectSuccess && ret == 0)) {
                error("\t... failed");
                fail("SSLEngine want/needClientAuth failed: \n" +
                     "\n  cWantClientAuth = " + c.clientWantClientAuth +
                     "\n  cNeedClientAuth = " + c.clientNeedClientAuth +
                     "\n  sWantClientAuth = " + c.serverWantClientAuth +
                     "\n  sNeedClientAuth = " + c.serverNeedClientAuth +
                     "\n  expectSuccess = " + c.expectSuccess +
                     "\n  got ret = " + ret);
            }
        }

        pass("\t... passed");
    }


    @Test
    public void testReuseSession()
        throws NoSuchProviderException, NoSuchAlgorithmException {
        SSLEngine server;
        SSLEngine client;
        int ret;

        /* create new SSLEngine */
        System.out.print("\tSession reuse");

        this.ctx = tf.createSSLContext("TLS", engineProvider);
        server = this.ctx.createSSLEngine();
        client = this.ctx.createSSLEngine("wolfSSL client test", 11111);

        server.setUseClientMode(false);
        server.setNeedClientAuth(false);
        client.setUseClientMode(true);
        ret = tf.testConnection(server, client, null, null, "Test reuse");
        if (ret != 0) {
            error("\t\t\t... failed");
            fail("failed to create engine");
        }

        try {
            /* test close connection */
            tf.CloseConnection(server, client, false);
        } catch (SSLException ex) {
            error("\t\t\t... failed");
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
            error("\t\t\t... failed");
            fail("failed to create engine");
        }
        try {
            /* test close connection */
            tf.CloseConnection(server, client, false);
        } catch (SSLException ex) {
            error("\t\t\t... failed");
            fail("failed to create engine");
        }

        if (client.getEnableSessionCreation() ||
            !server.getEnableSessionCreation()) {
            error("\t\t\t... failed");
            fail("bad enabled session creation");
        }
        pass("\t\t\t... passed");
    }

    /**
     * More extended threading test of SSLEngine class.
     * Launches a simple multi-threaded SSLSocket-based server, which
     * creates a new thread for each incoming client thread. Then, launches
     * "numThreads" concurrent SSLEngine clients which connect to that server.
     * SSLEngine clients use SocketChannel class to communicate with server.
     *
     * CountDownLatch is used with a 10 second timeout on latch.await(), so
     * that this test will time out and return with error instead of
     * infinitely block if SSLEngine threads end up in a bad state or
     * deadlock and never return.
     */
    @Test
    public void testExtendedThreadingUse()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InterruptedException {

        /* Number of SSLEngine client threads to start up */
        int numThreads = 50;

        /* Port of internal HTTPS server */
        final int svrPort = 11119;

        /* Create ExecutorService to launch client SSLEngine threads */
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final SSLContext localCtx = tf.createSSLContext("TLS", engineProvider);

        /* Used to detect timeout of CountDownLatch, don't run infinitely
         * if SSLEngine threads are stalled out or deadlocked */
        boolean returnWithoutTimeout = true;

        /* Keep track of failure and success count */
        final AtomicIntegerArray failures = new AtomicIntegerArray(1);
        final AtomicIntegerArray success = new AtomicIntegerArray(1);
        failures.set(0, 0);
        success.set(0, 0);

        System.out.print("\tExtended threading use");

        /* Start up simple TLS test server */
        CountDownLatch serverOpenLatch = new CountDownLatch(1);
        InternalMultiThreadedSSLSocketServer server =
            new InternalMultiThreadedSSLSocketServer(svrPort, serverOpenLatch,
            numThreads);
        server.start();

        /* Wait for server thread to start up before connecting clients */
        serverOpenLatch.await();

        /* Start up client threads */
        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override public void run() {
                    SSLEngineClient client =
                        new SSLEngineClient(localCtx, "localhost", svrPort);
                    try {
                        client.connect();
                    } catch (Exception e) {
                        e.printStackTrace();
                        failures.incrementAndGet(0);
                    }
                    success.incrementAndGet(0);

                    latch.countDown();
                }
            });
        }

        /* Wait for all client threads to finish, else time out */
        returnWithoutTimeout = latch.await(10, TimeUnit.SECONDS);
        server.join(1000);

        /* check failure count and success count against thread count */
        if (failures.get(0) == 0 && success.get(0) == numThreads) {
            pass("\t\t... passed");
        } else {
            if (returnWithoutTimeout == true) {
                error("\t\t... failed");
                fail("SSLEngine threading error: " +
                     failures.get(0) + " failures, " +
                     success.get(0) + " success, " +
                     numThreads + " num threads total");
            } else {
                error("\t\t... failed");
                fail("SSLEngine threading error, threads timed out");
            }
        }
    }

    /**
     * Internal protected class used by testSSLEngineExtendedThreadingUse.
     */
    protected class SSLEngineClient
    {
        /* Server host and port to connect SSLEngine client to */
        private int serverPort;
        private String host;

        /* SSLContext, created beforehand and passed via constructor */
        private SSLContext ctx;

        public SSLEngineClient(SSLContext ctx, String host, int port) {
            this.ctx = ctx;
            this.host = host;
            this.serverPort = port;
        }

        /**
         * After creating SSLEngineClient class, call connect() to
         * connect client to server and send/receive simple test data.
         */
        public void connect() throws Exception {

            SSLEngine engine = null;
            SSLSession sess = null;
            SSLEngineResult result;
            HandshakeStatus hsStatus = null;

            int appBuffSz = 0;
            int packBuffSz = 0;
            ByteBuffer appData = null;
            ByteBuffer netData = null;
            ByteBuffer peerAppData = null;
            ByteBuffer peerNetData = null;

            SocketChannel sock = null;

            /* Create SSLEngine, set as client */
            engine = this.ctx.createSSLEngine(host, serverPort);
            engine.setUseClientMode(true);

            /* Set up ByteBuffers for SSLEngine use */
            sess = engine.getSession();
            appBuffSz = sess.getApplicationBufferSize();
            packBuffSz = sess.getPacketBufferSize();
            appData = ByteBuffer.allocate(appBuffSz);
            netData = ByteBuffer.allocate(packBuffSz);
            peerAppData = ByteBuffer.allocate(appBuffSz);
            peerNetData = ByteBuffer.allocate(packBuffSz);

            /* Create SocketChannel for comm with peer, blocking I/O */
            sock = SocketChannel.open();
            sock.configureBlocking(true);
            sock.connect(new InetSocketAddress(host, serverPort));

            /* Do TLS handshake */
            engine.beginHandshake();

            hsStatus = engine.getHandshakeStatus();
            while (hsStatus != SSLEngineResult.HandshakeStatus.FINISHED &&
                  hsStatus != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
                switch (hsStatus) {
                    case NEED_WRAP:
                        netData.clear();
                        try {
                            result = engine.wrap(appData, netData);
                            hsStatus = engine.getHandshakeStatus();
                        } catch (Exception e) {
                            engine.closeOutbound();
                            throw e;
                        }
                        switch (result.getStatus()) {
                            case OK:
                            case CLOSED:
                                netData.flip();
                                while (netData.hasRemaining()) {
                                    sock.write(netData);
                                }
                                netData.compact();
                                break;
                            case BUFFER_OVERFLOW:
                                /* not handling BUFFER_OVERFLOW for simple
                                 * test case here. Shouldn't happen. */
                                throw new Exception(
                                    "BUFFER_OVERFLOW during engine.wrap()");
                            case BUFFER_UNDERFLOW:
                                /* not handling BUFFER_UNDERFLOW for simple
                                 * test case here. Shouldn't happen. */
                                throw new Exception(
                                    "BUFFER_UNDERFLOW during engine.wrap()");
                            default:
                                throw new Exception(
                                    "Unknown HandshakeStatus");
                        }
                        break;
                    case NEED_UNWRAP:
                        if (sock.read(peerNetData) < 0) {
                            engine.closeInbound();
                            engine.closeOutbound();
                        }
                        else {
                            peerNetData.flip();
                            try {
                                result = engine.unwrap(peerNetData, peerAppData);
                                peerNetData.compact();
                                hsStatus = engine.getHandshakeStatus();
                            } catch (Exception e) {
                                engine.closeOutbound();
                                throw e;
                            }
                            switch (result.getStatus()) {
                                case OK:
                                    break;
                                case CLOSED:
                                    engine.closeOutbound();
                                    break;
                                case BUFFER_UNDERFLOW:
                                    /* need more data, try to read again */
                                    break;
                                case BUFFER_OVERFLOW:
                                    /* not handling BUFFER_OVERFLOW for simple
                                     * test case here. Shouldn't happen. */
                                    throw new Exception(
                                        "BUFFER_OVERFLOW during engine.unwrap");
                                default:
                                    throw new Exception(
                                        "Unknown HandshakeStatus");
                            }
                        }
                        break;
                    case FINISHED:
                        break;
                    case NOT_HANDSHAKING:
                        break;
                    default:
                        throw new Exception("Invalid HandshakeStatus: " +
                            hsStatus);
                }
                hsStatus = engine.getHandshakeStatus();
            }

            /* write app data */
            appData.clear();
            appData.put("Hello from wolfJSSE".getBytes());
            appData.flip();

            while (appData.hasRemaining()) {
                netData.clear();
                result = engine.wrap(appData, netData);
                switch (result.getStatus()) {
                    case OK:
                        netData.flip();
                        while (netData.hasRemaining()) {
                            int sent = sock.write(netData);
                        }
                        break;
                    case CLOSED:
                        engine.closeOutbound();
                        engine.closeInbound();
                        break;
                    case BUFFER_OVERFLOW:
                        throw new Exception(
                            "BUFFER_OVERFLOW during engine.wrap()");
                    case BUFFER_UNDERFLOW:
                        throw new Exception(
                            "BUFFER_UNDERFLOW during engine.wrap()");
                    default:
                        throw new Exception(
                            "Unknown HandshakeStatus");
                }
            }

            /* read response */
            peerNetData.clear();
            int recvd = sock.read(peerNetData);
            if (recvd > 0) {
                peerNetData.flip();
                result = engine.unwrap(peerNetData, peerAppData);
                peerNetData.compact();
                switch (result.getStatus()) {
                    case OK:
                        peerAppData.flip();
                        /* not doing anything with returned data */
                        break;
                    case CLOSED:
                        engine.closeOutbound();
                        engine.closeInbound();
                        break;
                    case BUFFER_OVERFLOW:
                        throw new Exception(
                            "BUFFER_OVERFLOW during engine.unwrp()");
                    case BUFFER_UNDERFLOW:
                        throw new Exception(
                            "BUFFER_UNDERFLOW during engine.unwrap()");
                    default:
                        throw new Exception(
                            "Unknown HandshakeStatus");
                }
            }

            /* shutdown */
            engine.closeOutbound();
            while (engine.isOutboundDone() == false) {
                /* get close notify */
                result = engine.wrap(ByteBuffer.allocate(0), netData);
                /* send close notify */
                while (netData.hasRemaining()) {
                    sock.write(netData);
                }
                netData.compact();

            }
            sock.close();
        }
    }

    /**
     * Internal multi-threaded SSLSocket-based server.
     * Used when testing concurrent threaded SSLEngine client connections.
     */
    protected class InternalMultiThreadedSSLSocketServer extends Thread
    {
        private int serverPort;
        private CountDownLatch serverOpenLatch = null;
        private int clientConnections = 1;

        public InternalMultiThreadedSSLSocketServer(
            int port, CountDownLatch openLatch, int clientConnections) {
            this.serverPort = port;
            serverOpenLatch = openLatch;
            this.clientConnections = clientConnections;
        }

        @Override
        public void run() {
            try {
                SSLContext ctx = tf.createSSLContext("TLS", engineProvider);
                SSLServerSocket ss = (SSLServerSocket)ctx
                    .getServerSocketFactory().createServerSocket(serverPort);

                while (clientConnections > 0) {
                    serverOpenLatch.countDown();
                    SSLSocket sock = (SSLSocket)ss.accept();
                    ClientHandler client = new ClientHandler(sock);
                    client.start();
                    clientConnections--;
                }

            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        class ClientHandler extends Thread
        {
            SSLSocket sock;

            public ClientHandler(SSLSocket s) {
                sock = s;
            }

            public void run() {
                byte[] response = new byte[80];
                String msg = "I hear you fa shizzle, from Java!";

                try {
                    sock.startHandshake();
                    sock.getInputStream().read(response);
                    sock.getOutputStream().write(msg.getBytes());
                    sock.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
    } /* InternalMultiThreadedSSLSocketServer */

    private void pass(String msg) {
        WolfSSLTestFactory.pass(msg);
    }

    private void error(String msg) {
        WolfSSLTestFactory.fail(msg);
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

