/* WolfSSLEngineTest.java
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
import com.wolfssl.provider.jsse.WolfSSLProvider;
import java.io.EOFException;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.util.Random;
import java.util.ArrayList;
import java.net.Socket;
import java.net.InetSocketAddress;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.atomic.AtomicIntegerArray;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import static org.junit.Assert.assertEquals;
import org.junit.Rule;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.rules.Timeout;
import static org.junit.Assert.assertTrue;

import com.wolfssl.provider.jsse.WolfSSLEngine;

/**
 *
 * @author wolfSSL
 */
public class WolfSSLEngineTest {
    public final static char[] jksPass = "wolfSSL test".toCharArray();
    public final static String engineProvider = "wolfJSSE";
    private static WolfSSLTestFactory tf;

    private SSLContext ctx = null;
    private static String allProtocols[] = {
        "TLS",
        "TLSv1",
        "TLSv1.1",
        "TLSv1.2",
        "TLSv1.3",
        "TLS",
        "DTLSv1.3"
    };

    private static ArrayList<String> enabledProtocols =
        new ArrayList<String>();

    /**
     * Global timeout for all tests in this class.
     */
    @Rule
    public Timeout globalTimeout = new Timeout(60, TimeUnit.SECONDS);

    @BeforeClass
    public static void testProviderInstallationAtRuntime()
        throws NoSuchProviderException, WolfSSLException {

        System.out.println("WolfSSLEngine Class");

        /* install wolfJSSE provider at runtime */
        Security.insertProviderAt(new WolfSSLProvider(), 1);

        Provider p = Security.getProvider("wolfJSSE");
        assertNotNull(p);

        /* populate enabledProtocols */
        for (int i = 0; i < allProtocols.length; i++) {
            try {
                SSLContext.getInstance(allProtocols[i], "wolfJSSE");
                enabledProtocols.add(allProtocols[i]);

            } catch (NoSuchAlgorithmException e) {
                /* protocol not enabled */
            }
        }

        try {
            tf = new WolfSSLTestFactory();
        } catch (WolfSSLException e) {
            e.printStackTrace();
            throw e;
        }
    }


    @Test
    public void testSSLEngine()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               KeyManagementException, KeyStoreException, CertificateException,
               IOException, UnrecoverableKeyException {

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
        throws NoSuchProviderException, NoSuchAlgorithmException,
               KeyManagementException, KeyStoreException, CertificateException,
               IOException, UnrecoverableKeyException {

        SSLEngine e;
        String sup[];
        boolean ok = false;

        System.out.print("\tSetting ciphersuite");

        if (!WolfSSL.TLSv12Enabled()) {
            pass("\t\t... skipped");
            return;
        }

        for (int i = 0; i < enabledProtocols.size(); i++) {

            /* 'TLS' is not a 'supported' protocol from
             * SSLEngine.getSupportedProtocols(). That list returns
             * Strings such as: TLSv1, TLSv1.2, DTLSv1.3, etc. */
            if (enabledProtocols.get(i).equals("TLS")) {
                continue;
            }

            this.ctx = tf.createSSLContext(
                enabledProtocols.get(i), engineProvider);

            e = this.ctx.createSSLEngine();
            if (e == null) {
                error("\t\t... failed");
                fail("failed to create engine");
                return;
            }

            sup = e.getSupportedProtocols();
            for (String x : sup) {
                if (x.equals(enabledProtocols.get(i))) {
                    ok = true;
                }
            }
            if (!ok) {
                error("\t\t... failed");
                fail("failed to find " + enabledProtocols.get(i) +
                     " in supported protocols");
            }

            sup = e.getEnabledProtocols();
            for (String x : sup) {
                if (x.equals(enabledProtocols.get(i))) {
                    ok = true;
                }
            }
            if (!ok) {
                error("\t\t... failed");
                fail("failed to find " + enabledProtocols.get(i) +
                     " in enabled protocols");
            }

            /* check supported cipher suites */
            sup = e.getSupportedCipherSuites();
            e.setEnabledCipherSuites(new String[] {sup[0]});
            if (e.getEnabledCipherSuites() == null ||
                    !sup[0].equals(e.getEnabledCipherSuites()[0])) {
                error("\t\t... failed");
                fail("unexpected empty cipher list");
            }
        }

        pass("\t\t... passed");
    }

    @Test
    public void testCipherConnectionTLS()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               KeyManagementException, KeyStoreException, CertificateException,
               IOException, UnrecoverableKeyException {

        synchronized (WolfSSLTestFactory.jdkTlsDisabledAlgorithmsLock) {
            for (int i = 0; i < enabledProtocols.size(); i++) {
                if (enabledProtocols.get(i).equals("TLS")) {
                    /* 'TLS' is not a 'supported' protocol from
                     * SSLEngine.getSupportedProtocols(). That list returns
                     * Strings such as: TLSv1, TLSv1.2, DTLSv1.3, etc. */
                    continue;
                }

                testCipherConnectionByProtocol(enabledProtocols.get(i));
            }
        }
    }

    /**
     * Test the connection using the given protocol.
     *
     * Private method, called by testCipherConnectionTLS()
     */
    private void testCipherConnectionByProtocol(String protocol)
        throws NoSuchProviderException, NoSuchAlgorithmException,
               KeyManagementException, KeyStoreException, CertificateException,
               IOException, UnrecoverableKeyException {

        SSLEngine server;
        SSLEngine client;
        String    cipher = null;
        int ret;
        String[] ciphers;
        String   certType;
        Certificate[] certs;

        /* create new SSLEngine */
        System.out.print("\tBasic connection: " + protocol);

        this.ctx = tf.createSSLContext(protocol, engineProvider);
        server = this.ctx.createSSLEngine();
        client = this.ctx.createSSLEngine("wolfSSL client test", 11111);

        ciphers = client.getSupportedCipherSuites();
        certs = server.getSession().getLocalCertificates();
        if (certs == null) {
            error("\t... failed");
            fail("no certs available from server SSLEngine.getSession()");
        }
        else {
            /* For (D)TLS 1.3, pick the first available cipher. */
            if (protocol.equals("TLSv1.3") || protocol.equals("DTLSv1.3")) {
                for (String x : ciphers) {
                    if (x.startsWith("TLS_AES_") ||
                        x.startsWith("TLS_CHACHA20_")) {
                        cipher = x;
                        break;
                    }
                }
            }
            else {
                /* TLS 1.2 and below: select cipher based on cert type */
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
                    /* use a ECDHE-ECDSA suite if available */
                    for (String x : ciphers) {
                        if (x.contains("ECDHE_ECDSA")) {
                            cipher = x;
                            break;
                        }
                    }
                }
            }
        }

        server.setUseClientMode(false);
        server.setNeedClientAuth(false);
        client.setUseClientMode(true);
        ret = tf.testConnection(server, client, new String[] { cipher },
                new String[] { protocol }, "Test cipher suite");
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

        /* Test closing connection */
        try {
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
        throws NoSuchProviderException, NoSuchAlgorithmException,
               SSLException, KeyManagementException, KeyStoreException,
               CertificateException, IOException, UnrecoverableKeyException {

        SSLEngine server;
        SSLEngine client;
        int ret;

        /* create new SSLEngine */
        System.out.print("\tbeginHandshake()");

        for (int i = 0; i < enabledProtocols.size(); i++) {

            this.ctx = tf.createSSLContext(
                enabledProtocols.get(i), engineProvider);

            server = this.ctx.createSSLEngine();
            client = this.ctx.createSSLEngine(
                "wolfSSL begin handshake test", 11111);

            /* Calling beginHandshake() before setUseClientMode() should throw
             * IllegalStateException */
            try {
                server.beginHandshake();
                error("\t\t... failed");
                fail("beginHandshake() before setUseClientMode() should " +
                     "throw IllegalStateException");
            } catch (IllegalStateException e) {
                /* expected */
            }

            try {
                client.beginHandshake();
                error("\t\t... failed");
                fail("beginHandshake() before setUseClientMode() should " +
                     "throw IllegalStateException");
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

            ret = tf.testConnection(server, client, null, null,
                "Test in/out bound");
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
        }

        pass("\t\t... passed");
    }

    @Test
    public void testConnectionOutIn()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               KeyManagementException, KeyStoreException, CertificateException,
               IOException, UnrecoverableKeyException {

        SSLEngine server;
        SSLEngine client;
        int ret;

        /* create new SSLEngine */
        System.out.print("\tisIn/OutboundDone()");

        for (int i = 0; i < enabledProtocols.size(); i++) {

            this.ctx = tf.createSSLContext(
                enabledProtocols.get(i), engineProvider);

            server = this.ctx.createSSLEngine();
            client = this.ctx.createSSLEngine("wolfSSL in/out test", 11111);

            server.setUseClientMode(false);
            server.setNeedClientAuth(false);
            client.setUseClientMode(true);

            ret = tf.testConnection(server, client, null, null,
                "Test in/out bound");
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
        }

        pass("\t\t... passed");
    }

    @Test
    public void testSetUseClientMode()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               KeyManagementException, KeyStoreException, CertificateException,
               IOException, UnrecoverableKeyException {

        SSLEngine client;
        SSLEngine server;

        System.out.print("\tsetUseClientMode()");

        for (int i = 0; i < enabledProtocols.size(); i++) {

            /* expected to fail, not calling setUseClientMode() */
            this.ctx = tf.createSSLContext(
                enabledProtocols.get(i), engineProvider);

            server = this.ctx.createSSLEngine();
            client = this.ctx.createSSLEngine("wolfSSL test", 11111);
            server.setWantClientAuth(false);
            server.setNeedClientAuth(false);
            try {
                tf.testConnection(server, client, null, null, "Testing");
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
                tf.testConnection(server, client, null, null, "Testing");
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
                tf.testConnection(server, client, null, null, "Testing");
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
                tf.testConnection(server, client, null, null, "Testing");
            } catch (IllegalStateException e) {
                e.printStackTrace();
                error("\t\t... failed");
                fail("failed with setUseClientMode(), should succeed");
            }
        }

        pass("\t\t... passed");
    }

    @Test
    public void testMutualAuth()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               KeyManagementException, KeyStoreException, CertificateException,
               IOException, UnrecoverableKeyException {

        SSLEngine server;
        SSLEngine client;
        int ret;

        /* create new SSLEngine */
        System.out.print("\tMutual authentication");

        for (int i = 0; i < enabledProtocols.size(); i++) {

            /* success case */
            this.ctx = tf.createSSLContext(
                enabledProtocols.get(i), engineProvider);

            server = this.ctx.createSSLEngine();
            client = this.ctx.createSSLEngine("wolfSSL auth test", 11111);

            server.setWantClientAuth(true);
            server.setNeedClientAuth(true);
            client.setUseClientMode(true);
            server.setUseClientMode(false);
            ret = tf.testConnection(server, client, null, null,
                "Test mutual auth");
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
            this.ctx = tf.createSSLContext(
                enabledProtocols.get(i), engineProvider,
                tf.createTrustManager("SunX509", tf.serverJKS, engineProvider),
                tf.createKeyManager("SunX509", tf.serverJKS, engineProvider));
            server = this.ctx.createSSLEngine();
            client = this.ctx.createSSLEngine("wolfSSL auth fail test", 11111);

            server.setWantClientAuth(true);
            server.setNeedClientAuth(true);
            client.setUseClientMode(true);
            server.setUseClientMode(false);
            ret = tf.testConnection(server, client, null, null,
                "Test in/out bound");
            if (ret == 0) {
                error("\t\t... failed");
                fail("failed to create engine");
            }
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
        throws NoSuchProviderException, NoSuchAlgorithmException,
               KeyManagementException, KeyStoreException, CertificateException,
               IOException, UnrecoverableKeyException {

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

        for (int i = 0; i < enabledProtocols.size(); i++) {
            for (PeerAuthConfig c : configsDefaultManagers) {

                sCtx = tf.createSSLContext(
                    enabledProtocols.get(i), engineProvider);
                server = sCtx.createSSLEngine();
                server.setUseClientMode(false);
                server.setWantClientAuth(c.serverWantClientAuth);
                server.setNeedClientAuth(c.serverNeedClientAuth);

                cCtx = tf.createSSLContext(
                    enabledProtocols.get(i), engineProvider);
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
                         "\n  got ret = " + ret +
                         "\n  protocol = " + enabledProtocols.get(i));
                }
            }
        }

        pass("\t... passed");
    }

    @Test
    public void testSetWantNeedClientAuth_ClientNoKeyManager()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               KeyManagementException, KeyStoreException, CertificateException,
               IOException, UnrecoverableKeyException {

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

        for (int i = 0; i < enabledProtocols.size(); i++) {
            for (PeerAuthConfig c : configs) {

                sCtx = tf.createSSLContext(
                    enabledProtocols.get(i), engineProvider);
                server = sCtx.createSSLEngine();
                server.setUseClientMode(false);
                server.setWantClientAuth(c.serverWantClientAuth);
                server.setNeedClientAuth(c.serverNeedClientAuth);

                cCtx = tf.createSSLContextNoDefaults(
                    enabledProtocols.get(i), engineProvider,
                    tf.createTrustManager("SunX509", tf.clientJKS,
                        engineProvider),
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
                         "\n  got ret = " + ret +
                         "\n  protocol = " + enabledProtocols.get(i));
                }
            }
        }

        pass("\t... passed");
    }

    @Test
    public void testSetWantNeedClientAuth_ServerNoKeyManager()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               KeyManagementException, KeyStoreException, CertificateException,
               IOException, UnrecoverableKeyException {

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

        for (int i = 0; i < enabledProtocols.size(); i++) {
            for (PeerAuthConfig c : configs) {

                sCtx = tf.createSSLContextNoDefaults(enabledProtocols.get(i),
                    engineProvider,
                    tf.createTrustManager("SunX509", tf.clientJKS,
                        engineProvider),
                    null);
                server = sCtx.createSSLEngine();
                server.setUseClientMode(false);
                server.setWantClientAuth(c.serverWantClientAuth);
                server.setNeedClientAuth(c.serverNeedClientAuth);

                cCtx = tf.createSSLContext(enabledProtocols.get(i),
                    engineProvider);
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
                         "\n  got ret = " + ret +
                         "\n  protocol = " + enabledProtocols.get(i));
                }
            }
        }

        pass("\t... passed");
    }

    @Test
    public void testSetWantNeedClientAuth_ClientServerExternalTrustAllCerts()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               KeyStoreException, CertificateException, IOException,
               UnrecoverableKeyException {

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

        for (int i = 0; i < enabledProtocols.size(); i++) {
            for (PeerAuthConfig c : configsDefaultManagers) {

                sCtx = tf.createSSLContextNoDefaults(enabledProtocols.get(i),
                    engineProvider,
                    trustAllCerts,
                    tf.createKeyManager("SunX509", tf.clientJKS,
                        engineProvider));
                server = sCtx.createSSLEngine();
                server.setUseClientMode(false);
                server.setWantClientAuth(c.serverWantClientAuth);
                server.setNeedClientAuth(c.serverNeedClientAuth);

                cCtx = tf.createSSLContextNoDefaults(enabledProtocols.get(i),
                    engineProvider,
                    trustAllCerts,
                    tf.createKeyManager("SunX509", tf.clientJKS,
                        engineProvider));
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
                         "\n  got ret = " + ret +
                         "\n  protocol = " + enabledProtocols.get(i));
                }
            }
        }

        pass("\t... passed");
    }

    @Test
    public void testSetWantNeedClientAuth_ExternalTrustNoClientCerts()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               KeyStoreException, CertificateException, IOException,
               UnrecoverableKeyException {

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

        for (int i = 0; i < enabledProtocols.size(); i++) {
            for (PeerAuthConfig c : configsDefaultManagers) {

                sCtx = tf.createSSLContextNoDefaults(enabledProtocols.get(i),
                    engineProvider,
                    trustNoClientCerts,
                    tf.createKeyManager("SunX509", tf.clientJKS,
                        engineProvider));
                server = sCtx.createSSLEngine();
                server.setUseClientMode(false);
                server.setWantClientAuth(c.serverWantClientAuth);
                server.setNeedClientAuth(c.serverNeedClientAuth);

                cCtx = tf.createSSLContextNoDefaults(enabledProtocols.get(i),
                    engineProvider,
                    trustNoClientCerts,
                    tf.createKeyManager("SunX509", tf.clientJKS,
                        engineProvider));
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
                         "\n  got ret = " + ret +
                         "\n  protocol = " + enabledProtocols.get(i));
                }
            }
        }

        pass("\t... passed");
    }


    @Test
    public void testReuseSession()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               KeyManagementException, KeyStoreException, CertificateException,
               IOException, UnrecoverableKeyException {

        SSLEngine server;
        SSLEngine client;
        int ret;

        System.out.print("\tSession reuse");

        /* wolfjsse.clientSessionCache.disabled could be set in users
         * java.security file which would cause this test to not work
         * properly. Save their setting here, and re-enable session
         * cache for this test */
        String originalProp = Security.getProperty(
            "wolfjsse.clientSessionCache.disabled");
        Security.setProperty("wolfjsse.clientSessionCache.disabled", "false");

        try {
            for (int i = 0; i < enabledProtocols.size(); i++) {
                /* create new SSLEngine */
                this.ctx = tf.createSSLContext(enabledProtocols.get(i),
                    engineProvider);
                server = this.ctx.createSSLEngine();
                client = this.ctx.createSSLEngine("wolfSSL client test", 11111);

                server.setUseClientMode(false);
                server.setNeedClientAuth(false);
                client.setUseClientMode(true);
                ret = tf.testConnection(server, client, null, null,
                    "Test reuse");
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
                ret = tf.testConnection(server, client, null, null,
                    "Test reuse");
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
            }

            pass("\t\t\t... passed");

        } finally {
            if (originalProp != null && !originalProp.isEmpty()) {
                Security.setProperty(
                    "wolfjsse.clientSessionCache.disabled", originalProp);
            }
        }
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
               InterruptedException, KeyManagementException,
               KeyStoreException, CertificateException, IOException,
               UnrecoverableKeyException {

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
        InternalMultiThreadedSSLSocketServer server = null;

        try {
            server = new InternalMultiThreadedSSLSocketServer(svrPort, serverOpenLatch,
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
        } finally {
            /* Ensure proper cleanup in all cases */

            /* Close server socket to ensure it's released */
            if (server != null) {
                server.closeSocket();
                try {
                    server.join(1000);
                } catch (InterruptedException e) {
                    /* Ignore */
                }
            }

            /* Shutdown executor service and wait for it to terminate */
            service.shutdown();
            try {
                if (!service.awaitTermination(5, TimeUnit.SECONDS)) {
                    service.shutdownNow();
                }
            } catch (InterruptedException e) {
                service.shutdownNow();
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
            boolean readAgain = false;

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
                            sock.write(netData);
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

            /* read response (might get TLS 1.3 session ticket instead) */
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
                        /* With TLS 1.3, we may get a session ticket
                         * message post handshake, resulting in BUFFER_UNDERFLOW
                         * status since we read the ticket but didn't get the
                         * chance to read the response waiting from the peer. */
                        sess = engine.getSession();
                        if (sess.getProtocol().equals("TLSv1.3")) {
                            readAgain = true;
                            break;
                        }
                        else {
                            throw new Exception(
                                "BUFFER_UNDERFLOW during engine.unwrap()");
                        }
                    default:
                        throw new Exception(
                            "Unknown HandshakeStatus");
                }
            }

            if (readAgain) {
                /* read response */
                peerNetData.clear();
                recvd = sock.read(peerNetData);
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
        private SSLServerSocket ss = null;

        public InternalMultiThreadedSSLSocketServer(
            int port, CountDownLatch openLatch, int clientConnections) {
            this.serverPort = port;
            serverOpenLatch = openLatch;
            this.clientConnections = clientConnections;
        }

        /**
         * Explicitly closes the server socket if still open
         */
        public void closeSocket() {
            if (ss != null) {
                try {
                    ss.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        @Override
        public void run() {
            try {
                SSLContext ctx = tf.createSSLContext("TLS", engineProvider);
                ss = (SSLServerSocket)ctx
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
            } finally {
                /* Ensure server socket is closed */
                if (ss != null) {
                    try {
                        ss.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
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
                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    /* Ensure socket is closed */
                    try {
                        if (sock != null && !sock.isClosed()) {
                            sock.close();
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
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

        System.out.print("\tgetApplicationBufferSize()");

        try {
            for (int i = 0; i < enabledProtocols.size(); i++) {
                this.ctx = tf.createSSLContext(enabledProtocols.get(i),
                    engineProvider);

                engine = this.ctx.createSSLEngine("test", 11111);
                session = engine.getSession();
                appBufSz = session.getApplicationBufferSize();

                /* expected to be 16384 */
                if (appBufSz != 16384) {
                    error("\t... failed");
                    fail("got incorrect application buffer size (" +
                        enabledProtocols.get(i) + ")");
                }
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

        System.out.print("\tgetPacketBufferSize()");

        try {
            for (int i = 0; i < enabledProtocols.size(); i++) {
                this.ctx = tf.createSSLContext(enabledProtocols.get(i),
                    engineProvider);

                engine = this.ctx.createSSLEngine("test", 11111);
                session = engine.getSession();
                packetBufSz = session.getPacketBufferSize();

                /* expected to be 17k */
                if (packetBufSz != (17 * 1024)) {
                    error("\t\t... failed");
                    fail("got incorrect packet buffer size (" +
                        enabledProtocols.get(i) + ")");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            error("\t\t... failed");
            fail("unexpected Exception during getPacketBufferSize test");
        }

        pass("\t\t... passed");
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

                client.wrap(cOut, clientToServer);
                server.wrap(sOut, serverToClient);

                clientToServer.flip();
                serverToClient.flip();

                client.unwrap(serverToClient, cIn);
                server.unwrap(clientToServer, sIn);

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

                client.wrap(cOutBuffs, clientToServer);
                server.wrap(sOutBuffs, serverToClient);

                clientToServer.flip();
                serverToClient.flip();

                client.unwrap(serverToClient, cIn);
                server.unwrap(clientToServer, sIn);

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

    @Test
    public void testDTLSv13Engine()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               KeyManagementException, KeyStoreException, IOException,
               CertificateException, UnrecoverableKeyException {

        System.out.print("\tDTLSv1.3 basic connection");

        /* Skip if DTLSv1.3 not enabled */
        if (!enabledProtocols.contains("DTLSv1.3")) {
            System.out.println("\t... skipped");
            return;
        }

        SSLEngine client = null;
        SSLEngine server = null;

        try {
            /* Create SSLContext */
            this.ctx = tf.createSSLContext("DTLSv1.3", engineProvider);

            /* Create client engine */
            client = this.ctx.createSSLEngine("wolfSSL client", 11111);
            client.setUseClientMode(true);

            /* Create server engine */
            server = this.ctx.createSSLEngine();
            server.setUseClientMode(false);
            server.setNeedClientAuth(true);

            /* Test buffer sizes */
            SSLSession session = client.getSession();
            assertTrue(session.getApplicationBufferSize() > 0);
            assertTrue(session.getPacketBufferSize() > 0);

            /* Test handshake with small app data */
            tf.testConnection(client, server, null, null, "Test Message");

            /* Test handshake with large app data */
            byte[] largeData = new byte[16384];
            new Random().nextBytes(largeData);
            tf.testConnection(client, server, null, null, new String(largeData));

            pass("\t... passed");

        } catch (Exception e) {
            error("\t... failed");
            e.printStackTrace();
            fail("Failed DTLSv1.3 test with exception: " + e);
        }
    }

    /**
     * Internal helper method for testDTLSv13EngineResumeSession.
     */
    private void dtls13ResumeTest(String con1Host, String con2Host,
        boolean expectResume) throws Exception {

        SSLEngine client1 = null;
        SSLEngine client2 = null;
        SSLEngine server1 = null;
        SSLEngine server2 = null;
        boolean resumed = false;

        /* Create SSLContext */
        SSLContext dtlsCtx = tf.createSSLContext("DTLSv1.3", engineProvider);

        /* First connection */
        client1 = dtlsCtx.createSSLEngine(con1Host, 11111);
        client1.setUseClientMode(true);
        server1 = dtlsCtx.createSSLEngine();
        server1.setUseClientMode(false);
        server1.setNeedClientAuth(true);

        /* First handshake */
        tf.testConnection(client1, server1, null, null, "First Connection");

        /* Second connection */
        client2 = dtlsCtx.createSSLEngine(con2Host, 11111);
        client2.setUseClientMode(true);
        server2 = dtlsCtx.createSSLEngine();
        server2.setUseClientMode(false);
        server2.setNeedClientAuth(true);

        /* Second handshake */
        tf.testConnection(client2, server2, null, null, "Second Connection");

        /* Verify session was resumed */
        WolfSSLEngine we = (WolfSSLEngine)client2;
        resumed = we.sessionResumed();

        if (expectResume && !resumed) {
            throw new Exception(
                "Session was not resumed, but should have been");
        }
        else if (!expectResume && resumed) {
            throw new Exception(
                "Session was resumed, but should not have been");
        }
    }

    /**
     * Test that SSLEngine with DTLSv1.3 resumes (and not) as expected.
     */
    @Test
    public void testDTLSv13EngineResumeSession()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               KeyManagementException, KeyStoreException, IOException,
               CertificateException, UnrecoverableKeyException {

        System.out.print("\tDTLSv1.3 session resumption");

        /* Skip if DTLSv1.3 not enabled */
        if (!enabledProtocols.contains("DTLSv1.3")) {
            System.out.println("\t... skipped");
            return;
        }

        try {

            /* Test expected resumption case */
            dtls13ResumeTest("wolfSSL client", "wolfSSL client", true);
            /* Test expected not resumption case */
            dtls13ResumeTest("wolfSSL client", "wolfSSL client 2", false);

            pass("\t... passed");

        } catch (Exception e) {
            error("\t... failed");
            e.printStackTrace();
            fail("Failed DTLSv1.3 session resumption test " +
                 "with exception: " + e);
        }
    }

    /**
     * Test for incorrect BUFFER_OVERFLOW handling in non-blocking I/O.
     * Uses real SocketChannel I/O to verify unwrap() correctly handles
     * buffer overflow conditions.
     */
    @Test
    public void testNonBlockingIO() throws Exception {

        System.out.print("\tNon-blocking I/O");

        for (int i = 0; i < enabledProtocols.size(); i++) {
            String protocol = enabledProtocols.get(i);

            if (protocol.equals("TLS") || protocol.contains("DTLS")) {
                continue;
            }

            final boolean[] serverReady = new boolean[] { false };
            final int[] serverPort = new int[] { 0 };
            final Exception[] serverException = new Exception[] { null };
            final Exception[] clientException = new Exception[] { null };

            /* Barrier to synchronize data transfer phases between threads.
             * With this, both sides should complete each send/receive phase
             * before proceeding, preventing race conditions where one side
             * closes while the other is still processing. */
            final CyclicBarrier dataBarrier = new CyclicBarrier(2);

            Thread serverThread = new Thread() {
                public void run() {
                    try {
                        doNonBlockingIO(protocol, serverPort, serverReady,
                            false, dataBarrier);
                    } catch (Exception e) {
                        serverReady[0] = true;
                        serverException[0] = e;
                        dataBarrier.reset();
                    }
                }
            };

            serverThread.start();
            while (!serverReady[0]) {
                Thread.sleep(50);
            }
            if (serverException[0] != null) {
                throw serverException[0];
            }

            Thread clientThread = new Thread() {
                public void run() {
                    try {
                        doNonBlockingIO(protocol, serverPort, serverReady,
                            true, dataBarrier);
                    } catch (Exception e) {
                        clientException[0] = e;
                        dataBarrier.reset();
                    }
                }
            };

            clientThread.start();

            /* 5 second timeout */
            serverThread.join(5000);
            clientThread.join(5000);

            if (serverThread.isAlive() || clientThread.isAlive()) {
                error("... failed");
                fail("Test timed out for " + protocol);
            }

            if (serverException[0] != null) {
                error("... failed");
                throw serverException[0];
            }
            if (clientException[0] != null) {
                error("... failed");
                throw clientException[0];
            }
        }

        pass("\t\t... passed");
    }

    private void doNonBlockingIO(String protocol, int[] serverPort,
        boolean[] serverReady, boolean isClient,
        CyclicBarrier dataBarrier) throws Exception {

        ServerSocketChannel ssc = null;
        SocketChannel sc = null;
        SSLEngine engine = null;

        try {
            SSLContext ctx = tf.createSSLContext(protocol, engineProvider);
            engine = ctx.createSSLEngine("wolfSSL test", 11111);
            engine.setUseClientMode(isClient);
            if (!isClient) {
                engine.setNeedClientAuth(false);
            }

            if (!isClient) {
                ssc = ServerSocketChannel.open();
                ssc.socket().bind(new InetSocketAddress(
                    InetAddress.getLocalHost(), 0));
                serverPort[0] = ssc.socket().getLocalPort();
                serverReady[0] = true;
                sc = ssc.accept();
            } else {
                sc = SocketChannel.open();
                sc.connect(new InetSocketAddress(
                    InetAddress.getLocalHost(), serverPort[0]));
                engine.setEnabledProtocols(new String[] { protocol });
            }

            sc.configureBlocking(false);
            while (!sc.finishConnect()) {
                Thread.sleep(50);
            }

            doHandshake(engine, sc);

            /* Synchronize after handshake to ensure both sides are ready
             * before starting data transfer */
            try {
                dataBarrier.await(5, TimeUnit.SECONDS);
            } catch (BrokenBarrierException e) {
                return;
            }

            /* Phase 1: Server sends, client receives */
            if (!isClient) {
                doDataTransfer(engine, sc, true);
            } else {
                doDataTransfer(engine, sc, false);
            }

            /* Synchronize before phase 2. BrokenBarrierException means
             * peer hit an error and reset barrier - exit gracefully. */
            try {
                dataBarrier.await(5, TimeUnit.SECONDS);
            } catch (BrokenBarrierException e) {
                return;
            }

            /* Phase 2: Client sends, server receives */
            if (!isClient) {
                doDataTransfer(engine, sc, false);
            } else {
                doDataTransfer(engine, sc, true);
            }

            /* Synchronize before closing sockets */
            try {
                dataBarrier.await(5, TimeUnit.SECONDS);
            } catch (BrokenBarrierException e) {
                return;
            }

        } finally {
            /* Abrupt close is ok for test. close_notify may not be sent */
            if (sc != null) {
                try {
                    sc.close();
                } catch (Exception e) {
                    /* Ignore */
                }
            }
            if (ssc != null) {
                try {
                    ssc.close();
                } catch (Exception e) {
                    /* Ignore */
                }
            }
        }
    }

    private void doHandshake(SSLEngine engine, SocketChannel sc)
        throws Exception {

        int netSize = engine.getSession().getPacketBufferSize();
        ByteBuffer localNet = ByteBuffer.allocate(netSize / 10);
        ByteBuffer peerNet = ByteBuffer.allocate(netSize / 10);
        ByteBuffer localApp = ByteBuffer.allocate(0);
        ByteBuffer peerApp = ByteBuffer.allocate(0);

        engine.beginHandshake();
        HandshakeStatus hs = engine.getHandshakeStatus();
        boolean underflow = false;

        while (hs != HandshakeStatus.FINISHED &&
               hs != HandshakeStatus.NOT_HANDSHAKING) {

            /* Check if peer has closed - exit early to prevent timeout */
            if (engine.isInboundDone() || engine.isOutboundDone()) {
                break;
            }

            SSLEngineResult res;
            switch (hs) {
                case NEED_UNWRAP:
                    if (peerNet.position() == 0 || underflow) {
                        if (sc.read(peerNet) < 0) {
                            engine.closeInbound();
                            throw new EOFException();
                        }
                        underflow = false;
                    }
                    peerNet.flip();
                    res = engine.unwrap(peerNet, peerApp);
                    peerNet.compact();
                    hs = res.getHandshakeStatus();

                    if (res.getStatus() ==
                        SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                        int size = engine.getSession().getPacketBufferSize();
                        if (size > peerNet.capacity()) {
                            peerNet = enlargeBuffer(peerNet, size);
                        }
                        underflow = true;
                    } else if (res.getStatus() ==
                        SSLEngineResult.Status.BUFFER_OVERFLOW) {
                        int size = engine.getSession()
                            .getApplicationBufferSize();
                        if (size > peerApp.capacity()) {
                            peerApp = enlargeBuffer(peerApp, size);
                        }
                    }
                    break;

                case NEED_WRAP:
                    localNet.clear();
                    res = engine.wrap(localApp, localNet);
                    hs = res.getHandshakeStatus();
                    if (res.getStatus() == SSLEngineResult.Status.OK) {
                        localNet.flip();
                        while (localNet.hasRemaining()) {
                            sc.write(localNet);
                        }
                    } else if (res.getStatus() ==
                        SSLEngineResult.Status.BUFFER_OVERFLOW) {
                        int size = engine.getSession().getPacketBufferSize();
                        if (size > localNet.capacity()) {
                            localNet = enlargeBuffer(localNet, size);
                        }
                    }
                    break;

                case NEED_TASK:
                    Runnable task;
                    while ((task = engine.getDelegatedTask()) != null) {
                        task.run();
                    }
                    hs = engine.getHandshakeStatus();
                    break;

                default:
                    break;
            }
            hs = engine.getHandshakeStatus();
        }
    }

    private void doDataTransfer(SSLEngine engine, SocketChannel sc,
        boolean send) throws Exception {

        int appSize = engine.getSession().getApplicationBufferSize();
        int netSize = engine.getSession().getPacketBufferSize();

        if (send) {
            /* Large data to span multiple TLS records */
            ByteBuffer appData = ByteBuffer.allocate(
                appSize * (Integer.SIZE / 8));
            appData.putInt(appSize * (Integer.SIZE / 8));
            for (int i = 1; i < appSize; i++) {
                appData.putInt(i);
            }
            appData.flip();
            ByteBuffer netData = ByteBuffer.allocate(netSize / 2);

            while (appData.hasRemaining()) {
                /* Check if peer has closed - exit early to prevent timeout */
                if (engine.isInboundDone() || engine.isOutboundDone()) {
                    break;
                }
                netData.clear();
                SSLEngineResult res = engine.wrap(appData, netData);
                if (res.getStatus() == SSLEngineResult.Status.OK) {
                    netData.flip();
                    try {
                        while (netData.hasRemaining()) {
                            sc.write(netData);
                        }
                    } catch (IOException e) {
                        /* In non-blocking mode with concurrent threads, peer
                         * may close connection during write. This is not an
                         * error - peer may have received all expected data
                         * and initiated shutdown. Break out of loop. */
                        String msg = e.getMessage();
                        if (msg != null && (msg.contains("Connection reset") ||
                                            msg.contains("Broken pipe") ||
                                            msg.contains("Socket closed"))) {
                            break;
                        }
                        throw e;
                    }
                    if (res.getHandshakeStatus() ==
                        HandshakeStatus.NEED_TASK) {
                        Runnable task;
                        while ((task = engine.getDelegatedTask()) != null) {
                            task.run();
                        }
                    }
                } else if (res.getStatus() ==
                    SSLEngineResult.Status.BUFFER_OVERFLOW) {
                    int size = engine.getSession().getPacketBufferSize();
                    if (size > netData.capacity()) {
                        netData = enlargeBuffer(netData, size);
                    }
                }
            }
        } else {
            /* Small buffer to test BUFFER_OVERFLOW logic */
            ByteBuffer appData = ByteBuffer.allocate(appSize / 2);
            ByteBuffer netData = ByteBuffer.allocate(netSize);
            int received = -1;
            boolean needToReadMore = true;

            while (received != 0) {
                /* Check if peer has closed - exit early to prevent timeout */
                if (engine.isInboundDone() || engine.isOutboundDone()) {
                    break;
                }
                if (needToReadMore) {
                    try {
                        if (sc.read(netData) < 0) {
                            break;
                        }
                    } catch (IOException e) {
                        /* In non-blocking mode with concurrent threads, peer
                         * may close connection during read. This is not an
                         * error in the test - it's expected behavior when
                         * testing race conditions. Break out of loop. */
                        String msg = e.getMessage();
                        if (msg != null && (msg.contains("Connection reset") ||
                                            msg.contains("Broken pipe") ||
                                            msg.contains("Socket closed"))) {
                            break;
                        }
                        throw e;
                    }
                }

                netData.flip();
                /* Guard against unwrap on empty buffer after abrupt close. */
                if (!netData.hasRemaining() && engine.isInboundDone()) {
                    break;
                }
                SSLEngineResult res = engine.unwrap(netData, appData);
                netData.compact();

                switch (res.getStatus()) {
                    case OK:
                        if (res.getHandshakeStatus() ==
                            HandshakeStatus.NEED_TASK) {
                            Runnable task;
                            while ((task = engine.getDelegatedTask())
                                != null) {
                                task.run();
                            }
                        }
                        if (received < 0 && res.bytesProduced() >= 4) {
                            received = appData.getInt(0);
                        }
                        appData.clear();
                        received -= res.bytesProduced();
                        needToReadMore = (res.bytesProduced() == 0);
                        break;

                    case BUFFER_OVERFLOW:
                        /* Bug manifests: needToReadMore=false creates
                         * infinite loop if unwrap() falsely returns
                         * BUFFER_OVERFLOW based on ssl.pending(). */
                        int size = engine.getSession()
                            .getApplicationBufferSize();
                        if (size > appData.capacity()) {
                            appData = enlargeBuffer(appData, size);
                        }
                        needToReadMore = false;
                        break;

                    case BUFFER_UNDERFLOW:
                        size = engine.getSession().getPacketBufferSize();
                        if (size > netData.capacity()) {
                            netData = enlargeBuffer(netData, size);
                        }
                        needToReadMore = true;
                        break;

                    default:
                        throw new IOException("Invalid status: " +
                            res.getStatus());
                }
            }
        }
    }

    private ByteBuffer enlargeBuffer(ByteBuffer buffer, int size) {
        ByteBuffer bb = ByteBuffer.allocate(size);
        buffer.flip();
        bb.put(buffer);
        return bb;
    }

    /**
     * Verify getPeerCertificateChain() throws SSLPeerUnverifiedException
     * when no client auth requested, matching SunJSSE/Netty expectations.
     */
    @Test
    public void testGetPeerCertificateChainNoClientAuth() throws Exception {

        System.out.print("\tgetPeerCertChain no client auth");

        String protocol = null;
        for (String p : enabledProtocols) {
            if (!p.equals("TLS") && !p.contains("DTLS")) {
                protocol = p;
                break;
            }
        }

        if (protocol == null) {
            pass("\t... skipped");
            return;
        }

        SSLContext ctx = tf.createSSLContext(protocol, engineProvider);

        SSLEngine server = ctx.createSSLEngine();
        SSLEngine client = ctx.createSSLEngine("localhost", 11111);

        server.setUseClientMode(false);
        server.setNeedClientAuth(false);
        server.setWantClientAuth(false);
        client.setUseClientMode(true);

        tf.testConnection(server, client, null, null, "No client auth test");

        SSLSession serverSession = server.getSession();

        try {
            javax.security.cert.X509Certificate[] certs =
                serverSession.getPeerCertificateChain();
            error("\t... failed");
            fail("Expected SSLPeerUnverifiedException, got " +
                 (certs == null ? "null" : "certs"));
        } catch (SSLPeerUnverifiedException e) {
            /* Expected */
        }

        pass("\t... passed");
    }

    @Test
    public void testSSLHandshakeExceptionCauseChain()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               KeyManagementException, KeyStoreException,
               CertificateException, IOException,
               UnrecoverableKeyException {

        System.out.print("\tSSLEngine SSLHandshakeException cause chain");

        final String rejectMsg = "Intentional engine test rejection";
        TrustManager[] rejectingTMs = { new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain,
                String authType) throws CertificateException {
            }
            @Override
            public void checkServerTrusted(X509Certificate[] chain,
                String authType) throws CertificateException {
                throw new CertificateException(rejectMsg);
            }
            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        }};

        SSLContext srvCtx = tf.createSSLContext("TLS", engineProvider);
        SSLContext cliCtx = SSLContext.getInstance("TLS", "wolfJSSE");
        cliCtx.init(null, rejectingTMs, null);

        SSLEngine server = srvCtx.createSSLEngine();
        SSLEngine client = cliCtx.createSSLEngine("wolfSSL engine test", 11111);
        server.setUseClientMode(false);
        server.setNeedClientAuth(false);
        client.setUseClientMode(true);

        server.beginHandshake();
        client.beginHandshake();

        ByteBuffer cliToSer = ByteBuffer.allocateDirect(
            client.getSession().getPacketBufferSize());
        ByteBuffer serToCli = ByteBuffer.allocateDirect(
            server.getSession().getPacketBufferSize());
        ByteBuffer empty = ByteBuffer.allocate(0);
        ByteBuffer sink = ByteBuffer.allocate(
            server.getSession().getApplicationBufferSize());

        boolean sawExpected = false;
        for (int loops = 0; loops < 50 && !sawExpected; loops++) {
            try {
                if (client.getHandshakeStatus() == HandshakeStatus.NEED_WRAP) {
                    client.wrap(empty, cliToSer);
                }
            } catch (SSLHandshakeException e) {
                Throwable cause = e.getCause();
                assertNotNull("SSLHandshakeException cause should not be null",
                    cause);
                assertTrue("Cause should be CertificateException, got: " +
                    cause.getClass().getName(),
                    cause instanceof CertificateException);
                assertEquals("CertificateException message mismatch",
                    rejectMsg, cause.getMessage());
                sawExpected = true;
                break;
            }

            cliToSer.flip();
            if (cliToSer.hasRemaining() &&
                (server.getHandshakeStatus() ==
                    HandshakeStatus.NEED_UNWRAP ||
                 server.getHandshakeStatus() ==
                    HandshakeStatus.NOT_HANDSHAKING)) {
                try {
                    server.unwrap(cliToSer, sink);
                } catch (SSLException e) {
                    /* Server may see handshake failure after client reject */
                }
            }
            cliToSer.compact();

            if (server.getHandshakeStatus() == HandshakeStatus.NEED_WRAP) {
                try {
                    server.wrap(empty, serToCli);
                } catch (SSLException e) {
                    /* Server may fail after client rejection */
                }
            }

            serToCli.flip();
            if (serToCli.hasRemaining() &&
                (client.getHandshakeStatus() ==
                    HandshakeStatus.NEED_UNWRAP ||
                 client.getHandshakeStatus() ==
                    HandshakeStatus.NOT_HANDSHAKING)) {
                try {
                    client.unwrap(serToCli, sink);
                } catch (SSLHandshakeException e) {
                    Throwable cause = e.getCause();
                    assertNotNull(
                        "SSLHandshakeException cause " +
                        "should not be null", cause);
                    assertTrue("Cause should be CertificateException, got: " +
                        cause.getClass().getName(),
                        cause instanceof CertificateException);
                    assertEquals("CertificateException message mismatch",
                        rejectMsg, cause.getMessage());
                    sawExpected = true;
                }
            }
            serToCli.compact();
        }

        if (!sawExpected) {
            error("\t... failed");
            fail("Expected SSLHandshakeException " +
                "with CertificateException cause");
        }

        pass("\t... passed");
    }

    @Test
    public void testCloseNotifyTLS13HandshakeStatus()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               KeyManagementException, KeyStoreException, CertificateException,
               IOException, UnrecoverableKeyException {

        /* TLS 1.3 close_notify should return NOT_HANDSHAKING,
         * not NEED_WRAP (RFC 8446 Section 6.1). */
        System.out.print("\tTesting TLS 1.3 close_notify status");

        String[] proto = {"TLSv1.3"};
        this.ctx = tf.createSSLContext("TLSv1.3", engineProvider);
        if (this.ctx == null) {
            /* TLS 1.3 not available, skip */
            pass("\t... skipped");
            return;
        }

        SSLEngine server = this.ctx.createSSLEngine();
        SSLEngine client =
            this.ctx.createSSLEngine("wolfSSL test", 11111);

        server.setUseClientMode(false);
        server.setNeedClientAuth(false);
        client.setUseClientMode(true);
        server.setEnabledProtocols(proto);
        client.setEnabledProtocols(proto);

        server.beginHandshake();
        client.beginHandshake();

        int ret = tf.testConnection(server, client, null, null,
            "close_notify test");
        if (ret != 0) {
            error("\t... failed");
            fail("failed to create connection");
        }

        /* Client sends close_notify */
        client.closeOutbound();
        if (client.getHandshakeStatus() != HandshakeStatus.NEED_WRAP) {
            error("\t... failed");
            fail("closeOutbound should result in NEED_WRAP");
        }

        ByteBuffer netBuf = ByteBuffer.allocateDirect(
            client.getSession().getPacketBufferSize());
        ByteBuffer empty = ByteBuffer.allocate(
            client.getSession().getApplicationBufferSize());

        /* Wrap the close_notify */
        SSLEngineResult result = client.wrap(
            ByteBuffer.allocate(0), netBuf);
        if (result.getStatus() != SSLEngineResult.Status.CLOSED) {
            error("\t... failed");
            fail("wrap after closeOutbound should return CLOSED");
        }

        /* Server receives close_notify, should get
         * NOT_HANDSHAKING for TLS 1.3 */
        netBuf.flip();
        result = server.unwrap(netBuf, empty);

        /* After receiving close_notify, server sees CLOSED status
         * and calls closeOutbound to initiate its own close */
        if (result.getStatus() == SSLEngineResult.Status.CLOSED) {
            server.closeOutbound();
        }

        HandshakeStatus serverStatus = server.getHandshakeStatus();

        /* After closeOutbound, server needs to wrap its close_notify */
        if (serverStatus == HandshakeStatus.NEED_WRAP) {
            /* Wrap server's close_notify response */
            ByteBuffer serverNet = ByteBuffer.allocateDirect(
                server.getSession().getPacketBufferSize());
            result = server.wrap(ByteBuffer.allocate(0), serverNet);

            serverStatus = server.getHandshakeStatus();

            /* After wrapping close_notify, should be NOT_HANDSHAKING
             * (not stuck in NEED_WRAP forever) */
            if (serverStatus == HandshakeStatus.NEED_WRAP) {
                error("\t... failed");
                fail("server stuck in NEED_WRAP after wrapping " +
                     "close_notify response");
            }
        }

        /* Final state should be NOT_HANDSHAKING */
        if (serverStatus != HandshakeStatus.NOT_HANDSHAKING) {
            error("\t... failed");
            fail("expected NOT_HANDSHAKING after close_notify " +
                 "exchange, got " + serverStatus);
        }

        pass("\t... passed");
    }

    @Test
    public void testBufferUnderflowPartialRecord()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               KeyManagementException, KeyStoreException, CertificateException,
               IOException, UnrecoverableKeyException {

        /* Test that unwrap() returns BUFFER_UNDERFLOW with 0 bytes
         * consumed when given a partial TLS record. */
        System.out.print("\tTesting BUFFER_UNDERFLOW partial record");

        this.ctx = tf.createSSLContext("TLS", engineProvider);
        SSLEngine server = this.ctx.createSSLEngine();
        SSLEngine client =
            this.ctx.createSSLEngine("wolfSSL test", 11111);

        server.setUseClientMode(false);
        server.setNeedClientAuth(false);
        client.setUseClientMode(true);

        server.beginHandshake();
        client.beginHandshake();

        int ret = tf.testConnection(server, client, null, null,
            "underflow test");
        if (ret != 0) {
            error("\t... failed");
            fail("failed to create connection");
        }

        /* Client wraps some application data */
        String testData = "Hello from client for underflow test";
        ByteBuffer appBuf = ByteBuffer.wrap(testData.getBytes());
        ByteBuffer netBuf = ByteBuffer.allocateDirect(
            client.getSession().getPacketBufferSize());

        SSLEngineResult result = client.wrap(appBuf, netBuf);
        if (result.getStatus() != SSLEngineResult.Status.OK) {
            error("\t... failed");
            fail("wrap failed: " + result.getStatus());
        }
        netBuf.flip();
        int fullRecordLen = netBuf.remaining();

        if (fullRecordLen < 6) {
            error("\t... failed");
            fail("TLS record too short to test partial");
        }

        /* Create a partial record (only first 3 bytes of the
         * TLS record header — less than the 5-byte header) */
        ByteBuffer partialBuf = ByteBuffer.allocateDirect(3);
        byte[] partial = new byte[3];
        netBuf.get(partial);
        partialBuf.put(partial);
        partialBuf.flip();

        ByteBuffer outBuf = ByteBuffer.allocate(
            server.getSession().getApplicationBufferSize());

        /* Unwrap with partial record should return BUFFER_UNDERFLOW */
        result = server.unwrap(partialBuf, outBuf);

        if (result.getStatus() !=
            SSLEngineResult.Status.BUFFER_UNDERFLOW) {
            error("\t... failed");
            fail("expected BUFFER_UNDERFLOW for partial TLS record, " +
                 "got " + result.getStatus());
        }

        /* Should consume 0 bytes on BUFFER_UNDERFLOW */
        if (result.bytesConsumed() != 0) {
            error("\t... failed");
            fail("BUFFER_UNDERFLOW should consume 0 bytes, consumed " +
                 result.bytesConsumed());
        }

        pass("\t... passed");
    }

    @Test
    public void testBufferOverflowSmallOutput()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               KeyManagementException, KeyStoreException, CertificateException,
               IOException, UnrecoverableKeyException {

        /* Test BUFFER_OVERFLOW with small output, then retry
         * with larger buffer. */
        System.out.print("\tTesting BUFFER_OVERFLOW small output");

        this.ctx = tf.createSSLContext("TLS", engineProvider);
        SSLEngine server = this.ctx.createSSLEngine();
        SSLEngine client =
            this.ctx.createSSLEngine("wolfSSL test", 11111);

        server.setUseClientMode(false);
        server.setNeedClientAuth(false);
        client.setUseClientMode(true);

        server.beginHandshake();
        client.beginHandshake();

        int ret = tf.testConnection(server, client, null, null,
            "overflow test");
        if (ret != 0) {
            error("\t... failed");
            fail("failed to create connection");
        }

        /* Client wraps application data large enough to overflow
         * a small output buffer */
        byte[] bigData = new byte[1024];
        new Random().nextBytes(bigData);
        ByteBuffer appBuf = ByteBuffer.wrap(bigData);
        ByteBuffer netBuf = ByteBuffer.allocateDirect(
            client.getSession().getPacketBufferSize());

        SSLEngineResult result = client.wrap(appBuf, netBuf);
        if (result.getStatus() != SSLEngineResult.Status.OK) {
            error("\t... failed");
            fail("wrap failed: " + result.getStatus());
        }
        netBuf.flip();

        /* Try to unwrap into a tiny output buffer (64 bytes for
         * 1024 bytes of plaintext) */
        ByteBuffer tinyOut = ByteBuffer.allocate(64);
        ByteBuffer netCopy = netBuf.duplicate();

        result = server.unwrap(netCopy, tinyOut);

        if (result.getStatus() !=
            SSLEngineResult.Status.BUFFER_OVERFLOW) {
            error("\t... failed");
            fail("expected BUFFER_OVERFLOW for small output buffer, " +
                 "got " + result.getStatus());
        }

        /* Now retry with a properly-sized buffer */
        ByteBuffer properOut = ByteBuffer.allocate(
            server.getSession().getApplicationBufferSize());

        result = server.unwrap(netBuf, properOut);

        if (result.getStatus() != SSLEngineResult.Status.OK) {
            error("\t... failed");
            fail("unwrap with proper buffer should succeed, got " +
                 result.getStatus());
        }

        /* Verify we got the data */
        properOut.flip();
        if (properOut.remaining() != bigData.length) {
            error("\t... failed");
            fail("expected " + bigData.length + " bytes, got " +
                 properOut.remaining());
        }

        byte[] received = new byte[properOut.remaining()];
        properOut.get(received);
        if (!java.util.Arrays.equals(received, bigData)) {
            error("\t... failed");
            fail("received data does not match sent data");
        }

        pass("\t\t... passed");
    }
}
