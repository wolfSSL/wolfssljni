/* WolfSSLSessionTest.java
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

package com.wolfssl.provider.jsse.test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

import java.util.Arrays;

import java.util.concurrent.Callable;
import java.util.concurrent.Future;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.Provider;
import java.security.Security;
import java.security.KeyStoreException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import java.net.InetSocketAddress;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionBindingEvent;
import javax.net.ssl.SSLSessionBindingListener;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLHandshakeException;

import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLJNIException;
import com.wolfssl.provider.jsse.WolfSSLProvider;
import com.wolfssl.provider.jsse.WolfSSLX509X;
import com.wolfssl.test.TimedTestWatcher;

public class WolfSSLSessionTest {

    @Rule
    public TestRule testWatcher = TimedTestWatcher.create();

    public final static char[] jksPass = "wolfSSL test".toCharArray();
    public final static String engineProvider = "wolfJSSE";
    private static WolfSSLTestFactory tf;

    @BeforeClass
    public static void testProviderInstallationAtRuntime()
        throws NoSuchProviderException, WolfSSLException {

        System.out.println("WolfSSLImplementSSLSession Class");

        /* install wolfJSSE provider at runtime */
        Security.insertProviderAt(new WolfSSLProvider(), 1);

        Provider p = Security.getProvider("wolfJSSE");
        assertNotNull(p);

        /* Can throw WolfSSLException on error */
        tf = new WolfSSLTestFactory();
    }


    @Test
    @SuppressWarnings("removal")
    public void testSessionTimeAndCerts()
        throws NoSuchAlgorithmException, KeyManagementException,
               KeyStoreException, CertificateException, IOException,
               NoSuchProviderException, UnrecoverableKeyException {

        int ret;
        SSLSession session;

        SSLContext ctx = tf.createSSLContext("TLS", engineProvider);
        SSLEngine client = ctx.createSSLEngine("server", 12345);
        SSLEngine server = ctx.createSSLEngine();
        if (client == null || server == null) {
            fail("failed to create engine");
            return;
        }

        server.setUseClientMode(false);
        server.setNeedClientAuth(false);
        client.setUseClientMode(true);
        ret = tf.testConnection(server, client, null, null, "Test reuse");
        if (ret != 0) {
            fail("failed to connect");
        }

        session = client.getSession();
        if (session.getCreationTime() <= 0) {
            fail("failed to get creation time");
        }

        if (session.getCreationTime() > session.getLastAccessedTime() ||
                session.getLastAccessedTime() <= 0) {
            fail("failed creation time does not equal accessed time");
        }

        /* test certificates */
        session = client.getSession();
        /* TODO changes back to != null once we can check for client auth */
        if (session.getLocalPrincipal() == null) {
            fail("Principal is null when it should not be");
        }

        try {
            /* @TODO make match SunJSSE better */
            session.getPeerPrincipal().getName();
        } catch (SSLPeerUnverifiedException e) {
            fail("failed to find peer principal");
        }

        try {
            session.getPeerCertificateChain();
        } catch (SSLPeerUnverifiedException e) {
            fail("failed to get peer certificate chain");
        }
    }

    @Test
    @SuppressWarnings("removal")
    public void testNullSession()
        throws NoSuchAlgorithmException, KeyManagementException,
               KeyStoreException, CertificateException, IOException,
               NoSuchProviderException, UnrecoverableKeyException {

        int ret;
        SSLSession session;

        SSLContext ctx = tf.createSSLContext("TLS", engineProvider);
        SSLEngine client = ctx.createSSLEngine("server", 12345);
        SSLEngine server = ctx.createSSLEngine();
        if (client == null || server == null) {
            fail("failed to create engine");
            return;
        }
        /* get null session since handshake not done */
        session = client.getSession();

        server.setUseClientMode(false);
        server.setNeedClientAuth(false);
        client.setUseClientMode(true);
        ret = tf.testConnection(server, client, null, null, "Test reuse");
        if (ret != 0) {
            fail("failed to create engine");
        }

        /* session stored before handshake should still be null */
        if (session.getId() == null) {
            fail("failed to get ID");
        }

        if (session.getId().length != 0) {
            fail("ID longer than expected");
        }

        try {
            session.getPeerCertificates();
            fail("Unexpected peer certificates found");
        } catch (SSLPeerUnverifiedException e) {
            /* expected to fail with unverified exception */
        }

        if (!session.getCipherSuite().equals("SSL_NULL_WITH_NULL_NULL")) {
            fail("Unexpected cipher suite found");
        }

        if (!session.getProtocol().equals("NONE")) {
            fail("Unexpected protocol found");
        }

        try {
            session.getPeerPrincipal();
            fail("Unexpected peer principal found");
        } catch (SSLPeerUnverifiedException e) {
            /* expected to fail here */
        }

        try {
            session.getPeerCertificateChain();
            fail("Unexpected peer certificate chain found");
        } catch (SSLPeerUnverifiedException e) {
            /* expected to fail here */
        }
    }


    @Test
    public void testBinding()
        throws NoSuchAlgorithmException, KeyManagementException,
               KeyStoreException, CertificateException, IOException,
               NoSuchProviderException, UnrecoverableKeyException {

        int ret;
        String[] values;
        listner bound  = new listner();
        listner bound2 = new listner();

        SSLContext ctx = tf.createSSLContext("TLS", engineProvider);
        SSLEngine client = ctx.createSSLEngine("server", 12345);
        SSLEngine server = ctx.createSSLEngine();
        if (client == null || server == null) {
            fail("failed to create engine");
            return;
        }
        SSLSession session = client.getSession();
        session.putValue("testing", bound);
        bound.setInvalid();

        server.setUseClientMode(false);
        server.setNeedClientAuth(false);
        client.setUseClientMode(true);
        ret = tf.testConnection(server, client, null, null, "Test reuse");
        if (ret != 0) {
            fail("failed to create engine");
        }

        /* override null session set before handshake */
        session = client.getSession();
        session.putValue("testing", bound);
        if (!bound.checkID(session.getId())) {
            fail("test of ID failed");
        }

        if (!bound.checkPeer("server", 12345)) {
            fail("test of port and host fail");

        }

        try {
            if (session.getPeerCertificates() != null) {
                Certificate[] certs = session.getPeerCertificates();

                if (certs.length != 1) {
                    fail("unexpected number of peer certs found");
                }

                if (!certs[0].getType().equals("X.509")) {
                    fail("unexpected cert type found");
                }

                /* Check that Certificate[] returned from getPeerCertificates()
                 * is actually of subclass type X509Certificate[]. If not and
                 * we try to cast back to it, we should get a
                 * ClassCastException */
                try {
                    X509Certificate[] xCerts = (X509Certificate[])certs;
                    assertNotNull(xCerts);
                } catch (ClassCastException e) {
                    fail("getPeerCertificates() did not return array of type " +
                         "X509Certificate[]");
                }
            }
        } catch (SSLPeerUnverifiedException e) {
            fail("failed to get peer certificate");
        }

        if (!bound.checkCipher(server.getSession().getCipherSuite())) {
            fail("unexpected cipher suite");
        }

        session.removeValue("testing");
        if (bound.isBound) {
            fail("bound when should not be");
        }
        session.putValue("testing", bound);
        if (!bound.isBound) {
            fail("not bound when should be");
        }
        session.putValue("testing", bound2);
        if (!bound2.isBound || bound.isBound) {
            fail("override failed");
        }

        if (!bound2.checkPeer("server", 12345)) {
            fail("test of port and host fail");
        }

        if (!session.getValue("testing").equals(bound2)) {
            fail("failed to get value");
        }

        if (session.getValue("bad") != null) {
            fail("able to get bogus value");
        }

        session.putValue("testing 2", bound);
        values = session.getValueNames();
        if (values.length != 2) {
            fail("unexpected number of values");
        }

        if (!values[0].equals("testing 2") || !values[1].equals("testing")) {
            fail("unexpected value names");
        }

        try {
            session.removeValue("bad");
        } catch (IllegalArgumentException ex) {
            fail("could not remove a bogus value");
        }

        try {
            session.removeValue(null);
            fail("null sanity check failed");
        } catch (IllegalArgumentException ex) {
            /* expected to throw exception */
        }

        if (!server.getSession().getProtocol().equals(
                client.getSession().getProtocol())) {
            fail("protocols do not match");
        }
    }

    /**
     * Test that SSLSession.getPeerCertificates() returns the full cert chain
     * sent by the peer, peer cert first, matching expected JSSE behavior.
     */
    @Test
    @SuppressWarnings("removal")
    public void testGetPeerCertificatesReturnsFullChain()
        throws NoSuchAlgorithmException, KeyManagementException,
               KeyStoreException, CertificateException, IOException,
               NoSuchProviderException, UnrecoverableKeyException {

        int ret;
        byte[][] derChain;
        SSLContext ctxClient;
        SSLContext ctxServer;
        SSLEngine client;
        SSLEngine server;
        Certificate[] expectedCerts;
        KeyStore serverStore;
        KeyStore clientStore;
        javax.security.cert.X509Certificate[] oldPeerCerts;

        /* Server key store holds server cert followed by the CA signer,
         * both are sent to the client during the handshake */
        serverStore = KeyStore.getInstance(tf.keyStoreType);
        try (FileInputStream stream = new FileInputStream(tf.serverRSAJKS)) {
            serverStore.load(stream, WolfSSLTestFactory.jksPass);
        }
        expectedCerts = serverStore.getCertificateChain("server-rsa");
        assertNotNull(expectedCerts);

        /* Sanity check that the test key store still holds a chain, if it
         * only has the peer cert this test can not detect a regression */
        Assume.assumeTrue(expectedCerts.length > 1);

        Assume.assumeTrue(WolfSSL.sessionCertsEnabled());

        ctxClient = tf.createSSLContext("TLS", engineProvider,
            tf.createTrustManager("SunX509", tf.caServerJKS, engineProvider),
            tf.createKeyManager("SunX509", tf.clientRSAJKS, engineProvider));
        ctxServer = tf.createSSLContext("TLS", engineProvider,
            tf.createTrustManager("SunX509", tf.caClientJKS, engineProvider),
            tf.createKeyManager("SunX509", tf.serverRSAJKS, engineProvider));

        client = ctxClient.createSSLEngine("wolfSSL client test", 11111);
        server = ctxServer.createSSLEngine();

        client.setUseClientMode(true);
        server.setUseClientMode(false);
        /* Client auth on to cover server side. client-rsa.jks has one self
         * signed cert, so that leg checks the leaf only. */
        server.setNeedClientAuth(true);

        ret = tf.testConnection(server, client, null, null,
            "Test peer cert chain");
        if (ret != 0) {
            fail("failed to connect");
        }

        checkPeerChain(client.getSession().getPeerCertificates(),
            expectedCerts, "client side");

        /* Deprecated getPeerCertificateChain() reports the same chain */
        oldPeerCerts = client.getSession().getPeerCertificateChain();
        assertNotNull(oldPeerCerts);
        derChain = new byte[oldPeerCerts.length][];
        try {
            for (int i = 0; i < oldPeerCerts.length; i++) {
                derChain[i] = oldPeerCerts[i].getEncoded();
            }
        } catch (javax.security.cert.CertificateEncodingException e) {
            fail("failed to get encoding of peer certificate: " + e);
        } finally {
            freeX509XCerts(oldPeerCerts);
        }
        checkPeerChainDER(derChain, expectedCerts,
            "client side deprecated API");

        /* Server side sees the client's chain from the same code path */
        clientStore = KeyStore.getInstance(tf.keyStoreType);
        try (FileInputStream stream =
                new FileInputStream(tf.clientRSAJKS)) {
            clientStore.load(stream, WolfSSLTestFactory.jksPass);
        }
        expectedCerts = clientStore.getCertificateChain("client-rsa");
        assertNotNull(expectedCerts);

        checkPeerChain(server.getSession().getPeerCertificates(),
            expectedCerts, "server side");
    }

    /**
     * Test that a resumed session still reports the certificates from the
     * handshake that created it. No Certificate message is received on a
     * resumed connection, so wolfJSSE serves them from the certs cached during
     * the original handshake.
     */
    @Test
    public void testGetPeerCertificatesOnResumedSession()
        throws NoSuchAlgorithmException, KeyManagementException,
               KeyStoreException, CertificateException, IOException,
               NoSuchProviderException, UnrecoverableKeyException {

        int ret;
        SSLContext ctx;
        SSLEngine client;
        SSLEngine server;
        Certificate[] firstCerts;
        Certificate[] resumedCerts;
        byte[] firstId;

        /* Make sure session cache is not disabled for resume test */
        String originalProp = Security.getProperty(
            "wolfjsse.clientSessionCache.disabled");
        Security.setProperty("wolfjsse.clientSessionCache.disabled", "false");

        try {

            ctx = tf.createSSLContext("TLS", engineProvider);

            client = ctx.createSSLEngine("wolfSSL peer chain test", 11111);
            server = ctx.createSSLEngine();
            client.setUseClientMode(true);
            server.setUseClientMode(false);
            server.setNeedClientAuth(false);

            ret = tf.testConnection(server, client, null, null,
                "Test resume 1");
            if (ret != 0) {
                fail("failed to connect");
            }

            try {
                firstCerts = client.getSession().getPeerCertificates();
            } catch (SSLPeerUnverifiedException e) {
                fail("failed to get peer certificates: " + e);
                return;
            }
            assertNotNull(firstCerts);
            firstId = client.getSession().getId();

            /* Second connection off the same context, resumes the session */
            client = ctx.createSSLEngine("wolfSSL peer chain test", 11111);
            server = ctx.createSSLEngine();
            client.setUseClientMode(true);
            server.setUseClientMode(false);
            server.setNeedClientAuth(false);

            ret = tf.testConnection(server, client, null, null,
                "Test resume 2");
            if (ret != 0) {
                fail("failed to connect for resumption");
            }

            try {
                resumedCerts = client.getSession().getPeerCertificates();
            } catch (SSLPeerUnverifiedException e) {
                fail("failed to get resumed peer certificates: " + e);
                return;
            }

            /* Matching session IDs confirm the session resumed */
            assertArrayEquals("second connection did not resume the session",
                firstId, client.getSession().getId());

            assertNotNull(resumedCerts);
            assertEquals("resumed session peer chain length changed",
                firstCerts.length, resumedCerts.length);

            for (int i = 0; i < firstCerts.length; i++) {
                assertArrayEquals("resumed session cert mismatch at index " + i,
                    firstCerts[i].getEncoded(), resumedCerts[i].getEncoded());
            }

        } finally {
            if (originalProp != null && !originalProp.isEmpty()) {
                Security.setProperty(
                    "wolfjsse.clientSessionCache.disabled", originalProp);
            }
        }
    }

    /**
     * An invalidated session must not be resumed. Establish a session, mark
     * it invalid, then reconnect and verify a new session (different ID) is
     * negotiated instead of resuming the invalidated one.
     */
    @Test
    public void testInvalidatedSessionNotResumed()
        throws NoSuchAlgorithmException, KeyManagementException,
               KeyStoreException, CertificateException, IOException,
               NoSuchProviderException, UnrecoverableKeyException {

        int ret;
        SSLContext ctx;
        SSLEngine client;
        SSLEngine server;
        byte[] firstId;
        byte[] secondId;

        /* Make sure session cache is not disabled for this test */
        String originalProp = Security.getProperty(
            "wolfjsse.clientSessionCache.disabled");
        Security.setProperty("wolfjsse.clientSessionCache.disabled", "false");

        try {
            ctx = tf.createSSLContext("TLS", engineProvider);

            client = ctx.createSSLEngine("wolfSSL invalidate test", 11111);
            server = ctx.createSSLEngine();
            client.setUseClientMode(true);
            server.setUseClientMode(false);
            server.setNeedClientAuth(false);

            ret = tf.testConnection(server, client, null, null,
                "Test invalidate 1");
            if (ret != 0) {
                fail("failed to connect");
            }

            firstId = client.getSession().getId();
            assertNotNull(firstId);
            assertFalse("empty session ID", firstId.length == 0);

            /* Invalidate the cached session before reconnecting */
            client.getSession().invalidate();

            client = ctx.createSSLEngine("wolfSSL invalidate test", 11111);
            server = ctx.createSSLEngine();
            client.setUseClientMode(true);
            server.setUseClientMode(false);
            server.setNeedClientAuth(false);

            ret = tf.testConnection(server, client, null, null,
                "Test invalidate 2");
            if (ret != 0) {
                fail("failed to connect second time");
            }

            secondId = client.getSession().getId();
            assertNotNull(secondId);

            /* Invalidated session must not resume, so the new session must
             * have a different ID. */
            assertFalse("invalidated session was resumed",
                Arrays.equals(firstId, secondId));

        } finally {
            if (originalProp != null && !originalProp.isEmpty()) {
                Security.setProperty(
                    "wolfjsse.clientSessionCache.disabled", originalProp);
            }
        }
    }

    /**
     * Verify peer certs match the expected chain.
     */
    private void checkPeerChain(Certificate[] peerCerts,
        Certificate[] expectedCerts, String desc)
        throws CertificateException {

        byte[][] derChain;

        assertNotNull(peerCerts);

        derChain = new byte[peerCerts.length][];
        for (int i = 0; i < peerCerts.length; i++) {
            derChain[i] = peerCerts[i].getEncoded();
        }

        checkPeerChainDER(derChain, expectedCerts, desc);
    }

    /**
     * Verify DER encoded peer certs match the expected chain. Only the peer
     * cert is available when native wolfSSL has not been compiled with
     * SESSION_CERTS.
     */
    private void checkPeerChainDER(byte[][] derChain,
        Certificate[] expectedCerts, String desc)
        throws CertificateException {

        assertNotNull(derChain);
        assertEquals(desc + ": unexpected peer chain length",
            expectedCerts.length, derChain.length);

        for (int i = 0; i < expectedCerts.length; i++) {
            assertArrayEquals(desc + ": cert mismatch at index " + i,
                expectedCerts[i].getEncoded(), derChain[i]);
        }
    }

    /**
     * Test that SSLSession.getPeerCertificates() reports the peer cert at
     * index zero when the peer cert is large.
     *
     * Native wolfSSL skips certs of MAX_X509_SIZE or larger when storing the
     * peer chain. The peer's own cert is skipped the same way, which would
     * otherwise leave the issuing CA at index zero and make both
     * getPeerCertificates()[0] and getPeerPrincipal() report the CA.
     *
     * The generated leaf clears the 2048 byte MAX_X509_SIZE default, so the
     * skip is exercised on default native wolfSSL builds. Builds raising
     * MAX_X509_SIZE, for example those enabling ML-DSA (8192), store the leaf
     * normally and exercise the ordinary path, since native wolfSSL cannot
     * generate a cert larger than WC_MAX_X509_GEN (4096 bytes).
     */
    @Test
    @SuppressWarnings("removal")
    public void testGetPeerCertificatesLargePeerCert()
        throws NoSuchAlgorithmException, KeyManagementException,
               KeyStoreException, CertificateException, IOException,
               NoSuchProviderException, UnrecoverableKeyException,
               WolfSSLException, WolfSSLJNIException {

        int ret;
        KeyStore[] stores;
        X509Certificate leafCert;
        SSLContext ctxClient;
        SSLContext ctxServer;
        SSLEngine client;
        SSLEngine server;
        SSLSession session;
        Certificate[] peerCerts;

        Assume.assumeFalse(WolfSSLTestFactory.isAndroid());
        /* Without SESSION_CERTS no chain stored, skip test */
        Assume.assumeTrue(WolfSSL.sessionCertsEnabled());

        stores = tf.generateLargeLeafChain();
        leafCert = (X509Certificate)stores[0].getCertificateChain(
            WolfSSLTestFactory.largeLeafAlias)[0];

        /* Sanity check the leaf really is over the MAX_X509_SIZE default,
         * otherwise this duplicates the normal peer chain test */
        if (leafCert.getEncoded().length <= 2048) {
            fail("generated leaf certificate too small to test large peer " +
                 "certificate handling, size " +
                 leafCert.getEncoded().length);
        }

        ctxServer = tf.createSSLContext("TLS", engineProvider,
            tf.createTrustManager("SunX509", stores[1], engineProvider),
            tf.createKeyManager("SunX509", stores[0], engineProvider));
        /* No client key material, NoDefaults avoids both the test factory
         * default and the WolfSSLAuthStore default substitution */
        ctxClient = tf.createSSLContextNoDefaults("TLS", engineProvider,
            tf.createTrustManager("SunX509", stores[1], engineProvider), null);

        client = ctxClient.createSSLEngine("large.example.com", 11111);
        server = ctxServer.createSSLEngine();

        client.setUseClientMode(true);
        server.setUseClientMode(false);
        server.setNeedClientAuth(false);

        ret = tf.testConnection(server, client, null, null,
            "Test large peer cert");
        if (ret != 0) {
            fail("failed to connect with large peer certificate");
        }

        session = client.getSession();

        try {
            peerCerts = session.getPeerCertificates();
        } catch (SSLPeerUnverifiedException e) {
            fail("failed to get peer certificates: " + e);
            return;
        }

        assertNotNull(peerCerts);
        /* [leaf, CA] whether or not native skipped the leaf, so a silent
         * fall back to the peer cert alone shows up here */
        assertEquals("unexpected peer chain length", 2, peerCerts.length);

        /* Peer cert must be first */
        assertArrayEquals("peer cert at index 0 was not the peer's own cert",
            leafCert.getEncoded(), peerCerts[0].getEncoded());

        /* getPeerPrincipal() re-reads index zero */
        try {
            assertEquals("getPeerPrincipal() did not match peer cert subject",
                leafCert.getSubjectX500Principal(), session.getPeerPrincipal());
        } catch (SSLPeerUnverifiedException e) {
            fail("failed to get peer principal: " + e);
        }

        /* Deprecated API reports the same peer cert */
        javax.security.cert.X509Certificate[] oldCerts = null;
        try {
            oldCerts = session.getPeerCertificateChain();
            assertNotNull(oldCerts);
            assertArrayEquals("deprecated API peer cert at index 0 was not " +
                "the peer's own cert", leafCert.getEncoded(),
                oldCerts[0].getEncoded());
        } catch (SSLPeerUnverifiedException |
                 javax.security.cert.CertificateEncodingException e) {
            fail("failed to get peer certificate chain: " + e);
        } finally {
            freeX509XCerts(oldCerts);
        }
    }

    /**
     * Free native memory held by WolfSSLX509X certs from the deprecated
     * getPeerCertificateChain(), rather than waiting on the finalizer.
     */
    @SuppressWarnings("removal")
    private void freeX509XCerts(javax.security.cert.X509Certificate[] certs) {

        if (certs == null) {
            return;
        }

        for (int i = 0; i < certs.length; i++) {
            if (certs[i] instanceof WolfSSLX509X) {
                ((WolfSSLX509X)certs[i]).free();
            }
        }
    }

    @Test
    public void testSessionContext()
        throws NoSuchAlgorithmException, KeyManagementException,
               KeyStoreException, CertificateException, IOException,
               NoSuchProviderException, UnrecoverableKeyException {

        int ret;
        SSLSession session;
        SSLSessionContext context;

        SSLContext ctx = tf.createSSLContext("TLS", engineProvider);
        SSLEngine client = ctx.createSSLEngine("server", 12345);
        SSLEngine server = ctx.createSSLEngine();
        if (client == null || server == null) {
            fail("failed to create engine");
            return;
        }

        server.setUseClientMode(false);
        server.setNeedClientAuth(false);
        client.setUseClientMode(true);
        ret = tf.testConnection(server, client, null, null, "Test reuse");
        if (ret != 0) {
            fail("failed to create engine");
        }
        session = client.getSession();
        context = session.getSessionContext();

        if (!session.getProtocol().equals("TLSv1.3")) {
            /* TLSv1.3 uses session tickets */
            context.setSessionTimeout(100);
            if (context.getSessionTimeout() != 100) {
                fail("failed to set session timeout");
            }
        }

        /* @TODO difference in cache size for SunJSSE vs wolfJSSE  0 vs 33 */
        context.getSessionCacheSize();

        /* @TODO additional tests around setting session cache size */
        context.setSessionCacheSize(2);
    }

    @Test
    public void testGetSessionInSocketConnection() throws Exception {

        String protocol = null;
        SSLContext ctx = null;

        if (WolfSSL.TLSv12Enabled()) {
            protocol = "TLSv1.2";
        } else if (WolfSSL.TLSv11Enabled()) {
            protocol = "TLSv1.1";
        } else if (WolfSSL.TLSv1Enabled()) {
            protocol = "TLSv1.0";
        }

        Assume.assumeNotNull(protocol);

        /* create new CTX */
        ctx = tf.createSSLContext(protocol, engineProvider);

        /* create SSLServerSocket first to get ephemeral port */
        SSLServerSocket ss = (SSLServerSocket)ctx.getServerSocketFactory()
            .createServerSocket(0);

        SSLSocket cs = (SSLSocket)ctx.getSocketFactory().createSocket();
        cs.connect(new InetSocketAddress(ss.getLocalPort()));
        final SSLSocket server = (SSLSocket)ss.accept();
        server.setNeedClientAuth(true);

        ExecutorService es = Executors.newSingleThreadExecutor();
        Future<Void> serverFuture = es.submit(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                try {
                    testSSLSession(server, false);
                    server.startHandshake();
                    testSSLSession(server, true);

                } catch (SSLException e) {
                    fail();
                }
                return null;
            }
        });

        try {
            testSSLSession(cs, false);
            cs.startHandshake();
            testSSLSession(cs, true);

        } catch (SSLHandshakeException e) {
            fail();
        }

        es.shutdown();
        serverFuture.get();
        testSSLSession(cs, true);
        cs.close();
        testSSLSession(cs, true);
        testSSLSession(server, true);
        server.close();
        testSSLSession(server, true);
        ss.close();
    }

    /* Tests that setting/restricting TLS Signature Schemes with the
     * 'jdk.tls.client.SignatureSchemes' and 'jdk.tls.server.SignatureSchemes'
     * system properties works as expected.
     */
    @Test
    public void testSignatureSchemes()
        throws NoSuchAlgorithmException, KeyManagementException,
               KeyStoreException, CertificateException, IOException,
               NoSuchProviderException, UnrecoverableKeyException {

        int ret;
        String cSigSchemes = "jdk.tls.client.SignatureSchemes";
        String sSigSchemes = "jdk.tls.server.SignatureSchemes";
        String origClient = System.getProperty(cSigSchemes);
        String origServer = System.getProperty(sSigSchemes);

        try {
            /* Case 1: Mismatching schemes - Should Fail */
            /* Client: ECDSA only */
            System.setProperty(cSigSchemes, "ecdsa_secp256r1_sha256");
            /* Server: RSA only */
            System.setProperty(sSigSchemes, "rsa_pkcs1_sha256");

            SSLContext ctx1 = tf.createSSLContext("TLS", engineProvider);
            SSLEngine client = ctx1.createSSLEngine("server", 12345);
            SSLEngine server = ctx1.createSSLEngine();

            if (client == null || server == null) {
                fail("failed to create engine");
                return;
            }

            server.setUseClientMode(false);
            server.setNeedClientAuth(false);
            client.setUseClientMode(true);

            /* Handshake should fail due to signature scheme mismatch */
            ret = tf.testConnection(server, client, null, null,
                "Test sig mismatch");

            if (ret == 0) {
                fail("Handshake succeeded with mismatching signature schemes");
            }

            /* Case 2: Matching schemes - Should Pass */
            if (WolfSSL.EccEnabled()) {
                System.setProperty(cSigSchemes, "ecdsa_secp256r1_sha256");
                System.setProperty(sSigSchemes, "ecdsa_secp256r1_sha256");
            }
            else {
                System.setProperty(cSigSchemes, "rsa_pkcs1_sha256");
                System.setProperty(sSigSchemes, "rsa_pkcs1_sha256");
            }

            /* Create new SSLContext to ensure clean state */
            SSLContext ctx2 = tf.createSSLContext("TLS", engineProvider);
            client = ctx2.createSSLEngine("server", 12345);
            server = ctx2.createSSLEngine();

            if (client == null || server == null) {
                fail("failed to create engine");
                return;
            }

            server.setUseClientMode(false);
            server.setNeedClientAuth(false);
            client.setUseClientMode(true);

            ret = tf.testConnection(server, client, null, null,
                "Test sig match");
            if (ret != 0) {
                fail("Handshake failed with matching signature schemes");
            }

        } finally {
            /* Restore properties */
            if (origClient != null) {
                System.setProperty(cSigSchemes, origClient);
            } else {
                System.clearProperty(cSigSchemes);
            }

            if (origServer != null) {
                System.setProperty(sSigSchemes, origServer);
            } else {
                System.clearProperty(sSigSchemes);
            }
        }
    }

    /* Tests that signature scheme tokens not supported by the native
     * wolfSSL build are ignored rather than failing the connection,
     * matching the JDK contract that providers ignore unknown signature
     * scheme names. ML-DSA scheme names are accepted by wolfJSSE, but
     * native wolfSSL_set1_sigalgs_list() may not accept them. The
     * handshake must succeed using the remaining classical scheme whether
     * or not native ML-DSA sigalg list support is available.
     */
    @Test
    public void testSignatureSchemesUnsupportedTokenIgnored()
        throws NoSuchAlgorithmException, KeyManagementException,
               KeyStoreException, CertificateException, IOException,
               NoSuchProviderException, UnrecoverableKeyException {

        int ret;
        String cSigSchemes = "jdk.tls.client.SignatureSchemes";
        String sSigSchemes = "jdk.tls.server.SignatureSchemes";
        String origClient = System.getProperty(cSigSchemes);
        String origServer = System.getProperty(sSigSchemes);
        String schemes;

        if (WolfSSL.EccEnabled()) {
            schemes = "mldsa65,ecdsa_secp256r1_sha256";
        }
        else {
            schemes = "mldsa65,rsa_pkcs1_sha256";
        }

        try {
            System.setProperty(cSigSchemes, schemes);
            System.setProperty(sSigSchemes, schemes);

            SSLContext ctx = tf.createSSLContext("TLS", engineProvider);
            SSLEngine client = ctx.createSSLEngine("server", 12345);
            SSLEngine server = ctx.createSSLEngine();

            if (client == null || server == null) {
                fail("failed to create engine");
                return;
            }

            server.setUseClientMode(false);
            server.setNeedClientAuth(false);
            client.setUseClientMode(true);

            ret = tf.testConnection(server, client, null, null,
                "Test unsupported scheme ignored");
            if (ret != 0) {
                fail("Handshake failed, unsupported scheme token in " +
                     "SignatureSchemes property should be ignored");
            }

        } finally {
            /* Restore properties */
            if (origClient != null) {
                System.setProperty(cSigSchemes, origClient);
            } else {
                System.clearProperty(cSigSchemes);
            }

            if (origServer != null) {
                System.setProperty(sSigSchemes, origServer);
            } else {
                System.clearProperty(sSigSchemes);
            }
        }
    }

    /* Tests that a SignatureSchemes property list containing no usable
     * schemes fails with SSLException during handshake setup, matching
     * SunJSSE behavior when a restriction yields no supported schemes.
     * Uses a scheme name that will never be recognized.
     */
    @Test
    public void testSignatureSchemesAllUnsupportedFailsClosed()
        throws NoSuchAlgorithmException, KeyManagementException,
               KeyStoreException, CertificateException, IOException,
               NoSuchProviderException, UnrecoverableKeyException {

        int ret;
        String cSigSchemes = "jdk.tls.client.SignatureSchemes";
        String sSigSchemes = "jdk.tls.server.SignatureSchemes";
        String origClient = System.getProperty(cSigSchemes);
        String origServer = System.getProperty(sSigSchemes);

        try {
            System.setProperty(cSigSchemes, "bogus_scheme_sha256");
            System.setProperty(sSigSchemes, "bogus_scheme_sha256");

            SSLContext ctx = tf.createSSLContext("TLS", engineProvider);
            SSLEngine client = ctx.createSSLEngine("server", 12345);
            SSLEngine server = ctx.createSSLEngine();

            if (client == null || server == null) {
                fail("failed to create engine");
                return;
            }

            server.setUseClientMode(false);
            server.setNeedClientAuth(false);
            client.setUseClientMode(true);

            ret = tf.testConnection(server, client, null, null,
                "Test all-unsupported schemes");
            if (ret == 0) {
                fail("Handshake succeeded but SignatureSchemes property " +
                     "with no usable schemes should fail connection setup");
            }

        } finally {
            /* Restore properties */
            if (origClient != null) {
                System.setProperty(cSigSchemes, origClient);
            } else {
                System.clearProperty(cSigSchemes);
            }

            if (origServer != null) {
                System.setProperty(sSigSchemes, origServer);
            } else {
                System.clearProperty(sSigSchemes);
            }
        }
    }

    /**
     * Test SSLSession.hashCode().
     *
     * Verifies that WolfSSLImplementSSLSession declares its own hashCode()
     * method (not just inherited from Object). Tests hashCode consistency
     * and that different sessions produce different hash codes.
     */
    @Test
    public void testSessionHashCode()
        throws NoSuchAlgorithmException, KeyManagementException,
               KeyStoreException, CertificateException, IOException,
               NoSuchProviderException, UnrecoverableKeyException {

        int ret;
        SSLSession session;

        SSLContext ctx = tf.createSSLContext("TLS", engineProvider);
        SSLEngine client = ctx.createSSLEngine("localhost", 12345);
        SSLEngine server = ctx.createSSLEngine();

        if (client == null || server == null) {
            fail("failed to create engine");
            return;
        }

        server.setUseClientMode(false);
        server.setNeedClientAuth(false);
        client.setUseClientMode(true);

        ret = tf.testConnection(server, client, null, null, "Test hashCode");
        if (ret != 0) {
            fail("failed to create connection");
            return;
        }

        session = client.getSession();
        if (session == null) {
            fail("SSLEngine.getSession() returned null");
            return;
        }

        /* Test that hashCode() method is declared in the session class
         * (not just inherited from Object). */
        try {
            session.getClass().getDeclaredMethod("hashCode", new Class<?>[0]);
        } catch (NoSuchMethodException e) {
            fail("SSLSession class does not declare hashCode() method");
            return;
        }

        /* Test that hashCode() returns consistent value */
        int hash1 = session.hashCode();
        int hash2 = session.hashCode();
        if (hash1 != hash2) {
            fail("SSLSession.hashCode() not consistent: " +
                 hash1 + " != " + hash2);
            return;
        }

        /* Test that different session has different hashCode.
         * Create another connection */
        SSLContext ctx2 = tf.createSSLContext("TLS", engineProvider);
        SSLEngine client2 = ctx2.createSSLEngine("localhost", 54321);
        SSLEngine server2 = ctx2.createSSLEngine();

        server2.setUseClientMode(false);
        server2.setNeedClientAuth(false);
        client2.setUseClientMode(true);

        ret = tf.testConnection(server2, client2, null, null,
            "Test hashCode 2");
        if (ret != 0) {
            fail("failed to create second connection");
            return;
        }

        SSLSession session2 = client2.getSession();
        if (session2 == null) {
            fail("Second SSLEngine.getSession() returned null");
            return;
        }

        /* Test different sessions should have different hashCodes */
        int hash3 = session2.hashCode();
        if (hash1 == hash3) {
            /* Not a hard failure, just a warning since hashCode collisions
             * are technically allowed */
            System.out.println(" (warning: hash collision)");
        }
    }

    @Test
    public void testSessionEquals()
        throws NoSuchAlgorithmException, KeyManagementException,
               KeyStoreException, CertificateException, IOException,
               NoSuchProviderException, UnrecoverableKeyException {

        int ret;
        SSLSession session;

        SSLContext ctx = tf.createSSLContext("TLS", engineProvider);
        SSLEngine client = ctx.createSSLEngine("localhost", 12345);
        SSLEngine server = ctx.createSSLEngine();

        if (client == null || server == null) {
            fail("failed to create engine");
            return;
        }

        server.setUseClientMode(false);
        server.setNeedClientAuth(false);
        client.setUseClientMode(true);

        ret = tf.testConnection(server, client, null, null, "Test equals");
        if (ret != 0) {
            fail("failed to create connection");
            return;
        }

        session = client.getSession();
        if (session == null) {
            fail("SSLEngine.getSession() returned null");
            return;
        }

        /* Test that equals() method is declared in the session class
         * (not just inherited from Object). */
        try {
            session.getClass().getDeclaredMethod("equals",
                new Class<?>[] { Object.class });
        } catch (NoSuchMethodException e) {
            fail("SSLSession class does not declare equals() method");
            return;
        }

        /* Test reflexivity: session.equals(session) should be true */
        if (!session.equals(session)) {
            fail("SSLSession.equals() reflexivity failed");
            return;
        }

        /* Test null: session.equals(null) should be false */
        if (session.equals(null)) {
            fail("SSLSession.equals(null) should return false");
            return;
        }

        /* Test different type: session.equals(Object) should return false
         * when passed an incompatible type. This is intentional to verify
         * the equals() implementation handles type mismatches correctly. */
        Object differentType = "not a session";
        if (session.equals(differentType)) {
            fail("SSLSession.equals(Object) should return false for " +
                 "incompatible type");
            return;
        }

        /* Test hashCode/equals contract: equal objects must have same hash */
        if (session.equals(session) &&
            session.hashCode() != session.hashCode()) {
            fail("Equal sessions have different hashCodes");
            return;
        }
    }

    @Test
    public void testSessionHashCodeBeforeHandshake()
        throws NoSuchAlgorithmException, KeyManagementException,
               KeyStoreException, CertificateException, IOException,
               NoSuchProviderException, UnrecoverableKeyException {

        SSLContext ctx = tf.createSSLContext("TLS", engineProvider);
        SSLEngine engine = ctx.createSSLEngine("localhost", 12345);

        if (engine == null) {
            fail("failed to create engine");
            return;
        }

        engine.setUseClientMode(true);

        /* Get session before handshake - may have null session ID */
        SSLSession session = engine.getSession();
        if (session == null) {
            /* Some implementations return null before handshake */
            return;
        }

        /* Test that hashCode() does not throw even if getId() returns
         * null or empty (session not yet established) */
        try {
            int hash = session.hashCode();
            /* hashCode should work without throwing */
        } catch (Exception e) {
            fail("hashCode() threw exception before handshake: " +
                 e.getMessage());
            return;
        }

        /* Test that equals() does not throw either */
        try {
            boolean eq = session.equals(session);
        } catch (Exception e) {
            fail("equals() threw exception before handshake: " +
                 e.getMessage());
            return;
        }
    }

    /**
     * Test SSLSocket.getSession() and calling methods on the
     * SSLSession retrieved. */
    private void testSSLSession(SSLSocket sock, boolean handshakeDone)
        throws Exception {

        int ret;
        String val;
        Certificate[] certs;
        byte[] id;
        SSLSession session;

        if (sock == null) {
            throw new Exception("SSLSocket was null in testSSLSession");
        }

        session = sock.getSession();
        if (session == null) {
            throw new Exception("SSLSocket.getSession() returned null");
        }

        val = session.getCipherSuite();
        if (val == null || val.isEmpty()) {
            throw new Exception(
                "SSLSession.getCipherSuite() was null or empty");
        }

        val = session.getProtocol();
        if (val == null || val.isEmpty()) {
            throw new Exception(
                "SSLSession.getProtocol() was null or empty");
        }

        val = session.getPeerHost();
        if (handshakeDone && !sock.isClosed() &&
            (val == null || val.isEmpty())) {
            throw new Exception(
                "SSLSession.getPeerHost() was null or empty");
        }

        ret = session.getPeerPort();
        if (ret == 0) {
            throw new Exception("SSLSession.getPeerPort() was 0");
        }

        certs = session.getLocalCertificates();
        if (certs == null || certs.length == 0) {
            throw new Exception(
                "SSLSession.getLocalCertificates() was null or 0 length");
        }

        try {
            certs = session.getPeerCertificates();
            if (handshakeDone && (certs == null || certs.length == 0)) {
                throw new Exception(
                    "SSLSession.getPeerCertificates was null or 0 length");
            }
        } catch (SSLPeerUnverifiedException e) {
            if (handshakeDone && !sock.isClosed()) {
                throw new Exception(
                    "SSLSession.getPeerCertificates threw " +
                    "SSLPeerUnverifiedException when handshake was done: " + e);
            }
        }

        id = session.getId();
        if (!sock.isClosed() && (id == null || id.length == 0)) {
            throw new Exception("SSLSession.getId() was null or 0 length");
        }

        if (!sock.isClosed() && !session.isValid()) {
            throw new Exception("SSLSession.isValid() is false");
        }

        ret = session.getPacketBufferSize();
        if (ret == 0) {
            throw new Exception("SSLSession.getPacketBufferSize() is 0");
        }

        ret = session.getApplicationBufferSize();
        if (ret == 0) {
            throw new Exception("SSLSession.getApplicationBufferSize() is 0");
        }
    }


    private class listner implements SSLSessionBindingListener {
        private SSLSession ses;
        private boolean isBound = false;

        /**
         * Used to test if the right session was passed in
         * @param in ID to compare to local ID
         * @return true on success
         */
        protected boolean checkID(byte[] in) {
            int i;
            byte id[] = ses.getId();

            if (id.length != in.length) {
                return false;
            }

            for (i = 0; i < id.length; i++) {
                if (id[i] != in[i])
                    return false;
            }
            return true;
        }

        /**
         * Used to test host and port
         * @param host host to compare
         * @param port port to compare
         * @return true on success
         */
        protected boolean checkPeer(String host, int port) {
            if (!ses.getPeerHost().equals(host) || ses.getPeerPort() != port)
                return false;
            return true;
        }

        protected void setInvalid() {
            ses.invalidate();
        }

        protected boolean checkCipher(String in) {
            return in.equals(ses.getCipherSuite());
        }

        @Override
        public void valueBound(SSLSessionBindingEvent event) {
            ses = event.getSession();
            isBound = true;
       }

        @Override
        public void valueUnbound(SSLSessionBindingEvent event) {
            isBound = false;
        }
    }
}

