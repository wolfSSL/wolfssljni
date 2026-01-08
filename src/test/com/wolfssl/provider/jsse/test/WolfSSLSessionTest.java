/* WolfSSLSessionTest.java
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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.util.concurrent.Callable;
import java.util.concurrent.Future;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;

import java.io.IOException;
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

import org.junit.BeforeClass;
import org.junit.Test;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLException;
import com.wolfssl.provider.jsse.WolfSSLProvider;

public class WolfSSLSessionTest {
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
    public void testSessionTimeAndCerts()
        throws NoSuchAlgorithmException, KeyManagementException,
               KeyStoreException, CertificateException, IOException,
               NoSuchProviderException, UnrecoverableKeyException {

        int ret;
        SSLSession session;

        /* create new SSLEngine */
        System.out.print("\tTesting session time");

        SSLContext ctx = tf.createSSLContext("TLS", engineProvider);
        SSLEngine client = ctx.createSSLEngine("server", 12345);
        SSLEngine server = ctx.createSSLEngine();
        if (client == null || server == null) {
            error("\t\t... failed");
            fail("failed to create engine");
            return;
        }

        server.setUseClientMode(false);
        server.setNeedClientAuth(false);
        client.setUseClientMode(true);
        ret = tf.testConnection(server, client, null, null, "Test reuse");
        if (ret != 0) {
            error("\t... failed");
            fail("failed to connect");
        }

        session = client.getSession();
        if (session.getCreationTime() <= 0) {
            error("\t... failed");
            fail("failed to get creation time");
        }

        if (session.getCreationTime() > session.getLastAccessedTime() ||
                session.getLastAccessedTime() <= 0) {
            error("\t... failed");
            fail("failed creation time does not equal accessed time");
        }

        pass("\t\t... passed");


        /* test certificates */
        System.out.print("\tTesting session cert");
        session = client.getSession();
        /* TODO changes back to != null once we can check for client auth */
        if (session.getLocalPrincipal() == null) {
            error("\t... failed");
            fail("Principal is null when it should not be");
        }

        try {
            /* @TODO make match SunJSSE better */
            session.getPeerPrincipal().getName();
        } catch (SSLPeerUnverifiedException e) {
            error("\t... failed");
            fail("failed to find peer principal");
        }

        try {
            session.getPeerCertificateChain();
        } catch (SSLPeerUnverifiedException e) {
            error("\t... failed");
            fail("failed to get peer certificate chain");
        }

        pass("\t\t... passed");
    }

    @Test
    public void testNullSession()
        throws NoSuchAlgorithmException, KeyManagementException,
               KeyStoreException, CertificateException, IOException,
               NoSuchProviderException, UnrecoverableKeyException {

        int ret;
        SSLSession session;

        /* create new SSLEngine */
        System.out.print("\tTesting null session");

        SSLContext ctx = tf.createSSLContext("TLS", engineProvider);
        SSLEngine client = ctx.createSSLEngine("server", 12345);
        SSLEngine server = ctx.createSSLEngine();
        if (client == null || server == null) {
            error("\t\t... failed");
            fail("failed to create engine");
            return;
        }
        session = client.getSession(); /* get null session since handshake not done */

        server.setUseClientMode(false);
        server.setNeedClientAuth(false);
        client.setUseClientMode(true);
        ret = tf.testConnection(server, client, null, null, "Test reuse");
        if (ret != 0) {
            error("\t... failed");
            fail("failed to create engine");
        }

        /* session stored before handshake should still be null */
        if (session.getId() == null) {
            error("\t... failed");
            fail("failed to get ID");
        }

        if (session.getId().length != 0) {
            error("\t... failed");
            fail("ID longer than expected");
        }

        try {
            session.getPeerCertificates();
            error("\t... failed");
            fail("Unexpected peer certificates found");
        } catch (SSLPeerUnverifiedException e) {
            /* expected to fail with unverified exception */
        }

        if (!session.getCipherSuite().equals("SSL_NULL_WITH_NULL_NULL")) {
            error("\t... failed");
            fail("Unexpected cipher suite found");
        }

        if (!session.getProtocol().equals("NONE")) {
            error("\t... failed");
            fail("Unexpected protocol found");
        }

        try {
            session.getPeerPrincipal();
            error("\t... failed");
            fail("Unexpected peer principal found");
        } catch (SSLPeerUnverifiedException e) {
            /* expected to fail here */
        }

        try {
            session.getPeerCertificateChain();
            error("\t... failed");
            fail("Unexpected peer certificate chain found");
        } catch (SSLPeerUnverifiedException e) {
            /* expected to fail here */
        }

        pass("\t\t... passed");
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

        /* create new SSLEngine */
        System.out.print("\tTesting binding session");

        SSLContext ctx = tf.createSSLContext("TLS", engineProvider);
        SSLEngine client = ctx.createSSLEngine("server", 12345);
        SSLEngine server = ctx.createSSLEngine();
        if (client == null || server == null) {
            error("\t\t... failed");
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
            error("\t\t... failed");
            fail("failed to create engine");
        }

        /* override null session set before handshake */
        session = client.getSession();
        session.putValue("testing", bound);
        if (!bound.checkID(session.getId())) {
            error("\t\t... failed");
            fail("test of ID failed");
        }

        if (!bound.checkPeer("server", 12345)) {
            error("\t\t... failed");
            fail("test of port and host fail");

        }

        try {
            if (session.getPeerCertificates() != null) {
                Certificate[] certs = session.getPeerCertificates();

                if (certs.length != 1) {
                    error("\t\t... failed");
                    fail("unexpected number of peer certs found");
                }

                if (!certs[0].getType().equals("X.509")) {
                    error("\t\t... failed");
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
                    error("\t\t... failed");
                    fail("getPeerCertificates() did not return array of type " +
                         "X509Certificate[]");
                }
            }
        } catch (SSLPeerUnverifiedException e) {
            error("\t\t... failed");
            fail("failed to get peer certificate");
        }

        if (!bound.checkCipher(server.getSession().getCipherSuite())) {
            error("\t\t... failed");
            fail("unexpected cipher suite");
        }

        session.removeValue("testing");
        if (bound.isBound) {
            error("\t\t... failed");
            fail("bound when should not be");
        }
        session.putValue("testing", bound);
        if (!bound.isBound) {
            error("\t\t... failed");
            fail("not bound when should be");
        }
        session.putValue("testing", bound2);
        if (!bound2.isBound || bound.isBound) {
            error("\t\t... failed");
            fail("override failed");
        }

        if (!bound2.checkPeer("server", 12345)) {
            error("\t\t... failed");
            fail("test of port and host fail");
        }

        if (!session.getValue("testing").equals(bound2)) {
            error("\t\t... failed");
            fail("failed to get value");
        }

        if (session.getValue("bad") != null) {
            error("\t\t... failed");
            fail("able to get bogus value");
        }

        session.putValue("testing 2", bound);
        values = session.getValueNames();
        if (values.length != 2) {
            error("\t\t... failed");
            fail("unexpected number of values");
        }

        if (!values[0].equals("testing 2") || !values[1].equals("testing")) {
            error("\t\t... failed");
            fail("unexpected value names");
        }

        try {
            session.removeValue("bad");
        } catch (IllegalArgumentException ex) {
            error("\t\t... failed");
            fail("could not remove a bogus value");
        }

        try {
            session.removeValue(null);
            error("\t\t... failed");
            fail("null sanity check failed");
        } catch (IllegalArgumentException ex) {
            /* expected to throw exception */
        }

        if (!server.getSession().getProtocol().equals(
                client.getSession().getProtocol())) {
            error("\t... failed");
            fail("protocols do not match");
        }
        pass("\t\t... passed");
    }

    @Test
    public void testSessionContext()
        throws NoSuchAlgorithmException, KeyManagementException,
               KeyStoreException, CertificateException, IOException,
               NoSuchProviderException, UnrecoverableKeyException {

        int ret;
        SSLSession session;
        SSLSessionContext context;

        /* create new SSLEngine */
        System.out.print("\tTesting session context");

        SSLContext ctx = tf.createSSLContext("TLS", engineProvider);
        SSLEngine client = ctx.createSSLEngine("server", 12345);
        SSLEngine server = ctx.createSSLEngine();
        if (client == null || server == null) {
            error("\t\t... failed");
            fail("failed to create engine");
            return;
        }

        server.setUseClientMode(false);
        server.setNeedClientAuth(false);
        client.setUseClientMode(true);
        ret = tf.testConnection(server, client, null, null, "Test reuse");
        if (ret != 0) {
            error("\t\t... failed");
            fail("failed to create engine");
        }
        session = client.getSession();
        context = session.getSessionContext();

        if (!session.getProtocol().equals("TLSv1.3")) {
            /* TLSv1.3 uses session tickets */
            context.setSessionTimeout(100);
            if (context.getSessionTimeout() != 100) {
                error("\t\t... failed");
                fail("failed to set session timeout");
            }
        }

        /* @TODO difference in cache size for SunJSSE vs wolfJSSE  0 vs 33 */
        context.getSessionCacheSize();

        /* @TODO additional tests around setting session cache size */
        context.setSessionCacheSize(2);
        pass("\t\t... passed");
    }

    @Test
    public void testGetSessionInSocketConnection() throws Exception {

        String protocol = null;
        SSLContext ctx = null;

        System.out.print("\tTesting SSLSocket.getSession");

        if (WolfSSL.TLSv12Enabled()) {
            protocol = "TLSv1.2";
        } else if (WolfSSL.TLSv11Enabled()) {
            protocol = "TLSv1.1";
        } else if (WolfSSL.TLSv1Enabled()) {
            protocol = "TLSv1.0";
        } else {
            System.out.println("\t... skipped");
            return;
        }

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
                    error("\t... failed");
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
            error("\t... failed");
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

        pass("\t... passed");
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

        System.out.print("\tTesting Signature Schemes");

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
                error("\t... failed");
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
                error("\t... failed");
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
                error("\t... failed");
                fail("failed to create engine");
                return;
            }

            server.setUseClientMode(false);
            server.setNeedClientAuth(false);
            client.setUseClientMode(true);

            ret = tf.testConnection(server, client, null, null,
                "Test sig match");
            if (ret != 0) {
                error("\t... failed");
                fail("Handshake failed with matching signature schemes");
            }

            pass("\t... passed");

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

        System.out.print("\tTesting hashCode()");

        SSLContext ctx = tf.createSSLContext("TLS", engineProvider);
        SSLEngine client = ctx.createSSLEngine("localhost", 12345);
        SSLEngine server = ctx.createSSLEngine();

        if (client == null || server == null) {
            error("\t\t... failed");
            fail("failed to create engine");
            return;
        }

        server.setUseClientMode(false);
        server.setNeedClientAuth(false);
        client.setUseClientMode(true);

        ret = tf.testConnection(server, client, null, null, "Test hashCode");
        if (ret != 0) {
            error("\t\t... failed");
            fail("failed to create connection");
            return;
        }

        session = client.getSession();
        if (session == null) {
            error("\t\t... failed");
            fail("SSLEngine.getSession() returned null");
            return;
        }

        /* Test that hashCode() method is declared in the session class
         * (not just inherited from Object). */
        try {
            session.getClass().getDeclaredMethod("hashCode", new Class<?>[0]);
        } catch (NoSuchMethodException e) {
            error("\t\t... failed");
            fail("SSLSession class does not declare hashCode() method");
            return;
        }

        /* Test that hashCode() returns consistent value */
        int hash1 = session.hashCode();
        int hash2 = session.hashCode();
        if (hash1 != hash2) {
            error("\t\t... failed");
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
            error("\t\t... failed");
            fail("failed to create second connection");
            return;
        }

        SSLSession session2 = client2.getSession();
        if (session2 == null) {
            error("\t\t... failed");
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

        pass("\t\t... passed");
    }

    @Test
    public void testSessionEquals()
        throws NoSuchAlgorithmException, KeyManagementException,
               KeyStoreException, CertificateException, IOException,
               NoSuchProviderException, UnrecoverableKeyException {

        int ret;
        SSLSession session;

        System.out.print("\tTesting equals()");

        SSLContext ctx = tf.createSSLContext("TLS", engineProvider);
        SSLEngine client = ctx.createSSLEngine("localhost", 12345);
        SSLEngine server = ctx.createSSLEngine();

        if (client == null || server == null) {
            error("\t\t... failed");
            fail("failed to create engine");
            return;
        }

        server.setUseClientMode(false);
        server.setNeedClientAuth(false);
        client.setUseClientMode(true);

        ret = tf.testConnection(server, client, null, null, "Test equals");
        if (ret != 0) {
            error("\t\t... failed");
            fail("failed to create connection");
            return;
        }

        session = client.getSession();
        if (session == null) {
            error("\t\t... failed");
            fail("SSLEngine.getSession() returned null");
            return;
        }

        /* Test that equals() method is declared in the session class
         * (not just inherited from Object). */
        try {
            session.getClass().getDeclaredMethod("equals",
                new Class<?>[] { Object.class });
        } catch (NoSuchMethodException e) {
            error("\t\t... failed");
            fail("SSLSession class does not declare equals() method");
            return;
        }

        /* Test reflexivity: session.equals(session) should be true */
        if (!session.equals(session)) {
            error("\t\t... failed");
            fail("SSLSession.equals() reflexivity failed");
            return;
        }

        /* Test null: session.equals(null) should be false */
        if (session.equals(null)) {
            error("\t\t... failed");
            fail("SSLSession.equals(null) should return false");
            return;
        }

        /* Test different type: session.equals(Object) should return false
         * when passed an incompatible type. This is intentional to verify
         * the equals() implementation handles type mismatches correctly. */
        Object differentType = "not a session";
        if (session.equals(differentType)) {
            error("\t\t... failed");
            fail("SSLSession.equals(Object) should return false for " +
                 "incompatible type");
            return;
        }

        /* Test hashCode/equals contract: equal objects must have same hash */
        if (session.equals(session) &&
            session.hashCode() != session.hashCode()) {
            error("\t\t... failed");
            fail("Equal sessions have different hashCodes");
            return;
        }

        pass("\t\t... passed");
    }

    @Test
    public void testSessionHashCodeBeforeHandshake()
        throws NoSuchAlgorithmException, KeyManagementException,
               KeyStoreException, CertificateException, IOException,
               NoSuchProviderException, UnrecoverableKeyException {

        System.out.print("\tTesting hashCode() before HS");

        SSLContext ctx = tf.createSSLContext("TLS", engineProvider);
        SSLEngine engine = ctx.createSSLEngine("localhost", 12345);

        if (engine == null) {
            error("\t... failed");
            fail("failed to create engine");
            return;
        }

        engine.setUseClientMode(true);

        /* Get session before handshake - may have null session ID */
        SSLSession session = engine.getSession();
        if (session == null) {
            /* Some implementations return null before handshake */
            pass("\t... passed (null session)");
            return;
        }

        /* Test that hashCode() does not throw even if getId() returns
         * null or empty (session not yet established) */
        try {
            int hash = session.hashCode();
            /* hashCode should work without throwing */
        } catch (Exception e) {
            error("\t... failed");
            fail("hashCode() threw exception before handshake: " +
                 e.getMessage());
            return;
        }

        /* Test that equals() does not throw either */
        try {
            boolean eq = session.equals(session);
        } catch (Exception e) {
            error("\t... failed");
            fail("equals() threw exception before handshake: " +
                 e.getMessage());
            return;
        }

        pass("\t... passed");
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


    private void pass(String msg) {
        WolfSSLTestFactory.pass(msg);
    }

    private void error(String msg) {
        WolfSSLTestFactory.fail(msg);
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
