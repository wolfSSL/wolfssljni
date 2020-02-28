/* WolfSSLServerSocketTest.java
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

import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Callable;
import java.util.concurrent.Future;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.FileNotFoundException;
import java.net.InetSocketAddress;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import java.security.KeyStore;
import java.security.Security;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;

import com.wolfssl.WolfSSLException;
import com.wolfssl.provider.jsse.WolfSSLProvider;

public class WolfSSLServerSocketTest {

    private final static char[] jksPass = "wolfSSL test".toCharArray();
    private final static String ctxProvider = "wolfJSSE";
    private static WolfSSLTestFactory tf;
    private SSLContext ctx = null;
    private static KeyManagerFactory km;

    private static String allProtocols[] = {
        "TLSv1",
        "TLSv1.1",
        "TLSv1.2",
        "TLS"
    };

    private static ArrayList<String> enabledProtocols =
        new ArrayList<String>();

    /* list of SSLServerSocketFactories for each protocol supported */
    private static ArrayList<SSLServerSocketFactory> sockFactories =
        new ArrayList<SSLServerSocketFactory>();

    @BeforeClass
    public static void testSetupSocketFactory() throws NoSuchProviderException,
        NoSuchAlgorithmException, IllegalStateException,
        KeyManagementException, Exception {

        SSLContext ctx;
        TrustManagerFactory tm;
        KeyStore pKey, cert;

        System.out.println("WolfSSLServerSocket Class");

        tf = new WolfSSLTestFactory();

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

        try {
            /* set up KeyStore */
            InputStream stream = new FileInputStream(tf.serverJKS);
            pKey = KeyStore.getInstance(tf.keyStoreType);
            pKey.load(stream, jksPass);
            stream.close();

            stream = new FileInputStream(tf.serverJKS);
            cert = KeyStore.getInstance(tf.keyStoreType);
            cert.load(stream, jksPass);
            stream.close();

            /* trust manager (certificates) */
            tm = TrustManagerFactory.getInstance("SunX509");
            tm.init(cert);

            /* load private key */
            km = KeyManagerFactory.getInstance("SunX509");
            km.init(pKey, jksPass);

        } catch (KeyStoreException kse) {
            throw new Exception(kse);
        } catch (FileNotFoundException fnfe) {
            throw new Exception(fnfe);
        } catch (IOException ioe) {
            throw new Exception(ioe);
        }

        for (int i = 0; i < enabledProtocols.size(); i++) {
            ctx = SSLContext.getInstance(enabledProtocols.get(i), "wolfJSSE");

            ctx.init(km.getKeyManagers(), tm.getTrustManagers(), null);

            SSLServerSocketFactory sf = ctx.getServerSocketFactory();
            sockFactories.add(sf);
        }
    }

    @Test
    public void testGetSupportedCipherSuites()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               IOException {

        System.out.print("\tgetSupportedCipherSuites()");

        for (int i = 0; i < sockFactories.size(); i++) {
            SSLServerSocketFactory sf = sockFactories.get(i);
            SSLServerSocket s = (SSLServerSocket)sf.createServerSocket(0);
            String[] cipherSuites = s.getSupportedCipherSuites();
            s.close();

            if (cipherSuites == null) {
                System.out.println("\t... failed");
                fail("SSLServerSocket.getSupportedCipherSuites() failed");
            }
        }

        System.out.println("\t... passed");
    }

    @Test
    public void testGetEnabledCipherSuites()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               IOException {

        int port = 11118;
        System.out.print("\tgetEnabledCipherSuites()");

        for (int i = 0; i < sockFactories.size(); i++) {
            SSLServerSocketFactory sf = sockFactories.get(i);
            SSLServerSocket s = (SSLServerSocket)sf.createServerSocket(0);
            String[] cipherSuites = s.getEnabledCipherSuites();
            s.close();

            /* should be null since we haven't set them */
            if (cipherSuites == null) {
                System.out.println("\t... failed");
                fail("SSLServerSocket.getEnabledCipherSuites() failed");
            }
        }

        System.out.println("\t... passed");
    }

    @Test
    public void testGetSetEnabledCipherSuites()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               IOException {

        System.out.print("\tget/setEnabledCipherSuites()");

        for (int i = 0; i < sockFactories.size(); i++) {
            SSLServerSocketFactory sf = sockFactories.get(i);
            SSLServerSocket s = (SSLServerSocket)sf.createServerSocket(0);
            String[] cipherSuites = s.getEnabledCipherSuites();

            if (cipherSuites == null) {
                System.out.println("\t... failed");
                fail("getEnabledCipherSuites() failed");
            }

            /* verify we return a copy */
            assertNotSame(cipherSuites, s.getEnabledCipherSuites());

            /* test failure, null input */
            try {
                s.setEnabledCipherSuites(null);
                System.out.println("\t... failed");
                fail("setEnabledCipherSuites() failed");
            } catch (IllegalArgumentException e) {
                /* expected */
            }

            /* test failure, empty array */
            try {
                String[] empty = {};
                s.setEnabledCipherSuites(empty);
                System.out.println("\t... failed");
                fail("setEnabledCipherSuites() failed");
            } catch (IllegalArgumentException e) {
                /* expected */
            }

            /* test failure, bad value */
            try {
                String[] badvalue = { "badvalue" };
                s.setEnabledCipherSuites(badvalue);
                System.out.println("\t... failed");
                fail("setEnabledCipherSuites() failed");
            } catch (IllegalArgumentException e) {
                /* expected */
            }

            /* test set from supported suites */
            String[] suites = s.getSupportedCipherSuites();
            s.setEnabledCipherSuites(suites);

            /* test set from enabled suites */
            suites = s.getEnabledCipherSuites();
            s.setEnabledCipherSuites(suites);

            /* test that set works, using get to check */
            String[] oneSuite = {suites[1]};
            s.setEnabledCipherSuites(oneSuite);
            String[] after = s.getEnabledCipherSuites();
            if (after.length != 1 || !after[0].equals(oneSuite[0])) {
                System.out.println("\t... failed");
                fail("setEnabledCipherSuites() failed");
            }
        }

        System.out.println("\t... passed");
    }

    @Test
    public void testGetSupportedProtocols()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               IOException {

        System.out.print("\tgetSupportedProtocols()");

        for (int i = 0; i < sockFactories.size(); i++) {
            SSLServerSocketFactory sf = sockFactories.get(i);
            SSLServerSocket s = (SSLServerSocket)sf.createServerSocket(0);
            String[] protocols = s.getSupportedProtocols();

            if (protocols == null) {
                System.out.println("\t\t... failed");
                fail("getSupportedProtocols() failed");
            }

            /* verify we return a copy */
            assertNotSame(protocols, s.getSupportedProtocols());
        }

        System.out.println("\t\t... passed");
    }

    @Test
    public void testGetSetEnabledProtocols()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               IOException {

        System.out.print("\tget/setEnabledProtocols()");

        for (int i = 0; i < sockFactories.size(); i++) {
            SSLServerSocketFactory sf = sockFactories.get(i);
            SSLServerSocket s = (SSLServerSocket)sf.createServerSocket(0);
            String[] protocols = s.getEnabledProtocols();

            if (protocols == null) {
                System.out.println("\t... failed");
                fail("getEnabledProtocols() failed");
            }

            /* verify we return a copy */
            assertNotSame(protocols, s.getEnabledProtocols());

            /* test failure, null input */
            try {
                s.setEnabledProtocols(null);
                System.out.println("\t... failed");
                fail("setEnabledProtocols() failed");
            } catch (IllegalArgumentException e) {
                /* expected */
            }

            /* test failure, empty string */
            try {
                String[] empty = {};
                s.setEnabledProtocols(empty);
                System.out.println("\t... failed");
                fail("setEnabledProtocols() failed");
            } catch (IllegalArgumentException e) {
                /* expected */
            }

            /* test failure, bad value */
            try {
                String[] badvalue = { "badvalue" };
                s.setEnabledProtocols(badvalue);
                System.out.println("\t... failed");
                fail("setEnabledProtocols() failed");
            } catch (IllegalArgumentException e) {
                /* expected */
            }

            /* test set from supported protocols */
            String[] protos = s.getSupportedProtocols();
            s.setEnabledProtocols(protos);

            /* test set from enabled protos */
            protos = s.getEnabledProtocols();
            s.setEnabledProtocols(protos);

            /* test that set works, using get to check */
            String[] oneProto = {protos[0]};
            s.setEnabledProtocols(oneProto);
            String[] after = s.getEnabledProtocols();
            if (after.length != 1 || !after[0].equals(oneProto[0])) {
                System.out.println("\t... failed");
                fail("setEnabledProtocols() failed");
            }
        }

        System.out.println("\t... passed");
    }

    @Test
    public void testEnableSessionCreation() throws Exception {

        System.out.print("\tget/setEnableSessionCreation()");

        /* create new CTX */
        this.ctx = tf.createSSLContext("TLS", ctxProvider);

        /* create SSLServerSocket first to get ephemeral port */
        SSLServerSocket ss = (SSLServerSocket)ctx.getServerSocketFactory()
            .createServerSocket(0);

        SSLSocket cs = (SSLSocket)ctx.getSocketFactory().createSocket();
        cs.connect(new InetSocketAddress(ss.getLocalPort()));

        /* test getter/setter on server socket */
        assertEquals(ss.getEnableSessionCreation(), true);
        ss.setEnableSessionCreation(false);
        assertEquals(ss.getEnableSessionCreation(), false);
        ss.setEnableSessionCreation(true);

        final SSLSocket server = (SSLSocket)ss.accept();

        /* should default to true */
        assertEquals(server.getEnableSessionCreation(), true);

        /* disable session creation on server socket, should produce error */
        server.setEnableSessionCreation(false);

        /* verify getter works */
        assertEquals(server.getEnableSessionCreation(), false);

        ExecutorService es = Executors.newSingleThreadExecutor();
        Future<Void> serverFuture = es.submit(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                try {
                    server.startHandshake();
                    System.out.println("\t... failed");
                    fail();
                } catch (SSLException e) {
                    /* expected, SSLSocket not allowed to make new sessions */
                }
                return null;
            }
        });

        try {
            cs.startHandshake();
            System.out.println("\t... failed");
            fail();

        } catch (SSLHandshakeException e) {
            /* expected, server should send alert back to client */
        }

        es.shutdown();
        serverFuture.get();
        cs.close();
        server.close();
        ss.close();

        System.out.println("\t... passed");
    }

    @Test
    public void testSetNeedClientAuth() throws Exception {

        System.out.print("\tsetNeedClientAuth()");

        /* create ctx, uses client keystore (cert/key) and truststore (cert) */
        this.ctx = tf.createSSLContext("TLS", ctxProvider);

        /* create SSLServerSocket first to get ephemeral port */
        SSLServerSocket ss = (SSLServerSocket)ctx.getServerSocketFactory()
            .createServerSocket(0);

        ss.setWantClientAuth(true);
        assertTrue(ss.getWantClientAuth());
        ss.setNeedClientAuth(true);
        assertTrue(ss.getNeedClientAuth());

        SSLSocket cs = (SSLSocket)ctx.getSocketFactory().createSocket();
        cs.connect(new InetSocketAddress(ss.getLocalPort()));

        final SSLSocket server = (SSLSocket)ss.accept();

        /* should pass with mutual auth enabled */
        ExecutorService es = Executors.newSingleThreadExecutor();
        Future<Void> serverFuture = es.submit(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                try {
                    server.startHandshake();
                    server.close();

                } catch (SSLException e) {
                    System.out.println("\t... failed");
                    fail();
                }
                return null;
            }
        });

        try {
            cs.startHandshake();
            cs.close();

        } catch (SSLHandshakeException e) {
            System.out.println("\t... failed");
            fail();
        }

        es.shutdown();
        serverFuture.get();
        ss.close();

        /* fail case, incorrect root CA loaded to verify server cert.
         * serverJKS doesn't verify serverJKS */
        this.ctx = tf.createSSLContext("TLSv1.2", ctxProvider,
                tf.createTrustManager("SunX509", tf.serverJKS, ctxProvider),
                tf.createKeyManager("SunX509", tf.serverJKS, ctxProvider));

        ss = (SSLServerSocket)ctx.getServerSocketFactory()
            .createServerSocket(0);
        ss.setWantClientAuth(true);
        ss.setNeedClientAuth(true);

        cs = (SSLSocket)ctx.getSocketFactory().createSocket();
        cs.connect(new InetSocketAddress(ss.getLocalPort()));

        final SSLSocket server2 = (SSLSocket)ss.accept();

        /* should pass with mutual auth enabled */
        es = Executors.newSingleThreadExecutor();
        serverFuture = es.submit(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                try {
                    server2.startHandshake();
                    System.out.println("\t\t... failed");
                    fail();

                } catch (SSLException e) {
                    /* expected */
                    server2.close();
                }
                return null;
            }
        });

        try {
            cs.startHandshake();
            System.out.println("\t\t... failed");
            fail();

        } catch (SSLHandshakeException e) {
            /* expected */
            if (!e.toString().contains("ASN no signer")) {
                System.out.println("\t\t... failed");
                fail();
            }
            cs.close();
        }

        es.shutdown();
        serverFuture.get();
        ss.close();

        /* same as fail case, but should pass with needClientAuth disabled */
        /* server doesn't have correct CA to authenticate client, but should
           pass with setNeedClientAuth(false) */
        SSLContext srvCtx = tf.createSSLContext("TLSv1.2", ctxProvider,
                tf.createTrustManager("SunX509", tf.serverJKS, ctxProvider),
                tf.createKeyManager("SunX509", tf.serverJKS, ctxProvider));

        /* client has correct CA to authenticate server */
        SSLContext cliCtx = tf.createSSLContext("TLSv1.2", ctxProvider,
                tf.createTrustManager("SunX509", tf.clientJKS, ctxProvider),
                tf.createKeyManager("SunX509", tf.clientJKS, ctxProvider));

        ss = (SSLServerSocket)srvCtx.getServerSocketFactory()
            .createServerSocket(0);
        ss.setWantClientAuth(false);
        ss.setNeedClientAuth(false);

        cs = (SSLSocket)cliCtx.getSocketFactory().createSocket();
        cs.connect(new InetSocketAddress(ss.getLocalPort()));

        final SSLSocket server3 = (SSLSocket)ss.accept();

        /* should pass with mutual auth enabled */
        es = Executors.newSingleThreadExecutor();
        serverFuture = es.submit(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                try {
                    server3.startHandshake();
                    server3.close();

                } catch (SSLException e) {
                    System.out.println("\t\t... failed");
                    fail();
                }
                return null;
            }
        });

        try {
            cs.startHandshake();
            cs.close();

        } catch (SSLHandshakeException e) {
            System.out.println("\t\t... failed");
            fail();
        }

        es.shutdown();
        serverFuture.get();
        ss.close();

        System.out.println("\t\t... passed");
    }

    @Test
    public void testSetUseClientMode() throws Exception {

        System.out.print("\tget/setUseClientMode()");

        /* create new CTX */
        this.ctx = tf.createSSLContext("TLS", "wolfJSSE");

        /* create SSLServerSocket first to get ephemeral port */
        SSLServerSocket ss = (SSLServerSocket)ctx.getServerSocketFactory()
            .createServerSocket(0);

        /* test getter/setter on server socket, then restore to false */
        assertEquals(ss.getUseClientMode(), false);
        ss.setUseClientMode(true);
        assertEquals(ss.getUseClientMode(), true);
        ss.setUseClientMode(false);

        SSLSocket cs = (SSLSocket)ctx.getSocketFactory().createSocket();
        cs.connect(new InetSocketAddress(ss.getLocalPort()));

        final SSLSocket server = (SSLSocket)ss.accept();

        /* should default to false */
        assertEquals(server.getUseClientMode(), false);

        /* set client mode on server socket, should produce exception */
        server.setUseClientMode(true);

        /* verify getter works */
        assertEquals(server.getUseClientMode(), true);

        ExecutorService es = Executors.newSingleThreadExecutor();
        Future<Void> serverFuture = es.submit(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                try {
                    server.startHandshake();
                    System.out.println("\t\t... failed");
                    fail();
                } catch (SSLHandshakeException e) {
                    /* expected: Out of order message, fatal */
                }
                return null;
            }
        });

        try {
            cs.startHandshake();
            System.out.println("\t\t... failed");
            fail();

        } catch (SSLHandshakeException e) {
            /* expected, Out of order message, fatal */
        }

        es.shutdown();
        serverFuture.get();
        cs.close();
        server.close();
        ss.close();

        System.out.println("\t\t... passed");
    }

    @Test
    public void testCustomTrustManager() throws Exception {

        System.out.print("\tCustom TrustManager - ALL");

        /* TrustManager that trusts all certificates */
        TrustManager[] trustAllCerts = {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
                public void checkClientTrusted(X509Certificate[] xc,
                                               String type) {
                }
                public void checkServerTrusted(X509Certificate[] xc,
                                               String type) {
                }
            }
        };

        /* create new CTX */
        this.ctx = SSLContext.getInstance("TLS", "wolfJSSE");
        this.ctx.init(km.getKeyManagers(), trustAllCerts, new SecureRandom());

        /* create SSLServerSocket first to get ephemeral port */
        SSLServerSocket ss = (SSLServerSocket)ctx.getServerSocketFactory()
            .createServerSocket(0);
        ss.setWantClientAuth(true);
        ss.setNeedClientAuth(true);

        SSLSocket cs = (SSLSocket)ctx.getSocketFactory().createSocket();
        cs.connect(new InetSocketAddress(ss.getLocalPort()));

        final SSLSocket server = (SSLSocket)ss.accept();

        ExecutorService es = Executors.newSingleThreadExecutor();
        Future<Void> serverFuture = es.submit(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                try {
                    server.startHandshake();
                } catch (SSLHandshakeException e) {
                    e.printStackTrace();
                    /* should not fail, trust all certs */
                    System.out.println("\t... failed");
                    fail();
                }
                return null;
            }
        });

        try {
            cs.startHandshake();
        } catch (SSLHandshakeException e) {
            e.printStackTrace();
            System.out.println("\t... failed");
            fail();
        }

        es.shutdown();
        serverFuture.get();
        cs.close();
        server.close();
        ss.close();

        System.out.println("\t... passed");
    }

    @Test
    public void testCustomTrustManagerNone() throws Exception {

        System.out.print("\tCustom TrustManager - NONE");

        /* TrustManager that trusts no certificates */
        TrustManager[] trustNoCerts = {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
                public void checkClientTrusted(X509Certificate[] xc,
                                       String type) throws CertificateException{
                    throw new CertificateException();
                }
                public void checkServerTrusted(X509Certificate[] xc,
                                       String type) throws CertificateException{
                    throw new CertificateException();
                }
            }
        };

        /* create new CTX */
        this.ctx = SSLContext.getInstance("TLS", "wolfJSSE");
        this.ctx.init(km.getKeyManagers(), trustNoCerts, new SecureRandom());

        /* create SSLServerSocket first to get ephemeral port */
        SSLServerSocket ss = (SSLServerSocket)ctx.getServerSocketFactory()
            .createServerSocket(0);
        ss.setWantClientAuth(true);
        ss.setNeedClientAuth(true);

        SSLSocket cs = (SSLSocket)ctx.getSocketFactory().createSocket();
        cs.connect(new InetSocketAddress(ss.getLocalPort()));

        final SSLSocket server = (SSLSocket)ss.accept();

        ExecutorService es = Executors.newSingleThreadExecutor();
        Future<Void> serverFuture = es.submit(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                try {
                    server.startHandshake();
                    System.out.println("\t... failed");
                    fail();
                } catch (SSLHandshakeException e) {
                    /* should fail, trust no certs */
                }
                return null;
            }
        });

        try {
            cs.startHandshake();
            System.out.println("\t... failed");
            fail();
        } catch (SSLHandshakeException e) {
            /* should fail, trust no certs */
        }

        es.shutdown();
        serverFuture.get();
        cs.close();
        server.close();
        ss.close();

        System.out.println("\t... passed");
    }
}

