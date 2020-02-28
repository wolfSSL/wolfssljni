/* WolfSSLSocketTest.java
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

import java.util.Arrays;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Callable;
import java.util.concurrent.Future;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.FileInputStream;
import java.io.ByteArrayInputStream;
import java.net.Socket;
import java.net.ServerSocket;
import java.net.UnknownHostException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.HandshakeCompletedEvent;
import java.security.Security;
import java.security.Provider;
import java.security.KeyStore;
import java.net.InetSocketAddress;
import java.net.InetAddress;

import java.io.IOException;
import java.io.FileNotFoundException;
import java.security.KeyStoreException;
import java.security.KeyManagementException;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import com.wolfssl.provider.jsse.WolfSSLProvider;
import com.wolfssl.provider.jsse.WolfSSLSocketFactory;
import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLException;

public class WolfSSLSocketTest {

    public final static char[] jksPass = "wolfSSL test".toCharArray();
    private final static String ctxProvider = "wolfJSSE";
    private static WolfSSLTestFactory tf;

    private SSLContext ctx = null;
    protected Object portLock = new Object();

    static boolean clientFlag = false;
    static boolean serverFlag = false;

    private static String allProtocols[] = {
        "TLSv1",
        "TLSv1.1",
        "TLSv1.2",
        "TLSv1.3",
        "TLS"
    };

    private static ArrayList<String> enabledProtocols =
        new ArrayList<String>();

    /* list of SSLSocketFactories for each protocol supported */
    private static ArrayList<SSLSocketFactory> sockFactories =
        new ArrayList<SSLSocketFactory>();

    /* list of SSLSocket for each SSLSocketFactory in sockFactories */
    private static ArrayList<SSLSocket> socks = new ArrayList<SSLSocket>();

    @BeforeClass
    public static void testSetupSocketFactory() throws NoSuchProviderException,
        NoSuchAlgorithmException, IllegalStateException,
        KeyManagementException, Exception {

        SSLContext ctx;
        KeyManagerFactory km;
        TrustManagerFactory tm;
        KeyStore pKey, cert;

        System.out.println("WolfSSLSocket Class");

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
            InputStream stream = new FileInputStream(tf.clientJKS);
            pKey = KeyStore.getInstance("JKS");
            pKey.load(stream, jksPass);
            stream.close();

            stream = new FileInputStream(tf.clientJKS);
            cert = KeyStore.getInstance("JKS");
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

            SSLSocketFactory sf = ctx.getSocketFactory();
            sockFactories.add(sf);

            SSLSocket s;
            try {
                s = (SSLSocket)sf.createSocket("www.example.com", 443);
            } catch (UnknownHostException e) {
                /* skip adding, no Internet connection */
                continue;
            }

            socks.add(s);
        }
    }

    @Test
    public void testGetSupportedCipherSuites()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        System.out.print("\tgetSupportedCipherSuites()");

        for (int i = 0; i < socks.size(); i++) {
            SSLSocket s = socks.get(i);
            String[] cipherSuites = s.getSupportedCipherSuites();

            if (cipherSuites == null) {
                System.out.println("\t... failed");
                fail("SSLSocket.getSupportedCipherSuites() failed");
            }

            /* verify we return a copy */
            assertNotSame(cipherSuites, s.getSupportedCipherSuites());
        }

        System.out.println("\t... passed");
    }

    @Test
    public void testGetSetEnabledCipherSuites()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        System.out.print("\tget/setEnabledCipherSuites()");

        for (int i = 0; i < socks.size(); i++) {
            SSLSocket s = socks.get(i);
            String[] cipherSuites = s.getEnabledCipherSuites();

            if (cipherSuites == null) {
                System.out.println("\t... failed");
                fail("SSLSocket.getEnabledCipherSuites() failed");
            }

            /* verify we return a copy */
            assertNotSame(cipherSuites, s.getEnabledCipherSuites());

            /* test failure, null input */
            try {
                s.setEnabledCipherSuites(null);
                System.out.println("\t... failed");
                fail("SSLSocket.setEnabledCipherSuites() failed");
            } catch (IllegalArgumentException e) {
                /* expected */
            }

            /* test failure, empty array */
            try {
                String[] empty = {};
                s.setEnabledCipherSuites(empty);
                System.out.println("\t... failed");
                fail("SSLSocket.setEnabledCipherSuites() failed");
            } catch (IllegalArgumentException e) {
                /* expected */
            }

            /* test failure, bad value */
            try {
                String[] badvalue = { "badvalue" };
                s.setEnabledCipherSuites(badvalue);
                System.out.println("\t... failed");
                fail("SSLSocket.setEnabledCipherSuites() failed");
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
                fail("SSLSocket.setEnabledCipherSuites() failed");
            }
        }

        System.out.println("\t... passed");
    }

    @Test
    public void testGetSupportedProtocols()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        System.out.print("\tgetSupportedProtocols()");

        for (int i = 0; i < socks.size(); i++) {
            SSLSocket s = socks.get(i);
            String[] protocols = s.getSupportedProtocols();

            if (protocols == null) {
                System.out.println("\t\t... failed");
                fail("SSLSocket.getSupportedProtocols() failed");
            }

            /* verify we return a copy */
            assertNotSame(protocols, s.getSupportedProtocols());
        }

        System.out.println("\t\t... passed");
    }

    @Test
    public void testGetSetEnabledProtocols()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        System.out.print("\tget/setEnabledProtocols()");

        for (int i = 0; i < socks.size(); i++) {
            SSLSocket s = socks.get(i);
            String[] protocols = s.getEnabledProtocols();

            if (protocols == null) {
                System.out.println("\t... failed");
                fail("SSLSocket.getEnabledProtocols() failed");
            }

            /* verify we return a copy */
            assertNotSame(protocols, s.getEnabledProtocols());

            /* test failure, null input */
            try {
                s.setEnabledProtocols(null);
                System.out.println("\t\t... failed");
                fail("SSLSocket.setEnabledProtocols() failed");
            } catch (IllegalArgumentException e) {
                /* expected */
            }

            /* test failure, empty string */
            try {
                String[] empty = {};
                s.setEnabledProtocols(empty);
                System.out.println("\t\t... failed");
                fail("SSLSocket.setEnabledProtocols() failed");
            } catch (IllegalArgumentException e) {
                /* expected */
            }

            /* test failure, bad value */
            try {
                String[] badvalue = { "badvalue" };
                s.setEnabledProtocols(badvalue);
                System.out.println("\t\t... failed");
                fail("SSLSocket.setEnabledProtocols() failed");
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
                fail("SSLSocket.setEnabledProtocols() failed");
            }
        }

        System.out.println("\t... passed");
    }

    @Test
    public void testClientServerThreaded() throws Exception {

        System.out.print("\tTesting basic client/server");

        /* create new CTX */
        this.ctx = tf.createSSLContext("TLS", ctxProvider);

        /* create SSLServerSocket first to get ephemeral port */
        SSLServerSocket ss = (SSLServerSocket)ctx.getServerSocketFactory()
            .createServerSocket(0);

        TestServer server = new TestServer(this, ss);
        server.start();

        TestClient client = new TestClient(this, ss.getLocalPort());
        client.start();


        Exception srvException = server.getException();
        if (srvException != null) {
            throw srvException;
        }

        Exception cliException = client.getException();
        if (cliException != null) {
            throw cliException;
        }

        try {
            client.join(1000);
            server.join(1000);

        } catch (InterruptedException e) {
            System.out.println("interrupt happened");
            fail("Threaded client/server test failed");
        }

        System.out.println("\t... passed");
    }

    @Test
    public void testPreConsumedSocket() throws Exception {

        System.out.print("\tTesting consumed InputStream");

        /* create new CTX */
        this.ctx = tf.createSSLContext("TLS", ctxProvider);

        /* create plain TCP server socket */
        ServerSocket serverSock = new ServerSocket(0);

        /* connect TLS client to TCP server socket */
        SSLSocket cs = (SSLSocket)ctx.getSocketFactory().createSocket();
        cs.connect(new InetSocketAddress(serverSock.getLocalPort()));

        final Socket server = (Socket)serverSock.accept();

        ExecutorService es = Executors.newSingleThreadExecutor();
        Future<Void> serverFuture = es.submit(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                try {
                    /* read 5 bytes off the TCP socket */
                    byte[] tmp = new byte[5];
                    InputStream in = server.getInputStream();
                    in.read(tmp);

                    /* load them back into a new InputStream */
                    InputStream consumed = new ByteArrayInputStream(tmp);

                    /* create SSLSocket for server from Socket */
                    SSLSocket ss = (SSLSocket)((WolfSSLSocketFactory)ctx.getSocketFactory())
                        .createSocket(server, consumed, true);

                    ss.startHandshake();

                    /* read 5 bytes from client */
                    OutputStream ssOut = ss.getOutputStream();
                    byte[] outBytes = new byte[] {0x01, 0x02};
                    ssOut.write(outBytes);
                    InputStream ssIn = ss.getInputStream();
                    byte[] inBytes = new byte[2];
                    ssIn.read(inBytes);

                    ss.close();
                    server.close();

                    if (!Arrays.equals(outBytes, inBytes)) {
                        System.out.println("\t... failed");
                        fail();
                    }


                } catch (SSLException e) {
                    System.out.println("\t... failed");
                    fail();
                }
                return null;
            }
        });

        try {
            cs.startHandshake();
            InputStream csIn = cs.getInputStream();
            byte[] inBytes2 = new byte[2];
            csIn.read(inBytes2);

            OutputStream csOut = cs.getOutputStream();
            byte[] outBytes2 = new byte[] {0x01, 0x02};
            csOut.write(outBytes2);

            cs.close();

            if (!Arrays.equals(outBytes2, inBytes2)) {
                System.out.println("\t... failed");
                fail();
            }

        } catch (SSLHandshakeException e) {
            System.out.println("\t... failed");
            fail();
        }

        es.shutdown();
        serverFuture.get();

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

        /* test getter/setter on client socket */
        assertEquals(cs.getEnableSessionCreation(), true);
        cs.setEnableSessionCreation(false);
        assertEquals(cs.getEnableSessionCreation(), false);
        cs.setEnableSessionCreation(true);

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
    public void testSetUseClientMode() throws Exception {

        System.out.print("\tget/setUseClientMode()");

        /* create new CTX */
        this.ctx = tf.createSSLContext("TLS", "wolfJSSE");

        /* create SSLServerSocket first to get ephemeral port */
        SSLServerSocket ss = (SSLServerSocket)ctx.getServerSocketFactory()
            .createServerSocket(0);

        SSLSocket cs = (SSLSocket)ctx.getSocketFactory().createSocket();
        cs.connect(new InetSocketAddress(ss.getLocalPort()));

        /* test getter/setter on client socket, then restore to true */
        assertEquals(cs.getUseClientMode(), true);
        cs.setUseClientMode(false);
        assertEquals(cs.getUseClientMode(), false);
        cs.setUseClientMode(true);

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

        /* calling setUseClientMode() after handshake should throw exception */
        ss = (SSLServerSocket)ctx.getServerSocketFactory()
            .createServerSocket(0);

        cs = (SSLSocket)ctx.getSocketFactory().createSocket();
        cs.connect(new InetSocketAddress(ss.getLocalPort()));

        final SSLSocket server2 = (SSLSocket)ss.accept();

        es = Executors.newSingleThreadExecutor();
        serverFuture = es.submit(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                try {
                    server2.startHandshake();
                    server2.setUseClientMode(true);
                    System.out.println("\t\t... failed");
                    fail();
                } catch (IllegalArgumentException e) {
                    /* expected */
                }
                return null;
            }
        });

        try {
            cs.startHandshake();

        } catch (SSLHandshakeException e) {
            System.out.println("\t\t... failed");
            fail();
        }

        es.shutdown();
        serverFuture.get();
        cs.close();
        server2.close();
        ss.close();

        System.out.println("\t\t... passed");
    }

    @Test
    public void testGetSSLParameters() throws Exception {

        System.out.print("\tget/setSSLParameters()");

        /* create new CTX, SSLSocket */
        this.ctx = tf.createSSLContext("TLS", "wolfJSSE");
        SSLSocket s = (SSLSocket)ctx.getSocketFactory().createSocket();

        SSLParameters p = s.getSSLParameters();
        assertNotNull(p);

        /* TODO: this returns null for wolfJSSE. */
        /* assertNotNull(p.getAlgorithmConstraints()); */

        String[] suites = p.getCipherSuites();
        assertNotNull(suites);
        assertNotSame(suites, p.getCipherSuites());  /* should return copy */
        assertNotNull(s.getSupportedCipherSuites());
        p.setCipherSuites(s.getSupportedCipherSuites());
        assertArrayEquals(s.getSupportedCipherSuites(), p.getCipherSuites());

        assertFalse(p.getNeedClientAuth());          /* default: false */
        p.setNeedClientAuth(true);
        assertTrue(p.getNeedClientAuth());

        assertFalse(p.getWantClientAuth());          /* default: false */
        p.setWantClientAuth(true);
        assertTrue(p.getWantClientAuth());

        String[] protos = p.getProtocols();
        assertNotNull(protos);
        assertNotSame(protos, p.getProtocols());
        assertNotNull(s.getSupportedProtocols());
        p.setProtocols(s.getSupportedProtocols());
        assertArrayEquals(s.getSupportedProtocols(), p.getProtocols());

        s.close();

        System.out.println("\t\t... passed");
    }

    @Test
    public void testAddHandshakeCompletedListener() throws Exception {

        System.out.print("\taddHandshakeCompletedListener()");

        /* create new CTX */
        this.ctx = tf.createSSLContext("TLS", ctxProvider);
        this.clientFlag = false;
        this.serverFlag = false;

        /* create SSLServerSocket first to get ephemeral port */
        SSLServerSocket ss = (SSLServerSocket)ctx.getServerSocketFactory()
            .createServerSocket(0);

        SSLSocket cs = (SSLSocket)ctx.getSocketFactory().createSocket();
        cs.connect(new InetSocketAddress(ss.getLocalPort()));

        HandshakeCompletedListener clientListener =
            new HandshakeCompletedListener() {
            @Override
            public void handshakeCompleted(HandshakeCompletedEvent event) {
                /* toggle client flag */
                clientFlag = true;
            }
        };

        /* test failure on null argument */
        try {
            cs.addHandshakeCompletedListener(null);
            System.out.println("\t... failed");
            fail();
        } catch (IllegalArgumentException e) {
            /* expected */
        }

        /* test successful registration for client listener */
        try {
            cs.addHandshakeCompletedListener(clientListener);
        } catch (IllegalArgumentException e) {
            System.out.println("\t... failed");
            fail();
        }

        final SSLSocket server = (SSLSocket)ss.accept();

        HandshakeCompletedListener serverListener =
            new HandshakeCompletedListener() {
            @Override
            public void handshakeCompleted(HandshakeCompletedEvent event) {
                /* toggle client flag */
                serverFlag = true;
            }
        };

        /* test failure on null argument */
        try {
            server.addHandshakeCompletedListener(null);
            System.out.println("\t... failed");
            fail();
        } catch (IllegalArgumentException e) {
            /* expected */
        }

        /* test successful registration for server listener */
        try {
            server.addHandshakeCompletedListener(serverListener);
        } catch (IllegalArgumentException e) {
            System.out.println("\t... failed");
            fail();
        }

        ExecutorService es = Executors.newSingleThreadExecutor();
        Future<Void> serverFuture = es.submit(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                try {
                    server.startHandshake();

                } catch (SSLException e) {
                    System.out.println("\t... failed");
                    fail();
                }
                return null;
            }
        });

        try {
            cs.startHandshake();

        } catch (SSLHandshakeException e) {
            System.out.println("\t... failed");
            fail();
        }

        es.shutdown();
        serverFuture.get();
        cs.close();
        server.close();
        ss.close();

        /* verify that handshake listeners were called */
        if (clientFlag != true || serverFlag != true) {
            System.out.println("\t... failed");
            fail();
        }

        /* test removing handshake listners */
        try {
            server.removeHandshakeCompletedListener(serverListener);
        } catch (IllegalArgumentException e) {
            System.out.println("\t... failed");
            fail();
        }

        try {
            cs.removeHandshakeCompletedListener(clientListener);
        } catch (IllegalArgumentException e) {
            System.out.println("\t... failed");
            fail();
        }

        /* should throw exception if we remove one not registered */
        try {
            server.removeHandshakeCompletedListener(serverListener);
            System.out.println("\t... failed");
            fail();
        } catch (IllegalArgumentException e) {
            /* expected */
        }

        /* should throw exception if we use null argument */
        try {
            server.removeHandshakeCompletedListener(null);
            System.out.println("\t... failed");
            fail();
        } catch (IllegalArgumentException e) {
            /* expected */
        }

        System.out.println("\t... passed");
    }

    @Test
    public void testGetSession() throws Exception {

        System.out.print("\tgetSession()");

        /* create new CTX */
        this.ctx = tf.createSSLContext("TLS", ctxProvider);

        /* create SSLServerSocket first to get ephemeral port */
        SSLServerSocket ss = (SSLServerSocket)ctx.getServerSocketFactory()
            .createServerSocket(0);

        SSLSocket cs = (SSLSocket)ctx.getSocketFactory().createSocket();
        cs.connect(new InetSocketAddress(ss.getLocalPort()));

        final SSLSocket server = (SSLSocket)ss.accept();

        ExecutorService es = Executors.newSingleThreadExecutor();
        Future<Void> serverFuture = es.submit(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                try {
                    server.startHandshake();

                    /* get SSLSession */
                    SSLSession srvSess = server.getSession();
                    assertNotNull(srvSess);

                    server.close();

                } catch (SSLException e) {
                    System.out.println("\t\t\t... failed");
                    fail();
                }
                return null;
            }
        });

        try {
            cs.startHandshake();

            /* get SSLSession */
            SSLSession cliSess = cs.getSession();
            assertNotNull(cliSess);

            cs.close();

        } catch (SSLHandshakeException e) {
            System.out.println("\t\t\t... failed");
            fail();
        }

        es.shutdown();
        serverFuture.get();
        ss.close();

        System.out.println("\t\t\t... passed");
    }

    @Test
    public void testSetNeedClientAuth() throws Exception {

        System.out.print("\tsetNeedClientAuth()");

        /* create ctx, uses client keystore (cert/key) and truststore (cert) */
        this.ctx = tf.createSSLContext("TLSv1.2", ctxProvider);

        /* create SSLServerSocket first to get ephemeral port */
        SSLServerSocket ss = (SSLServerSocket)ctx.getServerSocketFactory()
            .createServerSocket(0);

        SSLSocket cs = (SSLSocket)ctx.getSocketFactory().createSocket();
        cs.connect(new InetSocketAddress(ss.getLocalPort()));

        final SSLSocket server = (SSLSocket)ss.accept();
        server.setWantClientAuth(true);
        server.setNeedClientAuth(true);

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

        /* fail case, incorrect root CA loaded to verify server cert */
        this.ctx = tf.createSSLContext("TLSv1.2", ctxProvider,
                tf.createTrustManager("SunX509", tf.serverJKS, ctxProvider),
                tf.createKeyManager("SunX509", tf.serverJKS, ctxProvider));

        ss = (SSLServerSocket)ctx.getServerSocketFactory()
            .createServerSocket(0);

        cs = (SSLSocket)ctx.getSocketFactory().createSocket();
        cs.connect(new InetSocketAddress(ss.getLocalPort()));

        final SSLSocket server2 = (SSLSocket)ss.accept();
        server2.setWantClientAuth(true);
        server2.setNeedClientAuth(true);

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

        cs = (SSLSocket)cliCtx.getSocketFactory().createSocket();
        cs.connect(new InetSocketAddress(ss.getLocalPort()));

        final SSLSocket server3 = (SSLSocket)ss.accept();
        server3.setWantClientAuth(false);
        server3.setNeedClientAuth(false);

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
    public void testProtocolTLSv10() throws Exception {

        System.out.print("\tTLS 1.0 connection test");

        /* skip if TLS 1.0 is not compiled in at native level */
        if (WolfSSL.TLSv1Enabled() == false) {
            System.out.println("\t\t... skipped");
            return;
        }

        protocolConnectionTest("TLSv1");
    }

    @Test
    public void testProtocolTLSv11() throws Exception {

        System.out.print("\tTLS 1.1 connection test");

        /* skip if TLS 1.1 is not compiled in at native level */
        if (WolfSSL.TLSv11Enabled() == false) {
            System.out.println("\t\t... skipped");
            return;
        }

        protocolConnectionTest("TLSv1.1");
    }

    @Test
    public void testProtocolTLSv12() throws Exception {

        System.out.print("\tTLS 1.2 connection test");

        /* skip if TLS 1.2 is not compiled in at native level */
        if (WolfSSL.TLSv12Enabled() == false) {
            System.out.println("\t\t... skipped");
            return;
        }

        protocolConnectionTest("TLSv1.2");
    }

    @Test
    public void testProtocolTLSv13() throws Exception {

        System.out.print("\tTLS 1.3 connection test");

        /* skip if TLS 1.3 is not compiled in at native level */
        if (WolfSSL.TLSv13Enabled() == false) {
            System.out.println("\t\t... skipped");
            return;
        }

        protocolConnectionTest("TLSv1.3");
    }

    private void protocolConnectionTest(String protocol) throws Exception {

        /* create new CTX */
        this.ctx = tf.createSSLContext(protocol, ctxProvider);

        /* create SSLServerSocket first to get ephemeral port */
        SSLServerSocket ss = (SSLServerSocket)ctx.getServerSocketFactory()
            .createServerSocket(0);

        SSLSocket cs = (SSLSocket)ctx.getSocketFactory().createSocket();
        cs.connect(new InetSocketAddress(ss.getLocalPort()));
        final SSLSocket server = (SSLSocket)ss.accept();

        ExecutorService es = Executors.newSingleThreadExecutor();
        Future<Void> serverFuture = es.submit(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                try {
                    server.startHandshake();

                } catch (SSLException e) {
                    System.out.println("\t\t... failed");
                    fail();
                }
                return null;
            }
        });

        try {
            cs.startHandshake();

        } catch (SSLHandshakeException e) {
            System.out.println("\t\t... failed");
            fail();
        }

        es.shutdown();
        serverFuture.get();
        cs.close();
        server.close();
        ss.close();

        System.out.println("\t\t... passed");
    }

    @Test
    public void testSessionResumption() throws Exception {

        byte[] sessionID1 = null;
        byte[] sessionID2 = null;
        String protocol = null;

        System.out.print("\tTesting session resumption");

        /* use TLS 1.2, else 1.1, else 1.0, else skip */
        /* TODO: TLS 1.3 handles session resumption differently */

        if (WolfSSL.TLSv12Enabled()) {
            protocol = "TLSv1.2";
        } else if (WolfSSL.TLSv11Enabled()) {
            protocol = "TLSv1.1";
        } else if (WolfSSL.TLSv1Enabled()) {
            protocol = "TLSv1.0";
        } else {
            System.out.println("\t\t... skipped");
            return;
        }

        /* create new CTX */
        this.ctx = tf.createSSLContext(protocol, ctxProvider);

        /* create SSLServerSocket first to get ephemeral port */
        final SSLServerSocket ss = (SSLServerSocket)ctx.getServerSocketFactory()
             .createServerSocket(0);

        SSLSocketFactory cliFactory = ctx.getSocketFactory();

        SSLSocket cs = (SSLSocket)cliFactory.createSocket();
        cs.connect(new InetSocketAddress(InetAddress.getLocalHost(),
                                         ss.getLocalPort()));

        /* start server */
        ExecutorService es = Executors.newSingleThreadExecutor();
        Future<Void> serverFuture = es.submit(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                try {
                    for (int i = 0; i < 2; i++) {
                        SSLSocket server = (SSLSocket)ss.accept();
                        server.startHandshake();
                        server.close();
                    }

                } catch (SSLException e) {
                    System.out.println("\t... failed");
                    fail();
                }
                return null;
            }
        });

        try {
            /* connection #1 */
            cs.startHandshake();
            sessionID1 = cs.getSession().getId();
            cs.close();

            /* connection #2, should resume */
            cs = (SSLSocket)cliFactory.createSocket();
            cs.connect(new InetSocketAddress(InetAddress.getLocalHost(),
                                             ss.getLocalPort()));
            cs.startHandshake();
            sessionID2 = cs.getSession().getId();
            cs.close();

            if (!Arrays.equals(sessionID1, sessionID2)) {
                /* session not resumed */
                System.out.println("\t... failed");
                fail();
            }

        } catch (SSLHandshakeException e) {
            System.out.println("\t... failed");
            fail();
        }


        es.shutdown();
        serverFuture.get();
        ss.close();

        System.out.println("\t... passed");
    }

    protected class TestServer extends Thread
    {
        private SSLContext ctx;
        private int port;
        private Exception exception = null;
        WolfSSLSocketTest wst;
        SSLServerSocket ss = null;

        public TestServer(WolfSSLSocketTest in, SSLServerSocket ss) {
            this.ctx = in.ctx;
            this.wst = in;
            this.ss = ss;
        }

        @Override
        public void run() {

            try {
                SSLSocket sock = (SSLSocket)ss.accept();
                sock.startHandshake();
                int in = sock.getInputStream().read();
                assertEquals(in, (int)'A');
                sock.getOutputStream().write('B');
                sock.close();

            } catch (Exception e) {
                this.exception = e;
                Logger.getLogger(WolfSSLSocketTest.class.getName())
                    .log(Level.SEVERE, null, e);
            }
        }

        public Exception getException() {
            return this.exception;
        }
    }

    protected class TestClient extends Thread
    {
        private SSLContext ctx;
        private int srvPort;
        private Exception exception = null;
        WolfSSLSocketTest wst;

        public TestClient(WolfSSLSocketTest in, int port) {
            this.ctx = in.ctx;
            this.srvPort = port;
            this.wst = in;
        }

        @Override
        public void run() {

            try {
                SSLSocket sock = (SSLSocket)ctx.getSocketFactory()
                    .createSocket();
                sock.connect(new InetSocketAddress(srvPort));
                sock.startHandshake();
                sock.getOutputStream().write('A');
                int in = sock.getInputStream().read();
                assertEquals(in, (int)'B');
                sock.close();

            } catch (Exception e) {
                this.exception = e;
                Logger.getLogger(WolfSSLSocketTest.class.getName())
                    .log(Level.SEVERE, null, e);
            }
        }

        public Exception getException() {
            return this.exception;
        }
    }
}

