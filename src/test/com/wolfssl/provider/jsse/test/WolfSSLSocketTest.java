/* WolfSSLSocketTest.java
 *
 * Copyright (C) 2006-2018 wolfSSL Inc.
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
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Callable;
import java.util.concurrent.Future;

import com.wolfssl.provider.jsse.WolfSSLSocketFactory;

import java.io.FileInputStream;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
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

import java.io.IOException;
import java.io.FileNotFoundException;
import java.security.KeyStoreException;
import java.security.KeyManagementException;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import com.wolfssl.provider.jsse.WolfSSLProvider;

public class WolfSSLSocketTest {

    public final static String clientJKS = "./examples/provider/client.jks";
    public final static String serverJKS = "./examples/provider/server.jks";
    public final static char[] jksPass = "wolfSSL test".toCharArray();
    private final static String ctxProvider = "wolfJSSE";
    private static WolfSSLTestFactory tf;

    private SSLContext ctx = null;
    protected Object portLock = new Object();

    static boolean clientFlag = false;
    static boolean serverFlag = false;

    private static String allProtocols[] = {
        "TLSV1",
        "TLSV1.1",
        "TLSV1.2",
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
        Security.addProvider(new WolfSSLProvider());

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
            /* set up KeyStore */
            pKey = KeyStore.getInstance("JKS");
            pKey.load(new FileInputStream(clientJKS), jksPass);
            cert = KeyStore.getInstance("JKS");
            cert.load(new FileInputStream(clientJKS), jksPass);

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
            SSLSocket s = (SSLSocket)sf.createSocket("www.example.com", 443);
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

            if (cipherSuites != null) {
                System.out.println("\t... failed");
                fail("SSLSocket.getEnabledCipherSuites() failed");
            }

            /* verify we return a copy */
            /* TODO: uncomment when fixed */
            //assertNotSame(cipherSuites, s.getEnabledCipherSuites());

            /* test failure, null input */
            /* TODO: uncomment when fixed */
            //try {
            //    s.setEnabledCipherSuites(null);
            //    System.out.println("\t... failed");
            //    fail("SSLSocket.setEnabledCipherSuites() failed");
            //} catch (IllegalArgumentException e) {
                /* expected */
            //}

            /* test failure, empty array */
            /* TODO: uncomment when fixed */
            //try {
            //    String[] empty = {};
            //    s.setEnabledCipherSuites(empty);
            //    System.out.println("\t... failed");
            //    fail("SSLSocket.setEnabledCipherSuites() failed");
            //} catch (IllegalArgumentException e) {
                /* expected */
            //}

            /* test failure, bad value */
            /* TODO: uncomment when fixed */
            //try {
            //    String[] badvalue = { "badvalue" };
            //    s.setEnabledCipherSuites(badvalue);
            //    System.out.println("\t... failed");
            //    fail("SSLSocket.setEnabledCipherSuites() failed");
            //} catch (IllegalArgumentException e) {
                /* expected */
            //}

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

            if (protocols != null) {
                System.out.println("\t\t... failed");
                fail("SSLSocket.getEnabledProtocols() failed");
            }

            /* verify we return a copy */
            /* TODO: uncomment when fixed */
            //assertNotSame(protocols, s.getEnabledProtocols());

            /* test failure, null input */
            /* TODO: uncomment when fixed */
            //try {
            //    s.setEnabledProtocols(null);
            //    System.out.println("\t\t... failed");
            //    fail("SSLSocket.setEnabledProtocols() failed");
            //} catch (IllegalArgumentException e) {
                /* expected */
            //}

            /* test failure, empty string */
            /* TODO: uncomment when fixed */
            //try {
            //    String[] empty = {};
            //    s.setEnabledProtocols(empty);
            //    System.out.println("\t\t... failed");
            //    fail("SSLSocket.setEnabledProtocols() failed");
            //} catch (IllegalArgumentException e) {
                /* expected */
            //}

            /* test failure, bad value */
            /* TODO: uncomment when fixed */
            //try {
            //    String[] badvalue = { "badvalue" };
            //    s.setEnabledProtocols(badvalue);
            //    System.out.println("\t\t... failed");
            //    fail("SSLSocket.setEnabledProtocols() failed");
            //} catch (IllegalArgumentException e) {
                /* expected */
            //}

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
                System.out.println("\t\t... failed");
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

