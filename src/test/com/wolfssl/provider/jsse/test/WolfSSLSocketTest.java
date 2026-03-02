/* WolfSSLSocketTest.java
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

import org.junit.Test;
import org.junit.BeforeClass;
import static org.junit.Assert.*;

import java.util.List;
import java.util.Arrays;
import java.util.Collection;
import java.util.ArrayList;
import java.util.concurrent.Callable;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicIntegerArray;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.FileInputStream;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.net.Socket;
import java.net.ServerSocket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.ConnectException;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
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
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.lang.reflect.Field;
import java.io.BufferedInputStream;
import java.util.Base64;

import com.wolfssl.provider.jsse.WolfSSLProvider;
import com.wolfssl.provider.jsse.WolfSSLSocketFactory;
import com.wolfssl.provider.jsse.WolfSSLSocket;
import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLException;

/* Tests run by this class:
    public void testGetSupportedCipherSuites();
    public void testGetSetEnabledCipherSuites();
    public void testGetSupportedProtocols();
    public void testGetSetEnabledProtocols();
    public void testClientServerThreaded();
    public void testExtendedThreadingUse();
    public void testPreConsumedSocket();
    public void testCreateSocketNullHost();
    public void testEnableSessionCreation();
    public void testSetUseClientMode();
    public void testGetSSLParameters();
    public void testAddHandshakeCompletedListener();
    public void testGetSession();
    public void testSetNeedClientAuth();
    public void testProtocolTLSv10();
    public void testProtocolTLSv11();
    public void testProtocolTLSv12();
    public void testProtocolTLSv13();
    public void testSessionResumption();
    public void testSessionResumptionWithTicketEnabled();
    public void testDoubleSocketClose();
    public void testSocketConnectException();
    public void testSocketCloseInterruptsWrite();
    public void testSocketCloseInterruptsRead();
    public void testSSLHandshakeExceptionCauseChain();
 */
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
            e.printStackTrace();
        }

        try {
            /* set up KeyStore */
            InputStream stream = new FileInputStream(tf.clientJKS);
            pKey = KeyStore.getInstance(tf.keyStoreType);
            pKey.load(stream, jksPass);
            stream.close();

            stream = new FileInputStream(tf.clientJKS);
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

            SSLSocketFactory sf = ctx.getSocketFactory();
            sockFactories.add(sf);

            SSLSocket s;
            try {
                s = (SSLSocket)sf.createSocket("www.example.com", 443);
            } catch (Exception e) {
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
    public void testServerUsesClientCipherSuitePreference() throws Exception {

        System.out.print("\tTesting client suite preference");

        this.ctx = tf.createSSLContext("TLS", "wolfJSSE");

        String[] serverSuites = {
            "TLS_AES_256_GCM_SHA384",
            "TLS_AES_128_GCM_SHA256"
        };

        String[] clientSuites = {
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384"
        };

        /* --- Case 1: default (server order) --- */
        SSLServerSocket ss1 = (SSLServerSocket)ctx.getServerSocketFactory()
            .createServerSocket(0);
        ss1.setEnabledCipherSuites(serverSuites);

        SSLSocket cs1 = (SSLSocket)ctx.getSocketFactory().createSocket();
        cs1.setEnabledCipherSuites(clientSuites);
        cs1.connect(new InetSocketAddress(ss1.getLocalPort()));

        final SSLSocket server1 = (SSLSocket)ss1.accept();

        ExecutorService es = Executors.newSingleThreadExecutor();
        Future<Void> f1 = es.submit(() -> {
            server1.startHandshake();
            return null;
        });

        cs1.startHandshake();
        f1.get();

        String chosen1 = cs1.getSession().getCipherSuite();
        /* Note: WolfSSL may report TLS 1.3 ciphers in IANA standard or wolfSSL
         * alias depending on wolfSSL configuration. */
        if (!"TLS_AES_256_GCM_SHA384".equals(chosen1) &&
            !"TLS13-AES256-GCM-SHA384".equals(chosen1)) {
            System.out.println("\t... failed");
            fail("Expected server preference cipher (AES_256), got "
                  + chosen1);
        }

        cs1.close();
        server1.close();
        ss1.close();

        /* --- Case 2: server honors client order --- */
        SSLServerSocket ss2 = (SSLServerSocket)ctx.getServerSocketFactory()
            .createServerSocket(0);
        ss2.setEnabledCipherSuites(serverSuites);

        /* Do not honor local cipher suites preference */
        SSLParameters ss2Params = ss2.getSSLParameters();
        ss2Params.setUseCipherSuitesOrder(false);
        ss2.setSSLParameters(ss2Params);

        SSLSocket cs2 = (SSLSocket)ctx.getSocketFactory().createSocket();
        cs2.setEnabledCipherSuites(clientSuites);
        cs2.connect(new InetSocketAddress(ss2.getLocalPort()));

        final SSLSocket server2 = (SSLSocket)ss2.accept();

        Future<Void> f2 = es.submit(() -> {
            server2.startHandshake();
            return null;
        });

        cs2.startHandshake();
        f2.get();

        String chosen2 = cs2.getSession().getCipherSuite();
        /* Note: WolfSSL may report TLS 1.3 ciphers in IANA standard or wolfSSL
         * alias depending on wolfSSL configuration. */
        if (!"TLS_AES_128_GCM_SHA256".equals(chosen2) &&
            !"TLS13-AES128-GCM-SHA256".equals(chosen2)) {
            System.out.println("\t... failed");
            fail("Expected client preference cipher (AES_128), got "
                 + chosen2);
        }

        cs2.close();
        server2.close();
        ss2.close();
        es.shutdown();

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

            /* test that removing protocols with jdk.tls.disabledAlgorithms
             * behaves as expected */
            synchronized (WolfSSLTestFactory.jdkTlsDisabledAlgorithmsLock) {
                String originalProperty =
                    Security.getProperty("jdk.tls.disabledAlgorithms");

                try {
                    Security.setProperty(
                        "jdk.tls.disabledAlgorithms", "TLSv1");
                    s.setEnabledProtocols(new String[] {"TLSv1"});
                    System.out.println("\t\t... failed");
                    fail("SSLSocket.setEnabledProtocols() failed");
                } catch (IllegalArgumentException e) {
                    /* expected */
                }

                try {
                    Security.setProperty(
                        "jdk.tls.disabledAlgorithms", "TLSv1.1");
                    s.setEnabledProtocols(new String[] {"TLSv1.1"});
                    System.out.println("\t\t... failed");
                    fail("SSLSocket.setEnabledProtocols() failed");
                } catch (IllegalArgumentException e) {
                    /* expected */
                }

                try {
                    Security.setProperty(
                        "jdk.tls.disabledAlgorithms", "TLSv1.2");
                    s.setEnabledProtocols(new String[] {"TLSv1.2"});
                    System.out.println("\t\t... failed");
                    fail("SSLSocket.setEnabledProtocols() failed");
                } catch (IllegalArgumentException e) {
                    /* expected */
                }

                try {
                    Security.setProperty(
                        "jdk.tls.disabledAlgorithms", "TLSv1.3");
                    s.setEnabledProtocols(new String[] {"TLSv1.3"});
                    System.out.println("\t\t... failed");
                    fail("SSLSocket.setEnabledProtocols() failed");
                } catch (IllegalArgumentException e) {
                    /* expected */
                }

                /* restore original property value */
                Security.setProperty("jdk.tls.disabledAlgorithms",
                    originalProperty);
            }
        }

        System.out.println("\t... passed");
    }

    @Test
    public void testEnabledSupportedCurvesProperty() throws Exception {

        SSLServerSocket ss = null;
        TestServer server = null;
        TestClient client = null;
        Exception srvException = null;
        Exception cliException = null;
        CountDownLatch sDoneLatch = null;
        CountDownLatch cDoneLatch = null;

        System.out.print("\twolfjsse.enabledSupportedCurves");

        /* create new CTX */
        this.ctx = tf.createSSLContext("TLS", ctxProvider);

        /* Save existing Security property before setting */
        String originalProperty =
            Security.getProperty("wolfjsse.enabledSupportedCurves");

        /* Test with empty property */
        {
            Security.setProperty("wolfjsse.enabledSupportedCurves", "");

            /* create SSLServerSocket first to get ephemeral port */
            ss = (SSLServerSocket)ctx.getServerSocketFactory()
                .createServerSocket(0);

            TestArgs sArgs = new TestArgs(null, null, true, true, true, null);
            TestArgs cArgs = new TestArgs(null, null, false, false, true, null);

            sDoneLatch = new CountDownLatch(1);
            cDoneLatch = new CountDownLatch(1);

            server = new TestServer(this.ctx, ss, sArgs, 1, sDoneLatch);
            server.start();
            client = new TestClient(this.ctx, ss.getLocalPort(), cArgs,
                cDoneLatch);
            client.start();

            cDoneLatch.await();
            sDoneLatch.await();

            srvException = server.getException();
            if (srvException != null) {
                Security.setProperty("wolfjsse.enabledSupportedCurves",
                    originalProperty);
                throw srvException;
            }

            cliException = client.getException();
            if (cliException != null) {
                Security.setProperty("wolfjsse.enabledSupportedCurves",
                    originalProperty);
                throw cliException;
            }

            try {
                client.join(1000);
                server.join(1000);

            } catch (InterruptedException e) {
                System.out.println("interrupt happened");
                Security.setProperty("wolfjsse.enabledSupportedCurves",
                    originalProperty);
                fail("Threaded client/server test failed");
            }
        }

        /* Test with single property entry */
        {
            Security.setProperty("wolfjsse.enabledSupportedCurves",
                "secp256r1");

            /* create SSLServerSocket first to get ephemeral port */
            ss = (SSLServerSocket)ctx.getServerSocketFactory()
                .createServerSocket(0);

            TestArgs sArgs = new TestArgs(null, null, true, true, true, null);
            TestArgs cArgs = new TestArgs(null, null, false, false, true, null);

            sDoneLatch = new CountDownLatch(1);
            cDoneLatch = new CountDownLatch(1);

            server = new TestServer(this.ctx, ss, sArgs, 1, sDoneLatch);
            server.start();
            client = new TestClient(this.ctx, ss.getLocalPort(), cArgs,
                cDoneLatch);
            client.start();

            cDoneLatch.await();
            sDoneLatch.await();

            srvException = server.getException();
            if (srvException != null) {
                Security.setProperty("wolfjsse.enabledSupportedCurves",
                    originalProperty);
                throw srvException;
            }

            cliException = client.getException();
            if (cliException != null) {
                Security.setProperty("wolfjsse.enabledSupportedCurves",
                    originalProperty);
                throw cliException;
            }

            try {
                client.join(1000);
                server.join(1000);

            } catch (InterruptedException e) {
                System.out.println("interrupt happened");
                Security.setProperty("wolfjsse.enabledSupportedCurves",
                    originalProperty);
                fail("Threaded client/server test failed");
            }
        }

        /* Test with multiple property entries */
        {
            Security.setProperty("wolfjsse.enabledSupportedCurves",
                "secp256r1, secp521r1");

            /* create SSLServerSocket first to get ephemeral port */
            ss = (SSLServerSocket)ctx.getServerSocketFactory()
                .createServerSocket(0);

            TestArgs sArgs = new TestArgs(null, null, true, true, true, null);
            TestArgs cArgs = new TestArgs(null, null, false, false, true, null);

            sDoneLatch = new CountDownLatch(1);
            cDoneLatch = new CountDownLatch(1);

            server = new TestServer(this.ctx, ss, sArgs, 1, sDoneLatch);
            server.start();
            client = new TestClient(this.ctx, ss.getLocalPort(), cArgs,
                cDoneLatch);
            client.start();

            cDoneLatch.await();
            sDoneLatch.await();

            srvException = server.getException();
            if (srvException != null) {
                Security.setProperty("wolfjsse.enabledSupportedCurves",
                    originalProperty);
                throw srvException;
            }

            cliException = client.getException();
            if (cliException != null) {
                Security.setProperty("wolfjsse.enabledSupportedCurves",
                    originalProperty);
                throw cliException;
            }

            try {
                client.join(1000);
                server.join(1000);

            } catch (InterruptedException e) {
                System.out.println("interrupt happened");
                Security.setProperty("wolfjsse.enabledSupportedCurves",
                    originalProperty);
                fail("Threaded client/server test failed");
            }
        }

        /* Test with invalid property entries.
         * Only need to start client thread, since it throws exception
         * before connecting to server. */
        {
            Security.setProperty("wolfjsse.enabledSupportedCurves",
                "badone, badtwo");

            /* create SSLServerSocket first to get ephemeral port */
            ss = (SSLServerSocket)ctx.getServerSocketFactory()
                .createServerSocket(0);

            TestArgs cArgs = new TestArgs(null, null, false, false, true, null);

            cDoneLatch = new CountDownLatch(1);

            client = new TestClient(this.ctx, ss.getLocalPort(), cArgs,
                cDoneLatch);
            client.start();

            cDoneLatch.await();

            cliException = client.getException();
            if (cliException != null) {
                /* expected Exception here, bad Supported Curve values */
            }

            try {
                client.join(1000);
                /* server.join(1000); */

            } catch (InterruptedException e) {
                System.out.println("interrupt happened");
                Security.setProperty("wolfjsse.enabledSupportedCurves",
                    originalProperty);
                fail("Threaded client/server test failed");
            }
        }


        /* restore original property value */
        if (originalProperty == null) {
            /* set property to empty if original was not set */
            Security.setProperty("wolfjsse.enabledSupportedCurves", "");
        } else {
            Security.setProperty("wolfjsse.enabledSupportedCurves",
                originalProperty);
        }

        System.out.println("\t... passed");
    }

    @Test
    public void testClientServerThreaded() throws Exception {

        CountDownLatch sDoneLatch = null;
        CountDownLatch cDoneLatch = null;

        System.out.print("\tTesting basic client/server");

        /* create new CTX */
        this.ctx = tf.createSSLContext("TLS", ctxProvider);

        /* create SSLServerSocket first to get ephemeral port */
        SSLServerSocket ss = (SSLServerSocket)ctx.getServerSocketFactory()
            .createServerSocket(0);

        TestArgs sArgs = new TestArgs(null, null, true, true, true, null);
        TestArgs cArgs = new TestArgs(null, null, false, false, true, null);

        sDoneLatch = new CountDownLatch(1);
        cDoneLatch = new CountDownLatch(1);

        TestServer server = new TestServer(this.ctx, ss, sArgs, 1, sDoneLatch);
        server.start();

        TestClient client = new TestClient(this.ctx, ss.getLocalPort(), cArgs,
            cDoneLatch);
        client.start();

        cDoneLatch.await();
        sDoneLatch.await();

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

    public void alpnClientServerRunner(TestArgs sArgs, TestArgs cArgs,
        boolean expectingException) throws Exception {

        CountDownLatch sDoneLatch = null;
        CountDownLatch cDoneLatch = null;

        if (sArgs == null || cArgs == null) {
            throw new Exception("client/server TestArgs can not be null");
        }

        this.ctx = tf.createSSLContext("TLS", ctxProvider);

        /* create SSLServerSocket first to get ephemeral port */
        SSLServerSocket ss = (SSLServerSocket)ctx.getServerSocketFactory()
            .createServerSocket(0);

        sDoneLatch = new CountDownLatch(1);
        cDoneLatch = new CountDownLatch(1);

        TestServer server = new TestServer(this.ctx, ss, sArgs, 1, sDoneLatch);
        server.start();

        TestClient client = new TestClient(this.ctx, ss.getLocalPort(), cArgs,
            cDoneLatch);
        client.start();

        cDoneLatch.await();
        sDoneLatch.await();

        try {
            client.join(1000);
            server.join(1000);

        } catch (InterruptedException e) {
            System.out.println("interrupt happened");
            fail("Threaded client/server test failed");
        }

        Exception srvException = server.getException();
        Exception cliException = client.getException();

        if (srvException != null || cliException != null) {
            if (!expectingException) {
                StringWriter sw = new StringWriter();
                PrintWriter pw = new PrintWriter(sw);
                if (srvException != null) {
                    srvException.printStackTrace(pw);
                }
                if (cliException != null) {
                    cliException.printStackTrace(pw);
                }
                String traceString = sw.toString();
                throw new Exception(traceString);
            }
        }
        else if (expectingException) {
            throw new Exception("Expecting exception but got none");
        }
    }

    @Test
    public void testClientServerThreadedAlpnSelectCallback() throws Exception {

        TestArgs sArgs = null;
        TestArgs cArgs = null;

        System.out.print("\tTesting ALPN select callback");

        /* wolfSSL_set_alpn_select_cb() added in wolfSSL 5.6.6 */
        if (WolfSSL.getLibVersionHex() < 0x05006006) {
            System.out.println("\t... skipped");
            return;
        }

        /* Successful test:
         * Sanity check, no ALPN */
        sArgs = new TestArgs(null, null, true, true, true, null);
        sArgs.setExpectedAlpn("");
        cArgs = new TestArgs(null, null, false, false, true, null);
        cArgs.setExpectedAlpn("");
        alpnClientServerRunner(sArgs, cArgs, false);

        /* Successful test:
         * ALPN callback, server selects matching protocol from client list */
        sArgs = new TestArgs(null, null, true, true, true, null);
        sArgs.setAlpnForCallback("h2");
        sArgs.setExpectedAlpn("h2");
        cArgs = new TestArgs(null, null, false, false, true, null);
        cArgs.setAlpnList(new String[] {"h2", "http/1.1"});
        cArgs.setExpectedAlpn("h2");
        alpnClientServerRunner(sArgs, cArgs, false);

        /* Successful test:
         * ALPN callback, server selects matching protocol from client list */
        sArgs = new TestArgs(null, null, true, true, true, null);
        sArgs.setAlpnForCallback("http/1.1");
        sArgs.setExpectedAlpn("http/1.1");
        cArgs = new TestArgs(null, null, false, false, true, null);
        cArgs.setAlpnList(new String[] {"h2", "http/1.1"});
        cArgs.setExpectedAlpn("http/1.1");
        alpnClientServerRunner(sArgs, cArgs, false);

        /* Successful test:
         * ALPN callback, client list is empty so callback not called */
        sArgs = new TestArgs(null, null, true, true, true, null);
        sArgs.setAlpnForCallback("h2");
        sArgs.setExpectedAlpn("");
        cArgs = new TestArgs(null, null, false, false, true, null);
        cArgs.setAlpnList(null);
        cArgs.setExpectedAlpn("");
        alpnClientServerRunner(sArgs, cArgs, false);

        /* Successful test:
         * ALPN set on client and server without callback */
        sArgs = new TestArgs(null, null, true, true, true, null);
        sArgs.setAlpnList(new String[] {"h2"});
        sArgs.setExpectedAlpn("h2");
        cArgs = new TestArgs(null, null, false, false, true, null);
        cArgs.setAlpnList(new String[] {"h2", "http/1.1"});
        cArgs.setExpectedAlpn("h2");
        alpnClientServerRunner(sArgs, cArgs, false);

        /* Failure test:
         * ALPN callback, server selects protocol not from client list */
        sArgs = new TestArgs(null, null, true, true, true, null);
        sArgs.setAlpnForCallback("invalid");
        cArgs = new TestArgs(null, null, false, false, true, null);
        cArgs.setAlpnList(new String[] {"h2", "http/1.1"});
        alpnClientServerRunner(sArgs, cArgs, true);

        /* Successful test:
         * ALPN with GREASE bytes (RFC 8701) containing non-ASCII values.
         * Tests that bytes > 127 are preserved correctly through useALPN()
         * and getAlpnSelectedString(). */
        byte[] greaseBytes = new byte[] {
            (byte)0x0A, (byte)0x1A, (byte)0x2A, (byte)0x3A,
            (byte)0x4A, (byte)0x5A, (byte)0x6A, (byte)0x7A,
            (byte)0x8A, (byte)0x9A, (byte)0xAA, (byte)0xBA,
            (byte)0xCA, (byte)0xDA, (byte)0xEA, (byte)0xFA
        };
        String greaseString = new String(greaseBytes,
            StandardCharsets.ISO_8859_1);
        sArgs = new TestArgs(null, null, true, true, true, null);
        sArgs.setAlpnList(new String[] {greaseString});
        sArgs.setExpectedAlpn(greaseString);
        cArgs = new TestArgs(null, null, false, false, true, null);
        cArgs.setAlpnList(new String[] {greaseString});
        cArgs.setExpectedAlpn(greaseString);
        alpnClientServerRunner(sArgs, cArgs, false);

        System.out.println("\t... passed");
    }

    /**
     * Internal multi-threaded SSLSocket-based server.
     * Used when testing concurrent threaded SSLSocket client connections
     * in testExtendedThreadingUse().
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
                SSLContext ctx = tf.createSSLContext("TLS", ctxProvider);
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

    /**
     * Internal protected class used by testExtendedThreadingUse(),
     * encapsulates client-side functionality.
     */
    protected class SSLSocketClient
    {
        /* Server host and port to connect SSLSocket client to */
        private int serverPort;
        private String host;

        /* SSLContext, created beforehand and passed via constructor */
        private SSLContext ctx;

        public SSLSocketClient(SSLContext ctx, String host, int port) {
            this.ctx = ctx;
            this.host = host;
            this.serverPort = port;
        }

        /**
         * After creating SSLSocketClient class, call connect() to
         * connect client to server and send/receive simple test data.
         */
        public void connect() throws Exception {

            byte[] inData = new byte[80];

            SSLSocket sock = (SSLSocket)ctx.getSocketFactory().
                createSocket();
            sock.connect(new InetSocketAddress(serverPort));

            /* Do TLS handshake */
            sock.startHandshake();

            /* Write app data */
            sock.getOutputStream().write("Hello from wolfJSSE".getBytes());

            /* Read response */
            InputStream in = sock.getInputStream();
            if (in == null) {
                throw new Exception("InputStream was null");
            }

            int ret = in.read(inData);
            if (ret <= 0) {
                throw new Exception("InputStream.read() was <= 0");
            }
            sock.close();

            try {
                /* Try to read from InputStream after socket is closed.
                 * We expect an exception to be thrown */
                ret = in.read(inData);
                throw new Exception("No exception thrown on read from " +
                        "InputStream after SSLSocket.close()");

            } catch (Exception e) {
                /* expected */
            }
        }
    }

    /**
     * Extended threading test of SSLSocket class.
     * Launches a simple multi-threaded SSLSocket-based server, which
     * creates a new thread for each incoming client thread. Then, launches
     * "numThreads" concurrent SSLSocket clients which connect to that server.
     *
     * CountDownLatch is used with a 20 second timeout on latch.await(), so
     * that this test will time out and return with error instead of
     * infinitely block if SSLSocket threads end up in a bad state or
     * deadlock and never return.
     */
    @Test
    public void testExtendedThreadingUse()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InterruptedException, KeyManagementException, KeyStoreException,
               CertificateException, UnrecoverableKeyException, IOException {

        /* Number of SSLSocket client threads to start up */
        int numThreads = 50;

        /* Port of internal HTTPS server. Using 11120 since SSLEngine
         * extended threading test uses 11119. If both tests end up running
         * concurrently by JUnit ports could conflict. */
        final int svrPort = 11120;

        /* Create ExecutorService to launch client SSLSocket threads */
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final SSLContext localCtx = tf.createSSLContext("TLS", ctxProvider);

        /* Used to detect timeout of CountDownLatch, don't run infinitely
         * if SSLSocket threads are stalled out or deadlocked */
        boolean returnWithoutTimeout = true;

        /* Keep track of failure and success count */
        final AtomicIntegerArray failures = new AtomicIntegerArray(1);
        final AtomicIntegerArray success = new AtomicIntegerArray(1);
        failures.set(0, 0);
        success.set(0, 0);

        System.out.print("\tTesting ExtendedThreadingUse");

        /* This test hangs on Android, marking TODO for later investigation.
         * Seems to be something specific to the test code, not library
         * proper. */
        if (WolfSSLTestFactory.isAndroid()) {
            System.out.println("\t... skipped");
            return;
        }

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
                    SSLSocketClient client =
                        new SSLSocketClient(localCtx, "localhost", svrPort);
                    try {
                        client.connect();
                        success.incrementAndGet(0);
                    } catch (Exception e) {
                        e.printStackTrace();
                        failures.incrementAndGet(0);
                    }

                    latch.countDown();
                }
            });
        }

        /* Wait for all client threads to finish, else time out */
        returnWithoutTimeout = latch.await(20, TimeUnit.SECONDS);
        server.join(1000);

        /* check failure count and success count against thread count */
        if (failures.get(0) == 0 && success.get(0) == numThreads) {
            System.out.println("\t... passed");
        } else {
            if (returnWithoutTimeout == true) {
                fail("SSLSocket threading error: " +
                     failures.get(0) + " failures, " +
                     success.get(0) + " success, " +
                     numThreads + " num threads total");
            } else {
                fail("SSLSocket threading error, threads timed out");
            }
        }
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

        final Socket server = serverSock.accept();

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
                    SSLSocket ss =
                        (SSLSocket)(
                            (WolfSSLSocketFactory)ctx.getSocketFactory())
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
        serverSock.close();

        System.out.println("\t... passed");
    }

    @Test
    public void testCreateSocketNullHost() throws Exception {

        System.out.print("\tcreateSocket(null host)");

        /* create new CTX */
        this.ctx = tf.createSSLContext("TLS", ctxProvider);

        /* create new ServerSocket first to get ephemeral port */
        ServerSocket ss = new ServerSocket(0);

        /* create new Socket, connect() to server */
        Socket cs = new Socket();
        cs.connect(new InetSocketAddress(ss.getLocalPort()));

        /* accept client connection, normal java.net.Socket */
        final Socket socket = ss.accept();

        /* Try to convert client Socket to SSLSocket, with null hostname.
         * This should not throw any Exceptions, null host is ok. */
        SSLSocket ssc = (SSLSocket)ctx.getSocketFactory().createSocket(
                cs, null, cs.getPort(), false);

        ssc.close();
        cs.close();
        socket.close();
        ss.close();

        System.out.println("\t\t... passed");
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

        /* test getting and setting cipher suites */
        String[] suites = p.getCipherSuites();
        assertNotNull(suites);
        assertNotSame(suites, p.getCipherSuites());  /* should return copy */

        String[] supportedSuites = s.getSupportedCipherSuites();
        assertNotNull(supportedSuites);
        p.setCipherSuites(supportedSuites);
        assertArrayEquals(supportedSuites, p.getCipherSuites());

        /* test getting and setting need client auth */
        assertFalse(p.getNeedClientAuth());          /* default: false */
        p.setNeedClientAuth(true);
        assertTrue(p.getNeedClientAuth());

        /* test getting and setting want client auth */
        assertFalse(p.getWantClientAuth());          /* default: false */
        p.setWantClientAuth(true);
        assertTrue(p.getWantClientAuth());

        /* test getting and setting protocols */
        String[] protos = p.getProtocols();
        assertNotNull(protos);
        assertNotSame(protos, p.getProtocols());

        String[] supportedProtos = s.getSupportedProtocols();
        assertNotNull(supportedProtos);
        p.setProtocols(supportedProtos);
        assertArrayEquals(supportedProtos, p.getProtocols());

        /* test setting SSLParameters on SSLSocket */
        p = s.getSSLParameters();
        String[] oneSuite = new String[] { supportedSuites[0] };
        p.setCipherSuites(oneSuite);
        s.setSSLParameters(p);
        p = s.getSSLParameters();
        assertArrayEquals(oneSuite, p.getCipherSuites());

        s.close();

        System.out.println("\t\t... passed");
    }

    @Test
    public void testAddHandshakeCompletedListener() throws Exception {

        System.out.print("\taddHandshakeCompletedListener()");

        /* create new CTX */
        this.ctx = tf.createSSLContext("TLS", ctxProvider);
        clientFlag = false;
        serverFlag = false;

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

        /* ------------------------------------------------------------*/
        /* Test that getSession() can do handshake if not completed yet
        /* ------------------------------------------------------------*/

        /* create new CTX */
        this.ctx = tf.createSSLContext("TLS", ctxProvider);

        /* create SSLServerSocket first to get ephemeral port */
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

                    /* get SSLSession */
                    SSLSession srvSess = server2.getSession();
                    assertNotNull(srvSess);

                    server2.close();

                } catch (SSLException e) {
                    System.out.println("\t\t\t... failed");
                    fail();
                }
                return null;
            }
        });

        try {
            /* get SSLSession, without calling startHandshake() first */
            SSLSession cliSess = cs.getSession();
            assertNotNull(cliSess);

            /* double check by seeing if we have peer certificates */
            Certificate[] certs = cliSess.getPeerCertificates();
            assertNotNull(certs);
            if (certs.length == 0) {
                System.out.println("\t\t\t... failed");
                fail();
            }

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

        /* fail case, no root CA loaded to verify client cert */
        this.ctx = tf.createSSLContext("TLSv1.2", ctxProvider,
                /* using null here for JKS, use system certs only */
                tf.createTrustManager("SunX509", (String)null, ctxProvider),
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
                tf.createTrustManager("SunX509", tf.caServerJKS, ctxProvider),
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

        /* reset disabledAlgorithms property to test TLS 1.0 which is
         * disabled by default */
        synchronized (WolfSSLTestFactory.jdkTlsDisabledAlgorithmsLock) {
            String originalProperty =
                Security.getProperty("jdk.tls.disabledAlgorithms");
            Security.setProperty("jdk.tls.disabledAlgorithms", "");

            protocolConnectionTest("TLSv1");

            System.out.print("\tTLS 1.0 extended Socket test");
            protocolConnectionTestExtendedSocket("TLSv1");

            /* restore system property if it was originally set */
            if (originalProperty != null) {
                Security.setProperty(
                    "jdk.tls.disabledAlgorithms", originalProperty);
            }
        }
    }

    @Test
    public void testProtocolTLSv11() throws Exception {

        System.out.print("\tTLS 1.1 connection test");

        /* skip if TLS 1.1 is not compiled in at native level */
        if (WolfSSL.TLSv11Enabled() == false) {
            System.out.println("\t\t... skipped");
            return;
        }

        /* reset disabledAlgorithms property to test TLS 1.1 which is
         * disabled by default */
        synchronized (WolfSSLTestFactory.jdkTlsDisabledAlgorithmsLock) {
            String originalProperty =
                Security.getProperty("jdk.tls.disabledAlgorithms");
            Security.setProperty("jdk.tls.disabledAlgorithms", "");

            protocolConnectionTest("TLSv1.1");

            System.out.print("\tTLS 1.1 extended Socket test");
            protocolConnectionTestExtendedSocket("TLSv1.1");

            /* restore system property if it was originally set */
            if (originalProperty != null) {
                Security.setProperty(
                    "jdk.tls.disabledAlgorithms", originalProperty);
            }
        }
    }

    @Test
    public void testProtocolTLSv12() throws Exception {

        System.out.print("\tTLS 1.2 connection test");

        /* skip if TLS 1.2 is not compiled in at native level */
        synchronized (WolfSSLTestFactory.jdkTlsDisabledAlgorithmsLock) {
            if (WolfSSL.TLSv12Enabled() == false ||
                WolfSSLTestFactory.securityPropContains(
                    "jdk.tls.disabledAlgorithms", "TLSv1.2")) {
                System.out.println("\t\t... skipped");
                return;
            }

            protocolConnectionTest("TLSv1.2");

            System.out.print("\tTLS 1.2 extended Socket test");
            protocolConnectionTestExtendedSocket("TLSv1.2");
        }
    }

    @Test
    public void testProtocolTLSv13() throws Exception {

        System.out.print("\tTLS 1.3 connection test");

        /* skip if TLS 1.3 is not compiled in at native level */
        synchronized (WolfSSLTestFactory.jdkTlsDisabledAlgorithmsLock) {
            if (WolfSSL.TLSv13Enabled() == false ||
                WolfSSLTestFactory.securityPropContains(
                    "jdk.tls.disabledAlgorithms", "TLSv1.3")) {
                System.out.println("\t\t... skipped");
                return;
            }

            protocolConnectionTest("TLSv1.3");

            System.out.print("\tTLS 1.3 extended Socket test");
            protocolConnectionTestExtendedSocket("TLSv1.3");
        }
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

    /**
     * Class that extends java.net.Socket, used for testing scenarios
     * where WolfSSLSession.setFd() is unable to find the internal
     * file descriptor or the internal descriptor is null. This can happen
     * in cases where applications use a subclass of java.net.Socket that
     * behaves differently and does not instantiate the internal file
     * descriptor.
     *
     * This class takes in a pre-connected Socket, and does not call the
     * super(), thus not setting up the file descriptor inside the
     * parent's SocketImpl class.
     */
    private class ExtendedSocket extends Socket {

        private Socket internalSock = null;

        public ExtendedSocket(Socket s) {
            internalSock = s;
        }

        @Override
        public InputStream getInputStream() throws IOException {
            return internalSock.getInputStream();
        }

        @Override
        public OutputStream getOutputStream() throws IOException {
            return internalSock.getOutputStream();
        }

        @Override
        public InetAddress getLocalAddress() {
            return internalSock.getLocalAddress();
        }

        @Override
        public int getLocalPort() {
            return internalSock.getLocalPort();
        }

        @Override
        public SocketAddress getLocalSocketAddress() {
            return internalSock.getLocalSocketAddress();
        }

        @Override
        public int getPort() {
            return internalSock.getPort();
        }

        @Override
        public int getSoTimeout() throws SocketException {
            return internalSock.getSoTimeout();
        }

        @Override
        public boolean isClosed() {
            return internalSock.isClosed();
        }

        @Override
        public boolean isConnected() {
            return internalSock.isConnected();
        }

        @Override
        public String toString() {
            return internalSock.toString();
        }

        @Override
        public void close() throws IOException {
            internalSock.close();
        }
    }

    private void protocolConnectionTestExtendedSocket(String protocol)
        throws Exception {

        /* create new CTX */
        this.ctx = tf.createSSLContext(protocol, ctxProvider);

        /* create SSLServerSocket first to get ephemeral port */
        SSLServerSocket ss = (SSLServerSocket)ctx.getServerSocketFactory()
            .createServerSocket(0);

        /* create Socket to wrap inside our ExtendedSocket */
        Socket sock1 = new Socket();
        sock1.connect(new InetSocketAddress(ss.getLocalPort()));

        /* create ExtendedSocket, tests non-Socket inside WolfSSLSocket */
        ExtendedSocket sock = new ExtendedSocket(sock1);

        SSLSocket cs = (SSLSocket)ctx.getSocketFactory()
            .createSocket(sock, ss.getInetAddress().getHostAddress(),
                ss.getLocalPort(), true);

        final SSLSocket server = (SSLSocket)ss.accept();

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

        System.out.println("\t... passed");
    }

    @Test
    public void testConnectionWithDisabledAlgorithms() throws Exception {

        System.out.print("\tConnect with disabled algos");

        /* create new CTX */
        this.ctx = tf.createSSLContext("TLS", ctxProvider);

        /* save current system property value */
        synchronized (WolfSSLTestFactory.jdkTlsDisabledAlgorithmsLock) {
            String originalProperty =
                Security.getProperty("jdk.tls.disabledAlgorithms");

            for (int i = 0; i < enabledProtocols.size(); i++) {

                /* skip generic "TLS" */
                if (enabledProtocols.get(i).equals("TLS")) {
                    continue;
                }

                /* create SSLServerSocket first to get ephemeral port */
                SSLServerSocket ss =
                    (SSLServerSocket)ctx.getServerSocketFactory()
                    .createServerSocket(0);

                SSLSocket cs = (SSLSocket)ctx.getSocketFactory().createSocket();
                /* restrict to single protocol that is being disabled */
                cs.setEnabledProtocols(new String[] {enabledProtocols.get(i)});

                /* disable protocol after socket setup, should fail conn */
                Security.setProperty("jdk.tls.disabledAlgorithms",
                        enabledProtocols.get(i));

                /* don't need server since should throw exception before */
                cs.connect(new InetSocketAddress(ss.getLocalPort()));

                try {
                    cs.startHandshake();
                    System.out.println("\t... failed");
                    fail();

                } catch (SSLException e) {
                    /* expected, should fail with
                     * "No protocols enabled or available" */
                }

                cs.close();
                ss.close();
            }

            /* restore system property */
            Security.setProperty(
                "jdk.tls.disabledAlgorithms", originalProperty);
        }

        System.out.println("\t... passed");
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

        /* wolfjsse.clientSessionCache.disabled could be set in users
         * java.security file which would cause this test to not work
         * properly. Save their setting here, and re-enable session
         * cache for this test */
        String originalProp = Security.getProperty(
            "wolfjsse.clientSessionCache.disabled");
        Security.setProperty("wolfjsse.clientSessionCache.disabled", "false");

        try {
            /* create new CTX */
            this.ctx = tf.createSSLContext(protocol, ctxProvider);

            /* create SSLServerSocket first to get ephemeral port */
            final SSLServerSocket ss =
                (SSLServerSocket)ctx.getServerSocketFactory()
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

        } finally {
            if (originalProp != null && !originalProp.isEmpty()) {
                Security.setProperty(
                    "wolfjsse.clientSessionCache.disabled", originalProp);
            }
        }
    }

    @Test
    public void testSessionResumptionSysPropDisabled() throws Exception {

        byte[] sessionID1 = null;
        byte[] sessionID2 = null;
        String protocol = null;

        System.out.print("\tDisabling client session cache");

        /* Use TLS 1.2, else 1.1, else 1.0, else skip */
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

        /* Save original Security property value */
        String originalProp = Security.getProperty(
            "wolfjsse.clientSessionCache.disabled");

        /* Disable client session cache */
        Security.setProperty("wolfjsse.clientSessionCache.disabled", "true");

        try {
            /* Create new CTX */
            this.ctx = tf.createSSLContext(protocol, ctxProvider);

            /* Create SSLServerSocket first to get ephemeral port */
            final SSLServerSocket ss =
                (SSLServerSocket)ctx.getServerSocketFactory()
                    .createServerSocket(0);

            SSLSocketFactory cliFactory = ctx.getSocketFactory();

            SSLSocket cs = (SSLSocket)cliFactory.createSocket();
            cs.connect(new InetSocketAddress(InetAddress.getLocalHost(),
                                             ss.getLocalPort()));

            /* Start server */
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

                /* connection #2, should NOT resume */
                cs = (SSLSocket)cliFactory.createSocket();
                cs.connect(new InetSocketAddress(InetAddress.getLocalHost(),
                                                 ss.getLocalPort()));
                cs.startHandshake();
                sessionID2 = cs.getSession().getId();
                cs.close();

                if (Arrays.equals(sessionID1, sessionID2)) {
                    /* session resumed, but should not */
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

        } finally {
            if (originalProp != null && !originalProp.isEmpty()) {
                Security.setProperty(
                    "wolfjsse.clientSessionCache.disabled", originalProp);
            }
        }
    }

    @Test
    public void testSessionResumptionWithTicketEnabled() throws Exception {

        /* wolfJSSE currently only supports client-side session tickets
         * for now. This test verifies that resumption will still fall
         * back and work with session IDs, since we test against the wolfJSSE
         * server, which does not have session tickets enabled. The client
         * side will still send the Session Ticket extension in the
         * ClientHello */

        byte[] sessionID1 = null;
        byte[] sessionID2 = null;
        String protocol = null;

        System.out.print("\tresumption with tickets enabled");

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

        /* wolfjsse.clientSessionCache.disabled could be set in users
         * java.security file which would cause this test to not work
         * properly. Save their setting here, and re-enable session
         * cache for this test */
        String originalProp = Security.getProperty(
            "wolfjsse.clientSessionCache.disabled");
        Security.setProperty("wolfjsse.clientSessionCache.disabled", "false");

        try {
            /* create new CTX */
            this.ctx = tf.createSSLContext(protocol, ctxProvider);

            /* create SSLServerSocket first to get ephemeral port */
            final SSLServerSocket ss =
                (SSLServerSocket)ctx.getServerSocketFactory()
                    .createServerSocket(0);

            SSLSocketFactory cliFactory = ctx.getSocketFactory();

            WolfSSLSocket cs = (WolfSSLSocket)cliFactory.createSocket();
            cs.setUseSessionTickets(true);
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
                cs = (WolfSSLSocket)cliFactory.createSocket();
                cs.setUseSessionTickets(true);
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

        } finally {
            if (originalProp != null && !originalProp.isEmpty()) {
                Security.setProperty(
                    "wolfjsse.clientSessionCache.disabled", originalProp);
            }
        }
    }

    @Test
    public void testDoubleSocketClose() throws Exception {

        String protocol = null;

        System.out.print("\tTesting duplicate close");

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
        cs.close();

        System.out.println("\t\t... passed");
    }

    @Test
    public void testSocketConnectException() throws Exception {

        System.out.print("\tTesting for ConnectException");

        this.ctx = tf.createSSLContext("TLS", ctxProvider);
        SocketFactory sf = this.ctx.getSocketFactory();

        try {
            /* connect to invalid host/port, expect java.net.ConnectException.
             * we do not expect anything to be running at localhost:12345 */
            SSLSocket cs = (SSLSocket)sf.createSocket("localhost", 12345);
            assertNotNull(cs);
        } catch (ConnectException ce) {
            /* expected */
        } catch (Exception e) {
            /* other Exceptions (ie NullPointerException) are unexpected */
            System.out.println("\t... failed");
            e.printStackTrace();
            fail();
        }

        System.out.println("\t... passed");
    }


    @Test
    public void testClientServerUsingSystemProperties() throws Exception {

        System.out.print("\tSystem Property Store Support");

        System.setProperty("javax.net.ssl.trustStore", tf.clientJKS);
        System.setProperty("javax.net.ssl.trustStoreType", tf.keyStoreType);
        System.setProperty("javax.net.ssl.trustStorePassword",
            WolfSSLTestFactory.jksPassStr);

        System.setProperty("javax.net.ssl.keyStore", tf.clientJKS);
        System.setProperty("javax.net.ssl.keyStoreType", tf.keyStoreType);
        System.setProperty("javax.net.ssl.keyStorePassword",
            WolfSSLTestFactory.jksPassStr);

        SSLContext ctx = SSLContext.getInstance("TLS", ctxProvider);

        /* not specifying TrustStore and KeyStore, expect to load from
         * system properties set above */
        ctx.init(null, null, null);

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

        /* ------------------------------------------------ */
        /* Test with bad trustStorePassword, expect to fail */
        /* ------------------------------------------------ */
        System.setProperty("javax.net.ssl.trustStore", tf.clientJKS);
        System.setProperty("javax.net.ssl.trustStoreType", tf.keyStoreType);
        System.setProperty("javax.net.ssl.trustStorePassword", "badpass");

        System.setProperty("javax.net.ssl.keyStore", tf.clientJKS);
        System.setProperty("javax.net.ssl.keyStoreType", tf.keyStoreType);
        System.setProperty("javax.net.ssl.keyStorePassword",
            WolfSSLTestFactory.jksPassStr);

        ctx = SSLContext.getInstance("TLS", ctxProvider);

        try {
            /* not specifying TrustStore and KeyStore, expect to load from
             * system properties set above */
            ctx.init(null, null, null);
            System.out.println("\t... failed");
            fail();
        } catch (KeyManagementException e) {
            /* expected: java.io.IOException: keystore password was incorrect */
        }

        /* ------------------------------------------------ */
        /* Test with bad trustStore path, expect to fail */
        /* ------------------------------------------------ */
        System.setProperty("javax.net.ssl.trustStore", "badstorepath");
        System.setProperty("javax.net.ssl.trustStoreType", tf.keyStoreType);
        System.setProperty("javax.net.ssl.trustStorePassword",
            WolfSSLTestFactory.jksPassStr);

        System.setProperty("javax.net.ssl.keyStore", tf.clientJKS);
        System.setProperty("javax.net.ssl.keyStoreType", tf.keyStoreType);
        System.setProperty("javax.net.ssl.keyStorePassword",
            WolfSSLTestFactory.jksPassStr);

        ctx = SSLContext.getInstance("TLS", ctxProvider);

        try {
            /* not specifying TrustStore and KeyStore, expect to load from
             * system properties set above */
            ctx.init(null, null, null);
            System.out.println("\t... failed");
            fail();
        } catch (KeyManagementException e) {
            /* expected: java.io.IOException: keystore password was incorrect */
        }

        /* ------------------------------------------------ */
        /* Test with bad trustStore type, expect to fail */
        /* ------------------------------------------------ */
        System.setProperty("javax.net.ssl.trustStore", tf.clientJKS);
        System.setProperty("javax.net.ssl.trustStoreType", "badtype");
        System.setProperty("javax.net.ssl.trustStorePassword",
            WolfSSLTestFactory.jksPassStr);

        System.setProperty("javax.net.ssl.keyStore", tf.clientJKS);
        System.setProperty("javax.net.ssl.keyStoreType", tf.keyStoreType);
        System.setProperty("javax.net.ssl.keyStorePassword",
            WolfSSLTestFactory.jksPassStr);

        ctx = SSLContext.getInstance("TLS", ctxProvider);

        try {
            /* not specifying TrustStore and KeyStore, expect to load from
             * system properties set above */
            ctx.init(null, null, null);
            System.out.println("\t... failed");
            fail();
        } catch (KeyManagementException e) {
            /* expected: java.io.IOException: keystore password was incorrect */
        }

        /* ------------------------------------------------ */
        /* Test with bad keyStorePassword, expect to fail */
        /* ------------------------------------------------ */
        System.setProperty("javax.net.ssl.trustStore", tf.clientJKS);
        System.setProperty("javax.net.ssl.trustStoreType", tf.keyStoreType);
        System.setProperty("javax.net.ssl.trustStorePassword",
            WolfSSLTestFactory.jksPassStr);

        System.setProperty("javax.net.ssl.keyStore", tf.clientJKS);
        System.setProperty("javax.net.ssl.keyStoreType", tf.keyStoreType);
        System.setProperty("javax.net.ssl.keyStorePassword", "badpass");

        ctx = SSLContext.getInstance("TLS", ctxProvider);

        try {
            /* not specifying TrustStore and KeyStore, expect to load from
             * system properties set above */
            ctx.init(null, null, null);
            System.out.println("\t... failed");
            fail();
        } catch (KeyManagementException e) {
            /* expected: java.io.IOException: keystore password was incorrect */
        }

        /* ------------------------------------------------ */
        /* Test with bad keyStore path, expect to fail */
        /* ------------------------------------------------ */
        System.setProperty("javax.net.ssl.trustStore", tf.clientJKS);
        System.setProperty("javax.net.ssl.trustStoreType", tf.keyStoreType);
        System.setProperty("javax.net.ssl.trustStorePassword",
            WolfSSLTestFactory.jksPassStr);

        System.setProperty("javax.net.ssl.keyStore", "badpath");
        System.setProperty("javax.net.ssl.keyStoreType", tf.keyStoreType);
        System.setProperty("javax.net.ssl.keyStorePassword",
            WolfSSLTestFactory.jksPassStr);

        ctx = SSLContext.getInstance("TLS", ctxProvider);

        try {
            /* not specifying TrustStore and KeyStore, expect to load from
             * system properties set above */
            ctx.init(null, null, null);
            System.out.println("\t... failed");
            fail();
        } catch (KeyManagementException e) {
            /* expected: java.io.IOException: keystore password was incorrect */
        }

        /* ------------------------------------------------ */
        /* Test with bad keyStore type, expect to fail */
        /* ------------------------------------------------ */
        System.setProperty("javax.net.ssl.trustStore", tf.clientJKS);
        System.setProperty("javax.net.ssl.trustStoreType", tf.keyStoreType);
        System.setProperty("javax.net.ssl.trustStorePassword",
            WolfSSLTestFactory.jksPassStr);

        System.setProperty("javax.net.ssl.keyStore", tf.clientJKS);
        System.setProperty("javax.net.ssl.keyStoreType", "badtype");
        System.setProperty("javax.net.ssl.keyStorePassword",
            WolfSSLTestFactory.jksPassStr);

        ctx = SSLContext.getInstance("TLS", ctxProvider);

        try {
            /* not specifying TrustStore and KeyStore, expect to load from
             * system properties set above */
            ctx.init(null, null, null);
            System.out.println("\t... failed");
            fail();
        } catch (KeyManagementException e) {
            /* expected: java.io.IOException: keystore password was incorrect */
        }

        /* reset properties back to empty */
        System.clearProperty("javax.net.ssl.trustStore");
        System.clearProperty("javax.net.ssl.trustStoreType");
        System.clearProperty("javax.net.ssl.trustStorePassword");
        System.clearProperty("javax.net.ssl.keyStore");
        System.clearProperty("javax.net.ssl.keyStoreType");
        System.clearProperty("javax.net.ssl.keyStorePassword");

        System.out.println("\t... passed");
    }

    /* Test timeout set to 10000 ms (10 sec) in case inerrupt code is not
     * working as expected, we will see the timeout as a hard error that
     * this test has failed */
    @Test(timeout = 10000)
    public void testSocketCloseInterruptsWrite() throws Exception {

        String protocol = null;
        SSLServerSocket ss = null;
        boolean passed = false;

        System.out.print("\tTesting close/write interrupt");

        /* pipe() interrupt mechamism not implemented for Windows yet since
         * Windows does not support Unix/Linux pipe(). Re-enable this test
         * for Windows when that support has been added */
        if (WolfSSLTestFactory.isWindows()) {
            System.out.println("\t... skipped");
            return;
        }

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
        this.ctx = tf.createSSLContext(protocol, ctxProvider);

        /* create SSLServerSocket first to get ephemeral port */
        ss = (SSLServerSocket)ctx.getServerSocketFactory()
            .createServerSocket(0);

        final SSLSocket cs = (SSLSocket)ctx.getSocketFactory().createSocket();
        cs.connect(new InetSocketAddress(ss.getLocalPort()));

        final SSLSocket server = (SSLSocket)ss.accept();
        final CountDownLatch closeLatch = new CountDownLatch(1);

        ExecutorService es = Executors.newSingleThreadExecutor();
        Future<Void> serverFuture = es.submit(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                try {
                    server.startHandshake();

                    boolean doClose = closeLatch.await(90L, TimeUnit.SECONDS);
                    if (!doClose) {
                        /* Return without closing, latch not hit within
                         * time limit */
                        return null;
                    }

                    /* Sleep so write thread has a chance to do some
                     * writing before interrupt */
                    Thread.sleep(1000);
                    cs.setSoLinger(true, 5);
                    cs.close();

                } catch (SSLException e) {
                    System.out.println("\t... failed");
                    e.printStackTrace();
                    fail("Server thread got SSLException when not expected");
                }
                return null;
            }
        });

        byte[] tmpArr = new byte[1024];
        Arrays.fill(tmpArr, (byte)0xA2);
        OutputStream out = cs.getOutputStream();

        try {
            try {
                cs.startHandshake();
                out.write(tmpArr);
            }
            catch (Exception e) {
                System.out.println("\t... failed");
                e.printStackTrace();
                fail("Exception from first out.write() when not expected");
            }

            try {
                /* signal server thread to try and close socket */
                closeLatch.countDown();

                /* keep writing, we should get interrupted */
                while (true) {
                    out.write(tmpArr);
                }

            } catch (SocketException e) {
                /* We expect SocketException with this message, error if
                 * different than expected */
                if (!e.getMessage().contains("Socket fd closed during poll")) {
                    System.out.println("\t... failed");
                    e.printStackTrace();
                    fail("Incorrect SocketException thrown by client");
                    throw e;
                }

                passed = true;
            }
        }
        finally {
            es.shutdown();
            serverFuture.get();
            if (!cs.isClosed()) {
                cs.close();
            }
            if (!server.isClosed()) {
                server.close();
            }
            if (!ss.isClosed()) {
                ss.close();
            }
        }

        if (passed) {
            System.out.println("\t... passed");
        }
    }

    /* Test timeout set to 10000 ms (10 sec) in case inerrupt code is not
     * working as expected, we will see the timeout as a hard error that
     * this test has failed */
    @Test(timeout = 10000)
    public void testSocketCloseInterruptsRead() throws Exception {

        int ret = 0;
        String protocol = null;
        SSLServerSocket ss = null;
        boolean passed = false;

        System.out.print("\tTesting close/read interrupt");

        /* pipe() interrupt mechamism not implemented for Windows yet since
         * Windows does not support Unix/Linux pipe(). Re-enable this test
         * for Windows when that support has been added */
        if (WolfSSLTestFactory.isWindows()) {
            System.out.println("\t... skipped");
            return;
        }

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
        this.ctx = tf.createSSLContext(protocol, ctxProvider);

        /* create SSLServerSocket first to get ephemeral port */
        ss = (SSLServerSocket)ctx.getServerSocketFactory()
            .createServerSocket(0);

        final SSLSocket cs = (SSLSocket)ctx.getSocketFactory().createSocket();
        cs.connect(new InetSocketAddress(ss.getLocalPort()));

        final SSLSocket server = (SSLSocket)ss.accept();
        final CountDownLatch closeLatch = new CountDownLatch(1);

        ExecutorService es = Executors.newSingleThreadExecutor();
        Future<Void> serverFuture = es.submit(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                try {
                    server.startHandshake();

                    boolean doClose = closeLatch.await(90L, TimeUnit.SECONDS);
                    if (!doClose) {
                        /* Return without closing, latch not hit within
                         * time limit */
                        return null;
                    }

                    /* Sleep to let client thread hit read call */
                    Thread.sleep(1000);
                    cs.setSoLinger(true, 5);
                    cs.close();

                } catch (SSLException e) {
                    System.out.println("\t... failed");
                    e.printStackTrace();
                    fail("Server thread got SSLException when not expected");
                }
                return null;
            }
        });

        byte[] tmpArr = new byte[1024];
        InputStream in = cs.getInputStream();

        try {
            try {
                cs.startHandshake();
            }
            catch (Exception e) {
                System.out.println("\t... failed");
                e.printStackTrace();
                fail("Exception from startHandshake() when not expected");
            }

            try {
                /* signal server thread to try and close socket */
                closeLatch.countDown();

                while (true) {
                    ret = in.read(tmpArr, 0, tmpArr.length);
                    if (ret == -1) {
                        /* end of stream */
                        break;
                    }
                }

            } catch (SocketException e) {
                /* We expect SocketException with this message, error if
                 * different than expected */
                if (!e.getMessage().contains("Socket is closed") &&
                    !e.getMessage().contains("Connection already shutdown") &&
                    !e.getMessage().contains("object has been freed")) {
                    System.out.println("\t... failed");
                    e.printStackTrace();
                    fail("Incorrect SocketException thrown by client");
                    throw e;
                }
            }

            passed = true;
        }
        finally {
            es.shutdown();
            serverFuture.get();
            if (!cs.isClosed()) {
                cs.close();
            }
            if (!server.isClosed()) {
                server.close();
            }
            if (!ss.isClosed()) {
                ss.close();
            }
        }

        if (passed) {
            System.out.println("\t... passed");
        }
    }

    @Test
    public void testSocketMethodsAfterClose() throws Exception {

        String protocol = null;

        System.out.print("\tTesting methods after close");

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

        /* Test calling public SSLSocket methods after close, make sure
         * exception or return value is what we expect. */

        try {
            cs.getApplicationProtocol();
        } catch (Exception e) {
            /* should not throw exception */
            System.out.println("\t... failed");
            fail("getApplicationProtocol() exception after close()");
        }

        try {
            cs.getEnableSessionCreation();
        } catch (Exception e) {
            /* should not throw exception */
            System.out.println("\t... failed");
            fail("getEnableSessionCreation() exception after close()");
        }

        try {
            cs.setEnableSessionCreation(true);
        } catch (Exception e) {
            /* should not throw exception */
            System.out.println("\t... failed");
            fail("setEnableSessionCreation() exception after close()");
        }

        try {
            if (cs.getWantClientAuth() != false) {
                System.out.println("\t... failed");
                fail("getWantClientAuth() not false after close()");
            }
        } catch (Exception e) {
            /* should not throw exception */
            System.out.println("\t... failed");
            fail("getWantClientAuth() exception after close()");
        }

        try {
            cs.setWantClientAuth(true);
        } catch (Exception e) {
            /* should not throw exception */
            System.out.println("\t... failed");
            fail("setWantClientAuth() exception after close()");
        }

        try {
            if (cs.getNeedClientAuth() != false) {
                System.out.println("\t... failed");
                fail("getNeedClientAuth() not false after close()");
            }
        } catch (Exception e) {
            /* should not throw exception */
            System.out.println("\t... failed");
            fail("getNeedClientAuth() exception after close()");
        }

        try {
            cs.setNeedClientAuth(true);
        } catch (Exception e) {
            /* should not throw exception */
            System.out.println("\t... failed");
            fail("setNeedClientAuth() exception after close()");
        }

        try {
            if (cs.getUseClientMode() != true) {
                System.out.println("\t... failed");
                fail("getUseClientMode() on client not true after close()");
            }
        } catch (Exception e) {
            /* should not throw exception */
            System.out.println("\t... failed");
            fail("getUseClientMode() exception after close()");
        }

        try {
            cs.setUseClientMode(true);
        } catch (Exception e) {
            /* should not throw exception */
            System.out.println("\t... failed");
            fail("setUseClientMode() exception after close()");
        }

        try {
            if (cs.getHandshakeSession() != null) {
                System.out.println("\t... failed");
                fail("getHandshakeSession() not null after close()");
            }
        } catch (Exception e) {
            /* should not throw exception */
            System.out.println("\t... failed");
            fail("getHandshakeSession() exception after close()");
        }

        try {
            SSLSession closeSess = cs.getSession();
            if (closeSess == null ||
                !closeSess.getCipherSuite().equals("SSL_NULL_WITH_NULL_NULL")) {
                System.out.println("\t... failed");
                fail("getSession() null or wrong cipher suite after close()");
            }
        } catch (Exception e) {
            /* should not throw exception */
            System.out.println("\t... failed");
            fail("getSession() exception after close()");
        }

        try {
            if (cs.getEnabledProtocols() != null) {
                System.out.println("\t... failed");
                fail("getEnabledProtocols() not null after close()");
            }
        } catch (Exception e) {
            /* should not throw exception */
            System.out.println("\t... failed");
            fail("getEnabledProtocols() exception after close()");
        }

        try {
            cs.setEnabledProtocols(new String[] {"INVALID"});
        } catch (Exception e) {
            /* should not throw exception */
            System.out.println("\t... failed");
            fail("setEnabledProtocols() exception after close()");
        }

        try {
            cs.setEnabledCipherSuites(new String[] {"INVALID"});
        } catch (Exception e) {
            /* should not throw exception */
            System.out.println("\t... failed");
            fail("setEnabledCipherSuites() exception after close()");
        }

        try {
            String[] suppProtos = cs.getSupportedProtocols();
            if (suppProtos == null || suppProtos.length == 0) {
                System.out.println("\t... failed");
                fail("getSupportedProtocols() null or empty after close()");
            }
        } catch (Exception e) {
            /* should not throw exception */
            System.out.println("\t... failed");
            fail("getSupportedProtocols() exception after close()");
        }

        try {
            String[] suppSuites = cs.getSupportedCipherSuites();
            if (suppSuites == null || suppSuites.length == 0) {
                System.out.println("\t... failed");
                fail("getSupportedCipherSuites() null or empty after close()");
            }
        } catch (Exception e) {
            /* should not throw exception */
            System.out.println("\t... failed");
            fail("getSupportedCipherSuites() exception after close()");
        }

        try {
            if (cs.getEnabledCipherSuites() != null) {
                System.out.println("\t... failed");
                fail("getEnabledCipherSuites() not null after close()");
            }
        } catch (Exception e) {
            /* should not throw exception */
            System.out.println("\t... failed");
            fail("getEnabledCipherSuites() exception after close()");
        }

        System.out.println("\t... passed");
    }
    @Test
    public void testAutoSNIProperty() throws Exception {
        System.out.print("\tTesting autoSNI property");

        /* Save original System property value */
        String originalProp = System.getProperty("wolfjsse.autoSNI");

        try {
            /* Test with autoSNI enabled */
            System.setProperty("wolfjsse.autoSNI", "true");

            /* Create new CTX */
            this.ctx = tf.createSSLContext("TLS", ctxProvider);

            /* Create SSLServerSocket first to get ephemeral port */
            SSLServerSocket ss = (SSLServerSocket)ctx.getServerSocketFactory()
                .createServerSocket(0);

            /* Set up test arguments without explicit SNI configuration.
             * With autoSNI=true, SNI should be automatically set based on
             * hostname */
            TestArgs sArgs = new TestArgs(null,
                            null, true,
                            true,
                            true,
                            null);
            TestArgs cArgs = new TestArgs(null,
                            null,
                            false,
                            false,
                            true,
                            null);

            CountDownLatch sDoneLatch = new CountDownLatch(1);
            CountDownLatch cDoneLatch = new CountDownLatch(1);

            TestServer server =
                new TestServer(this.ctx, ss, sArgs, 1, sDoneLatch);
            server.start();

            TestClient client =
                new TestClient(this.ctx, ss.getLocalPort(), cArgs, cDoneLatch);
            client.start();

            cDoneLatch.await();
            sDoneLatch.await();

            Exception srvException = server.getException();
            if (srvException != null) {
                throw srvException;
            }

            Exception cliException = client.getException();
            if (cliException != null) {
                throw cliException;
            }

            /* Test with autoSNI disabled */
            System.setProperty("wolfjsse.autoSNI", "false");

            ss = (SSLServerSocket)ctx.getServerSocketFactory()
                .createServerSocket(0);

            sDoneLatch = new CountDownLatch(1);
            cDoneLatch = new CountDownLatch(1);

            server = new TestServer(this.ctx, ss, sArgs,
                            1, sDoneLatch);
            server.start();

            client = new TestClient(this.ctx, ss.getLocalPort(), cArgs,
                cDoneLatch);
            client.start();

            cDoneLatch.await();
            sDoneLatch.await();

            srvException = server.getException();
            if (srvException != null) {
                throw srvException;
            }

            cliException = client.getException();
            if (cliException != null) {
                throw cliException;
            }

            System.out.println("\t... passed");

        } finally {
            /* Restore original property value */
            if (originalProp != null) {
                System.setProperty("wolfjsse.autoSNI", originalProp);
            } else {
                System.setProperty("wolfjsse.autoSNI", "true");
            }
        }
    }

    @Test
    public void testSNIMatchers() throws Exception {

        System.out.print("\tTesting SNI Matchers");

        /* SNI matcher functionality requires wolfSSL 5.7.6 or later.
         * Older versions have a limitation where wolfSSL_SNI_GetRequest()
         * only returns SNI data if native wolfSSL already matched it, but
         * wolfJSSE relies on retrieving the SNI to do matching at the Java
         * level. wolfSSL 5.7.2 added an ignoreStatus parameter to
         * TLSX_SNI_GetRequest(), and wolfSSL 5.7.6 enabled
         * WOLFSSL_ALWAYS_KEEP_SNI by default with --enable-jni (PR 8283),
         * which is required for full SNI matcher rejection behavior. */
        long libVerHex = WolfSSL.getLibVersionHex();
        if (libVerHex < 0x05007006L) {
            System.out.println("\t\t... skipped");
            return;
        }

        /* create new CTX */
        this.ctx = tf.createSSLContext("TLS", ctxProvider);

        /* create SSLServerSocket first to get ephemeral port */
        final SSLServerSocket ss =
            (SSLServerSocket)ctx.getServerSocketFactory()
                .createServerSocket(0);

        /* Configure SNI matcher for server*/
        SNIMatcher matcher =
            SNIHostName.createSNIMatcher("www\\.example\\.com");
        Collection<SNIMatcher> matchers = new ArrayList<>();
        matchers.add(matcher);
        SSLParameters sp = ss.getSSLParameters();
        sp.setSNIMatchers(matchers);
        ss.setSSLParameters(sp);

        try {

            /* ------------------------------------ */
            /* Test matched SNI case, should pass */
            /* ------------------------------------ */

            SSLSocket cs = (SSLSocket)ctx.getSocketFactory().createSocket();
            cs.connect(new InetSocketAddress(ss.getLocalPort()));

            /* Set SNI hostname for client */
            SNIHostName serverName = new SNIHostName("www.example.com");
            List<SNIServerName> serverNames = new ArrayList<>();
            serverNames.add(serverName);
            SSLParameters cp = cs.getSSLParameters();
            cp.setServerNames(serverNames);
            cs.setSSLParameters(cp);

            final SSLSocket serverMatched = (SSLSocket)ss.accept();

            ExecutorService es = Executors.newSingleThreadExecutor();
            Future<Void> serverFuture = es.submit(new Callable<Void>() {
                @Override
                public Void call() throws Exception {
                    try {
                        serverMatched.startHandshake();
                        serverMatched.close();
                    } catch (SSLException e) {
                        System.out.println("\t... failed");
                        fail();
                    }
                    return null;
                }
            });

            cs.startHandshake();
            cs.close();

            es.shutdown();
            serverFuture.get();

            /* ------------------------------------ */
            /* Test unmatched SNI case, should fail */
            /* ------------------------------------ */
            cs = (SSLSocket)ctx.getSocketFactory().createSocket();
            cs.connect(new InetSocketAddress(ss.getLocalPort()));

            /* Set non-matching SNI hostname for client */
            serverName = new SNIHostName("www.example.org");
            serverNames = new ArrayList<>();
            serverNames.add(serverName);
            cp = cs.getSSLParameters();
            cp.setServerNames(serverNames);
            cs.setSSLParameters(cp);

            final SSLSocket serverUnmatched = (SSLSocket)ss.accept();

            es = Executors.newSingleThreadExecutor();
            serverFuture = es.submit(() -> {
                try {
                    serverUnmatched.startHandshake();
                    fail("Server handshake succeeded with non-matching SNI");
                } catch (SSLHandshakeException e) {
                    /* Expected failure with non-matching SNI */
                }
                return null;
            });

            try {
                cs.startHandshake();
            } catch (SSLHandshakeException e) {
                /* Expect client to close connection, wolfJSSE does not expect
                 * to an exception. However, SunJSSE will throw an exception */
            }

            es.shutdown();
            serverFuture.get();
            cs.close();

            System.out.println("\t\t... passed");
        } catch (Exception e) {
            System.out.println("\t\t... failed");
            e.printStackTrace();
            fail("SNI Matcher test failed: " + e.getMessage());
        } finally {
            ss.close();
        }
    }

    /**
     * Inner class used to hold configuration options for
     * TestServer and TestClient classes.
     */
    protected class TestArgs
    {
        private String endpointIDAlg = null;
        private String sniName = null;
        private boolean wantClientAuth = true;
        private boolean needClientAuth = true;
        private boolean callStartHandshake = true;
        private X509Certificate expectedPeerCert = null;
        private String[] alpnList = null;
        private String callbackAlpn = null;
        private String expectedAlpn = null;

        public TestArgs() { }

        public TestArgs(String endpointID, String sni,
            boolean wantClientAuth, boolean needClientAuth,
            boolean callStartHandshake, X509Certificate expectedPeerCert) {

            this.endpointIDAlg = endpointID;
            this.sniName = sni;
            this.wantClientAuth = wantClientAuth;
            this.needClientAuth = needClientAuth;
            this.callStartHandshake = callStartHandshake;
            this.expectedPeerCert = expectedPeerCert;
        }

        public void setEndpointIdentificationAlg(String alg) {
            this.endpointIDAlg = alg;
        }

        public String getEndpointIdentificationAlg() {
            return this.endpointIDAlg;
        }

        public void setSNIName(String sni) {
            this.sniName = sni;
        }

        public String getSNIName() {
            return this.sniName;
        }

        public void setWantClientAuth(boolean want) {
            this.wantClientAuth = want;
        }

        public boolean getWantClientAuth() {
            return this.wantClientAuth;
        }

        public void setExpectedPeerCert(X509Certificate cert) {
            this.expectedPeerCert = cert;
        }

        public X509Certificate getExpectedPeerCert() {
            return this.expectedPeerCert;
        }

        public void setNeedClientAuth(boolean need) {
            this.needClientAuth = need;
        }

        public boolean getNeedClientAuth() {
            return this.needClientAuth;
        }

        public void setCallStartHandshake(boolean call) {
            this.callStartHandshake = call;
        }

        public boolean getCallStartHandshake() {
            return this.callStartHandshake;
        }

        public void setAlpnList(String[] alpns) {
            this.alpnList = alpns;
        }

        public String[] getAlpnList() {
            return this.alpnList;
        }

        public void setAlpnForCallback(String alpn) {
            this.callbackAlpn = alpn;
        }

        public String getAlpnForCallback() {
            return this.callbackAlpn;
        }

        public void setExpectedAlpn(String alpn) {
            this.expectedAlpn = alpn;
        }

        public String getExpectedAlpn() {
            return this.expectedAlpn;
        }
    }

    protected class TestServer extends Thread
    {
        private SSLContext ctx;
        private int port;
        private Exception exception = null;
        private TestArgs args = null;
        private int numConnections = 1;
        WolfSSLSocketTest wst;
        SSLServerSocket ss = null;
        CountDownLatch doneLatch = null;

        public TestServer(SSLContext ctx, SSLServerSocket ss,
            TestArgs args, int numConnections, CountDownLatch doneLatch) {
            this.ctx = ctx;
            this.ss = ss;
            this.args = args;
            this.numConnections = numConnections;
            this.doneLatch = doneLatch;
        }


        @Override
        public void run() {

            try {
                for (int i = 0; i < numConnections; i++) {
                    SSLSocket sock = (SSLSocket)ss.accept();
                    sock.setUseClientMode(false);

                    SSLParameters params = sock.getSSLParameters();

                    params.setWantClientAuth(this.args.getWantClientAuth());
                    params.setNeedClientAuth(this.args.getNeedClientAuth());

                    /* Set ALPN list of supported */
                    if (this.args.getAlpnList() != null) {
                        params.setApplicationProtocols(this.args.getAlpnList());
                    }

                    sock.setSSLParameters(params);

                    if (sock.getHandshakeApplicationProtocol() != null) {
                        throw new Exception(
                            "getHandshakeApplicationProtocol() should be " +
                            "null before handshake");
                    }

                    if (sock.getHandshakeApplicationProtocolSelector()
                            != null) {
                        throw new Exception(
                            "getHandshakeApplicationProtocolSelector() " +
                            "should be null before being set");
                    }

                    /* wolfSSL_set_alpn_select_cb() added in wolfSSL 5.6.6 */
                    if (WolfSSL.getLibVersionHex() >= 0x05006006) {
                        /* Set ALPN selector callback if needed, Calls
                         * chooseAppProtocol during handshake to let server
                         * pick desired ALPN value */
                        if (this.args.getAlpnForCallback() != null) {
                            sock.setHandshakeApplicationProtocolSelector(
                                (serverSocket, clientProtocols) -> {
                                SSLSession s =
                                    serverSocket.getHandshakeSession();
                                return chooseAppProtocol(
                                    serverSocket,
                                    clientProtocols,
                                    s.getProtocol(),
                                    s.getCipherSuite());
                            });
                        }
                    }

                    if (this.args.getCallStartHandshake()) {
                        sock.startHandshake();
                    }

                    int in = sock.getInputStream().read();
                    assertEquals(in, (int)'A');
                    sock.getOutputStream().write('B');

                    if (this.args.getExpectedAlpn() != null) {
                        if (!sock.getApplicationProtocol().equals(
                            this.args.getExpectedAlpn())) {
                            throw new Exception(
                                "Expected getApplicationProtocol() " +
                                "did not match actual\n" +
                                "expected: " + this.args.getExpectedAlpn() +
                                "\nactual: " + sock.getApplicationProtocol());
                        }
                    }

                    sock.close();
                }

            } catch (Exception e) {
                this.exception = e;
            } finally {
                this.doneLatch.countDown();
            }
        }

        public String chooseAppProtocol(SSLSocket serverSock,
            List<String> clientProtocols, String protocol,
            String cipherSuite) {

            if (this.args.getAlpnForCallback() == null) {
                /* empty string will ignore ALPN and continue handshake */
                return "";
            }

            return this.args.getAlpnForCallback();
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
        private TestArgs args = null;
        WolfSSLSocketTest wst;
        CountDownLatch doneLatch = null;

        public TestClient(SSLContext ctx, int port, TestArgs args,
            CountDownLatch doneLatch) {
            this.ctx = ctx;
            this.srvPort = port;
            this.args = args;
            this.doneLatch = doneLatch;
        }

        @Override
        public void run() {

            try {
                SSLSocket sock = (SSLSocket)ctx.getSocketFactory()
                    .createSocket();
                sock.setUseClientMode(true);
                sock.connect(new InetSocketAddress(srvPort));

                SSLParameters params = sock.getSSLParameters();

                /* Enable Endpoint Identification for hostname verification */
                if (this.args.getEndpointIdentificationAlg() != null) {
                    params.setEndpointIdentificationAlgorithm(
                        this.args.getEndpointIdentificationAlg());
                }

                /* Set SNI, used for hostname verification of server cert */
                if (this.args.getSNIName() != null) {
                    SNIHostName sniName = new SNIHostName(
                        this.args.getSNIName());
                    List<SNIServerName> sniNames = new ArrayList<>(1);
                    sniNames.add(sniName);
                    params.setServerNames(sniNames);
                }

                /* Set client ALPN list to include in ClientHello */
                if (this.args.getAlpnList() != null) {
                    params.setApplicationProtocols(this.args.getAlpnList());
                }

                sock.setSSLParameters(params);

                if (sock.getHandshakeApplicationProtocol() != null) {
                    throw new Exception(
                        "getHandshakeApplicationProtocol() should be " +
                        "null before handshake");
                }

                if (this.args.getCallStartHandshake()) {
                    sock.startHandshake();
                }

                sock.getOutputStream().write('A');
                int in = sock.getInputStream().read();
                assertEquals(in, (int)'B');

                if (this.args.getExpectedAlpn() != null) {
                    if (!sock.getApplicationProtocol().equals(
                        this.args.getExpectedAlpn())) {
                        throw new Exception(
                            "Expected getApplicationProtocol() " +
                            "did not match actual\n" +
                            "expected: " + this.args.getExpectedAlpn() +
                            "\nactual: " + sock.getApplicationProtocol());
                    }
                }

                sock.close();

            } catch (Exception e) {
                this.exception = e;
            } finally {
                this.doneLatch.countDown();
            }
        }

        public Exception getException() {
            return this.exception;
        }
    }

    @Test
    public void testDoubleCloseNPERegression()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               IOException {

        System.out.print("\tdouble close() regression test");

        /* Test that calling close() when ssl field is null does not cause
         * NullPointerException. This is a regression test for the fix where
         * this.ssl could be null during close() operations. */

        if (sockFactories.size() > 0) {
            SSLSocketFactory sf = sockFactories.get(0);
            SSLSocket sock = null;

            try {
                /* Create unconnected socket to test close() behavior */
                sock = (SSLSocket)sf.createSocket();

                /* Use reflection to simulate the scenario where ssl field
                 * becomes null (as happens after first close or due to
                 * race conditions) */
                if (sock instanceof com.wolfssl.provider.jsse.WolfSSLSocket) {
                    try {
                        Field sslField =
                            com.wolfssl.provider.jsse
                                .WolfSSLSocket.class.getDeclaredField("ssl");
                        sslField.setAccessible(true);
                        sslField.set(sock, null);

                        /* Now call close() with ssl=null - this should NOT
                         * throw NPE if the fix is in place, but WILL throw
                         * NPE with vulnerable code */
                        sock.close();

                    } catch (NoSuchFieldException | IllegalAccessException e) {
                        /* If reflection fails,
                         * skip this specific test but don't fail */
                        System.out.print(" (reflection skipped)");
                    } catch (NullPointerException e) {
                        System.out.println("\t... failed");
                        fail("close() call with null ssl field threw " +
                             "NullPointerException: " + e.getMessage() +
                             ". This indicates the NPE fix is not working.");
                    }
                }

            } catch (IOException e) {
                /* Socket creation failed, but that's not what we're testing */
            }
        }

        System.out.println("\t... passed");
    }

    @Test
    public void testCloseWithNullEngineHelper()
        throws NoSuchFieldException, IllegalAccessException {

        System.out.print("\tclose() with null EngineHelper");

        /* Create a normal WolfSSLSocket first using the factory */
        SSLSocketFactory factory = null;
        for (SSLSocketFactory f : sockFactories) {
            if (f != null) {
                factory = f;
                break;
            }
        }
        assertNotNull("No SSLSocketFactory available for test", factory);

        WolfSSLSocket socket = null;
        try {
            /* Create a socket but don't connect it */
            socket = (WolfSSLSocket) factory.createSocket();

            /* Use reflection to set EngineHelper to null, simulating the
             * scenario where constructor failed after partial
             * initialization */
            Field engineHelperField =
                WolfSSLSocket.class.getDeclaredField("EngineHelper");
            engineHelperField.setAccessible(true);
            engineHelperField.set(socket, null);

        } catch (Exception e) {
            fail("Failed to create test socket or set EngineHelper to null: "
                 + e.getMessage());
        }

        /* Verify that calling close() on the socket with null EngineHelper
         * does not throw NullPointerException */
        try {
            if (socket != null) {
                socket.close();
            }
            /* Test should fail here if NPE occurs */
        } catch (NullPointerException npe) {
            fail("close() threw NullPointerException when EngineHelper " +
                "is null: " + npe.getMessage());
        } catch (IOException e) {
            /* IOException from close() is acceptable */
        }

        System.out.println("\t... passed");
    }

    /**
     * This test verifies that WolfSSLX509StoreCtx.getCerts() returns
     * certificates in the correct peer to root order during a TLS
     * handshake. Register a custom X509TrustManager (not WolfSSLTrustX509)
     * so that the internal sorting logic in WolfSSLTrustX509 doesn't run.
     * This exposes the raw certificate order coming from the JNI layer.
     */
    @Test
    public void testCertificateChainOrderingFromStoreCtx()
        throws Exception {

        System.out.print("\tProper chain ordering");

        /* Custom TrustManager that checks certificate order */
        final boolean[] wasCalled = {false};
        final boolean[] orderCorrect = {false};
        final String[] errorMsg = {null};
        final int[] chainLen = {0};

        String serverIntCert =
            "examples/certs/intermediate/server-int-ecc-cert.pem";
        String serverIntKey = "examples/certs/ecc-key.pem";
        String intCaCert = "examples/certs/intermediate/ca-int-ecc-cert.pem";
        String int2CaCert =
            "examples/certs/intermediate/ca-int2-ecc-cert.pem";
        String serverEccJKS = "examples/provider/server-ecc.jks";

        if (WolfSSLTestFactory.isAndroid()) {
            serverIntCert = "/data/local/tmp/" + serverIntCert;
            serverIntKey = "/data/local/tmp/" + serverIntKey;
            intCaCert = "/data/local/tmp/" + intCaCert;
            int2CaCert = "/data/local/tmp/" + int2CaCert;
            serverEccJKS = "/data/local/tmp/examples/provider/server-ecc.bks";
        }

        X509TrustManager customTM = new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain,
                String authType) throws CertificateException {
                /* Not used in this test */
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain,
                String authType) throws CertificateException {
                wasCalled[0] = true;

                if (chain == null || chain.length == 0) {
                    errorMsg[0] = "Certificate chain is null or empty";
                    throw new CertificateException(errorMsg[0]);
                }

                chainLen[0] = chain.length;

                /* Per RFC 5280, leaf/end-entity certs have
                 * getBasicConstraints() return -1, while CA certs return
                 * >= 0. The first certificate in the chain MUST be the
                 * peer/leaf certificate. */
                int firstCertBC = chain[0].getBasicConstraints();

                if (firstCertBC == -1) {
                    /* First cert is leaf/peer cert, order is correct */
                    orderCorrect[0] = true;

                } else {
                    /* First cert is a CA cert, order is WRONG */
                    orderCorrect[0] = false;
                    errorMsg[0] = "Certificate chain order is incorrect: " +
                        "first cert is CA (BasicConstraints=" + firstCertBC +
                        "), expected leaf/peer cert (BasicConstraints=-1). " +
                        "Chain length: " + chain.length + ". " +
                        "First cert subject: " +
                        chain[0].getSubjectX500Principal().getName();
                    /* NOTE: We don't throw here so test can verify the flag,
                     * but in production a wrapper TrustManager would fail */
                }
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        };

        /* Build server KeyStore with intermediate chain from pem files */
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        FileInputStream fis = new FileInputStream(serverIntCert);
        BufferedInputStream bis = new BufferedInputStream(fis);
        X509Certificate serverCert =
            (X509Certificate)cf.generateCertificate(bis);
        bis.close();
        fis.close();

        fis = new FileInputStream(intCaCert);
        bis = new BufferedInputStream(fis);
        X509Certificate intCert = (X509Certificate)cf.generateCertificate(bis);
        bis.close();
        fis.close();

        fis = new FileInputStream(int2CaCert);
        bis = new BufferedInputStream(fis);
        X509Certificate int2Cert = (X509Certificate)cf.generateCertificate(bis);
        bis.close();
        fis.close();

        /* Create KeyStore and add server cert with chain */
        KeyStore serverKeyStore = KeyStore.getInstance(tf.keyStoreType);
        serverKeyStore.load(null, null);

        /* Build certificate chain: server, int2 (immediate issuer), int */
        Certificate[] certChain = new Certificate[3];
        certChain[0] = serverCert;
        certChain[1] = int2Cert;
        certChain[2] = intCert;

        /* Load existing ECC private key from server-ecc.jks, since Java
         * doesn't natively support SEC1 ECC format without Bouncy Castle */
        KeyStore tmpKS = KeyStore.getInstance(tf.keyStoreType);
        fis = new FileInputStream(serverEccJKS);
        tmpKS.load(fis, "wolfSSL test".toCharArray());
        fis.close();

        java.security.PrivateKey privateKey =
            (java.security.PrivateKey)tmpKS.getKey("server-ecc",
                "wolfSSL test".toCharArray());

        /* Add private key with intermediate certificate chain to keystore */
        serverKeyStore.setKeyEntry("server-int-ecc", privateKey,
            "wolfSSL test".toCharArray(), certChain);

        /* Set up server with intermediate certificate chain */
        ExecutorService executor = Executors.newSingleThreadExecutor();
        SSLServerSocket serverSocket = null;

        try {
            KeyManagerFactory serverKM =
                KeyManagerFactory.getInstance("SunX509");
            serverKM.init(serverKeyStore, "wolfSSL test".toCharArray());

            /* Server uses default wolfSSL TrustManager */
            TrustManagerFactory serverTM =
                TrustManagerFactory.getInstance("SunX509");
            serverTM.init(serverKeyStore);

            SSLContext serverCtx =
                SSLContext.getInstance("TLSv1.2", "wolfJSSE");
            serverCtx.init(serverKM.getKeyManagers(),
                           serverTM.getTrustManagers(), null);

            serverSocket =
                (SSLServerSocket)serverCtx.getServerSocketFactory()
                    .createServerSocket(0);
            final int serverPort = serverSocket.getLocalPort();
            final SSLServerSocket finalServerSocket = serverSocket;

            /* Start server thread */
            Future<Void> serverFuture =
                executor.submit(new Callable<Void>() {
                @Override
                public Void call() throws Exception {
                    SSLSocket serverSock = null;
                    try {
                        serverSock =
                            (SSLSocket)finalServerSocket.accept();
                        InputStream in = serverSock.getInputStream();
                        OutputStream out = serverSock.getOutputStream();

                        /* Simple echo */
                        byte[] buf = new byte[1024];
                        int read = in.read(buf);
                        if (read > 0) {
                            out.write(buf, 0, read);
                        }
                    } finally {
                        if (serverSock != null) {
                            serverSock.close();
                        }
                    }
                    return null;
                }
            });

            /* Set up client with CUSTOM TrustManager (not WolfSSLTrustX509) */
            KeyStore clientKeyStore = KeyStore.getInstance(tf.keyStoreType);
            InputStream stream = new FileInputStream(tf.clientJKS);
            clientKeyStore.load(stream, jksPass);
            stream.close();

            KeyManagerFactory clientKM =
                KeyManagerFactory.getInstance("SunX509");
            clientKM.init(clientKeyStore, jksPass);

            /* Client uses our CUSTOM TrustManager */
            SSLContext clientCtx =
                SSLContext.getInstance("TLSv1.2", "wolfJSSE");
            clientCtx.init(clientKM.getKeyManagers(),
                           new TrustManager[] { customTM }, null);

            /* Connect client */
            SSLSocket clientSocket = null;
            try {
                clientSocket = (SSLSocket)clientCtx.getSocketFactory()
                    .createSocket("localhost", serverPort);

                /* Force handshake - this will call our custom TrustManager */
                clientSocket.startHandshake();

                /* Send test data */
                OutputStream out = clientSocket.getOutputStream();
                out.write("test".getBytes());
                out.flush();

                /* Read response */
                InputStream in = clientSocket.getInputStream();
                byte[] buf = new byte[1024];
                in.read(buf);

            } finally {
                if (clientSocket != null) {
                    clientSocket.close();
                }
            }

            /* Wait for server to finish */
            serverFuture.get(10, TimeUnit.SECONDS);

        } finally {
            if (serverSocket != null) {
                serverSocket.close();
            }
            executor.shutdown();
        }

        /* Verify TrustManager was called */
        assertTrue("Custom TrustManager.checkServerTrusted() was not called",
            wasCalled[0]);

        /* Verify we got a chain with multiple certs */
        assertTrue("Expected chain length > 1, got: " + chainLen[0],
            chainLen[0] > 1);

        assertTrue("Certificate chain order is incorrect: " +
            (errorMsg[0] != null ? errorMsg[0] :
                "first cert was not peer/leaf cert"),
            orderCorrect[0]);

        System.out.println("\t\t... passed");
    }

    @Test
    public void testSSLHandshakeExceptionCauseChain()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               KeyManagementException, KeyStoreException,
               CertificateException, IOException,
               UnrecoverableKeyException, InterruptedException,
               java.util.concurrent.ExecutionException {

        System.out.print("\tSSLHandshakeException cause chain");

        /* Create server context with valid certs */
        SSLContext srvCtx = tf.createSSLContext("TLS", ctxProvider);

        /* Create client context with rejecting TrustManager.
         * When checkServerTrusted() throws CertificateException,
         * wolfJSSE should preserve it as the cause of
         * SSLHandshakeException thrown from startHandshake(). */
        final String rejectMsg = "Intentional test rejection";
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

        SSLContext cliCtx = SSLContext.getInstance("TLS", "wolfJSSE");
        cliCtx.init(null, rejectingTMs, null);

        /* Create server socket on ephemeral port */
        SSLServerSocket ss = (SSLServerSocket)srvCtx
            .getServerSocketFactory().createServerSocket(0);

        SSLSocket cs = (SSLSocket)cliCtx.getSocketFactory().createSocket();
        cs.connect(new InetSocketAddress(
            InetAddress.getLocalHost(), ss.getLocalPort()));

        final SSLSocket server = (SSLSocket)ss.accept();

        ExecutorService es = Executors.newSingleThreadExecutor();
        Future<Void> serverFuture = es.submit(new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                try {
                    server.startHandshake();
                } catch (SSLException e) {
                    /* expected, client will reject server cert */
                }
                return null;
            }
        });

        try {
            cs.startHandshake();
            System.out.println("\t... failed");
            fail("Expected SSLHandshakeException from rejecting " +
                 "TrustManager");
        } catch (SSLHandshakeException e) {
            /* Verify the cause chain preserves CertificateException */
            Throwable cause = e.getCause();
            assertNotNull(
                "SSLHandshakeException cause should not be null",
                cause);
            assertTrue(
                "Cause should be CertificateException, got: " +
                cause.getClass().getName(),
                cause instanceof CertificateException);
            assertEquals(
                "CertificateException message mismatch",
                rejectMsg, cause.getMessage());
        }

        es.shutdown();
        serverFuture.get();
        cs.close();
        server.close();
        ss.close();

        System.out.println("\t... passed");
    }
}

