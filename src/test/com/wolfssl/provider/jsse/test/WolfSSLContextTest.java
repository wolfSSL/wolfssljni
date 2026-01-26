/* WolfSSLContextTest.java
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
import java.util.ArrayList;

import com.wolfssl.WolfSSLException;

import java.io.FileInputStream;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLParameters;
import java.security.Security;
import java.security.Provider;
import java.security.KeyStore;
import java.security.SecureRandom;

import java.io.IOException;
import java.io.InputStream;
import java.io.FileNotFoundException;
import java.security.KeyStoreException;
import java.security.KeyManagementException;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;

import com.wolfssl.WolfSSL;
import com.wolfssl.provider.jsse.WolfSSLProvider;

import java.lang.reflect.Method;

public class WolfSSLContextTest {

    private static WolfSSLTestFactory tf;
    private static final char[] jksPass = "wolfSSL test".toCharArray();
    private static final String ctxProvider = "wolfJSSE";

    private static String[] allProtocols = {
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

        System.out.println("WolfSSLContext Class");

        /* install wolfJSSE provider at runtime */
        Security.insertProviderAt(new WolfSSLProvider(), 1);

        Provider p = Security.getProvider("wolfJSSE");
        assertNotNull(p);

        System.out.print("\tGetting provider name");
        if (p.getName().contains("wolfJSSE")) {
            System.out.println("\t\t... passed");
        } else {
            System.out.println("\t\t... failed");
            fail("Failed to get proper wolfJSSE provider name");
        }

        try {
            tf = new WolfSSLTestFactory();
        } catch (WolfSSLException e) {
            e.printStackTrace();
        }

        /* populate enabledProtocols */
        synchronized (WolfSSLTestFactory.jdkTlsDisabledAlgorithmsLock) {
            for (int i = 0; i < allProtocols.length; i++) {
                try {
                    SSLContext ctx = SSLContext.getInstance(allProtocols[i],
                        ctxProvider);

                    if (WolfSSLTestFactory.securityPropContains(
                        "jdk.tls.disabledAlgorithms", allProtocols[i])) {
                        /* skip adding, protocol has been disabled */
                        continue;
                    }

                    enabledProtocols.add(allProtocols[i]);

                } catch (NoSuchAlgorithmException e) {
                    /* protocol not enabled */
                }
            }
        } /* jdkTlsDisabledAlgorithmsLock */
    }

    @Test
    public void testGetSSLContextFromProvider()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        SSLContext ctx;

        System.out.print("\tTesting protocol support");

        /* try to get all available protocols we expect to have */
        for (int i = 0; i < enabledProtocols.size(); i++) {
            ctx = SSLContext.getInstance(enabledProtocols.get(i),
                ctxProvider);
        }

        /* getting a garbage protocol should throw an exception */
        try {
            ctx = SSLContext.getInstance("NotValid", ctxProvider);

            System.out.println("\t... failed");
            fail("SSLContext.getInstance should throw " +
                 "NoSuchAlgorithmException when given bad protocol");

        } catch (NoSuchAlgorithmException nsae) {
            System.out.println("\t... passed");
        }
    }

    @Test
    public void testGetSocketFactory() throws NoSuchProviderException,
        NoSuchAlgorithmException, IllegalStateException,
        KeyManagementException, Exception {

        SSLContext ctx;
        KeyManagerFactory km;
        TrustManagerFactory tm;
        KeyStore pKey, cert;
        SSLSocketFactory ssf;

        System.out.print("\tgetSocketFactory()");

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
            ctx = SSLContext.getInstance(enabledProtocols.get(i),
                ctxProvider);

            ctx.init(km.getKeyManagers(), tm.getTrustManagers(), null);

            ssf = ctx.getSocketFactory();
            assertNotNull(ssf);
        }

        System.out.println("\t\t... passed");
    }

    @Test
    public void testInit() throws NoSuchProviderException,
        NoSuchAlgorithmException, IllegalStateException,
        KeyManagementException {

        System.out.print("\tinit()");

        SecureRandom rand = new SecureRandom();
        SSLContext ctx = null;

        /* test with null TrustManagerFactory and KeyManagerFactory */
        for (int i = 0; i < enabledProtocols.size(); i++) {

            try {
                ctx = SSLContext.getInstance(enabledProtocols.get(i),
                    ctxProvider);
                ctx.init(null, null, rand);
            } catch (Exception e) {
                System.out.println("\t\t\t\t... failed");
                e.printStackTrace();
                fail("Failed to initialize SSLContext with null params");
            }
        }

        /* test with null TrustManagerFactory, KeyManagerFactory, random */
        for (int i = 0; i < enabledProtocols.size(); i++) {

            try {
                ctx = SSLContext.getInstance(enabledProtocols.get(i),
                    ctxProvider);
                ctx.init(null, null, null);
            } catch (Exception e) {
                System.out.println("\t\t\t\t... failed");
                fail("Failed to initialize SSLContext with null params");
            }
        }

        System.out.println("\t\t\t\t... passed");
    }

    @Test
    public void testGetSessionContext() throws NoSuchProviderException,
        NoSuchAlgorithmException, IllegalStateException,
        KeyManagementException {

        System.out.print("\tgetSessionContext()");

        SSLContext ctx = null;

        for (int i = 0; i < enabledProtocols.size(); i++) {

            try {
                ctx = SSLContext.getInstance(enabledProtocols.get(i),
                    ctxProvider);
                ctx.init(null, null, null);
            } catch (Exception e) {
                System.out.println("\t\t... failed");
                fail("Failed to init SSLContext");
                return;
            }

            /* test for getting session context @TODO additional tests */
            try {
                SSLSessionContext sess = ctx.getServerSessionContext();
                assertNotNull(sess);
            } catch (UnsupportedOperationException e) {
                System.out.println("\t\t... failed");
                fail("Failed to get SSLSessionContext");
            }

            /* test for getting client session context @TODO additional tests */
            try {
                SSLSessionContext sess = ctx.getClientSessionContext();
                assertNotNull(sess);
            } catch (UnsupportedOperationException e) {
                System.out.println("\t\t... failed");
                fail("Failed to return client SSLSessionContext");
            }
        }
        System.out.println("\t\t... passed");
    }

    @Test
    public void testGetSessionContextBeforeInit()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        System.out.print("\tgetSessionContext before init");

        SSLContext ctx = null;
        SSLSessionContext sess = null;

        for (int i = 0; i < enabledProtocols.size(); i++) {

            ctx = SSLContext.getInstance(enabledProtocols.get(i), ctxProvider);

            /* getServerSessionContext() should work before init() */
            sess = ctx.getServerSessionContext();
            if (sess == null) {
                System.out.println("\t... failed");
                fail("getServerSessionContext() returned null before init()");
                return;
            }

            /* getClientSessionContext() should work before init() */
            sess = ctx.getClientSessionContext();
            if (sess == null) {
                System.out.println("\t... failed");
                fail("getClientSessionContext() returned null before init()");
                return;
            }

            /* Verify session context operations work before init() */
            int timeout = sess.getSessionTimeout();
            sess.setSessionTimeout(timeout);
        }
        System.out.println("\t... passed");
    }

    @Test
    public void testGetSupportedSSLParameters() throws NoSuchProviderException,
        NoSuchAlgorithmException, IllegalStateException,
        KeyManagementException {

        System.out.print("\tgetSupportedSSLParameters()");

        SSLContext ctx = null;

        for (int i = 0; i < enabledProtocols.size(); i++) {

            try {
                ctx = SSLContext.getInstance(enabledProtocols.get(i),
                        ctxProvider);
                ctx.init(null, null, null);
            } catch (Exception e) {
                System.out.println("\t\t... failed");
                fail("Failed to init SSLContext");
                return;
            }

            /* test for UnsupportedOperationException */
            try {
                SSLParameters params = ctx.getSupportedSSLParameters();
                if (params == null) {
                    System.out.println("\t... failed");
                    fail("Failed to valid supported SSLParameters");
                }

                /* make sure protocol list is not null */
                String[] protocols = params.getProtocols();
                if (protocols == null || protocols.length == 0) {
                    System.out.println("\t... failed");
                    fail("SSLParameters.getProtocols() returned null");
                }

                /* make sure cipher suite list is not null */
                String[] ciphers = params.getCipherSuites();
                if (ciphers == null || ciphers.length == 0) {
                    System.out.println("\t... failed");
                    fail("SSLParameters.getCipherSuites() returned null");
                }

            } catch (UnsupportedOperationException e) {
                System.out.println("\t... failed");
                fail("UnsupportedOperationException thrown but not expected");
            }
        }
        System.out.println("\t... passed");
    }

    @Test
    public void testGetDefaultSSLParameters() throws NoSuchProviderException,
        NoSuchAlgorithmException, IllegalStateException,
        KeyManagementException {

        System.out.print("\tgetDefaultSSLParameters()");

        SSLContext ctx = null;

        for (int i = 0; i < enabledProtocols.size(); i++) {

            try {
                ctx = SSLContext.getInstance(enabledProtocols.get(i),
                        ctxProvider);
                ctx.init(null, null, null);
            } catch (Exception e) {
                System.out.println("\t\t... failed");
                fail("Failed to init SSLContext");
                return;
            }

            /* test for UnsupportedOperationException */
            try {
                SSLParameters params = ctx.getDefaultSSLParameters();
                if (params == null) {
                    System.out.println("\t... failed");
                    fail("Failed to valid default SSLParameters");
                }

                /* make sure protocol list is not null */
                String[] protocols = params.getProtocols();
                if (protocols == null || protocols.length == 0) {
                    System.out.println("\t... failed");
                    fail("SSLParameters.getProtocols() returned null");
                }

                /* make sure cipher suite list is not null */
                String[] ciphers = params.getCipherSuites();
                if (ciphers == null || ciphers.length == 0) {
                    System.out.println("\t... failed");
                    fail("SSLParameters.getCipherSuites() returned null");
                }

                /* needClientAuth should default to false */
                boolean needClientAuth = params.getNeedClientAuth();
                if (needClientAuth == true) {
                    System.out.println("\t... failed");
                    fail("SSLParameters.getNeedClientAuth() should default " +
                         "to false");
                }

                /* wantClientAuth should default to false */
                boolean wantClientAuth = params.getWantClientAuth();
                if (wantClientAuth == true) {
                    System.out.println("\t... failed");
                    fail("SSLParameters.getWantClientAuth() should default " +
                         "to false");
                }

            } catch (UnsupportedOperationException e) {
                System.out.println("\t... failed");
                fail("UnsupportedOperationException thrown but not expected");
            }
        }

        System.out.println("\t... passed");
    }

    /* Returns ArrayList of expected default SSLcontext protocols, assuming
     * none have been disabled at the system level via system/security
     * properties. The order of items in the list should also match expected
     * order. */
    private ArrayList<String> buildExpectedDefaultProtocolList(
        String ctxProtocol) {

        ArrayList<String> expected = new ArrayList<String>();

        /* already sorted highest to lowest (ie TLSv1.3, ..., TLSv1.1) */
        List<?> enabledNativeProtocols = Arrays.asList(WolfSSL.getProtocols());

        if (ctxProtocol.equals("TLS")) {
            if (enabledNativeProtocols.contains("TLSv1.3")) {
                expected.add("TLSv1.3");
            }
            if (enabledNativeProtocols.contains("TLSv1.2")) {
                expected.add("TLSv1.2");
            }
            if (enabledNativeProtocols.contains("TLSv1.1")) {
                expected.add("TLSv1.1");
            }
            if (enabledNativeProtocols.contains("TLSv1")) {
                expected.add("TLSv1");
            }
        }

        else if (ctxProtocol.equals("TLSv1.3")) {
            if (enabledNativeProtocols.contains("TLSv1.3")) {
                expected.add("TLSv1.3");
            }
            if (enabledNativeProtocols.contains("TLSv1.2")) {
                expected.add("TLSv1.2");
            }
            if (enabledNativeProtocols.contains("TLSv1.1")) {
                expected.add("TLSv1.1");
            }
            if (enabledNativeProtocols.contains("TLSv1")) {
                expected.add("TLSv1");
            }
        }

        else if (ctxProtocol.equals("TLSv1.2")) {
            if (enabledNativeProtocols.contains("TLSv1.2")) {
                expected.add("TLSv1.2");
            }
            if (enabledNativeProtocols.contains("TLSv1.1")) {
                expected.add("TLSv1.1");
            }
            if (enabledNativeProtocols.contains("TLSv1")) {
                expected.add("TLSv1");
            }
        }

        else if (ctxProtocol.equals("TLSv1.1")) {
            if (enabledNativeProtocols.contains("TLSv1.1")) {
                expected.add("TLSv1.1");
            }
            if (enabledNativeProtocols.contains("TLSv1")) {
                expected.add("TLSv1");
            }
        }

        else if (ctxProtocol.equals("TLSv1")) {
            if (enabledNativeProtocols.contains("TLSv1")) {
                expected.add("TLSv1");
            }
        }

        return expected;
    }

     /* Tests that disabling protocols using the system property
      * 'jdk.tls.disabledAlgorithms' works as expected.
      */
    @Test
    public void testJdkTlsDisabledAlgorithms() throws NoSuchProviderException,
        NoSuchAlgorithmException, IllegalStateException,
        KeyManagementException, IOException {

        SSLContext ctx = null;
        SocketFactory sf = null;
        SSLSocket sock = null;
        String[] defaultSSLContextProtocols = null;
        ArrayList<String> expectedList = null;

        System.out.print("\tjdk.tls.disabledAlgorithms");

        List<?> enabledNativeProtocols = Arrays.asList(WolfSSL.getProtocols());
        if (enabledNativeProtocols == null) {
            System.out.println("\t... failed");
            fail("WolfSSL.getProtocols() returned null");
        }

        synchronized (WolfSSLTestFactory.jdkTlsDisabledAlgorithmsLock) {
            /* Save original property value to reset after test */
            String originalProperty =
                Security.getProperty("jdk.tls.disabledAlgorithms");
            if (originalProperty == null) {
                /* Default back to empty string, otherwise we may get a
                 * NullPointerException when trying to restore this back to
                 * the original value later */
                originalProperty = "";
            }

            /* Test with no protocols disabled */
            Security.setProperty("jdk.tls.disabledAlgorithms", "");
            for (int i = 0; i < allProtocols.length; i++) {

                if (!enabledNativeProtocols.contains(allProtocols[i])) {
                    /* protocol not available in native library, skip */
                    continue;
                }

                ctx = SSLContext.getInstance(allProtocols[i]);
                ctx.init(null, null, null);

                expectedList =
                    buildExpectedDefaultProtocolList(allProtocols[i]);
                defaultSSLContextProtocols =
                    ctx.getDefaultSSLParameters().getProtocols();

                if (!Arrays.equals(defaultSSLContextProtocols,
                        expectedList.toArray(
                            new String[expectedList.size()]))) {
                    System.out.print("\t... failed");
                    fail("Default SSLContext(" + allProtocols[i] +
                         ") protocol list did not match " +
                         "expected. Got: " +
                         Arrays.toString(defaultSSLContextProtocols) +
                         " Expected: " + Arrays.toString(expectedList.toArray(
                            new String[expectedList.size()])));
                }

                /* Also test SSLSocket.getEnabledProtocols() */
                sf = ctx.getSocketFactory();
                sock = (SSLSocket)sf.createSocket();
                String[] sockEnabledProtocols = sock.getEnabledProtocols();

                if (!Arrays.equals(sockEnabledProtocols,
                        expectedList.toArray(
                            new String[expectedList.size()]))) {
                    System.out.print("\t... failed");
                    fail("Default SSLSocket protocol list did not " +
                         "match expected");
                }
            }

            /* Test with each allProtocol disabled individually */
            for (int i = 0; i < allProtocols.length; i++) {
                Security.setProperty("jdk.tls.disabledAlgorithms",
                    allProtocols[i]);
                for (int j = 0; j < allProtocols.length; j++) {

                    if (!enabledNativeProtocols.contains(allProtocols[j])) {
                        /* protocol not available in native library, skip */
                        continue;
                    }

                    ctx = SSLContext.getInstance(allProtocols[j]);
                    ctx.init(null, null, null);

                    expectedList =
                        buildExpectedDefaultProtocolList(allProtocols[j]);
                    /* remove protocol under test */
                    expectedList.remove(allProtocols[i]);
                    defaultSSLContextProtocols =
                        ctx.getDefaultSSLParameters().getProtocols();

                    if (!Arrays.equals(defaultSSLContextProtocols,
                            expectedList.toArray(
                                new String[expectedList.size()]))) {
                        System.out.print("\t... failed");
                        fail("Default SSLContext protocol list did not " +
                             "match expected");
                    }

                    /* Also test SSLSocket.getEnabledProtocols() */
                    sf = ctx.getSocketFactory();
                    sock = (SSLSocket)sf.createSocket();
                    String[] sockEnabledProtocols = sock.getEnabledProtocols();

                    if (!Arrays.equals(sockEnabledProtocols,
                            expectedList.toArray(
                                new String[expectedList.size()]))) {
                        System.out.print("\t... failed");
                        fail("Default SSLSocket protocol list did not " +
                             "match expected");
                    }
                }
            }

            /* Test with TLSv1, TLSv1.1 protocols disabled */
            Security.setProperty("jdk.tls.disabledAlgorithms",
                "TLSv1, TLSv1.1");
            for (int i = 0; i < allProtocols.length; i++) {

                if (!enabledNativeProtocols.contains(allProtocols[i])) {
                    /* protocol not available in native library, skip */
                    continue;
                }

                ctx = SSLContext.getInstance(allProtocols[i]);
                ctx.init(null, null, null);

                expectedList =
                    buildExpectedDefaultProtocolList(allProtocols[i]);
                expectedList.remove("TLSv1");
                expectedList.remove("TLSv1.1");
                defaultSSLContextProtocols =
                    ctx.getDefaultSSLParameters().getProtocols();

                if (!Arrays.equals(defaultSSLContextProtocols,
                        expectedList.toArray(
                            new String[expectedList.size()]))) {
                    System.out.print("\t... failed");
                    fail("Default SSLContext protocol list did not " +
                         "match expected");
                }

                /* Also test SSLSocket.getEnabledProtocols() */
                sf = ctx.getSocketFactory();
                sock = (SSLSocket)sf.createSocket();
                String[] sockEnabledProtocols = sock.getEnabledProtocols();

                if (!Arrays.equals(sockEnabledProtocols,
                        expectedList.toArray(
                            new String[expectedList.size()]))) {
                    System.out.print("\t... failed");
                    fail("Default SSLSocket protocol list did not " +
                         "match expected");
                }
            }

            /* Test with TLSv1.1, TLSv1.2 protocols disabled */
            Security.setProperty("jdk.tls.disabledAlgorithms",
                "TLSv1.1, TLSv1.2");
            for (int i = 0; i < allProtocols.length; i++) {

                if (!enabledNativeProtocols.contains(allProtocols[i])) {
                    /* protocol not available in native library, skip */
                    continue;
                }

                ctx = SSLContext.getInstance(allProtocols[i]);
                ctx.init(null, null, null);

                expectedList =
                    buildExpectedDefaultProtocolList(allProtocols[i]);
                expectedList.remove("TLSv1.1");
                expectedList.remove("TLSv1.2");
                defaultSSLContextProtocols =
                    ctx.getDefaultSSLParameters().getProtocols();

                if (!Arrays.equals(defaultSSLContextProtocols,
                        expectedList.toArray(
                            new String[expectedList.size()]))) {
                    System.out.print("\t... failed");
                    fail("Default SSLContext protocol list did not " +
                         "match expected");
                }

                /* Also test SSLSocket.getEnabledProtocols() */
                sf = ctx.getSocketFactory();
                sock = (SSLSocket)sf.createSocket();
                String[] sockEnabledProtocols = sock.getEnabledProtocols();

                if (!Arrays.equals(sockEnabledProtocols,
                        expectedList.toArray(
                            new String[expectedList.size()]))) {
                    System.out.print("\t... failed");
                    fail("Default SSLSocket protocol list did not " +
                         "match expected");
                }
            }

            /* Restore original system property value */
            Security.setProperty("jdk.tls.disabledAlgorithms",
                originalProperty);
        } /* jdkTlsDisabledAlgorithmsLock */

        System.out.println("\t... passed");
    }

    /** Helper method for testWolfJSSEEnabledCipherSuites() */
    private WolfSSL.TLS_VERSION getWolfSSLTLSVersion(String version) {

        WolfSSL.TLS_VERSION verEnum = WolfSSL.TLS_VERSION.INVALID;

        switch (version) {
            case "TLSv1":
                verEnum = WolfSSL.TLS_VERSION.TLSv1;
                break;
            case "TLSv1.1":
                verEnum = WolfSSL.TLS_VERSION.TLSv1_1;
                break;
            case "TLSv1.2":
                verEnum = WolfSSL.TLS_VERSION.TLSv1_2;
                break;
            case "TLSv1.3":
                verEnum = WolfSSL.TLS_VERSION.TLSv1_3;
                break;
            case "TLS":
                verEnum = WolfSSL.TLS_VERSION.SSLv23;
                break;
            default:
                break;
        }

        return verEnum;
    }

    /* Tests that setting/restricting TLS cipher suites with the
     * 'wolfjsse.enabledCipherSuites' system Security property works as
     * expected.
     */
    @Test
    public void testWolfJSSEEnabledCipherSuites()
        throws NoSuchProviderException, NoSuchAlgorithmException,
        IllegalStateException, KeyManagementException, IOException {

        SSLContext ctx = null;
        SocketFactory sf = null;
        SSLSocket sock = null;
        String[] nativeSuites = null;
        String[] defaultSSLContextSuites = null;
        WolfSSL.TLS_VERSION version = WolfSSL.TLS_VERSION.INVALID;

        System.out.print("\twolfjsse.enabledCipherSuites");

        List<?> enabledNativeProtocols = Arrays.asList(WolfSSL.getProtocols());
        if (enabledNativeProtocols == null) {
            System.out.println("\t... failed");
            fail("WolfSSL.getProtocols() returned null");
        }

        /* Save original property value to reset after test */
        String originalProperty =
            Security.getProperty("wolfjsse.enabledCipherSuites");

        /* Test all enabled protocols */
        for (int i = 0; i < allProtocols.length; i++) {

            if (!enabledNativeProtocols.contains(allProtocols[i])) {
                /* protocol not available in native library, skip */
                continue;
            }

            /* get TLS_VERSION enum value from protocol version */
            version = getWolfSSLTLSVersion(allProtocols[i]);
            if (version == WolfSSL.TLS_VERSION.INVALID) {
                System.out.print("\t... failed");
                fail("Invalid TLS version");
            }

            /* String[] of all available native wolfSSL suites for version */
            nativeSuites = WolfSSL.getCiphersAvailableIana(version);

            /* ------------------------------------------------------------- */

            /* Test with no cipher suites restricted, make sure SSLContext
             * gives back the expected/full list of cipher suites. */
            Security.setProperty("wolfjsse.enabledCipherSuites", "");

            ctx = SSLContext.getInstance(allProtocols[i]);
            ctx.init(null, null, null);

            defaultSSLContextSuites =
                ctx.getDefaultSSLParameters().getCipherSuites();

            if (!Arrays.equals(defaultSSLContextSuites, nativeSuites)) {
                System.out.print("\t... failed");
                fail("Default SSLContext cipher list did not " +
                     "match expected");
            }

            sf = ctx.getSocketFactory();
            sock = (SSLSocket)sf.createSocket();

            /* Test SSLSocket.getEnabledCipherSuites() */
            String[] sockEnabledSuites = sock.getEnabledCipherSuites();

            if (!Arrays.equals(sockEnabledSuites, nativeSuites)) {
                System.out.print("\t... failed");
                fail("SSLSocket enabled cipher list did not " +
                     "match expected");
            }

            /* ------------------------------------------------------------- */

            /* Set first default cipher suite as the only suite enabled,
             * then make sure only that suite is available after
             * SSLContext creation */
            Security.setProperty("wolfjsse.enabledCipherSuites",
                nativeSuites[0]);

            ctx = SSLContext.getInstance(allProtocols[i]);
            ctx.init(null, null, null);

            defaultSSLContextSuites =
                ctx.getDefaultSSLParameters().getCipherSuites();

            if (!Arrays.equals(defaultSSLContextSuites,
                    new String[] { nativeSuites[0] } )) {
                System.out.print("\t... failed");
                fail("Default SSLContext cipher list did not " +
                     "match expected single suite");
            }

            sf = ctx.getSocketFactory();
            sock = (SSLSocket)sf.createSocket();

            /* Test SSLSocket.getEnabledCipherSuites() */
            sockEnabledSuites = sock.getEnabledCipherSuites();
            if (!Arrays.equals(sockEnabledSuites,
                    new String[] { nativeSuites[0] } )) {
                System.out.print("\t... failed");
                fail("SSLSocket enabled cipher list did not " +
                     "match expected single suite");
            }

            /* Test SSLSocket.getSupportedCipherSuites() */
            sockEnabledSuites = sock.getSupportedCipherSuites();
            if (!Arrays.equals(sockEnabledSuites,
                    new String[] { nativeSuites[0] } )) {
                System.out.print("\t... failed");
                fail("SSLSocket supported cipher list did not " +
                     "match expected single suite");
            }

            /* ------------------------------------------------------------- */

            /* Set first two default cipher suites as the only suite enabled,
             * then make sure only those suites are available after
             * SSLContext creation. Tests property with multiple values. */

            if (nativeSuites.length >= 2) {
                Security.setProperty("wolfjsse.enabledCipherSuites",
                        nativeSuites[0] + ", " + nativeSuites[1]);

                ctx = SSLContext.getInstance(allProtocols[i]);
                ctx.init(null, null, null);

                defaultSSLContextSuites =
                    ctx.getDefaultSSLParameters().getCipherSuites();

                if (!Arrays.equals(defaultSSLContextSuites,
                        new String[] { nativeSuites[0], nativeSuites[1] } )) {
                    System.out.print("\t... failed");
                    fail("Default SSLContext cipher list did not " +
                         "match expected single suite");
                }

                sf = ctx.getSocketFactory();
                sock = (SSLSocket)sf.createSocket();

                /* Test SSLSocket.getEnabledCipherSuites() */
                sockEnabledSuites = sock.getEnabledCipherSuites();
                if (!Arrays.equals(sockEnabledSuites,
                        new String[] { nativeSuites[0], nativeSuites[1] } )) {
                    System.out.print("\t... failed");
                    fail("SSLSocket enabled cipher list did not " +
                         "match expected single suite");
                }

                /* Test SSLSocket.getSupportedCipherSuites(), may have
                 * different order based on native sorting */
                sockEnabledSuites = sock.getSupportedCipherSuites();
                if (!Arrays.asList(sockEnabledSuites)
                        .containsAll(Arrays.asList(
                            new String[] {
                                nativeSuites[0], nativeSuites[1] }))) {
                    System.out.print("\t... failed");
                    fail("SSLSocket supported cipher list did not " +
                         "match expected single suite");
                }
            }

            /* ------------------------------------------------------------- */

            /* Set first default cipher suite as the only suite enabled,
             * then make sure we get an exception when we try to set
             * another/different suite on the SSLSocket */

            if (nativeSuites.length >= 2) {
                Security.setProperty("wolfjsse.enabledCipherSuites",
                                   nativeSuites[0]);

                ctx = SSLContext.getInstance(allProtocols[i]);
                ctx.init(null, null, null);

                sf = ctx.getSocketFactory();
                sock = (SSLSocket)sf.createSocket();

                try {
                    /* set enabled suites as second available suite
                     * (shouldn't work), should throw exception */
                    sock.setEnabledCipherSuites(
                        new String[] { nativeSuites[1] });
                } catch (IllegalArgumentException e) {
                    /* expected */
                }

                sockEnabledSuites = sock.getEnabledCipherSuites();

                if (!Arrays.equals(sockEnabledSuites,
                        new String[] { nativeSuites[0] } )) {
                    System.out.print("\t... failed");
                    fail("Default SSLSocket cipher list did not " +
                         "match expected single suite");
                }
            }

        } /* protocol for loop */

        /* Restore original system property value */
        if (originalProperty != null) {
            Security.setProperty("wolfjsse.enabledCipherSuites",
                originalProperty);
        }
        else {
            Security.setProperty("wolfjsse.enabledCipherSuites", "");
        }

        System.out.println("\t... passed");
    }

    @Test
    public void testSanitizeProtocolsNullInput() {

        System.out.print("\tTesting sanitizeProtocols(null)");

        try {
            Class<?> utilClass = Class.forName(
                "com.wolfssl.provider.jsse.WolfSSLUtil");
            Method sanitizeMethod = utilClass.getDeclaredMethod(
                "sanitizeProtocols",
                String[].class,
                WolfSSL.TLS_VERSION.class);
            sanitizeMethod.setAccessible(true);

            String[] result = (String[]) sanitizeMethod.invoke(
                null, (String[]) null, WolfSSL.TLS_VERSION.TLSv1_2);

            if (result != null) {
                System.out.println("\t... failed");
                fail("sanitizeProtocols(null) should return null");
                return;
            }

            System.out.println("\t\t... passed");

        } catch (Exception e) {
            System.out.println("\t... failed");
            fail("Exception during sanitizeProtocols test: " + e.getMessage());
        }
    }
}

