/* WolfSSLTrustX509Test.java
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

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLException;
import com.wolfssl.provider.jsse.WolfSSLProvider;
import com.wolfssl.provider.jsse.WolfSSLTrustX509;

import java.util.List;
import java.util.ArrayList;
import java.io.File;
import java.io.FileInputStream;
import java.io.BufferedInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.io.PrintWriter;
import java.time.Instant;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.net.Socket;
import java.net.InetSocketAddress;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.X509KeyManager;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import static org.junit.Assert.*;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author wolfSSL
 */
public class WolfSSLTrustX509Test {
    private static WolfSSLTestFactory tf;
    private String provider = "wolfJSSE";

    @BeforeClass
    public static void testProviderInstallationAtRuntime()
        throws NoSuchProviderException {

        System.out.println("WolfSSLTrustX509 Class");

        /* install wolfJSSE provider at runtime */
        Security.insertProviderAt(new WolfSSLProvider(), 1);

        Provider p = Security.getProvider("wolfJSSE");
        assertNotNull(p);

        try {
            tf = new WolfSSLTestFactory();
        } catch (WolfSSLException e) {
            e.printStackTrace();
            return;
        }

    }

    /* Testing WolfSSLTrustX509.getAcceptedIssuers() with all.jks */
    @Test
    public void testCAParsing()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               KeyStoreException, IOException, CertificateException {

        TrustManager[] tm;
        X509TrustManager x509tm;
        X509Certificate cas[];

        String OU[] = { "OU=ECC", "OU=Programming-2048", "OU=Support",
            "OU=Support_1024", "OU=Consulting", "OU=Development",
            "OU=Fast", "OU=Consulting_1024", "OU=Programming-1024" };

        int i = 0;
        int expected = OU.length;

        System.out.print("\tTesting parse all.jks");

        if (WolfSSLTestFactory.isAndroid()) {
            /* @TODO finding that BKS has different order of certs */
            pass("\t... skipped");
            return;
        }

        /* wolfSSL only returns a list of CA's, server-ecc basic constraint is
         * set to false so it is not added as a CA */
        if (this.provider != null && this.provider.equals("wolfJSSE") &&
            !WolfSSL.trustPeerCertEnabled()) {
            /* one less than SunJSSE because of server-ecc */
            expected = expected - 1;
        }

        tm = tf.createTrustManager("SunX509", tf.allJKS, provider);
        if (tm == null) {
            error("\t\t... failed");
            fail("failed to create trustmanager");
            return;
        }
        x509tm = (X509TrustManager) tm[0];
        cas = x509tm.getAcceptedIssuers();
        if (cas == null) {
            error("\t\t... failed");
            fail("no CAs where found");
            return;
        }

        if (cas.length != expected) {
            error("\t\t... failed");
            fail("wrong number of CAs found: found " + cas.length +
                 ", expected " + expected);
        }

        for (String x: OU) {
            if (this.provider != null &&
                    provider.equals("wolfJSSE") && x.equals("OU=ECC")) {
                /* skip checking ECC certs, since not all Java versions
                 * support them */
                if (WolfSSL.trustPeerCertEnabled()) {
                    i++;
                }
                continue;
            }

            if (!cas[i].getSubjectDN().getName().contains(x)) {
                error("\t\t... failed");
                fail("wrong CA found");
            }
            i++;

        }
        pass("\t\t... passed");
    }

    @Test
    public void testUseBeforeInit()
        throws NoSuchProviderException, NoSuchAlgorithmException {
        TrustManagerFactory tmf;
        KeyManagerFactory kmf;

        System.out.print("\tTesting use before init()");

        if (WolfSSLTestFactory.isAndroid()) {
            /* @TODO finding that BKS has different order of certs */
            pass("\t... skipped");
            return;
        }

        tmf = TrustManagerFactory.getInstance("SunX509", provider);
        if (tmf == null) {
            error("\t... failed");
            fail("failed to get instance of trustmanager factory");
            return;
        }

        try {
            tmf.getTrustManagers();
            error("\t... failed");
            fail("getTrustManagers() before init() did not throw an error");
        } catch (IllegalStateException e) {
            /* Expected, TrustManagerFactory not yet initialized */
        }

        kmf = KeyManagerFactory.getInstance("SunX509", provider);
        if (kmf == null) {
            error("\t... failed");
            fail("failed to get instance of keymanager factory");
            return;
        }

        try {
            kmf.getKeyManagers();
            error("\t... failed");
            fail("getKeyManagers() before init() did not throw an error");
        } catch (IllegalStateException e) {
            /* Expected, KeyManagerFactory not yet initialized */
        }

        pass("\t... passed");
    }

    /* Testing WolfSSLTrustX509.getAcceptedIssuers() with server.jks */
    @Test
    public void testServerParsing()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               KeyStoreException, IOException, CertificateException {

        TrustManager[] tm;
        X509TrustManager x509tm;
        X509Certificate cas[];

        String OU[] = { "OU=Support", "OU=ECC" };

        int i = 0;
        int expected = OU.length;

        System.out.print("\tTesting parsing server.jks");

        if (WolfSSLTestFactory.isAndroid()) {
            /* @TODO finding that BKS has different order of certs */
            pass("\t... skipped");
            return;
        }

        /* wolfSSL only returns a list of CA's, server-ecc basic constraint is
         * set to false so it is not added as a CA */
        if (this.provider != null && this.provider.equals("wolfJSSE") &&
            !WolfSSL.trustPeerCertEnabled()) {
            /* one less than SunJSSE because of server-ecc */
            expected = expected - 1;
        }

        tm = tf.createTrustManager("SunX509", tf.serverJKS, provider);
        if (tm == null) {
            error("\t... failed");
            fail("failed to create trustmanager");
            return;
        }
        x509tm = (X509TrustManager) tm[0];
        cas = x509tm.getAcceptedIssuers();
        if (cas == null) {
            error("\t... failed");
            fail("no CAs were found");
            return;
        }

        if (cas.length != expected) {
            error("\t... failed");
            fail("wrong number of CAs found: found " + cas.length +
                 ", expected " + expected);
        }

        for (String x : OU) {
            if (this.provider != null &&
                    provider.equals("wolfJSSE") && x.equals("OU=ECC")) {
                continue;
            }

            if (!cas[i].getSubjectDN().getName().contains(x)) {
                error("\t... failed");
                fail("wrong CA found");
            }
            i++;

        }
        pass("\t... passed");
    }


    /* Testing WolfSSLTrustX509.getAcceptedIssuers() with all_mixed.jks */
    @Test
    public void testCAParsingMixed()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               KeyStoreException, IOException, CertificateException {

        TrustManager[] tm;
        X509TrustManager x509tm;
        X509Certificate cas[];

        String OU[] = { "OU=Consulting", "OU=Programming-2048", "OU=Fast",
            "OU=Support", "OU=ECC", "OU=Programming-1024", "OU=Consulting_1024",
            "OU=Support_1024" };

        int i = 0, j;
        int expected = OU.length;

        System.out.print("\tTesting parse all_mixed.jks");

        if (WolfSSLTestFactory.isAndroid()) {
            /* @TODO finding that BKS has different order of certs */
            pass("\t... skipped");
            return;
        }
        /* wolfSSL only returns a list of CA's, server-ecc basic constraint is
         * set to false so it is not added as a CA */
        if (this.provider != null && this.provider.equals("wolfJSSE") &&
            !WolfSSL.trustPeerCertEnabled()) {
            /* one less than SunJSSE because of server-ecc */
            expected = expected - 1;
        }

        tm = tf.createTrustManager("SunX509", tf.allMixedJKS, provider);
        if (tm == null) {
            error("\t... failed");
            fail("failed to create trustmanager");
            return;
        }
        x509tm = (X509TrustManager) tm[0];
        cas = x509tm.getAcceptedIssuers();
        if (cas == null) {
            error("\t... failed");
            fail("no CAs where found");
            return;
        }

        if (cas.length != expected) {
            error("\t... failed");
            fail("wrong number of CAs found: found " + cas.length +
                 ", expected " + expected);
        }

        for (j = 0; j < OU.length && i < cas.length; j++) {
            if (this.provider != null &&
                    provider.equals("wolfJSSE") && OU[j].equals("OU=ECC")) {
                /* skip checking ECC certs, since not all Java versions
                 * support them */
                if (WolfSSL.trustPeerCertEnabled()) {
                    i++;
                }
                continue;
            }

            if (!cas[i].getSubjectDN().getName().contains(OU[j])) {
                error("\t... failed");
                fail("wrong CA found");
            }
            i++;

        }
        pass("\t... passed");
    }

    @Test
    public void testSystemLoad()
        throws NoSuchAlgorithmException, KeyStoreException, IOException,
               CertificateException, NoSuchProviderException {

        String file = System.getProperty("javax.net.ssl.trustStore");
        TrustManager[] tm;

        System.out.print("\tTesting loading default certs");

        if (file == null) {
            String home = System.getenv("JAVA_HOME");
            if (home != null) {
                File f = new File(home.concat("lib/security/jssecacerts"));
                if (f.exists()) {
                    tm = tf.createTrustManager(
                            "SunX509", (String)null, provider);
                    if (tm == null) {
                        error("\t... failed");
                        fail("failed to create trustmanager with default");
                    }
                    pass("\t... passed");
                    return;
                }
                else {
                    f = new File(home.concat("lib/security/cacerts"));
                    if (f.exists()) {
                        tm = tf.createTrustManager(
                                "SunX509", (String)null, provider);
                        if (tm == null) {
                            error("\t... failed");
                            fail("failed to create trustmanager with default");
                        }
                        pass("\t... passed");
                        return;
                    }
                }
            }
        }
        else {
            tm = tf.createTrustManager("SunX509", (String)null, provider);
            if (tm == null) {
                error("\t... failed");
                fail("failed to create trustmanager with default");
            }
            pass("\t... passed");
            return;
        }

        /* case of no default found */
        pass("\t... skipped");
    }


    @Test
    public void testVerify()
        throws NoSuchProviderException, NoSuchAlgorithmException,
            KeyStoreException, FileNotFoundException, IOException,
            CertificateException, NoSuchAlgorithmException {

        TrustManager[] tm;
        X509TrustManager x509tm;
        X509Certificate cas[];
        InputStream stream;
        KeyStore ks;

        System.out.print("\tTesting verify");

        /* success case */
        tm = tf.createTrustManager("SunX509", tf.caJKS, provider);
        if (tm == null) {
            error("\t\t\t... failed");
            fail("failed to create trustmanager");
            return;
        }
        x509tm = (X509TrustManager) tm[0];
        cas = x509tm.getAcceptedIssuers();
        if (cas == null) {
            error("\t\t\t... failed");
            fail("no CAs where found");
            return;
        }

        ks = KeyStore.getInstance(tf.keyStoreType);
        stream = new FileInputStream(tf.serverJKS);
        ks.load(stream, "wolfSSL test".toCharArray());
        stream.close();
        try {
            x509tm.checkServerTrusted(new X509Certificate[] {
            (X509Certificate)ks.getCertificate("server") }, "RSA");
        }
        catch (Exception e) {
            error("\t\t\t... failed");
            fail("failed to verify");
        }


        /* fail case */
        tm = tf.createTrustManager("SunX509", tf.serverJKS, provider);
        if (tm == null) {
            error("\t\t\t... failed");
            fail("failed to create trustmanager");
            return;
        }
        x509tm = (X509TrustManager) tm[0];
        cas = x509tm.getAcceptedIssuers();
        if (cas == null) {
            error("\t\t\t... failed");
            fail("no CAs where found");
        }

        ks = KeyStore.getInstance(tf.keyStoreType);
        stream = new FileInputStream(tf.clientJKS);
        ks.load(stream, "wolfSSL test".toCharArray());
        stream.close();
        try {
            x509tm.checkServerTrusted(new X509Certificate[] {
            (X509Certificate)ks.getCertificate("ca-ecc-cert") }, "ECC");
            error("\t\t\t... failed");
            fail("able to verify when should not have");
        }
        catch (Exception e) {
            /* expected to error out */
        }
        pass("\t\t\t... passed");
    }

    @Test
    public void testVerifyRsaPss()
        throws NoSuchProviderException, NoSuchAlgorithmException,
            KeyStoreException, FileNotFoundException, IOException,
            CertificateException {

        /* skip if RSA_PSS is not compiled in at native level */
        if (WolfSSL.RsaPssEnabled() == false) {
            return;
        }

        TrustManager[] tm;
        X509TrustManager x509tm;
        X509Certificate cas[];
        InputStream stream;
        KeyStore ks;

        System.out.print("\tTesting verify rsa_pss");

        tm = tf.createTrustManager("SunX509", tf.caServerJKS, provider);
        if (tm == null) {
            error("\t\t\t... failed");
            fail("failed to create trustmanager");
            return;
        }

        x509tm = (X509TrustManager) tm[0];
        cas = x509tm.getAcceptedIssuers();
        if (cas == null) {
            error("\t\t\t... failed");
            fail("no CAs where found");
            return;
        }

        ks = KeyStore.getInstance(tf.keyStoreType);
        stream = new FileInputStream(tf.serverRSAPSSJKS);
        ks.load(stream, "wolfSSL test".toCharArray());
        stream.close();
        try {
            x509tm.checkServerTrusted(new X509Certificate[] {
            (X509Certificate)ks.getCertificate("server-rsapss") }, "RSASSA-PSS");
        }
        catch (Exception e) {
            e.printStackTrace();
            error("\t\t... failed");
            fail("failed to verify");
        }

        pass("\t\t... passed");
    }

    @Test
    public void testCheckServerTrustedWithChain()
        throws NoSuchProviderException, NoSuchAlgorithmException,
            KeyStoreException, FileNotFoundException, IOException,
            CertificateException {

        TrustManager[] tm;
        X509TrustManager x509tm;
        Certificate cert = null;
        X509Certificate[] certArray = null;
        FileInputStream fis = null;
        BufferedInputStream bis = null;
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        System.out.print("\tcheckServerTrusted() chain");

        String rsaServerCert =
            "examples/certs/intermediate/server-int-cert.pem";
        String rsaInt1Cert = "examples/certs/intermediate/ca-int-cert.pem";
        String rsaInt2Cert = "examples/certs/intermediate/ca-int2-cert.pem";

        String eccServerCert =
            "examples/certs/intermediate/server-int-ecc-cert.pem";
        String eccInt1Cert = "examples/certs/intermediate/ca-int-ecc-cert.pem";
        String eccInt2Cert = "examples/certs/intermediate/ca-int2-ecc-cert.pem";

        if (WolfSSLTestFactory.isAndroid()) {
            rsaServerCert = "/sdcard/" + rsaServerCert;
            rsaInt1Cert = "/sdcard/" + rsaInt1Cert;
            rsaInt2Cert = "/sdcard/" + rsaInt2Cert;

            eccServerCert = "/sdcard/" + eccServerCert;
            eccInt1Cert = "/sdcard/" + eccInt1Cert;
            eccInt2Cert = "/sdcard/" + eccInt2Cert;
        }

        tm = tf.createTrustManager("SunX509", tf.caJKS, provider);
        if (tm == null) {
            error("\t... failed");
            fail("failed to create trustmanager");
            return;
        }

        x509tm = (X509TrustManager) tm[0];

        /* ---------- RSA Based Chain ---------- */

        /* build up X509Certificate[] chain */
        certArray = new X509Certificate[3];

        /* certArray[0]: server/peer cert */
        fis = new FileInputStream(rsaServerCert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[0] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* certArray[1]: intermediate CA 1 */
        fis = new FileInputStream(rsaInt1Cert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[1] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* certArray[2]: intermediate CA 2 */
        fis = new FileInputStream(rsaInt2Cert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[2] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* verify chain, root (certs/ca-cert.pem) should be in caJKS */
        try {
            x509tm.checkServerTrusted(certArray, "RSA");
        } catch (CertificateException e) {
            error("\t... failed");
            fail("Failed verify of RSA chain with intermediates");
        }

        /* ---------- ECC Based Chain ---------- */

        /* build up X509Certificate[] chain */
        certArray = new X509Certificate[3];

        /* certArray[0]: server/peer cert */
        fis = new FileInputStream(eccServerCert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[0] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* certArray[1]: intermediate CA 1 */
        fis = new FileInputStream(eccInt1Cert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[1] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* certArray[2]: intermediate CA 2 */
        fis = new FileInputStream(eccInt2Cert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[2] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* verify chain, root (certs/ca-ecc-cert.pem) should be in caJKS */
        try {
            x509tm.checkServerTrusted(certArray, "ECC");
        } catch (CertificateException e) {
            error("\t... failed");
            fail("Failed verify of ECC chain with intermediates");
        }

        pass("\t... passed");
    }

    @Test
    public void testCheckServerTrustedWithBadChainCert()
        throws NoSuchProviderException, NoSuchAlgorithmException,
            KeyStoreException, FileNotFoundException, IOException,
            CertificateException {

        TrustManager[] tm;
        X509TrustManager x509tm;
        Certificate cert = null;
        X509Certificate[] certArray = null;
        FileInputStream fis = null;
        BufferedInputStream bis = null;
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        System.out.print("\tcheckServerTrusted() bad int");

        String rsaServerCert = "examples/certs/intermediate/server-int-cert.pem";
        /* wrong/bad CA as intermediate, should not verify. Using int CA
         * from ECC chain but correct one is from RSA chain. */
        String rsaInt1CertWrong =
            "examples/certs/intermediate/ca-int2-ecc-cert.pem";
        String rsaInt2Cert = "examples/certs/intermediate/ca-int2-cert.pem";

        String eccServerCert =
            "examples/certs/intermediate/server-int-ecc-cert.pem";
        /* wrong/bad CA as intermediate, should not verify. Using int CA
         * from RSA chain but correct one is from ECC chain. */
        String eccInt1CertWrong =
            "examples/certs/intermediate/ca-int-cert.pem";
        String eccInt2Cert = "examples/certs/intermediate/ca-int2-ecc-cert.pem";

        if (WolfSSLTestFactory.isAndroid()) {
            rsaServerCert = "/sdcard/" + rsaServerCert;
            rsaInt1CertWrong = "/sdcard/" + rsaInt1CertWrong;
            rsaInt2Cert = "/sdcard/" + rsaInt2Cert;

            eccServerCert = "/sdcard/" + eccServerCert;
            eccInt1CertWrong = "/sdcard/" + eccInt1CertWrong;
            eccInt2Cert = "/sdcard/" + eccInt2Cert;
        }

        tm = tf.createTrustManager("SunX509", tf.caJKS, provider);
        if (tm == null) {
            error("\t... failed");
            fail("failed to create trustmanager");
            return;
        }

        x509tm = (X509TrustManager) tm[0];

        /* ---------- RSA Based Chain ---------- */

        /* build up X509Certificate[] chain */
        certArray = new X509Certificate[3];

        /* certArray[0]: server/peer cert */
        fis = new FileInputStream(rsaServerCert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[0] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* certArray[1]: intermediate CA 1 (wrong one, should cause error) */
        fis = new FileInputStream(rsaInt1CertWrong);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[1] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* certArray[2]: intermediate CA 2 */
        fis = new FileInputStream(rsaInt2Cert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[2] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* verify chain, root (certs/ca-cert.pem) should be in caJKS */
        try {
            x509tm.checkServerTrusted(certArray, "RSA");
            error("\t... failed");
            fail("Verified RSA chain with bad CA, but shouldn't have");
        } catch (CertificateException e) {
            /* expected, should fail with wrong intermediate chain CA */
        }

        /* ---------- ECC Based Chain ---------- */

        /* build up X509Certificate[] chain */
        certArray = new X509Certificate[3];

        /* certArray[0]: server/peer cert */
        fis = new FileInputStream(eccServerCert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[0] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* certArray[1]: intermediate CA 1 (wrong one, should cause error) */
        fis = new FileInputStream(eccInt1CertWrong);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[1] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* certArray[2]: intermediate CA 2 */
        fis = new FileInputStream(eccInt2Cert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[2] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* verify chain, root (certs/ca-ecc-cert.pem) should be in caJKS */
        try {
            x509tm.checkServerTrusted(certArray, "ECC");
            error("\t... failed");
            fail("Verified RSA chain with bad CA, but shouldn't have");
        } catch (CertificateException e) {
            /* expected, should fail with wrong intermediate chain CA */
        }

        pass("\t... passed");
    }

    @Test
    public void testCheckServerTrustedWithWrongChain()
        throws NoSuchProviderException, NoSuchAlgorithmException,
            KeyStoreException, FileNotFoundException, IOException,
            CertificateException {

        TrustManager[] tm;
        X509TrustManager x509tm;
        Certificate cert = null;
        X509Certificate[] certArray = null;
        FileInputStream fis = null;
        BufferedInputStream bis = null;
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        System.out.print("\tcheckServerTrusted() bad chain");

        /* server/peer cert is ECC, but is using RSA example chain. Should
         * not verify correctly */
        String rsaServerCert =
            "examples/certs/intermediate/server-int-ecc-cert.pem";
        String rsaInt1Cert = "examples/certs/intermediate/ca-int-cert.pem";
        String rsaInt2Cert = "examples/certs/intermediate/ca-int2-cert.pem";

        /* server/peer cert is RSA, but is using ECC example chain. Should
         * not verify correctly */
        String eccServerCert =
            "examples/certs/intermediate/server-int-cert.pem";
        String eccInt1Cert = "examples/certs/intermediate/ca-int-ecc-cert.pem";
        String eccInt2Cert = "examples/certs/intermediate/ca-int2-ecc-cert.pem";

        if (WolfSSLTestFactory.isAndroid()) {
            rsaServerCert = "/sdcard/" + rsaServerCert;
            rsaInt1Cert = "/sdcard/" + rsaInt1Cert;
            rsaInt2Cert = "/sdcard/" + rsaInt2Cert;

            eccServerCert = "/sdcard/" + eccServerCert;
            eccInt1Cert = "/sdcard/" + eccInt1Cert;
            eccInt2Cert = "/sdcard/" + eccInt2Cert;
        }

        tm = tf.createTrustManager("SunX509", tf.caJKS, provider);
        if (tm == null) {
            error("\t... failed");
            fail("failed to create trustmanager");
            return;
        }

        x509tm = (X509TrustManager) tm[0];

        /* ---------- ECC Peer Cert, RSA chain ---------- */

        /* build up X509Certificate[] chain */
        certArray = new X509Certificate[3];

        /* certArray[0]: server/peer cert */
        fis = new FileInputStream(rsaServerCert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[0] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* certArray[1]: intermediate CA 1 (wrong one, should cause error) */
        fis = new FileInputStream(rsaInt1Cert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[1] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* certArray[2]: intermediate CA 2 */
        fis = new FileInputStream(rsaInt2Cert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[2] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* verify chain, root (certs/ca-ecc-cert.pem) should be in caJKS */
        try {
            x509tm.checkServerTrusted(certArray, "ECC");
            error("\t... failed");
            fail("Verified cert with wrong chain, should not happen");
        } catch (CertificateException e) {
            /* expected, should fail with wrong intermediate chain CA */
        }

        /* ---------- RSA Peer Cert, ECC chain ---------- */

        /* build up X509Certificate[] chain */
        certArray = new X509Certificate[3];

        /* certArray[0]: server/peer cert */
        fis = new FileInputStream(eccServerCert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[0] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* certArray[1]: intermediate CA 1 (wrong one, should cause error) */
        fis = new FileInputStream(eccInt1Cert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[1] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* certArray[2]: intermediate CA 2 */
        fis = new FileInputStream(eccInt2Cert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[2] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* verify chain, root (certs/ca-cert.pem) should be in caJKS */
        try {
            x509tm.checkServerTrusted(certArray, "RSA");
            error("\t... failed");
            fail("Verified cert with wrong chain, should not happen");
        } catch (CertificateException e) {
            /* expected, should fail with wrong intermediate chain CA */
        }

        pass("\t... passed");
    }

    @Test
    public void testCheckServerTrustedMissingChain()
        throws NoSuchProviderException, NoSuchAlgorithmException,
            KeyStoreException, FileNotFoundException, IOException,
            CertificateException {

        TrustManager[] tm;
        X509TrustManager x509tm;
        Certificate cert = null;
        X509Certificate[] certArray = null;
        FileInputStream fis = null;
        BufferedInputStream bis = null;
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        System.out.print("\tcheckServerTrusted() miss chain");

        /* RSA chain, missing intermediate CA 1 */
        String rsaServerCert = "examples/certs/intermediate/server-int-cert.pem";
        String rsaInt2Cert = "examples/certs/intermediate/ca-int2-cert.pem";

        /* ECC chain, missing intermediate CA 1 */
        String eccServerCert =
            "examples/certs/intermediate/server-int-ecc-cert.pem";
        String eccInt2Cert = "examples/certs/intermediate/ca-int2-ecc-cert.pem";

        if (WolfSSLTestFactory.isAndroid()) {
            rsaServerCert = "/sdcard/" + rsaServerCert;
            rsaInt2Cert = "/sdcard/" + rsaInt2Cert;

            eccServerCert = "/sdcard/" + eccServerCert;
            eccInt2Cert = "/sdcard/" + eccInt2Cert;
        }

        tm = tf.createTrustManager("SunX509", tf.caJKS, provider);
        if (tm == null) {
            error("\t... failed");
            fail("failed to create trustmanager");
            return;
        }

        x509tm = (X509TrustManager) tm[0];

        /* ---------- RSA Cert Chain ---------- */

        /* build up X509Certificate[] chain, missing intermediate 1 */
        certArray = new X509Certificate[2];

        /* certArray[0]: server/peer cert */
        fis = new FileInputStream(rsaServerCert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[0] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* certArray[1]: intermediate CA 2 */
        fis = new FileInputStream(rsaInt2Cert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[1] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* try to verify chain, root (certs/ca-cert.pem) should be in caJKS */
        try {
            x509tm.checkServerTrusted(certArray, "RSA");
            error("\t... failed");
            fail("Did not fail verify like expected when missing intermediate");
        } catch (CertificateException e) {
            /* Expected, missing intermediate 1 from chain */
        }

        /* ---------- ECC Cert Chain ---------- */

        /* build up X509Certificate[] chain, missing intermediate 1 */
        certArray = new X509Certificate[2];

        /* certArray[0]: server/peer cert */
        fis = new FileInputStream(eccServerCert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[0] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* certArray[1]: intermediate CA 2 */
        fis = new FileInputStream(eccInt2Cert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[1] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* try to verify chain, root (certs/ca-cert.pem) should be in caJKS */
        try {
            x509tm.checkServerTrusted(certArray, "ECC");
            error("\t... failed");
            fail("Did not fail verify like expected when missing intermediate");
        } catch (CertificateException e) {
            /* Expected, missing intermediate 1 from chain */
        }

        pass("\t... passed");
    }

    @Test
    public void testCheckServerTrustedWithChainWrongOrder()
        throws NoSuchProviderException, NoSuchAlgorithmException,
            KeyStoreException, FileNotFoundException, IOException,
            CertificateException {

        TrustManager[] tm;
        X509TrustManager x509tm;
        Certificate cert = null;
        X509Certificate[] certArray = null;
        FileInputStream fis = null;
        BufferedInputStream bis = null;
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        System.out.print("\tcheckServerTrusted() ooo chain");

        /* RSA chain, out of order intermediate CAs */
        String rsaServerCert = "examples/certs/intermediate/server-int-cert.pem";
        String rsaInt1Cert = "examples/certs/intermediate/ca-int-cert.pem";
        String rsaInt2Cert = "examples/certs/intermediate/ca-int2-cert.pem";

        /* ECC chain, out of order intermediate CAs */
        String eccServerCert = "examples/certs/intermediate/server-int-ecc-cert.pem";
        String eccInt1Cert = "examples/certs/intermediate/ca-int-ecc-cert.pem";
        String eccInt2Cert = "examples/certs/intermediate/ca-int2-ecc-cert.pem";

        if (WolfSSLTestFactory.isAndroid()) {
            rsaServerCert = "/sdcard/" + rsaServerCert;
            rsaInt1Cert = "/sdcard/" + rsaInt1Cert;
            rsaInt2Cert = "/sdcard/" + rsaInt2Cert;

            eccServerCert = "/sdcard/" + eccServerCert;
            eccInt1Cert = "/sdcard/" + eccInt1Cert;
            eccInt2Cert = "/sdcard/" + eccInt2Cert;
        }

        tm = tf.createTrustManager("SunX509", tf.caJKS, provider);
        if (tm == null) {
            error("\t... failed");
            fail("failed to create trustmanager");
            return;
        }

        x509tm = (X509TrustManager) tm[0];

        /* ---------- RSA Cert Chain ---------- */

        /* build up X509Certificate[] chain, out of order intermediates */
        certArray = new X509Certificate[3];

        /* certArray[0]: server/peer cert */
        fis = new FileInputStream(rsaServerCert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[0] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* certArray[1]: intermediate CA 2 */
        fis = new FileInputStream(rsaInt2Cert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[1] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* certArray[2]: intermediate CA 1 */
        fis = new FileInputStream(rsaInt1Cert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[2] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* verify chain, root (certs/ca-cert.pem) should be in caJKS */
        try {
            x509tm.checkServerTrusted(certArray, "RSA");
        } catch (CertificateException e) {
            error("\t... failed");
            fail("Failed verify of RSA chain with intermediates");
        }

        /* ---------- ECC Cert Chain ---------- */

        /* build up X509Certificate[] chain, out of order intermediates */
        certArray = new X509Certificate[3];

        /* certArray[0]: server/peer cert */
        fis = new FileInputStream(eccServerCert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[0] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* certArray[1]: intermediate CA 2 */
        fis = new FileInputStream(eccInt2Cert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[1] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* certArray[2]: intermediate CA 1 */
        fis = new FileInputStream(eccInt1Cert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[2] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* verify chain, root (certs/ca-ecc-cert.pem) should be in caJKS */
        try {
            x509tm.checkServerTrusted(certArray, "ECC");
        } catch (CertificateException e) {
            error("\t... failed");
            fail("Failed verify of ECC chain with intermediates");
        }

        pass("\t... passed");
    }

    @Test
    public void testCheckServerTrustedWithChainReturnsChain()
        throws NoSuchProviderException, NoSuchAlgorithmException,
            KeyStoreException, FileNotFoundException, IOException,
            CertificateException {

        TrustManager[] tm;
        X509TrustManager x509tm;
        WolfSSLTrustX509 wolfX509tm;
        Certificate cert = null;
        X509Certificate[] certArray = null;
        FileInputStream fis = null;
        BufferedInputStream bis = null;
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List<X509Certificate> retChain = null;

        System.out.print("\tcheckServerTrusted() ret chain");

        /* RSA chain */
        String rsaServerCert =
            "examples/certs/intermediate/server-int-cert.pem";
        String rsaInt1Cert = "examples/certs/intermediate/ca-int-cert.pem";
        String rsaInt2Cert = "examples/certs/intermediate/ca-int2-cert.pem";

        /* ECC chain */
        String eccServerCert =
            "examples/certs/intermediate/server-int-ecc-cert.pem";
        String eccInt1Cert = "examples/certs/intermediate/ca-int-ecc-cert.pem";
        String eccInt2Cert = "examples/certs/intermediate/ca-int2-ecc-cert.pem";

        if (WolfSSLTestFactory.isAndroid()) {
            rsaServerCert = "/sdcard/" + rsaServerCert;
            rsaInt1Cert = "/sdcard/" + rsaInt1Cert;
            rsaInt2Cert = "/sdcard/" + rsaInt2Cert;

            eccServerCert = "/sdcard/" + eccServerCert;
            eccInt1Cert = "/sdcard/" + eccInt1Cert;
            eccInt2Cert = "/sdcard/" + eccInt2Cert;
        }

        tm = tf.createTrustManager("SunX509", tf.caJKS, provider);
        if (tm == null) {
            error("\t... failed");
            fail("failed to create trustmanager");
            return;
        }

        x509tm = (X509TrustManager) tm[0];

        /* checkServerTrusted() that returns List<X509Certificate> is non
         * standard, must call directly from WolfSSLTrustX509. Called by
         * okhttp on Android. */
        wolfX509tm = (WolfSSLTrustX509)x509tm;

        /* ---------- RSA Cert Chain ---------- */

        /* build up X509Certificate[] chain, out of order intermediates */
        certArray = new X509Certificate[3];

        /* certArray[0]: server/peer cert */
        fis = new FileInputStream(rsaServerCert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[0] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* certArray[1]: intermediate CA 1 */
        fis = new FileInputStream(rsaInt1Cert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[1] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* certArray[2]: intermediate CA 2 */
        fis = new FileInputStream(rsaInt2Cert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[2] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* verify chain, root (certs/ca-cert.pem) should be in caJKS */
        try {
            /* hostname cert pinning not supported yet by wolfJSSE */
            retChain = wolfX509tm.checkServerTrusted(certArray,
                                                     "RSA", "localhost");
        } catch (CertificateException e) {
            error("\t... failed");
            fail("Failed verify of RSA chain with intermediates");
        }

        if (retChain == null) {
            error("\t... failed");
            fail("checkServerTrusted() did not return expected List of certs");
        }

        /* cert chain returned should include peer, ints, and root */
        if (retChain.size() != 4) {
            error("\t... failed");
            fail("checkServerTrusted() didn't return expected number of certs");
        }

        /* ---------- ECC Cert Chain ---------- */

        /* build up X509Certificate[] chain, out of order intermediates */
        certArray = new X509Certificate[3];

        /* certArray[0]: server/peer cert */
        fis = new FileInputStream(eccServerCert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[0] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* certArray[1]: intermediate CA 1 */
        fis = new FileInputStream(eccInt1Cert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[1] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* certArray[2]: intermediate CA 2 */
        fis = new FileInputStream(eccInt2Cert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[2] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* verify chain, root (certs/ca-ecc-cert.pem) should be in caJKS */
        try {
            /* hostname cert pinning not supported yet by wolfJSSE */
            retChain = wolfX509tm.checkServerTrusted(certArray,
                                                     "ECC", "localhost");
        } catch (CertificateException e) {
            error("\t... failed");
            fail("Failed verify of ECC chain with intermediates");
        }

        if (retChain == null) {
            error("\t... failed");
            fail("checkServerTrusted() did not return expected List of certs");
        }

        /* cert chain returned should include peer, ints, and root */
        if (retChain.size() != 4) {
            error("\t... failed");
            fail("checkServerTrusted() didn't return expected number of certs");
        }

        pass("\t... passed");
    }

    @Test
    public void testCheckServerTrustedWithDuplicatedRootInChain()
        throws NoSuchProviderException, NoSuchAlgorithmException,
            KeyStoreException, FileNotFoundException, IOException,
            CertificateException {

        int rootCount = 0;
        TrustManager[] tm;
        X509TrustManager x509tm;
        WolfSSLTrustX509 wolfX509tm;
        Certificate cert = null;
        X509Certificate[] certArray = null;
        FileInputStream fis = null;
        BufferedInputStream bis = null;
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List<X509Certificate> retChain = null;

        System.out.print("\tcheckServerTrusted() dup root");

        /* RSA chain, including root (which is already in caJKS) */
        String rsaServerCert =
            "examples/certs/intermediate/server-int-cert.pem";
        String rsaInt2Cert = "examples/certs/intermediate/ca-int2-cert.pem";
        String rsaInt1Cert = "examples/certs/intermediate/ca-int-cert.pem";
        String rsaRootCert = "examples/certs/ca-cert.pem";

        /* ECC chain, including root (which is already in caJKS) */
        String eccServerCert =
            "examples/certs/intermediate/server-int-ecc-cert.pem";
        String eccInt2Cert = "examples/certs/intermediate/ca-int2-ecc-cert.pem";
        String eccInt1Cert = "examples/certs/intermediate/ca-int-ecc-cert.pem";
        String eccRootCert = "examples/certs/ca-ecc-cert.pem";

        if (WolfSSLTestFactory.isAndroid()) {
            rsaServerCert = "/sdcard/" + rsaServerCert;
            rsaInt1Cert = "/sdcard/" + rsaInt1Cert;
            rsaInt2Cert = "/sdcard/" + rsaInt2Cert;
            rsaRootCert = "/sdcard/" + rsaRootCert;

            eccServerCert = "/sdcard/" + eccServerCert;
            eccInt1Cert = "/sdcard/" + eccInt1Cert;
            eccInt2Cert = "/sdcard/" + eccInt2Cert;
            eccRootCert = "/sdcard/" + eccRootCert;
        }

        tm = tf.createTrustManager("SunX509", tf.caJKS, provider);
        if (tm == null) {
            error("\t... failed");
            fail("failed to create trustmanager");
            return;
        }

        x509tm = (X509TrustManager) tm[0];

        /* checkServerTrusted() that returns List<X509Certificate> is non
         * standard, must call directly from WolfSSLTrustX509. Called by
         * okhttp on Android. */
        wolfX509tm = (WolfSSLTrustX509)x509tm;

        /* ---------- RSA Cert Chain ---------- */

        /* build up X509Certificate[] chain, out of order intermediates */
        certArray = new X509Certificate[4];

        /* certArray[0]: server/peer cert */
        fis = new FileInputStream(rsaServerCert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[0] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* certArray[1]: intermediate CA 1 */
        fis = new FileInputStream(rsaInt1Cert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[1] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* certArray[2]: intermediate CA 2 */
        fis = new FileInputStream(rsaInt2Cert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[2] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* certArray[3]: root CA */
        fis = new FileInputStream(rsaRootCert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[3] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* verify chain, root (certs/ca-cert.pem) should be in caJKS */
        try {
            /* hostname cert pinning not supported yet by wolfJSSE */
            retChain = wolfX509tm.checkServerTrusted(certArray,
                                                     "RSA", "localhost");
        } catch (CertificateException e) {
            error("\t... failed");
            fail("Failed verify of RSA chain with intermediates");
        }

        if (retChain == null) {
            error("\t... failed");
            fail("checkServerTrusted() did not return expected List of certs");
        }

        /* cert chain returned should include peer, ints, and root, but
         * not a duplicate of root if in both TrustStore and chain */
        if (retChain.size() != 4) {
            error("\t... failed");
            fail("checkServerTrusted() didn't return expected number of certs");
        }

        /* make sure root is not in chain twice */
        rootCount = 0;
        for (X509Certificate x509Cert : retChain) {
            if (x509Cert.equals(cert)) {
                rootCount++;
            }
        }
        if (rootCount != 1) {
            error("\t... failed");
            fail("checkServerTrusted() contained more than one copy of root");
        }

        /* ---------- ECC Cert Chain ---------- */

        /* build up X509Certificate[] chain, out of order intermediates */
        certArray = new X509Certificate[4];

        /* certArray[0]: server/peer cert */
        fis = new FileInputStream(eccServerCert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[0] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* certArray[1]: intermediate CA 1 */
        fis = new FileInputStream(eccInt1Cert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[1] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* certArray[2]: intermediate CA 2 */
        fis = new FileInputStream(eccInt2Cert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[2] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* certArray[3]: root CA */
        fis = new FileInputStream(eccRootCert);
        bis = new BufferedInputStream(fis);
        cert = cf.generateCertificate(bis);
        certArray[3] = (X509Certificate)cert;
        bis.close();
        fis.close();

        /* verify chain, root (certs/ca-ecc-cert.pem) should be in caJKS */
        try {
            /* hostname cert pinning not supported yet by wolfJSSE */
            retChain = wolfX509tm.checkServerTrusted(certArray,
                                                     "ECC", "localhost");
        } catch (CertificateException e) {
            error("\t... failed");
            fail("Failed verify of ECC chain with intermediates");
        }

        if (retChain == null) {
            error("\t... failed");
            fail("checkServerTrusted() did not return expected List of certs");
        }

        /* cert chain returned should include peer, ints, and root, but
         * not a duplicate of root if in both TrustStore and chain */
        if (retChain.size() != 4) {
            error("\t... failed");
            fail("checkServerTrusted() didn't return expected number of certs");
        }

        /* make sure root is not in chain twice */
        rootCount = 0;
        for (X509Certificate x509Cert : retChain) {
            if (x509Cert.equals(cert)) {
                rootCount++;
            }
        }
        if (rootCount != 1) {
            error("\t... failed");
            fail("checkServerTrusted() contained more than one copy of root");
        }

        pass("\t... passed");
    }

    @Test
    public void testUsingRsaPssCert()
        throws Exception {
        /* skip if RSA_PSS or TLS 1.3 are not compiled in at native level */
        if ((WolfSSL.RsaPssEnabled() == false) ||
            (WolfSSL.TLSv13Enabled() == false)) {
            return;
        }

        System.out.print("\tTest using rsa_pss certs");

        SSLContext srvCtx = tf.createSSLContext("TLSv1.3", provider,
            tf.createTrustManager("SunX509", tf.caClientJKS, provider),
            tf.createKeyManager("SunX509", tf.serverRSAPSSJKS, provider));

        SSLContext cliCtx = tf.createSSLContext("TLSv1.3", provider,
            tf.createTrustManager("SunX509", tf.caServerJKS, provider),
            tf.createKeyManager("SunX509", tf.clientRSAPSSJKS, provider));

        SSLServerSocket ss = (SSLServerSocket)srvCtx.getServerSocketFactory()
            .createServerSocket(0);

        TestArgs serverArgs = new TestArgs(null, null, true, true, true, null);
        TestSSLSocketServer server = new TestSSLSocketServer(
            srvCtx, ss, serverArgs, 1);
        server.start();

        TestArgs clientArgs = new TestArgs(
            "HTTPS", "www.wolfssl.com", false, false, true, null);
        TestSSLSocketClient client = new TestSSLSocketClient(
            cliCtx, ss.getLocalPort(), clientArgs);
        client.start();

        try {
            client.join(1000);
            server.join(1000);
        } catch (InterruptedException e) {
            System.out.println("interrupt happened");
            fail("RSA_PSS cert test failed");
        }

        /* Fail if client or server encountered exception */
        Exception srvException = server.getException();
        Exception cliException = client.getException();
        if (srvException != null || cliException != null) {
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

        pass("\t... passed");
    }

    @Test
    public void testX509ExtendedTrustManagerInternal()
        throws CertificateException, IOException, Exception {

        System.out.print("\tX509ExtendedTrustManager int");

        /* Basic SSLSocket success case, SNI matches server cert CN */
        testX509ExtendedTrustManagerSSLSocketBasicSuccess();

        /* Basic SSLSocket success case, SNI matches server cert CN,
         * do not call startHandshake(), should still succeed */
        testX509ExtendedTrustManagerSSLSocketNoStartHandshakeSuccess();
        testX509ExtendedTrustManagerSSLSocketNoClientStartHandshakeSuccess();
        testX509ExtendedTrustManagerSSLSocketNoServerStartHandshakeSuccess();

        /* Basic SSLSocket fail case, SNI does not match server cert CN */
        testX509ExtendedTrustManagerSSLSocketBasicFail();

        /* SSLSocket should fail if trying to use bad endoint alg */
        testX509ExtendedTrustManagerSSLSocketEndpointAlgFail();

        /* SSLSocket should succeed if server cert changes after resume */
        testX509ExtendedTrustManagerSSLSocketCertChangeSuccess();

        /* Basic SSLEngine success case, HTTPS hostname verification,
         * SNI matches server cert CN */
        testX509ExtendedTrustManagerSSLEngineBasicSuccess();

        /* Basic SSLEngine success case, LDAPS hostname verification,
         * SNI matches server cert CN */
        testX509ExtendedTrustManagerSSLEngineBasicSuccessLDAPS();

        /* Basic SSLEngine fail case, HTTPS hostname verification,
         * SNI does not match server cert CN */
        testX509ExtendedTrustManagerSSLEngineBasicFail();

        /* Basic SSLEngine fail case, LDAPS hostname verification,
         * SNI does not match server cert CN */
        testX509ExtendedTrustManagerSSLEngineBasicFailLDAPS();

        /* LDAPS hostname verification test, wildcard failures */
        testX509ExtendedTrustManagerSSLEngineWildcardFailLDAPS();

        /* LDAPS hostname verification test, wildcard success */
        testX509ExtendedTrustManagerSSLEngineWildcardSuccessLDAPS();

        /* SSLEngine should fail if trying to use bad endoint alg */
        testX509ExtendedTrustManagerSSLEngineEndpointAlgFail();

        pass("\t... passed");
    }

    private void testX509ExtendedTrustManagerSSLSocketBasicSuccess()
        throws CertificateException, IOException, Exception {

        SSLContext srvCtx = tf.createSSLContext("TLSv1.2", provider,
                tf.createTrustManager("SunX509", tf.caClientJKS, provider),
                tf.createKeyManager("SunX509", tf.serverJKS, provider));

        SSLContext cliCtx = tf.createSSLContext("TLSv1.2", provider,
                tf.createTrustManager("SunX509", tf.caServerJKS, provider),
                tf.createKeyManager("SunX509", tf.clientJKS, provider));

        /* create SSLServerSocket first to get ephemeral port */
        SSLServerSocket ss = (SSLServerSocket)srvCtx.getServerSocketFactory()
            .createServerSocket(0);

        TestArgs serverArgs = new TestArgs(null, null, true, true, true, null);
        TestSSLSocketServer server = new TestSSLSocketServer(
            srvCtx, ss, serverArgs, 1);
        server.start();

        TestArgs clientArgs = new TestArgs(
            "HTTPS", "www.wolfssl.com", false, false, true, null);
        TestSSLSocketClient client = new TestSSLSocketClient(
            cliCtx, ss.getLocalPort(), clientArgs);
        client.start();

        try {
            client.join(1000);
            server.join(1000);

        } catch (InterruptedException e) {
            System.out.println("interrupt happened");
            fail("ExtendedX509TrustManager basic test failed");
        }

        /* Fail if client or server encountered exception */
        Exception srvException = server.getException();
        Exception cliException = client.getException();
        if (srvException != null || cliException != null) {
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

    private void testX509ExtendedTrustManagerSSLSocketNoStartHandshakeSuccess()
        throws CertificateException, IOException, Exception {

        SSLContext srvCtx = tf.createSSLContext("TLSv1.2", provider,
                tf.createTrustManager("SunX509", tf.caClientJKS, provider),
                tf.createKeyManager("SunX509", tf.serverJKS, provider));

        SSLContext cliCtx = tf.createSSLContext("TLSv1.2", provider,
                tf.createTrustManager("SunX509", tf.caServerJKS, provider),
                tf.createKeyManager("SunX509", tf.clientJKS, provider));

        /* create SSLServerSocket first to get ephemeral port */
        SSLServerSocket ss = (SSLServerSocket)srvCtx.getServerSocketFactory()
            .createServerSocket(0);

        TestArgs serverArgs = new TestArgs(null, null, true, true, false, null);
        TestSSLSocketServer server = new TestSSLSocketServer(
            srvCtx, ss, serverArgs, 1);
        server.start();

        TestArgs clientArgs = new TestArgs(
            "HTTPS", "www.wolfssl.com", false, false, false, null);
        TestSSLSocketClient client = new TestSSLSocketClient(
            cliCtx, ss.getLocalPort(), clientArgs);
        client.start();

        try {
            client.join(1000);
            server.join(1000);

        } catch (InterruptedException e) {
            System.out.println("interrupt happened");
            fail("ExtendedX509TrustManager no startHandshake() test failed");
        }

        /* Fail if client or server encountered exception */
        Exception srvException = server.getException();
        Exception cliException = client.getException();
        if (srvException != null || cliException != null) {
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

    private void testX509ExtendedTrustManagerSSLSocketNoClientStartHandshakeSuccess()
        throws CertificateException, IOException, Exception {

        SSLContext srvCtx = tf.createSSLContext("TLSv1.2", provider,
                tf.createTrustManager("SunX509", tf.caClientJKS, provider),
                tf.createKeyManager("SunX509", tf.serverJKS, provider));

        SSLContext cliCtx = tf.createSSLContext("TLSv1.2", provider,
                tf.createTrustManager("SunX509", tf.caServerJKS, provider),
                tf.createKeyManager("SunX509", tf.clientJKS, provider));

        /* create SSLServerSocket first to get ephemeral port */
        SSLServerSocket ss = (SSLServerSocket)srvCtx.getServerSocketFactory()
            .createServerSocket(0);

        TestArgs serverArgs = new TestArgs(null, null, true, true, true, null);
        TestSSLSocketServer server = new TestSSLSocketServer(
            srvCtx, ss, serverArgs, 1);
        server.start();

        TestArgs clientArgs = new TestArgs(
            "HTTPS", "www.wolfssl.com", false, false, false, null);
        TestSSLSocketClient client = new TestSSLSocketClient(
            cliCtx, ss.getLocalPort(), clientArgs);
        client.start();

        try {
            client.join(1000);
            server.join(1000);

        } catch (InterruptedException e) {
            System.out.println("interrupt happened");
            fail("ExtendedX509TrustManager no startHandshake() test failed");
        }

        /* Fail if client or server encountered exception */
        Exception srvException = server.getException();
        Exception cliException = client.getException();
        if (srvException != null || cliException != null) {
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

    private void testX509ExtendedTrustManagerSSLSocketNoServerStartHandshakeSuccess()
        throws CertificateException, IOException, Exception {

        SSLContext srvCtx = tf.createSSLContext("TLSv1.2", provider,
                tf.createTrustManager("SunX509", tf.caClientJKS, provider),
                tf.createKeyManager("SunX509", tf.serverJKS, provider));

        SSLContext cliCtx = tf.createSSLContext("TLSv1.2", provider,
                tf.createTrustManager("SunX509", tf.caServerJKS, provider),
                tf.createKeyManager("SunX509", tf.clientJKS, provider));

        /* create SSLServerSocket first to get ephemeral port */
        SSLServerSocket ss = (SSLServerSocket)srvCtx.getServerSocketFactory()
            .createServerSocket(0);

        TestArgs serverArgs = new TestArgs(null, null, true, true, false, null);
        TestSSLSocketServer server = new TestSSLSocketServer(
            srvCtx, ss, serverArgs, 1);
        server.start();

        TestArgs clientArgs = new TestArgs(
            "HTTPS", "www.wolfssl.com", false, false, true, null);
        TestSSLSocketClient client = new TestSSLSocketClient(
            cliCtx, ss.getLocalPort(), clientArgs);
        client.start();

        try {
            client.join(1000);
            server.join(1000);

        } catch (InterruptedException e) {
            System.out.println("interrupt happened");
            fail("ExtendedX509TrustManager no startHandshake() test failed");
        }

        /* Fail if client or server encountered exception */
        Exception srvException = server.getException();
        Exception cliException = client.getException();
        if (srvException != null || cliException != null) {
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

    private void testX509ExtendedTrustManagerSSLSocketBasicFail()
        throws CertificateException, IOException, Exception {

        SSLContext srvCtx = tf.createSSLContext("TLSv1.2", provider,
                tf.createTrustManager("SunX509", tf.caClientJKS, provider),
                tf.createKeyManager("SunX509", tf.serverJKS, provider));

        SSLContext cliCtx = tf.createSSLContext("TLSv1.2", provider,
                tf.createTrustManager("SunX509", tf.caServerJKS, provider),
                tf.createKeyManager("SunX509", tf.clientJKS, provider));

        /* create SSLServerSocket first to get ephemeral port */
        SSLServerSocket ss = (SSLServerSocket)srvCtx.getServerSocketFactory()
            .createServerSocket(0);

        TestArgs serverArgs = new TestArgs(null, null, true, true, true, null);
        TestSSLSocketServer server = new TestSSLSocketServer(
            srvCtx, ss, serverArgs, 1);
        server.start();

        /* Correct SNI is www.wolfssl.com, this should cause a failure */
        TestArgs clientArgs = new TestArgs(
            "HTTPS", "www.invalid.com", false, false, true, null);
        TestSSLSocketClient client = new TestSSLSocketClient(
            cliCtx, ss.getLocalPort(), clientArgs);
        client.start();

        try {
            client.join(1000);
            server.join(1000);

        } catch (InterruptedException e) {
            System.out.println("interrupt happened");
            fail("X509ExtendedTrustManager basic test failed");
        }

        /* Fail if client or server encountered exception */
        Exception srvException = server.getException();

        if (srvException == null) {
            throw new Exception("Expecting exception but did not get one");
        }
    }

    private void testX509ExtendedTrustManagerSSLSocketEndpointAlgFail()
        throws CertificateException, IOException, Exception {

        SSLContext srvCtx = tf.createSSLContext("TLSv1.2", provider,
                tf.createTrustManager("SunX509", tf.caClientJKS, provider),
                tf.createKeyManager("SunX509", tf.serverJKS, provider));

        SSLContext cliCtx = tf.createSSLContext("TLSv1.2", provider,
                tf.createTrustManager("SunX509", tf.caServerJKS, provider),
                tf.createKeyManager("SunX509", tf.clientJKS, provider));

        /* create SSLServerSocket first to get ephemeral port */
        SSLServerSocket ss = (SSLServerSocket)srvCtx.getServerSocketFactory()
            .createServerSocket(0);

        TestArgs serverArgs = new TestArgs(null, null, true, true, true, null);
        TestSSLSocketServer server = new TestSSLSocketServer(
            srvCtx, ss, serverArgs, 1);
        server.start();

        /* We only support "HTTPS" and "LDAPS" as an endpoint algorithms.
         * Setting "BADTYPE" should fail as unsupported */
        TestArgs clientArgs = new TestArgs(
            "BADTYPE", "www.wolfssl.com", false, false, true, null);
        TestSSLSocketClient client = new TestSSLSocketClient(
            cliCtx, ss.getLocalPort(), clientArgs);
        client.start();

        try {
            client.join(1000);
            server.join(1000);

        } catch (InterruptedException e) {
            System.out.println("interrupt happened");
            fail("X509ExtendedTrustManager basic test failed");
        }

        /* Fail if client or server encountered exception */
        Exception srvException = server.getException();
        Exception cliException = client.getException();

        if (srvException == null && cliException == null) {
            throw new Exception("Expecting exception but did not get one");
        }
    }

    private void testX509ExtendedTrustManagerSSLEngineBasicSuccess()
        throws CertificateException, IOException, Exception {

        int ret;
        SSLEngine client;
        SSLEngine server;

        SSLContext ctx = tf.createSSLContext("TLS", provider);
        server = ctx.createSSLEngine();
        client = ctx.createSSLEngine("wolfSSL auth test", 11111);

        server.setWantClientAuth(true);
        server.setNeedClientAuth(true);
        client.setUseClientMode(true);
        server.setUseClientMode(false);

        SSLParameters cliParams = client.getSSLParameters();

        /* Enable Endpoint Identification for hostname verification on client */
        cliParams.setEndpointIdentificationAlgorithm("HTTPS");

        /* Set SNI, used for hostname verification of server cert. Peer cert
         * has altName set to "example.com". */
        SNIHostName sniName = new SNIHostName("example.com");
        List<SNIServerName> sniNames = new ArrayList<>(1);
        sniNames.add(sniName);
        cliParams.setServerNames(sniNames);

        client.setSSLParameters(cliParams);

        ret = tf.testConnection(server, client, null, null, "Test mutual auth");
        if (ret != 0) {
            throw new Exception("Failed SSLEngine connection");
        }
    }

    private void testX509ExtendedTrustManagerSSLEngineBasicSuccessLDAPS()
        throws CertificateException, IOException, Exception {

        int ret;
        SSLEngine client;
        SSLEngine server;

        SSLContext ctx = tf.createSSLContext("TLS", provider);
        server = ctx.createSSLEngine();
        client = ctx.createSSLEngine("example.com", 11111);

        server.setWantClientAuth(true);
        server.setNeedClientAuth(true);
        client.setUseClientMode(true);
        server.setUseClientMode(false);

        SSLParameters cliParams = client.getSSLParameters();

        /* Enable Endpoint Identification for hostname verification on client */
        cliParams.setEndpointIdentificationAlgorithm("LDAPS");

        /* Not setting SNI, since LDAPS hostname verification requires server
         * name to come directly from when connection was made. Peer cert
         * has altName set to "example.com" */

        client.setSSLParameters(cliParams);

        ret = tf.testConnection(server, client, null, null, "Test mutual auth");
        if (ret != 0) {
            throw new Exception("Failed SSLEngine connection");
        }
    }

    private void testX509ExtendedTrustManagerSSLEngineBasicFail()
        throws CertificateException, IOException, Exception {

        int ret;
        SSLEngine client;
        SSLEngine server;

        SSLContext ctx = tf.createSSLContext("TLS", provider);
        server = ctx.createSSLEngine();
        client = ctx.createSSLEngine("wolfSSL auth test", 11111);

        server.setWantClientAuth(true);
        server.setNeedClientAuth(true);
        client.setUseClientMode(true);
        server.setUseClientMode(false);

        SSLParameters cliParams = client.getSSLParameters();

        /* Enable Endpoint Identification for hostname verification on client */
        cliParams.setEndpointIdentificationAlgorithm("HTTPS");

        /* Set SNI, used for hostname verification of server cert. Peer cert
         * has altName set to "example.com", so "www.invalid.com" should cause
         * a failure. */
        SNIHostName sniName = new SNIHostName("www.invalid.com");
        List<SNIServerName> sniNames = new ArrayList<>(1);
        sniNames.add(sniName);
        cliParams.setServerNames(sniNames);

        client.setSSLParameters(cliParams);

        ret = tf.testConnection(server, client, null, null, "Test mutual auth");
        if (ret == 0) {
            throw new Exception("Expected connection to fail, but did not");
        }
    }

    private void testX509ExtendedTrustManagerSSLEngineBasicFailLDAPS()
        throws CertificateException, IOException, Exception {

        int ret;
        SSLEngine client;
        SSLEngine server;

        SSLContext ctx = tf.createSSLContext("TLS", provider);
        server = ctx.createSSLEngine();
        /* Setting wrong hostname */
        client = ctx.createSSLEngine("www.invalid.com", 11111);

        server.setWantClientAuth(true);
        server.setNeedClientAuth(true);
        client.setUseClientMode(true);
        server.setUseClientMode(false);

        SSLParameters cliParams = client.getSSLParameters();

        /* Enable Endpoint Identification for hostname verification on client */
        cliParams.setEndpointIdentificationAlgorithm("LDAPS");

        client.setSSLParameters(cliParams);

        ret = tf.testConnection(server, client, null, null, "Test mutual auth");
        if (ret == 0) {
            throw new Exception("Expected connection to fail, but did not");
        }
    }

    private void testX509ExtendedTrustManagerSSLEngineWildcardFailLDAPS()
        throws CertificateException, IOException, Exception {

        int ret;
        SSLContext srvCtx = null;
        SSLContext cliCtx = null;
        KeyStore srvCertStore = null;
        SSLEngine client = null;
        SSLEngine server = null;
        SSLParameters cliParams = null;

        /* Generate new KeyStore with new self-signed cert. CN is set to
         * invalidname.com so we don't match on that. Subject altName is
         * set to '*.example.com' */
        srvCertStore = tf.generateSelfSignedCertJKS(
            "invalidname.com", "*.example.com", true);

        srvCtx = tf.createSSLContext("TLS", provider,
            tf.createTrustManager("SunX509", tf.caClientJKS, provider),
            tf.createKeyManager("SunX509", srvCertStore, provider));

        cliCtx = tf.createSSLContext("TLS", provider,
            tf.createTrustManager("SunX509", srvCertStore, provider),
            tf.createKeyManager("SunX509", tf.clientJKS, provider));

        /* --------------------------------------------------------------------
         * LDAPS hostname verification should fail for 'example.com', since
         * altName contains '*.example.com'
         * ------------------------------------------------------------------ */
        server = srvCtx.createSSLEngine();
        client = cliCtx.createSSLEngine("example.com", 11111);

        server.setWantClientAuth(true);
        server.setNeedClientAuth(true);
        client.setUseClientMode(true);
        server.setUseClientMode(false);

        /* Enable Endpoint Identification for hostname verification on client.
         * Not setting SNI, since LDAPS hostname verification requires server
         * name to come directly from when connection was made. Peer cert
         * has altName set to "example.com" */
        cliParams = client.getSSLParameters();
        cliParams.setEndpointIdentificationAlgorithm("LDAPS");
        client.setSSLParameters(cliParams);

        ret = tf.testConnection(server, client, null, null, "Test mutual auth");
        if (ret == 0) {
            throw new Exception(
                "Should fail SSLEngine connection, but succeeded");
        }

        /* --------------------------------------------------------------------
         * LDAPS hostname verification should fail for 'a.b.example.com', since
         * altName contains '*.example.com' and LDAPS only matches left-most
         * wildcard.
         * ------------------------------------------------------------------ */
        server = srvCtx.createSSLEngine();
        client = cliCtx.createSSLEngine("a.b.example.com", 11111);

        server.setWantClientAuth(true);
        server.setNeedClientAuth(true);
        client.setUseClientMode(true);
        server.setUseClientMode(false);


        /* Enable Endpoint Identification for hostname verification on client.
         * Not setting SNI, since LDAPS hostname verification requires server
         * name to come directly from when connection was made. Peer cert
         * has altName set to "example.com" */
        cliParams = client.getSSLParameters();
        cliParams.setEndpointIdentificationAlgorithm("LDAPS");
        client.setSSLParameters(cliParams);

        ret = tf.testConnection(server, client, null, null, "Test mutual auth");
        if (ret == 0) {
            throw new Exception(
                "Should fail SSLEngine connection, but succeeded");
        }

        /* --------------------------------------------------------------------
         * LDAPS hostname verification should fail for 'a.example*.com', since
         * altName contains '*.example.com' and LDAPS only matches left-most
         * wildcard.
         * ------------------------------------------------------------------ */
        server = srvCtx.createSSLEngine();
        client = cliCtx.createSSLEngine("a.example*.com", 11111);

        server.setWantClientAuth(true);
        server.setNeedClientAuth(true);
        client.setUseClientMode(true);
        server.setUseClientMode(false);


        /* Enable Endpoint Identification for hostname verification on client.
         * Not setting SNI, since LDAPS hostname verification requires server
         * name to come directly from when connection was made. Peer cert
         * has altName set to "example.com" */
        cliParams = client.getSSLParameters();
        cliParams.setEndpointIdentificationAlgorithm("LDAPS");
        client.setSSLParameters(cliParams);

        ret = tf.testConnection(server, client, null, null, "Test mutual auth");
        if (ret == 0) {
            throw new Exception(
                "Should fail SSLEngine connection, but succeeded");
        }
    }

    private void testX509ExtendedTrustManagerSSLEngineWildcardSuccessLDAPS()
        throws CertificateException, IOException, Exception {

        int ret;
        SSLContext srvCtx = null;
        SSLContext cliCtx = null;
        KeyStore srvCertStore = null;
        SSLEngine client = null;
        SSLEngine server = null;
        SSLParameters cliParams = null;

        /* Generate new KeyStore with new self-signed cert. CN is set to
         * invalidname.com so we don't match on that. Subject altName is
         * set to '*.example.com' */
        srvCertStore = tf.generateSelfSignedCertJKS(
            "invalidname.com", "*.example.com", true);

        srvCtx = tf.createSSLContext("TLS", provider,
            tf.createTrustManager("SunX509", tf.caClientJKS, provider),
            tf.createKeyManager("SunX509", srvCertStore, provider));

        cliCtx = tf.createSSLContext("TLS", provider,
            tf.createTrustManager("SunX509", srvCertStore, provider),
            tf.createKeyManager("SunX509", tf.clientJKS, provider));

        /* --------------------------------------------------------------------
         * LDAPS hostname verification 'test.example.com' should match against
         * '*.example.com' altName in server cert.
         * ------------------------------------------------------------------ */
        server = srvCtx.createSSLEngine();
        client = cliCtx.createSSLEngine("test.example.com", 11111);

        server.setWantClientAuth(true);
        server.setNeedClientAuth(true);
        client.setUseClientMode(true);
        server.setUseClientMode(false);

        /* Enable Endpoint Identification for hostname verification on client.
         * Not setting SNI, since LDAPS hostname verification requires server
         * name to come directly from when connection was made. Peer cert
         * has altName set to "example.com" */
        cliParams = client.getSSLParameters();
        cliParams.setEndpointIdentificationAlgorithm("LDAPS");
        client.setSSLParameters(cliParams);

        ret = tf.testConnection(server, client, null, null, "Test mutual auth");
        if (ret != 0) {
            throw new Exception("Failed SSLEngine connection");
        }
    }

    private void testX509ExtendedTrustManagerSSLEngineEndpointAlgFail()
        throws CertificateException, IOException, Exception {

        int ret;
        SSLEngine client;
        SSLEngine server;

        SSLContext ctx = tf.createSSLContext("TLS", provider);
        server = ctx.createSSLEngine();
        client = ctx.createSSLEngine("wolfSSL auth test", 11111);

        server.setWantClientAuth(true);
        server.setNeedClientAuth(true);
        client.setUseClientMode(true);
        server.setUseClientMode(false);

        SSLParameters cliParams = client.getSSLParameters();

        /* Enable Endpoint Identification for hostname verification on client.
         * We only support "HTTPS" so setting "LDAPS" here should cause a
         * failure. */
        cliParams.setEndpointIdentificationAlgorithm("LDAPS");

        /* Set SNI, used for hostname verification of server cert. Peer cert
         * has altName set to "example.com" */
        SNIHostName sniName = new SNIHostName("example.com");
        List<SNIServerName> sniNames = new ArrayList<>(1);
        sniNames.add(sniName);
        cliParams.setServerNames(sniNames);

        client.setSSLParameters(cliParams);

        ret = tf.testConnection(server, client, null, null, "Test mutual auth");
        if (ret == 0) {
            throw new Exception("Expected connection to fail, but did not");
        }
    }

    /**
     * Get expected peer certificate from this KeyStore, used to compare
     * cert we get to what we expect.
     *
     * This method mimmics behavior inside our WolfSSLContext when we choose
     * the client/server cert to load into native wolfSSL.
     *
     * @param jks path to Java KeyStore (.jks file) to get peer cert from
     * @param pwd KeyStore password
     * @return peer cert if found, or null if not or keystore is null/empty
     */
    private X509Certificate getPeerCertFromKeyStore(String jks, String pwd) {

        if (jks == null | jks.isEmpty()) {
            return null;
        }

        try {
            String javaVersion = System.getProperty("java.version");

            FileInputStream stream = new FileInputStream(jks);
            KeyStore store = KeyStore.getInstance("JKS");
            store.load(stream, pwd.toCharArray());
            stream.close();

            KeyManagerFactory km = KeyManagerFactory.getInstance("SunX509");
            km.init(store, pwd.toCharArray());

            KeyManager[] kms = km.getKeyManagers();
            if (!(kms[0] instanceof X509KeyManager)) {
                return null;
            }
            X509KeyManager x509km = (X509KeyManager)kms[0];

            ArrayList<String> keyAlgos = new ArrayList<String>();
            if (WolfSSL.EccEnabled() &&
                (!javaVersion.equals("1.7.0_201") &&
                 !javaVersion.equals("1.7.0_171"))) {
                keyAlgos.add("EC");
            }
            if (WolfSSL.RsaEnabled()) {
                keyAlgos.add("RSA");
            }

            String[] keyStrings = new String[keyAlgos.size()];
            keyStrings = keyAlgos.toArray(keyStrings);

            String alias = x509km.chooseClientAlias(keyStrings, null, null);
            X509Certificate[] cert = x509km.getCertificateChain(alias);
            /* this is only set up to handle one cert currently for these
             * test cases */
            if (cert == null || cert.length == 0) {
                return null;
            }

            return cert[0];

        } catch (Exception e) {
            return null;
        }
    }

    private void testX509ExtendedTrustManagerSSLSocketCertChangeSuccess()
        throws CertificateException, IOException, Exception {

        int serverPort = 0;
        Exception cliException = null;
        Exception srvException = null;
        TestSSLSocketClient client = null;
        TestSSLSocketServer server = null;
        TestArgs serverArgs = null;
        TestArgs clientArgs = null;

        /* Expected server certificates */
        X509Certificate serverCertA = getPeerCertFromKeyStore(tf.serverJKS,
                "wolfSSL test");
        X509Certificate serverCertB = getPeerCertFromKeyStore(tf.clientJKS,
                "wolfSSL test");

        SSLContext srvCtx = tf.createSSLContext("TLSv1.2", provider,
                tf.createTrustManager("SunX509", tf.caClientJKS, provider),
                tf.createKeyManager("SunX509", tf.serverJKS, provider));

        /* Loading caJKS so client SSLContext can verify server both
         * before and after cert changes */
        SSLContext cliCtx = tf.createSSLContext("TLSv1.2", provider,
                tf.createTrustManager("SunX509", tf.caJKS, provider),
                tf.createKeyManager("SunX509", tf.clientJKS, provider));

        /* create SSLServerSocket first to get ephemeral port */
        SSLServerSocket ss = (SSLServerSocket)srvCtx.getServerSocketFactory()
            .createServerSocket(serverPort);
        serverPort = ss.getLocalPort();

        serverArgs = new TestArgs(null, null, true, true, true, null);
        server = new TestSSLSocketServer(srvCtx, ss, serverArgs, 2);
        server.start();

        /* FIRST client connection will do a full TLS handshake */
        clientArgs = new TestArgs(
            "HTTPS", "www.wolfssl.com", false, false, true, serverCertA);
        client = new TestSSLSocketClient(cliCtx, serverPort, clientArgs);
        client.start();
        try {
            client.join(1000);

        } catch (InterruptedException e) {
            System.out.println("interrupt happened");
            fail("ExtendedX509TrustManager cert change test failed");
        }

        /* We shouldn't have any exceptions at this point, if so error out */
        cliException = client.getException();
        if (cliException != null) {
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            if (cliException != null) {
                cliException.printStackTrace(pw);
            }
            String traceString = sw.toString();
            throw new Exception(traceString);
        }

        /* SECOND client connection will do a TLS resumed handshake. Server
         * should shut down after two client connections. */
        clientArgs = new TestArgs(
            "HTTPS", "www.wolfssl.com", false, false, true, serverCertA);
        client = new TestSSLSocketClient(cliCtx, serverPort, clientArgs);
        client.start();
        try {
            client.join(1000);
            server.join(1000);

        } catch (InterruptedException e) {
            System.out.println("interrupt happened");
            fail("ExtendedX509TrustManager cert change test failed");
        }

        /* We shouldn't have any exceptions at this point, if so error out */
        srvException = server.getException();
        cliException = client.getException();
        if (srvException != null || cliException != null) {
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

        /* Start up server, but with different certificate loaded. Here we just
         * switch to loading the client cert, since we have that available.
         * Also re-create the client SSLContext to make sure the client has the
         * correct root CA loaded to correctly verify the new/updated server
         * cert. */
        ss.close();
        srvCtx = tf.createSSLContext("TLSv1.2", provider,
            tf.createTrustManager("SunX509", tf.caClientJKS, provider),
            tf.createKeyManager("SunX509", tf.clientJKS, provider));

        /* Clear session cache on server side so we don't resume. We just
         * create a new WolfSSLContext here since the native session cache
         * is static and shared between WOLFSSL_CONTEXT objects. */
        com.wolfssl.WolfSSLContext wctx =
            new com.wolfssl.WolfSSLContext(WolfSSL.SSLv23_ServerMethod());
        wctx.flushSessions((int)(Instant.now().getEpochSecond() + 1000));
        wctx.free();

        ss = (SSLServerSocket)srvCtx.getServerSocketFactory()
            .createServerSocket(serverPort);

        serverArgs = new TestArgs(null, null, true, true, true, null);
        server = new TestSSLSocketServer(srvCtx, ss, serverArgs, 1);
        server.start();

        /* THIRD client connection will try to do a TLS resumed handshake,
         * since we connect to the same host+port, but the server has
         * been restarted and certificate has changed, so server will
         * do a new full TLS session. Client should update the cached peer
         * cert since session is not resumed, and connection + hostname
         * verificaiton + validation should succeed. */
        clientArgs = new TestArgs(
            "HTTPS", "example.com", false, false, true, serverCertB);
        client = new TestSSLSocketClient(cliCtx, serverPort, clientArgs);
        client.start();
        try {
            client.join(1000);
            server.join(1000);

        } catch (InterruptedException e) {
            System.out.println("interrupt happened");
            fail("ExtendedX509TrustManager cert change test failed");
        }

        /* We shouldn't have any exceptions at this point, if so error out */
        srvException = server.getException();
        cliException = client.getException();
        if (srvException != null || cliException != null) {
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

    @Test
    public void testX509ExtendedTrustManagerExternal()
        throws CertificateException, IOException, Exception {

        System.out.print("\tX509ExtendedTrustManager ext");

        /* Basic SSLSocket success case, SNI matches server cert CN */
        testX509ExtendedTrustManagerSSLSocketBasicExtSuccess();

        /* Basic SSLSocket fail case, custom X509ExtendedTrustManager that
         * verifies no certificates */
        testX509ExtendedTrustManagerSSLSocketBasicExtFail();

        /* Basic SSLSocket success case, SNI matches server cert CN,
         * do not call startHandshake(), should still succeed. Custom
         * X509ExtendedTrustManager used that verifies all certs. */
        testX509ExtendedTrustManagerSSLSocketExtNoStartHandshakeSuccess();
        testX509ExtendedTrustManagerSSLSocketExtNoClientStartHandshakeSuccess();
        testX509ExtendedTrustManagerSSLSocketExtNoServerStartHandshakeSuccess();

        pass("\t... passed");
    }

    /* TrustManager that trusts all certificates */
    TrustManager[] trustAllCerts = {
        new X509ExtendedTrustManager() {
            public X509Certificate[] getAcceptedIssuers() {
                return null;
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

    /* TrustManager that trusts no certificates */
    TrustManager[] trustNoCerts = {
        new X509ExtendedTrustManager() {
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }
            public void checkClientTrusted(X509Certificate[] chain,
                String authType) throws CertificateException {
                throw new CertificateException("fail on purpose / bad cert");
            }
            public void checkClientTrusted(X509Certificate[] chain,
                String authType, Socket socket) throws CertificateException {
                throw new CertificateException("fail on purpose / bad cert");
            }
            public void checkClientTrusted(X509Certificate[] chain,
                String authType, SSLEngine engine) throws CertificateException {
                throw new CertificateException("fail on purpose / bad cert");
            }
            public void checkServerTrusted(X509Certificate[] chain,
                String authType) throws CertificateException {
                throw new CertificateException("fail on purpose / bad cert");
            }
            public void checkServerTrusted(X509Certificate[] chain,
                String authType, Socket socket) throws CertificateException {
                throw new CertificateException("fail on purpose / bad cert");
            }
            public void checkServerTrusted(X509Certificate[] chain,
                String authType, SSLEngine engine) throws CertificateException {
                throw new CertificateException("fail on purpose / bad cert");
            }
        }
    };

    private void testX509ExtendedTrustManagerSSLSocketBasicExtSuccess()
        throws CertificateException, IOException, Exception {

        SSLContext srvCtx = tf.createSSLContext("TLSv1.2", provider,
                trustAllCerts,
                tf.createKeyManager("SunX509", tf.serverJKS, provider));

        SSLContext cliCtx = tf.createSSLContext("TLSv1.2", provider,
                trustAllCerts,
                tf.createKeyManager("SunX509", tf.clientJKS, provider));

        /* create SSLServerSocket first to get ephemeral port */
        SSLServerSocket ss = (SSLServerSocket)srvCtx.getServerSocketFactory()
            .createServerSocket(0);

        TestArgs serverArgs = new TestArgs(null, null, true, true, true, null);
        TestSSLSocketServer server = new TestSSLSocketServer(
            srvCtx, ss, serverArgs, 1);
        server.start();

        TestArgs clientArgs = new TestArgs(
            "HTTPS", "www.wolfssl.com", false, false, true, null);
        TestSSLSocketClient client = new TestSSLSocketClient(
            cliCtx, ss.getLocalPort(), clientArgs);
        client.start();

        try {
            client.join(1000);
            server.join(1000);

        } catch (InterruptedException e) {
            System.out.println("interrupt happened");
            fail("ExtendedX509TrustManager ext test failed");
        }

        /* Fail if client or server encountered exception */
        Exception srvException = server.getException();
        Exception cliException = client.getException();
        if (srvException != null || cliException != null) {
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

    private void testX509ExtendedTrustManagerSSLSocketBasicExtFail()
        throws CertificateException, IOException, Exception {

        SSLContext srvCtx = tf.createSSLContext("TLSv1.2", provider,
                trustNoCerts,
                tf.createKeyManager("SunX509", tf.serverJKS, provider));

        SSLContext cliCtx = tf.createSSLContext("TLSv1.2", provider,
                trustNoCerts,
                tf.createKeyManager("SunX509", tf.clientJKS, provider));

        /* create SSLServerSocket first to get ephemeral port */
        SSLServerSocket ss = (SSLServerSocket)srvCtx.getServerSocketFactory()
            .createServerSocket(0);

        TestArgs serverArgs = new TestArgs(null, null, true, true, true, null);
        TestSSLSocketServer server = new TestSSLSocketServer(
            srvCtx, ss, serverArgs, 1);
        server.start();

        TestArgs clientArgs = new TestArgs(
            "HTTPS", "www.wolfssl.com", false, false, true, null);
        TestSSLSocketClient client = new TestSSLSocketClient(
            cliCtx, ss.getLocalPort(), clientArgs);
        client.start();

        try {
            client.join(1000);
            server.join(1000);

        } catch (InterruptedException e) {
            System.out.println("interrupt happened");
            fail("X509ExtendedTrustManager basic external test failed");
        }

        Exception srvException = server.getException();
        Exception cliException = client.getException();

        if (srvException == null) {
            throw new Exception("Expecting exception but did not get one");
        }
    }

    private void testX509ExtendedTrustManagerSSLSocketExtNoStartHandshakeSuccess()
        throws CertificateException, IOException, Exception {

        SSLContext srvCtx = tf.createSSLContext("TLSv1.2", provider,
                trustAllCerts,
                tf.createKeyManager("SunX509", tf.serverJKS, provider));

        SSLContext cliCtx = tf.createSSLContext("TLSv1.2", provider,
                trustAllCerts,
                tf.createKeyManager("SunX509", tf.clientJKS, provider));

        /* create SSLServerSocket first to get ephemeral port */
        SSLServerSocket ss = (SSLServerSocket)srvCtx.getServerSocketFactory()
            .createServerSocket(0);

        TestArgs serverArgs = new TestArgs(null, null, true, true, false, null);
        TestSSLSocketServer server = new TestSSLSocketServer(
            srvCtx, ss, serverArgs, 1);
        server.start();

        TestArgs clientArgs = new TestArgs(
            "HTTPS", "www.wolfssl.com", false, false, false, null);
        TestSSLSocketClient client = new TestSSLSocketClient(
            cliCtx, ss.getLocalPort(), clientArgs);
        client.start();

        try {
            client.join(1000);
            server.join(1000);

        } catch (InterruptedException e) {
            System.out.println("interrupt happened");
            fail("ExtendedX509TrustManager ext no startHandshake() " +
                 "test failed");
        }

        /* Fail if client or server encountered exception */
        Exception srvException = server.getException();
        Exception cliException = client.getException();
        if (srvException != null || cliException != null) {
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

    private void testX509ExtendedTrustManagerSSLSocketExtNoClientStartHandshakeSuccess()
        throws CertificateException, IOException, Exception {

        SSLContext srvCtx = tf.createSSLContext("TLSv1.2", provider,
                trustAllCerts,
                tf.createKeyManager("SunX509", tf.serverJKS, provider));

        SSLContext cliCtx = tf.createSSLContext("TLSv1.2", provider,
                trustAllCerts,
                tf.createKeyManager("SunX509", tf.clientJKS, provider));

        /* create SSLServerSocket first to get ephemeral port */
        SSLServerSocket ss = (SSLServerSocket)srvCtx.getServerSocketFactory()
            .createServerSocket(0);

        TestArgs serverArgs = new TestArgs(null, null, true, true, true, null);
        TestSSLSocketServer server = new TestSSLSocketServer(
            srvCtx, ss, serverArgs, 1);
        server.start();

        TestArgs clientArgs = new TestArgs(
            "HTTPS", "www.wolfssl.com", false, false, false, null);
        TestSSLSocketClient client = new TestSSLSocketClient(
            cliCtx, ss.getLocalPort(), clientArgs);
        client.start();

        try {
            client.join(1000);
            server.join(1000);

        } catch (InterruptedException e) {
            System.out.println("interrupt happened");
            fail("ExtendedX509TrustManager ext no client startHandshake() " +
                 "test failed");
        }

        /* Fail if client or server encountered exception */
        Exception srvException = server.getException();
        Exception cliException = client.getException();
        if (srvException != null || cliException != null) {
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

    private void testX509ExtendedTrustManagerSSLSocketExtNoServerStartHandshakeSuccess()
        throws CertificateException, IOException, Exception {

        SSLContext srvCtx = tf.createSSLContext("TLSv1.2", provider,
                trustAllCerts,
                tf.createKeyManager("SunX509", tf.serverJKS, provider));

        SSLContext cliCtx = tf.createSSLContext("TLSv1.2", provider,
                trustAllCerts,
                tf.createKeyManager("SunX509", tf.clientJKS, provider));

        /* create SSLServerSocket first to get ephemeral port */
        SSLServerSocket ss = (SSLServerSocket)srvCtx.getServerSocketFactory()
            .createServerSocket(0);

        TestArgs serverArgs = new TestArgs(null, null, true, true, false, null);
        TestSSLSocketServer server = new TestSSLSocketServer(
            srvCtx, ss, serverArgs, 1);
        server.start();

        TestArgs clientArgs = new TestArgs(
            "HTTPS", "www.wolfssl.com", false, false, true, null);
        TestSSLSocketClient client = new TestSSLSocketClient(
            cliCtx, ss.getLocalPort(), clientArgs);
        client.start();

        try {
            client.join(1000);
            server.join(1000);

        } catch (InterruptedException e) {
            System.out.println("interrupt happened");
            fail("ExtendedX509TrustManager ext no server startHandshake() " +
                 "test failed");
        }

        /* Fail if client or server encountered exception */
        Exception srvException = server.getException();
        Exception cliException = client.getException();
        if (srvException != null || cliException != null) {
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

    private void pass(String msg) {
        WolfSSLTestFactory.pass(msg);
    }

    private void error(String msg) {
        WolfSSLTestFactory.fail(msg);
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

        public void setExpectedPeerCert(X509Certificate cert) {
            this.expectedPeerCert = cert;
        }

        public boolean getWantClientAuth() {
            return this.wantClientAuth;
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

        public X509Certificate getExpectedPeerCert() {
            return this.expectedPeerCert;
        }
    }

    protected class TestSSLSocketServer extends Thread
    {
        private SSLContext ctx;
        private int port;
        private int numConnections;
        private Exception exception = null;
        private TestArgs args = null;
        SSLServerSocket ss = null;

        public TestSSLSocketServer(SSLContext ctx, SSLServerSocket ss,
            TestArgs args, int numConnections) {

            this.ctx = ctx;
            this.ss = ss;
            this.args = args;
            this.numConnections = numConnections;
        }

        @Override
        public void run() {

            try {
                for (int i = 0; i < numConnections; i++) {
                    SSLSocket sock = (SSLSocket)ss.accept();
                    sock.setUseClientMode(false);

                    /* Not enabling endpoint identification algo here since
                     * cert does not match client hostname */
                    SSLParameters params = sock.getSSLParameters();

                    /* Enable client auth */
                    params.setWantClientAuth(this.args.getWantClientAuth());
                    params.setNeedClientAuth(this.args.getNeedClientAuth());
                    sock.setSSLParameters(params);

                    if (this.args.getCallStartHandshake()) {
                        sock.startHandshake();
                    }

                    int in = sock.getInputStream().read();
                    assertEquals(in, (int)'A');
                    sock.getOutputStream().write('B');
                    sock.close();
                }

            } catch (Exception e) {
                this.exception = e;
            }
        }

        public Exception getException() {
            return this.exception;
        }
    }

    protected class TestSSLSocketClient extends Thread
    {
        private SSLContext ctx;
        private int srvPort;
        private Exception exception = null;
        private TestArgs args = null;

        public TestSSLSocketClient(SSLContext ctx, int port, TestArgs args) {

            this.ctx = ctx;
            this.srvPort = port;
            this.args = args;
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
                params.setEndpointIdentificationAlgorithm(
                    this.args.getEndpointIdentificationAlg());

                /* Set SNI, used for hostname verification of server cert */
                SNIHostName sniName = new SNIHostName(
                    this.args.getSNIName());
                List<SNIServerName> sniNames = new ArrayList<>(1);
                sniNames.add(sniName);
                params.setServerNames(sniNames);

                sock.setSSLParameters(params);

                if (this.args.getCallStartHandshake()) {
                    sock.startHandshake();
                }

                sock.getOutputStream().write('A');
                int in = sock.getInputStream().read();
                assertEquals(in, (int)'B');

                X509Certificate expectedPeerCert =
                    this.args.getExpectedPeerCert();
                if (expectedPeerCert != null) {
                    SSLSession sess = sock.getSession();
                    if (sess == null) {
                        sock.close();
                        throw new Exception(
                            "SSLSocket.getSession() returned null");
                    }
                    Certificate[] certs = sess.getPeerCertificates();
                    if (certs == null || certs.length == 0) {
                        sock.close();
                        throw new Exception(
                            "SSLSession.getPeerCertificates() was null " +
                            "or empty");
                    }

                    if (!(certs[0] instanceof X509Certificate)) {
                        sock.close();
                        throw new Exception(
                            "Peer cert from SSLSession not of type " +
                            "X509Certificate");
                    }
                    X509Certificate peerCert = (X509Certificate)certs[0];
                    if (!peerCert.equals(expectedPeerCert)) {
                        sock.close();
                        throw new Exception(
                            "Peer cert from SSLSession did not match " +
                            "expected\nExpected:" + expectedPeerCert +
                            "\nGot:" + peerCert);
                    }
               }

                sock.close();

            } catch (Exception e) {
                this.exception = e;
            }
        }

        public Exception getException() {
            return this.exception;
        }
    }
}
