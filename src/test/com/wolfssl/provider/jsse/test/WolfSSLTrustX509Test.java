/* WolfSSLTrustX509Test.java
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLException;
import com.wolfssl.provider.jsse.WolfSSLProvider;
import com.wolfssl.provider.jsse.WolfSSLTrustX509;

import java.util.List;
import java.io.File;
import java.io.FileInputStream;
import java.io.BufferedInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
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
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
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
        throws NoSuchProviderException, NoSuchAlgorithmException {
        TrustManager[] tm;
        X509TrustManager x509tm;
        X509Certificate cas[];

        String OU[] = { "OU=Programming-2048", "OU=Support",
            "OU=Support_1024", "OU=Consulting", "OU=Development",
            "OU=Fast", "OU=Consulting_1024", "OU=Programming-1024", "OU=ECC" };

        int i = 0;
        int expected = OU.length;

        System.out.print("\tTesting parse all.jks");

        if (tf.isAndroid()) {
            /* @TODO finding that BKS has different order of certs */
            pass("\t... skipped");
            return;
        }

        /* wolfSSL only returns a list of CA's, server-ecc basic constraint is
         * set to false so it is not added as a CA */
        if (this.provider != null && this.provider.equals("wolfJSSE")) {
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
            fail("wrong number of CAs found");
        }

        for (String x: OU) {
            if (this.provider != null &&
                    provider.equals("wolfJSSE") && x.equals("OU=ECC")) {
                /* skip checking ECC certs, since not all Java versions
                 * support them */
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

    /* Testing WolfSSLTrustX509.getAcceptedIssuers() with server.jks */
    @Test
    public void testServerParsing()
        throws NoSuchProviderException, NoSuchAlgorithmException {
        TrustManager[] tm;
        X509TrustManager x509tm;
        X509Certificate cas[];

        String OU[] = { "OU=Support", "OU=ECC" };

        int i = 0;
        int expected = OU.length;

        System.out.print("\tTesting parsing server.jks");

        if (tf.isAndroid()) {
            /* @TODO finding that BKS has different order of certs */
            pass("\t... skipped");
            return;
        }

        /* wolfSSL only returns a list of CA's, server-ecc basic constraint is
         * set to false so it is not added as a CA */
        if (this.provider != null && this.provider.equals("wolfJSSE")) {
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
            fail("wrong number of CAs found");
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
        throws NoSuchProviderException, NoSuchAlgorithmException {
        TrustManager[] tm;
        X509TrustManager x509tm;
        X509Certificate cas[];

        String OU[] = { "OU=Consulting", "OU=Programming-2048", "OU=Fast",
            "OU=Support", "OU=Programming-1024", "OU=Consulting_1024",
            "OU=Support_1024", "OU=ECC" };

        int i = 0, j;
        int expected = OU.length;

        System.out.print("\tTesting parse all_mixed.jks");

        if (tf.isAndroid()) {
            /* @TODO finding that BKS has different order of certs */
            pass("\t... skipped");
            return;
        }
        /* wolfSSL only returns a list of CA's, server-ecc basic constraint is
         * set to false so it is not added as a CA */
        if (this.provider != null && this.provider.equals("wolfJSSE")) {
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
            fail("wrong number of CAs found");
        }

        for (j = 0; j < OU.length && i < cas.length; j++) {
            if (this.provider != null &&
                    provider.equals("wolfJSSE") && OU[j].equals("OU=ECC")) {
                /* skip checking ECC certs, since not all Java versions
                 * support them */
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
    public void testSystemLoad() {
        String file = System.getProperty("javax.net.ssl.trustStore");
        TrustManager[] tm;

        System.out.print("\tTesting loading default certs");

        if (file == null) {
            String home = System.getenv("JAVA_HOME");
            if (home != null) {
                File f = new File(home.concat("lib/security/jssecacerts"));
                if (f.exists()) {
                    tm = tf.createTrustManager("SunX509", null, provider);
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
                        tm = tf.createTrustManager("SunX509", null, provider);
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
            tm = tf.createTrustManager("SunX509", null, provider);
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
            CertificateException {
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

        if (tf.isAndroid()) {
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

        if (tf.isAndroid()) {
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

        if (tf.isAndroid()) {
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

        if (tf.isAndroid()) {
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

        if (tf.isAndroid()) {
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

        if (tf.isAndroid()) {
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

    private void pass(String msg) {
        WolfSSLTestFactory.pass(msg);
    }

    private void error(String msg) {
        WolfSSLTestFactory.fail(msg);
    }
}
