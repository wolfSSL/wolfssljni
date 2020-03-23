/* WolfSSLTrustX509Test.java
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

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLException;
import com.wolfssl.provider.jsse.WolfSSLProvider;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
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

    @Test
    public void testCAParsing()
        throws NoSuchProviderException, NoSuchAlgorithmException {
        TrustManager[] tm;
        X509TrustManager x509tm;
        X509Certificate cas[];
        int i = 0;
        int expected = 9;
        String OU[] = { "OU=Programming-2048", "OU=Programming-1024",
            "OU=Support", "OU=Support_1024", "OU=Fast", "OU=Consulting",
            "OU=ECC", "OU=Consulting_1024" };

        System.out.print("\tTesting parse all.jks");

        if (tf.isAndroid()) {
            /* @TODO finding that BKS has different order of certs */
            pass("\t... skipped");
            return;
        }

        /* wolfSSL only returns a list of CA's, server-ecc basic constraint is set
         * to false so it is not added as a CA */
        if (this.provider != null && this.provider.equals("wolfJSSE")) {
            expected = 8; /* one less than SunJSSE because of server-ecc */
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
    public void testServerParsing()
        throws NoSuchProviderException, NoSuchAlgorithmException {
        TrustManager[] tm;
        X509TrustManager x509tm;
        X509Certificate cas[];
        int i = 0;
        int expected = 6;
        String OU[] = { "OU=Support", "OU=Support_1024", "OU=Fast",
            "OU=Programming-2048", "OU=Programming-1024" };

        System.out.print("\tTesting parsing server.jks");

        if (tf.isAndroid()) {
            /* @TODO finding that BKS has different order of certs */
            pass("\t... skipped");
            return;
        }

        /* wolfSSL only returns a list of CA's, server-ecc basic constraint is set
         * to false so it is not added as a CA */
        if (this.provider != null && this.provider.equals("wolfJSSE")) {
            expected = expected-1; /* one less than SunJSSE because of server-ecc */
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

            if (!cas[i].getSubjectDN().getName().contains(x)) {
                error("\t... failed");
                fail("wrong CA found");
            }
            i++;

        }
        pass("\t... passed");
    }


    @Test
    public void testCAParsingMixed()
        throws NoSuchProviderException, NoSuchAlgorithmException {
        TrustManager[] tm;
        X509TrustManager x509tm;
        X509Certificate cas[];
        int i = 0, j;
        int expected = 8;
        String OU[] = { "OU=Fast", "OU=Consulting", "OU=Programming-1024",
            "OU=Programming-2048", "OU=ECC", "OU=Support", "OU=Support_1024",
            "OU=Consulting_1024" };

        System.out.print("\tTesting parse all_mixed.jks");

        if (tf.isAndroid()) {
            /* @TODO finding that BKS has different order of certs */
            pass("\t... skipped");
            return;
        }
        /* wolfSSL only returns a list of CA's, server-ecc basic constraint is set
         * to false so it is not added as a CA */
        if (this.provider != null && this.provider.equals("wolfJSSE")) {
            expected = 7; /* one less than SunJSSE because of server-ecc */
        }

        tm = tf.createTrustManager("SunX509", tf.mixedJKS, provider);
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
        throws NoSuchProviderException, NoSuchAlgorithmException, KeyStoreException,
            FileNotFoundException, IOException, CertificateException {
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
    
    
    private void pass(String msg) {
        WolfSSLTestFactory.pass(msg);
    }
    
    private void error(String msg) {
        WolfSSLTestFactory.fail(msg);
    }
}
