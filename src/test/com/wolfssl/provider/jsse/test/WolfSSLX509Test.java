/* WolfSSLX509Test.java
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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Set;
import java.util.List;
import java.util.ArrayList;
import java.util.Collection;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLPeerUnverifiedException;

import org.junit.BeforeClass;
import org.junit.Test;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLException;
import com.wolfssl.provider.jsse.WolfSSLProvider;
import com.wolfssl.provider.jsse.WolfSSLX509;
import com.wolfssl.provider.jsse.WolfSSLX509X;

public class WolfSSLX509Test {
    private static WolfSSLTestFactory tf;
    private String provider = "wolfJSSE";
    private javax.security.cert.X509Certificate[] certs;

    @BeforeClass
    public static void testProviderInstallationAtRuntime()
        throws NoSuchProviderException {

        System.out.println("WolfSSLX509 Class");

                /* install wolfJSSE provider at runtime */
        Security.insertProviderAt(new WolfSSLProvider(), 1);


        Provider p = Security.getProvider("wolfJSSE");
        assertNotNull(p);

        try {
            tf = new WolfSSLTestFactory();
        } catch (WolfSSLException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }


    @Test
    public void testServerParsing() {
        System.out.print("\tTesting server cert");
        try {
            X509Certificate x509, ca;
            byte[] der;
            der = tf.getCert("server");
            x509 = new WolfSSLX509(der);
            try {
                x509.checkValidity();
            } catch (CertificateExpiredException |
                    CertificateNotYetValidException e) {
                error("\t\t... failed");
                fail("certificae not valid");
            }

            if (x509.getBasicConstraints() <=0) {
                error("\t\t... failed");
                fail("certificae does not have basic constraint set to true");
            }

            der = tf.getCert("ca");
            ca = new WolfSSLX509(der);
            try {
                WolfSSLX509X x509x = new WolfSSLX509X(x509.getEncoded());
                PublicKey pkey = ca.getPublicKey();
                x509.verify(pkey);
                x509x.verify(pkey);
            } catch (InvalidKeyException | NoSuchProviderException |
                    SignatureException | javax.security.cert.CertificateException e) {
                error("\t\t... failed");
                fail("certificae not valid");
            }
        } catch (KeyStoreException | WolfSSLException | NoSuchAlgorithmException |
                CertificateException | IOException e) {
            error("\t\t... failed");
            fail("general parsing failure");
        }
        pass("\t\t... passed");
    }


    @Test
    public void testExtensions() {

        X509Certificate x509;
        javax.security.cert.X509Certificate x509X;
        int i;
        Set<String> oids;
        String [] o;

        /* check key usage */
        boolean[] keyUsage;
        boolean[] expected = {true,false,false,false,false,true,true,false,false};
        String[] expectCrit = {"2.5.29.15" , "2.5.29.19"};
        String[] expectNonCrit = {"2.5.29.14"};

        System.out.print("\tTesting x509 ext");

        /* skip if wolfSSL compiled with NO_FILESYSTEM */
        if (WolfSSL.FileSystemEnabled() == false) {
            pass("\t\t... skipped");
            return;
        }

        try {
            x509 = new WolfSSLX509(tf.googleCACert);

            keyUsage = x509.getKeyUsage();
            if (keyUsage.length != expected.length) {
                error("\t... failed");
                fail("unexpected key usage found");
            }

            for (i = 0; i < expected.length; i++) {
                if (keyUsage[i] != expected[i])  {
                    error("\t... failed");
                    fail("unexpected key usage found");
                }
            }

            oids = x509.getCriticalExtensionOIDs();
            o = oids.toArray(new String[oids.size()]);
            if (o.length != expectCrit.length) {
                error("\t... failed");
                fail("unexpected crit extension length");
            }
            for (i = 0; i < o.length; i++) {
                if (!o[i].equals(expectCrit[i])) {
                    error("\t... failed");
                    fail("unexpected crit extension found");
                }
            }

            oids = x509.getNonCriticalExtensionOIDs();
            o = oids.toArray(new String[oids.size()]);
            if (o.length != expectNonCrit.length) {
                error("\t... failed");
                fail("unexpected non crit extension length");
            }
            for (i = 0; i < o.length; i++) {
                if (!o[i].equals(expectNonCrit[i])) {
                    error("\t... failed");
                    fail("unexpected non crit extension found");
                }
            }

            if (x509.hasUnsupportedCriticalExtension()) {
                error("\t... failed");
                fail("unexpected crit extension found");
            }

            /* @TODO testing for correctness of return value */
            if (x509.getExtensionValue("2.5.29.19") == null) {
                error("\t... failed");
                fail("failed to find basic constraint extension");
            }

             if (!x509.getSigAlgOID().equals("1.2.840.113549.1.1.12")) {
                 error("\t... failed");
                 fail("unexpected sig alg OID found");
             }

             x509X = new WolfSSLX509X(x509.getEncoded());
             if (!x509X.getSigAlgOID().equals("1.2.840.113549.1.1.12")) {
                 error("\t... failed");
                 fail("unexpected sig alg OID found");
             }
        } catch (Exception ex) {
            error("\t... failed");
            fail("unexpected exception found");
        }
        pass("\t\t... passed");
    }

    @Test
    public void testX509XValidity() {
        WolfSSLX509X x509;

        System.out.print("\tTesting X509X validity");

        /* skip if wolfSSL compiled with NO_FILESYSTEM */
        if (WolfSSL.FileSystemEnabled() == false) {
            pass("\t\t... skipped");
            return;
        }

        try {
            x509 = new WolfSSLX509X(tf.googleCACert);
            x509.checkValidity();
            x509.checkValidity(new Date());
        } catch (WolfSSLException | javax.security.cert.CertificateExpiredException |
                javax.security.cert.CertificateNotYetValidException e) {
            error("\t\t... failed");
            fail("failed date validity test");
        }
        pass("\t\t... passed");
   }

    @Test
    public void testTBS() {
        byte[] tbs;
        int i;
        WolfSSLX509 x509;

        System.out.print("\tTesting TBS");

        /* skip if wolfSSL compiled with NO_FILESYSTEM */
        if (WolfSSL.FileSystemEnabled() == false) {
            pass("\t\t\t... skipped");
            return;
        }

        try {
            x509 = new WolfSSLX509(tf.googleCACert);
            tbs = x509.getTBSCertificate();
            if (tbs == null) {
                error("\t\t\t... failed");
                fail("failed to get TBS cert");
                return;
            }

            if (tbs.length != expectedTbs.length) {
                error("\t\t\t... failed");
                fail("unexpected tbs length");
            }

            for (i = 0; i < tbs.length; i++) {
                if (tbs[i] != expectedTbs[i]) {
                    error("\t\t\t... failed");
                    fail("unexpected TBS cert");
                }
            }

        } catch (CertificateEncodingException | WolfSSLException e) {
            error("\t\t\t... failed");
            fail("unexpected TBS cert");
        }

        pass("\t\t\t... passed");
    }

    @Test
    public void testPublicKey() {
        KeyStore store;
        InputStream stream;
        WolfSSLX509 ca;
        WolfSSLX509X cax;
        PublicKey pkey;
        byte[] key;

        System.out.print("\tTesting public key");
        try {
            store = KeyStore.getInstance(tf.keyStoreType);
            stream = new FileInputStream(tf.allJKS);

            store.load(stream, tf.jksPass);
            stream.close();
            ca = new WolfSSLX509(store.getCertificate("ca").getEncoded());
            cax = new WolfSSLX509X(ca.getEncoded());
            pkey = cax.getPublicKey();
            if (pkey == null) {
                error("\t\t... failed");
                fail("failed to get public key");
            }

            pkey = ca.getPublicKey();

            if (!pkey.getFormat().equals("X.509")) {
                error("\t\t... failed");
                fail("unexpected public key format");
            }

            if (!pkey.getAlgorithm().equals("RSA")) {
                error("\t\t... failed");
                fail("unexpected public key algorithm found");
            }

            key = pkey.getEncoded();
            for (int i = 0; i < key.length; i++) {
                if (key[i] != expectedPkey[i]) {
                    error("\t\t... failed");
                    fail("unexpected public key found");
                }
            }
        } catch (KeyStoreException | WolfSSLException |
                NoSuchAlgorithmException | CertificateException |
                IOException e) {
            error("\t\t... failed");
            fail("failed");
        }

        pass("\t\t... passed");
    }

    @Test
    public void testVerifyProvider() {
        KeyStore store;
        InputStream stream;
        WolfSSLX509 server, ca;
        WolfSSLX509X serverx;
        Provider[] p;
        Provider sigProvider = null;

        System.out.print("\tTesting verify");
        try {
            /* check if signature providers available */
            p = Security.getProviders();
            for (Provider x : p) {
                if (x.getService("Signature","SHA256withRSA") != null) {
                    sigProvider = x;
                    break;
                }
            }
            if (sigProvider == null || tf.isAndroid()) {
                pass("\t\t\t... skipped");
                return;
            }
            System.out.print("\n\t  Signature provider " + sigProvider.getName());

            store = KeyStore.getInstance(tf.keyStoreType);
            stream = new FileInputStream(tf.allJKS);
            store.load(stream, tf.jksPass);
            stream.close();
            server = new WolfSSLX509(store.getCertificate("server").getEncoded());
            ca = new WolfSSLX509(store.getCertificate("ca").getEncoded());

            try {
                serverx = new WolfSSLX509X(server.getEncoded());
                server.verify(ca.getPublicKey(), sigProvider);
                serverx.verify(ca.getPublicKey(), sigProvider.getName());
            } catch (InvalidKeyException | SignatureException |
                    NoSuchProviderException | javax.security.cert.CertificateException e) {
                error("\t... failed");
                fail("failed to verify certificate");
            }

            try {
                server.verify(ca.getPublicKey(), sigProvider.getName());
            } catch (InvalidKeyException | SignatureException |
                    NoSuchProviderException e) {
                error("\t... failed");
                fail("failed to verify certificate");
            }

            try {
                server.verify(server.getPublicKey(), sigProvider);
                error("\t... failed");
                fail("able to verify when should not have been");
            } catch (InvalidKeyException | SignatureException e) {
                /* expected fail case */
            }

        } catch (KeyStoreException | NoSuchAlgorithmException |
                CertificateException | IOException | WolfSSLException e) {
            error("\t... failed");
            fail("general failure");
        }
        pass("\t... passed");
    }


    @Test
    public void testGetters() {
        SSLEngine server;
        SSLEngine client;
        String    cipher = null;
        int ret, i;
        String[] ciphers;
        String   certType;
        SSLContext ctxClient;
        SSLContext ctxServer;
        System.out.print("\tTesting x509 getters");

        ctxClient = tf.createSSLContext("TLS", provider,
                    tf.createTrustManager("SunX509", tf.caServerJKS, provider),
                    tf.createKeyManager("SunX509", tf.clientRSAJKS, provider));
        ctxServer = tf.createSSLContext("TLS", provider,
                    tf.createTrustManager("SunX509", tf.caClientJKS, provider),
                    tf.createKeyManager("SunX509", tf.serverRSAJKS, provider));

        server = ctxServer.createSSLEngine();
        client = ctxClient.createSSLEngine("wolfSSL client test", 11111);

        /* make connection using RSA certificate */
        server.setUseClientMode(false);
        server.setNeedClientAuth(false);
        client.setUseClientMode(true);
        ret = tf.testConnection(server, client, null, null,
                "Test cipher suite");
        if (ret != 0) {
            error("\t\t... failed");
            fail("failed to create engine");
        }

        try {
            java.security.cert.X509Certificate x509 = null;
            javax.security.cert.X509Certificate peer = null;
            java.security.cert.Certificate local[];

            /* getPeerCertificateChain() returns array of javax.security.cert.X509Certificate */
            certs = client.getSession().getPeerCertificateChain();
            if (certs == null) {
                error("\t\t... failed");
                fail("failed to get peer certificate chain");
            }
            /* @TODO certs.length != 2 test */
            peer = certs[0];


            /* getLocalCertificates() returns array of java.security.cert.Certificate */
            local = (X509Certificate[]) server.getSession().getLocalCertificates();
            if (local == null) {
                error("\t\t... failed");
                fail("failed to get local certificate");
                return;
            }
            /* @TODO local.length != 2 test */

            /* check that getLocalCertificates() returned type X509Certificate */
            if (local[0].getType().equals("X.509")) {
                x509 = (X509Certificate)local[0];
            } else {
                error("\t\t... failed");
                fail("getLocalCertificates() did not return X509Certificate type");
            }

            if (x509.getVersion() != 3 || peer.getVersion() != 2) {
                error("\t\t... failed");
                fail("unexpected x509 version");
            }

            if (!x509.getSigAlgName().equals(peer.getSigAlgName())) {
                error("\t\t... failed");
                fail("failed to match sig alg name");
            }

            /* check serial numbers */
           if (x509.getSerialNumber().intValue() !=
                   peer.getSerialNumber().intValue()) {
               error("\t\t... failed");
               fail("failed to match serial number");
           }


           if (!x509.getNotBefore().before(new Date()) ||
                   !peer.getNotBefore().before(new Date())) {
               error("\t\t... failed");
               fail("failed date not before");
           }

           if (!x509.getNotAfter().after(new Date()) ||
                   !peer.getNotAfter().after(new Date())) {
               error("\t\t... failed");
               fail("failed date not after");
           }

           /* Android KeyStore formats x509 getName() differently than peer getName() */
           if (!tf.isAndroid()) {
               if (!x509.getSubjectDN().getName().equals(
                       peer.getSubjectDN().getName())) {
                   error("\t\t... failed");
                   fail("subject DN does not match");
               }

               if (!x509.getIssuerDN().getName().equals(
                       peer.getIssuerDN().getName())) {
                   error("\t\t... failed");
                   fail("issuer DN does not match");
               }
           }

           if (peer.toString() == null || x509.toString() == null) {
               error("\t\t... failed");
               fail("failed to get cert string");
           }

           /* check encoding can be parsed (throws exception if not).
            * Use WolfSSLX509 for tests below to ensure we are using our
            * implementation of X509Certificate. */
           WolfSSLX509 tmp;
           tmp = new WolfSSLX509(peer.getEncoded());
           tmp = new WolfSSLX509(x509.getEncoded());

           /* test getter for signature, correctness of return is tested in
            * WolfSSLCertificateTest */
           if (x509.getSignature() == null) {
               error("\t\t... failed");
               fail("failed to get cert signature");
           }

           try {
               tmp.getIssuerUniqueID();
               error("\t\t... failed: A test case for getIssuerUniqueID is needed");
               fail("getIssuerUniqueID implemented without test case");
           } catch (Exception ex) {
               /* @TODO not supported */
           }

           try {
               tmp.getSubjectUniqueID();
               error("\t\t... failed: A test case for getSubjectUniqueID is needed");
               fail("getSubjectUniqueID implemented without test case");
           } catch (Exception ex) {
               /* @TODO not supported */
           }

           try {
               tmp.getSigAlgParams();
               error("\t\t... failed: A test case for getSigAlgParams is needed");
               fail("getSigAlgParams implemented without test case");
           } catch (Exception ex) {
               /* @TODO not supported */
           }

           try {
               peer.getSigAlgParams();
               error("\t\t... failed: A test case for getSigAlgParams is needed");
               fail("getSigAlgParams implemented without test case");
           } catch (Exception ex) {
               /* @TODO not supported */
           }

           try {
               peer.getSigAlgParams();
               error("\t\t... failed: A test case for getSigAlgParams is needed");
               fail("getSigAlgParams implemented without test case");
           } catch (Exception ex) {
               /* @TODO not supported */
           }

        } catch (SSLPeerUnverifiedException | WolfSSLException |
                CertificateEncodingException |
                javax.security.cert.CertificateEncodingException e) {
            error("\t\t... failed");
            fail("failed to get peer certificate chain");
        }

        pass("\t\t... passed");
    }

    @Test
    public void testSubjectAlternativeNames() {

        X509Certificate x509;
        int ALT_DNS_NAME = 2; /* dNSName type */

        System.out.print("\tTesting getting alt names");

        /* skip if wolfSSL compiled with NO_FILESYSTEM */
        if (WolfSSL.FileSystemEnabled() == false) {
            pass("\t... skipped");
            return;
        }

        /* populate known alt name list for example.com cert, for comparison */
        List<String> expected = new ArrayList<>();
        expected.add("www.example.org");
        expected.add("example.com");
        expected.add("example.edu");
        expected.add("example.net");
        expected.add("example.org");
        expected.add("www.example.com");
        expected.add("www.example.edu");
        expected.add("www.example.net");

        /* list to hold found altNames */
        List<String> found = new ArrayList<>();

        try {
            x509 = new WolfSSLX509(tf.exampleComCert);

            Collection<?> subjectAltNames = x509.getSubjectAlternativeNames();
            if (subjectAltNames == null) {
                error("\t... failed");
                fail("subjectAltNames Collection was null");
            }

            for (Object subjectAltName : subjectAltNames) {
                List<?> entry = (List<?>)subjectAltName;
                if (entry == null || entry.size() < 2) {
                    error("\t... failed");
                    fail("subjectAltName List<?> null or length < 2");
                }
                Integer altNameType = (Integer)entry.get(0);
                if (altNameType == null) {
                    error("\t... failed");
                    fail("subjectAltName List[0] was null, should be Integer");
                }
                if (altNameType != ALT_DNS_NAME) {
                    error("\t... failed");
                    fail("subjectAltName type is not ALT_DNS_NAME (2)");
                }
                String altName = (String)entry.get(1);
                if (altName == null) {
                    error("\t... failed");
                    fail("Individual altName was null, should not be");
                }
                found.add(altName);
            }

            if (found.size() != expected.size()) {
                error("\r... failed");
                fail("altName list size differs from expected size");
            }

            for (int i = 0; i < found.size(); i++) {
                if (!found.get(i).equals(expected.get(i))) {
                    error("\r... failed");
                    fail("altName entry does not match expected: found: " +
                         found.get(i) + ", expected: " + expected.get(i));
                }
            }

        } catch (Exception ex) {
            error("\t... failed");
            fail("unexpected exception found");
        }
        pass("\t... passed");
    }

    private void pass(String msg) {
        WolfSSLTestFactory.pass(msg);
    }

    private void error(String msg) {
        WolfSSLTestFactory.fail(msg);
    }

    private byte[] expectedTbs = {
        (byte)0x30, (byte)0x82, (byte)0x03, (byte)0x3f,
        (byte)0xa0, (byte)0x03, (byte)0x02, (byte)0x01,
        (byte)0x02, (byte)0x02, (byte)0x0d, (byte)0x02,
        (byte)0x03, (byte)0xe5, (byte)0xae, (byte)0xc5,
        (byte)0x8d, (byte)0x04, (byte)0x25, (byte)0x1a,
        (byte)0xab, (byte)0x11, (byte)0x25, (byte)0xaa,
        (byte)0x30, (byte)0x0d, (byte)0x06, (byte)0x09,
        (byte)0x2a, (byte)0x86, (byte)0x48, (byte)0x86,
        (byte)0xf7, (byte)0x0d, (byte)0x01, (byte)0x01,
        (byte)0x0c, (byte)0x05, (byte)0x00, (byte)0x30,
        (byte)0x47, (byte)0x31, (byte)0x0b, (byte)0x30,
        (byte)0x09, (byte)0x06, (byte)0x03, (byte)0x55,
        (byte)0x04, (byte)0x06, (byte)0x13, (byte)0x02,
        (byte)0x55, (byte)0x53, (byte)0x31, (byte)0x22,
        (byte)0x30, (byte)0x20, (byte)0x06, (byte)0x03,
        (byte)0x55, (byte)0x04, (byte)0x0a, (byte)0x13,
        (byte)0x19, (byte)0x47, (byte)0x6f, (byte)0x6f,
        (byte)0x67, (byte)0x6c, (byte)0x65, (byte)0x20,
        (byte)0x54, (byte)0x72, (byte)0x75, (byte)0x73,
        (byte)0x74, (byte)0x20, (byte)0x53, (byte)0x65,
        (byte)0x72, (byte)0x76, (byte)0x69, (byte)0x63,
        (byte)0x65, (byte)0x73, (byte)0x20, (byte)0x4c,
        (byte)0x4c, (byte)0x43, (byte)0x31, (byte)0x14,
        (byte)0x30, (byte)0x12, (byte)0x06, (byte)0x03,
        (byte)0x55, (byte)0x04, (byte)0x03, (byte)0x13,
        (byte)0x0b, (byte)0x47, (byte)0x54, (byte)0x53,
        (byte)0x20, (byte)0x52, (byte)0x6f, (byte)0x6f,
        (byte)0x74, (byte)0x20, (byte)0x52, (byte)0x32,
        (byte)0x30, (byte)0x1e, (byte)0x17, (byte)0x0d,
        (byte)0x31, (byte)0x36, (byte)0x30, (byte)0x36,
        (byte)0x32, (byte)0x32, (byte)0x30, (byte)0x30,
        (byte)0x30, (byte)0x30, (byte)0x30, (byte)0x30,
        (byte)0x5a, (byte)0x17, (byte)0x0d, (byte)0x33,
        (byte)0x36, (byte)0x30, (byte)0x36, (byte)0x32,
        (byte)0x32, (byte)0x30, (byte)0x30, (byte)0x30,
        (byte)0x30, (byte)0x30, (byte)0x30, (byte)0x5a,
        (byte)0x30, (byte)0x47, (byte)0x31, (byte)0x0b,
        (byte)0x30, (byte)0x09, (byte)0x06, (byte)0x03,
        (byte)0x55, (byte)0x04, (byte)0x06, (byte)0x13,
        (byte)0x02, (byte)0x55, (byte)0x53, (byte)0x31,
        (byte)0x22, (byte)0x30, (byte)0x20, (byte)0x06,
        (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x0a,
        (byte)0x13, (byte)0x19, (byte)0x47, (byte)0x6f,
        (byte)0x6f, (byte)0x67, (byte)0x6c, (byte)0x65,
        (byte)0x20, (byte)0x54, (byte)0x72, (byte)0x75,
        (byte)0x73, (byte)0x74, (byte)0x20, (byte)0x53,
        (byte)0x65, (byte)0x72, (byte)0x76, (byte)0x69,
        (byte)0x63, (byte)0x65, (byte)0x73, (byte)0x20,
        (byte)0x4c, (byte)0x4c, (byte)0x43, (byte)0x31,
        (byte)0x14, (byte)0x30, (byte)0x12, (byte)0x06,
        (byte)0x03, (byte)0x55, (byte)0x04, (byte)0x03,
        (byte)0x13, (byte)0x0b, (byte)0x47, (byte)0x54,
        (byte)0x53, (byte)0x20, (byte)0x52, (byte)0x6f,
        (byte)0x6f, (byte)0x74, (byte)0x20, (byte)0x52,
        (byte)0x32, (byte)0x30, (byte)0x82, (byte)0x02,
        (byte)0x22, (byte)0x30, (byte)0x0d, (byte)0x06,
        (byte)0x09, (byte)0x2a, (byte)0x86, (byte)0x48,
        (byte)0x86, (byte)0xf7, (byte)0x0d, (byte)0x01,
        (byte)0x01, (byte)0x01, (byte)0x05, (byte)0x00,
        (byte)0x03, (byte)0x82, (byte)0x02, (byte)0x0f,
        (byte)0x00, (byte)0x30, (byte)0x82, (byte)0x02,
        (byte)0x0a, (byte)0x02, (byte)0x82, (byte)0x02,
        (byte)0x01, (byte)0x00, (byte)0xce, (byte)0xde,
        (byte)0xfd, (byte)0xa6, (byte)0xfb, (byte)0xec,
        (byte)0xec, (byte)0x14, (byte)0x34, (byte)0x3c,
        (byte)0x07, (byte)0x06, (byte)0x5a, (byte)0x6c,
        (byte)0x59, (byte)0xf7, (byte)0x19, (byte)0x35,
        (byte)0xdd, (byte)0xf7, (byte)0xc1, (byte)0x9d,
        (byte)0x55, (byte)0xaa, (byte)0xd3, (byte)0xcd,
        (byte)0x3b, (byte)0xa4, (byte)0x93, (byte)0x72,
        (byte)0xef, (byte)0x0a, (byte)0xfa, (byte)0x6d,
        (byte)0x9d, (byte)0xf6, (byte)0xf0, (byte)0x85,
        (byte)0x80, (byte)0x5b, (byte)0xa1, (byte)0x48,
        (byte)0x52, (byte)0x9f, (byte)0x39, (byte)0xc5,
        (byte)0xb7, (byte)0xee, (byte)0x28, (byte)0xac,
        (byte)0xef, (byte)0xcb, (byte)0x76, (byte)0x68,
        (byte)0x14, (byte)0xb9, (byte)0xdf, (byte)0xad,
        (byte)0x01, (byte)0x6c, (byte)0x99, (byte)0x1f,
        (byte)0xc4, (byte)0x22, (byte)0x1d, (byte)0x9f,
        (byte)0xfe, (byte)0x72, (byte)0x77, (byte)0xe0,
        (byte)0x2c, (byte)0x5b, (byte)0xaf, (byte)0xe4,
        (byte)0x04, (byte)0xbf, (byte)0x4f, (byte)0x72,
        (byte)0xa0, (byte)0x1a, (byte)0x34, (byte)0x98,
        (byte)0xe8, (byte)0x39, (byte)0x68, (byte)0xec,
        (byte)0x95, (byte)0x25, (byte)0x7b, (byte)0x76,
        (byte)0xa1, (byte)0xe6, (byte)0x69, (byte)0xb9,
        (byte)0x85, (byte)0x19, (byte)0xbd, (byte)0x89,
        (byte)0x8c, (byte)0xfe, (byte)0xad, (byte)0xed,
        (byte)0x36, (byte)0xea, (byte)0x73, (byte)0xbc,
        (byte)0xff, (byte)0x83, (byte)0xe2, (byte)0xcb,
        (byte)0x7d, (byte)0xc1, (byte)0xd2, (byte)0xce,
        (byte)0x4a, (byte)0xb3, (byte)0x8d, (byte)0x05,
        (byte)0x9e, (byte)0x8b, (byte)0x49, (byte)0x93,
        (byte)0xdf, (byte)0xc1, (byte)0x5b, (byte)0xd0,
        (byte)0x6e, (byte)0x5e, (byte)0xf0, (byte)0x2e,
        (byte)0x30, (byte)0x2e, (byte)0x82, (byte)0xfc,
        (byte)0xfa, (byte)0xbc, (byte)0xb4, (byte)0x17,
        (byte)0x0a, (byte)0x48, (byte)0xe5, (byte)0x88,
        (byte)0x9b, (byte)0xc5, (byte)0x9b, (byte)0x6b,
        (byte)0xde, (byte)0xb0, (byte)0xca, (byte)0xb4,
        (byte)0x03, (byte)0xf0, (byte)0xda, (byte)0xf4,
        (byte)0x90, (byte)0xb8, (byte)0x65, (byte)0x64,
        (byte)0xf7, (byte)0x5c, (byte)0x4c, (byte)0xad,
        (byte)0xe8, (byte)0x7e, (byte)0x66, (byte)0x5e,
        (byte)0x99, (byte)0xd7, (byte)0xb8, (byte)0xc2,
        (byte)0x3e, (byte)0xc8, (byte)0xd0, (byte)0x13,
        (byte)0x9d, (byte)0xad, (byte)0xee, (byte)0xe4,
        (byte)0x45, (byte)0x7b, (byte)0x89, (byte)0x55,
        (byte)0xf7, (byte)0x8a, (byte)0x1f, (byte)0x62,
        (byte)0x52, (byte)0x84, (byte)0x12, (byte)0xb3,
        (byte)0xc2, (byte)0x40, (byte)0x97, (byte)0xe3,
        (byte)0x8a, (byte)0x1f, (byte)0x47, (byte)0x91,
        (byte)0xa6, (byte)0x74, (byte)0x5a, (byte)0xd2,
        (byte)0xf8, (byte)0xb1, (byte)0x63, (byte)0x28,
        (byte)0x10, (byte)0xb8, (byte)0xb3, (byte)0x09,
        (byte)0xb8, (byte)0x56, (byte)0x77, (byte)0x40,
        (byte)0xa2, (byte)0x26, (byte)0x98, (byte)0x79,
        (byte)0xc6, (byte)0xfe, (byte)0xdf, (byte)0x25,
        (byte)0xee, (byte)0x3e, (byte)0xe5, (byte)0xa0,
        (byte)0x7f, (byte)0xd4, (byte)0x61, (byte)0x0f,
        (byte)0x51, (byte)0x4b, (byte)0x3c, (byte)0x3f,
        (byte)0x8c, (byte)0xda, (byte)0xe1, (byte)0x70,
        (byte)0x74, (byte)0xd8, (byte)0xc2, (byte)0x68,
        (byte)0xa1, (byte)0xf9, (byte)0xc1, (byte)0x0c,
        (byte)0xe9, (byte)0xa1, (byte)0xe2, (byte)0x7f,
        (byte)0xbb, (byte)0x55, (byte)0x3c, (byte)0x76,
        (byte)0x06, (byte)0xee, (byte)0x6a, (byte)0x4e,
        (byte)0xcc, (byte)0x92, (byte)0x88, (byte)0x30,
        (byte)0x4d, (byte)0x9a, (byte)0xbd, (byte)0x4f,
        (byte)0x0b, (byte)0x48, (byte)0x9a, (byte)0x84,
        (byte)0xb5, (byte)0x98, (byte)0xa3, (byte)0xd5,
        (byte)0xfb, (byte)0x73, (byte)0xc1, (byte)0x57,
        (byte)0x61, (byte)0xdd, (byte)0x28, (byte)0x56,
        (byte)0x75, (byte)0x13, (byte)0xae, (byte)0x87,
        (byte)0x8e, (byte)0xe7, (byte)0x0c, (byte)0x51,
        (byte)0x09, (byte)0x10, (byte)0x75, (byte)0x88,
        (byte)0x4c, (byte)0xbc, (byte)0x8d, (byte)0xf9,
        (byte)0x7b, (byte)0x3c, (byte)0xd4, (byte)0x22,
        (byte)0x48, (byte)0x1f, (byte)0x2a, (byte)0xdc,
        (byte)0xeb, (byte)0x6b, (byte)0xbb, (byte)0x44,
        (byte)0xb1, (byte)0xcb, (byte)0x33, (byte)0x71,
        (byte)0x32, (byte)0x46, (byte)0xaf, (byte)0xad,
        (byte)0x4a, (byte)0xf1, (byte)0x8c, (byte)0xe8,
        (byte)0x74, (byte)0x3a, (byte)0xac, (byte)0xe7,
        (byte)0x1a, (byte)0x22, (byte)0x73, (byte)0x80,
        (byte)0xd2, (byte)0x30, (byte)0xf7, (byte)0x25,
        (byte)0x42, (byte)0xc7, (byte)0x22, (byte)0x3b,
        (byte)0x3b, (byte)0x12, (byte)0xad, (byte)0x96,
        (byte)0x2e, (byte)0xc6, (byte)0xc3, (byte)0x76,
        (byte)0x07, (byte)0xaa, (byte)0x20, (byte)0xb7,
        (byte)0x35, (byte)0x49, (byte)0x57, (byte)0xe9,
        (byte)0x92, (byte)0x49, (byte)0xe8, (byte)0x76,
        (byte)0x16, (byte)0x72, (byte)0x31, (byte)0x67,
        (byte)0x2b, (byte)0x96, (byte)0x7e, (byte)0x8a,
        (byte)0xa3, (byte)0xc7, (byte)0x94, (byte)0x56,
        (byte)0x22, (byte)0xbf, (byte)0x6a, (byte)0x4b,
        (byte)0x7e, (byte)0x01, (byte)0x21, (byte)0xb2,
        (byte)0x23, (byte)0x32, (byte)0xdf, (byte)0xe4,
        (byte)0x9a, (byte)0x44, (byte)0x6d, (byte)0x59,
        (byte)0x5b, (byte)0x5d, (byte)0xf5, (byte)0x00,
        (byte)0xa0, (byte)0x1c, (byte)0x9b, (byte)0xc6,
        (byte)0x78, (byte)0x97, (byte)0x8d, (byte)0x90,
        (byte)0xff, (byte)0x9b, (byte)0xc8, (byte)0xaa,
        (byte)0xb4, (byte)0xaf, (byte)0x11, (byte)0x51,
        (byte)0x39, (byte)0x5e, (byte)0xd9, (byte)0xfb,
        (byte)0x67, (byte)0xad, (byte)0xd5, (byte)0x5b,
        (byte)0x11, (byte)0x9d, (byte)0x32, (byte)0x9a,
        (byte)0x1b, (byte)0xbd, (byte)0xd5, (byte)0xba,
        (byte)0x5b, (byte)0xa5, (byte)0xc9, (byte)0xcb,
        (byte)0x25, (byte)0x69, (byte)0x53, (byte)0x55,
        (byte)0x27, (byte)0x5c, (byte)0xe0, (byte)0xca,
        (byte)0x36, (byte)0xcb, (byte)0x88, (byte)0x61,
        (byte)0xfb, (byte)0x1e, (byte)0xb7, (byte)0xd0,
        (byte)0xcb, (byte)0xee, (byte)0x16, (byte)0xfb,
        (byte)0xd3, (byte)0xa6, (byte)0x4c, (byte)0xde,
        (byte)0x92, (byte)0xa5, (byte)0xd4, (byte)0xe2,
        (byte)0xdf, (byte)0xf5, (byte)0x06, (byte)0x54,
        (byte)0xde, (byte)0x2e, (byte)0x9d, (byte)0x4b,
        (byte)0xb4, (byte)0x93, (byte)0x30, (byte)0xaa,
        (byte)0x81, (byte)0xce, (byte)0xdd, (byte)0x1a,
        (byte)0xdc, (byte)0x51, (byte)0x73, (byte)0x0d,
        (byte)0x4f, (byte)0x70, (byte)0xe9, (byte)0xe5,
        (byte)0xb6, (byte)0x16, (byte)0x21, (byte)0x19,
        (byte)0x79, (byte)0xb2, (byte)0xe6, (byte)0x89,
        (byte)0x0b, (byte)0x75, (byte)0x64, (byte)0xca,
        (byte)0xd5, (byte)0xab, (byte)0xbc, (byte)0x09,
        (byte)0xc1, (byte)0x18, (byte)0xa1, (byte)0xff,
        (byte)0xd4, (byte)0x54, (byte)0xa1, (byte)0x85,
        (byte)0x3c, (byte)0xfd, (byte)0x14, (byte)0x24,
        (byte)0x03, (byte)0xb2, (byte)0x87, (byte)0xd3,
        (byte)0xa4, (byte)0xb7, (byte)0x02, (byte)0x03,
        (byte)0x01, (byte)0x00, (byte)0x01, (byte)0xa3,
        (byte)0x42, (byte)0x30, (byte)0x40, (byte)0x30,
        (byte)0x0e, (byte)0x06, (byte)0x03, (byte)0x55,
        (byte)0x1d, (byte)0x0f, (byte)0x01, (byte)0x01,
        (byte)0xff, (byte)0x04, (byte)0x04, (byte)0x03,
        (byte)0x02, (byte)0x01, (byte)0x86, (byte)0x30,
        (byte)0x0f, (byte)0x06, (byte)0x03, (byte)0x55,
        (byte)0x1d, (byte)0x13, (byte)0x01, (byte)0x01,
        (byte)0xff, (byte)0x04, (byte)0x05, (byte)0x30,
        (byte)0x03, (byte)0x01, (byte)0x01, (byte)0xff,
        (byte)0x30, (byte)0x1d, (byte)0x06, (byte)0x03,
        (byte)0x55, (byte)0x1d, (byte)0x0e, (byte)0x04,
        (byte)0x16, (byte)0x04, (byte)0x14, (byte)0xbb,
        (byte)0xff, (byte)0xca, (byte)0x8e, (byte)0x23,
        (byte)0x9f, (byte)0x4f, (byte)0x99, (byte)0xca,
        (byte)0xdb, (byte)0xe2, (byte)0x68, (byte)0xa6,
        (byte)0xa5, (byte)0x15, (byte)0x27, (byte)0x17,
        (byte)0x1e, (byte)0xd9, (byte)0x0e
    };

    private byte[] expectedPkey = {
            (byte)0x30, (byte)0x82, (byte)0x01, (byte)0x22,
            (byte)0x30, (byte)0x0D, (byte)0x06, (byte)0x09,
            (byte)0x2A, (byte)0x86, (byte)0x48, (byte)0x86,
            (byte)0xF7, (byte)0x0D, (byte)0x01, (byte)0x01,
            (byte)0x01, (byte)0x05, (byte)0x00, (byte)0x03,
            (byte)0x82, (byte)0x01, (byte)0x0F, (byte)0x00,
            (byte)0x30, (byte)0x82, (byte)0x01, (byte)0x0A,
            (byte)0x02, (byte)0x82, (byte)0x01, (byte)0x01,
            (byte)0x00, (byte)0xBF, (byte)0x0C, (byte)0xCA,
            (byte)0x2D, (byte)0x14, (byte)0xB2, (byte)0x1E,
            (byte)0x84, (byte)0x42, (byte)0x5B, (byte)0xCD,
            (byte)0x38, (byte)0x1F, (byte)0x4A, (byte)0xF2,
            (byte)0x4D, (byte)0x75, (byte)0x10, (byte)0xF1,
            (byte)0xB6, (byte)0x35, (byte)0x9F, (byte)0xDF,
            (byte)0xCA, (byte)0x7D, (byte)0x03, (byte)0x98,
            (byte)0xD3, (byte)0xAC, (byte)0xDE, (byte)0x03,
            (byte)0x66, (byte)0xEE, (byte)0x2A, (byte)0xF1,
            (byte)0xD8, (byte)0xB0, (byte)0x7D, (byte)0x6E,
            (byte)0x07, (byte)0x54, (byte)0x0B, (byte)0x10,
            (byte)0x98, (byte)0x21, (byte)0x4D, (byte)0x80,
            (byte)0xCB, (byte)0x12, (byte)0x20, (byte)0xE7,
            (byte)0xCC, (byte)0x4F, (byte)0xDE, (byte)0x45,
            (byte)0x7D, (byte)0xC9, (byte)0x72, (byte)0x77,
            (byte)0x32, (byte)0xEA, (byte)0xCA, (byte)0x90,
            (byte)0xBB, (byte)0x69, (byte)0x52, (byte)0x10,
            (byte)0x03, (byte)0x2F, (byte)0xA8, (byte)0xF3,
            (byte)0x95, (byte)0xC5, (byte)0xF1, (byte)0x8B,
            (byte)0x62, (byte)0x56, (byte)0x1B, (byte)0xEF,
            (byte)0x67, (byte)0x6F, (byte)0xA4, (byte)0x10,
            (byte)0x41, (byte)0x95, (byte)0xAD, (byte)0x0A,
            (byte)0x9B, (byte)0xE3, (byte)0xA5, (byte)0xC0,
            (byte)0xB0, (byte)0xD2, (byte)0x70, (byte)0x76,
            (byte)0x50, (byte)0x30, (byte)0x5B, (byte)0xA8,
            (byte)0xE8, (byte)0x08, (byte)0x2C, (byte)0x7C,
            (byte)0xED, (byte)0xA7, (byte)0xA2, (byte)0x7A,
            (byte)0x8D, (byte)0x38, (byte)0x29, (byte)0x1C,
            (byte)0xAC, (byte)0xC7, (byte)0xED, (byte)0xF2,
            (byte)0x7C, (byte)0x95, (byte)0xB0, (byte)0x95,
            (byte)0x82, (byte)0x7D, (byte)0x49, (byte)0x5C,
            (byte)0x38, (byte)0xCD, (byte)0x77, (byte)0x25,
            (byte)0xEF, (byte)0xBD, (byte)0x80, (byte)0x75,
            (byte)0x53, (byte)0x94, (byte)0x3C, (byte)0x3D,
            (byte)0xCA, (byte)0x63, (byte)0x5B, (byte)0x9F,
            (byte)0x15, (byte)0xB5, (byte)0xD3, (byte)0x1D,
            (byte)0x13, (byte)0x2F, (byte)0x19, (byte)0xD1,
            (byte)0x3C, (byte)0xDB, (byte)0x76, (byte)0x3A,
            (byte)0xCC, (byte)0xB8, (byte)0x7D, (byte)0xC9,
            (byte)0xE5, (byte)0xC2, (byte)0xD7, (byte)0xDA,
            (byte)0x40, (byte)0x6F, (byte)0xD8, (byte)0x21,
            (byte)0xDC, (byte)0x73, (byte)0x1B, (byte)0x42,
            (byte)0x2D, (byte)0x53, (byte)0x9C, (byte)0xFE,
            (byte)0x1A, (byte)0xFC, (byte)0x7D, (byte)0xAB,
            (byte)0x7A, (byte)0x36, (byte)0x3F, (byte)0x98,
            (byte)0xDE, (byte)0x84, (byte)0x7C, (byte)0x05,
            (byte)0x67, (byte)0xCE, (byte)0x6A, (byte)0x14,
            (byte)0x38, (byte)0x87, (byte)0xA9, (byte)0xF1,
            (byte)0x8C, (byte)0xB5, (byte)0x68, (byte)0xCB,
            (byte)0x68, (byte)0x7F, (byte)0x71, (byte)0x20,
            (byte)0x2B, (byte)0xF5, (byte)0xA0, (byte)0x63,
            (byte)0xF5, (byte)0x56, (byte)0x2F, (byte)0xA3,
            (byte)0x26, (byte)0xD2, (byte)0xB7, (byte)0x6F,
            (byte)0xB1, (byte)0x5A, (byte)0x17, (byte)0xD7,
            (byte)0x38, (byte)0x99, (byte)0x08, (byte)0xFE,
            (byte)0x93, (byte)0x58, (byte)0x6F, (byte)0xFE,
            (byte)0xC3, (byte)0x13, (byte)0x49, (byte)0x08,
            (byte)0x16, (byte)0x0B, (byte)0xA7, (byte)0x4D,
            (byte)0x67, (byte)0x00, (byte)0x52, (byte)0x31,
            (byte)0x67, (byte)0x23, (byte)0x4E, (byte)0x98,
            (byte)0xED, (byte)0x51, (byte)0x45, (byte)0x1D,
            (byte)0xB9, (byte)0x04, (byte)0xD9, (byte)0x0B,
            (byte)0xEC, (byte)0xD8, (byte)0x28, (byte)0xB3,
            (byte)0x4B, (byte)0xBD, (byte)0xED, (byte)0x36,
            (byte)0x79, (byte)0x02, (byte)0x03, (byte)0x01,
            (byte)0x00, (byte)0x01
    };
}
