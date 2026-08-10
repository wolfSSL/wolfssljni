/* WolfSSLCertRequestTest.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

package com.wolfssl.test;

import org.junit.Assume;
import org.junit.Rule;
import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.rules.TestRule;
import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLX509Name;
import com.wolfssl.WolfSSLCertRequest;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLJNIException;

/**
 * @author wolfSSL
 */
public class WolfSSLCertRequestTest {

    @Rule
    public TestRule testWatcher = TimedTestWatcher.create();

    public final static int TEST_FAIL    = -1;
    public final static int TEST_SUCCESS =  0;

    public static String cliKeyDer = "examples/certs/client-key.der";
    public static String cliKeyPem = "examples/certs/client-key.pem";
    public static String cliKeyPubDer = "examples/certs/client-keyPub.der";
    public static String cliEccKeyDer = "examples/certs/ecc-client-key.der";
    public static String cliEccKeyPem = "examples/certs/ecc-client-key.pem";

    @BeforeClass
    public static void setCertPaths() throws WolfSSLException {

        System.out.println("WolfSSLCertRequest Class");

        try {
            WolfSSL.loadLibrary();
        } catch (UnsatisfiedLinkError ule) {
            fail("failed to load native JNI library");
        }

        cliKeyDer = WolfSSLTestCommon.getPath(cliKeyDer);
        cliKeyPem = WolfSSLTestCommon.getPath(cliKeyPem);
        cliKeyPubDer = WolfSSLTestCommon.getPath(cliKeyPubDer);
        cliEccKeyDer = WolfSSLTestCommon.getPath(cliEccKeyDer);
        cliEccKeyPem = WolfSSLTestCommon.getPath(cliEccKeyPem);
    }

    private boolean isNotCompiledIn(WolfSSLException e) {
        String msg = e.getMessage();
        if (msg == null) {
            return false;
        }
        return msg.contains(
            Integer.toString(WolfSSL.NOT_COMPILED_IN)) ||
            msg.contains("NOT_COMPILED_IN");
    }

    /* Internal helper method, generate test SubjectName for cert generation */
    private WolfSSLX509Name GenerateTestSubjectName() throws WolfSSLException {

        WolfSSLX509Name name = new WolfSSLX509Name();

        name.setCountryName("US");
        name.setStateOrProvinceName("Montana");
        name.setStreetAddress("12345 Test Address");
        name.setLocalityName("Bozeman");
        name.setSurname("Test Surname");
        name.setCommonName("wolfssl.com");
        name.setEmailAddress("support@wolfssl.com");
        name.setOrganizationName("wolfSSL Inc.");
        name.setOrganizationalUnitName("Development Test");
        name.setUserId("TestUserID");

        return name;
    }

    @Test
    public void testAddAttribute()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException {

        Assume.assumeTrue(WolfSSL.certReqEnabled());

        WolfSSLCertRequest req = new WolfSSLCertRequest();
        assertNotNull(req);

        /* Test adding supported attributes by NID */
        req.addAttribute(WolfSSL.NID_pkcs9_challengePassword,
            "12345".getBytes());
        req.addAttribute(WolfSSL.NID_serialNumber,
            "12345".getBytes());
        req.addAttribute(WolfSSL.NID_pkcs9_unstructuredName,
            "12345".getBytes());
        req.addAttribute(WolfSSL.NID_pkcs9_contentType,
            "12345".getBytes());
        req.addAttribute(WolfSSL.NID_surname,
            "12345".getBytes());
        req.addAttribute(WolfSSL.NID_initials,
            "12345".getBytes());
        req.addAttribute(WolfSSL.NID_givenName,
            "12345".getBytes());
        req.addAttribute(WolfSSL.NID_dnQualifier,
            "12345".getBytes());

        /* Adding unsupported NID should throw exception */
        try {
            req.addAttribute(123456, "12345".getBytes());
            fail("Unsupported NID did not throw exception");
        } catch (WolfSSLException e) {
            /* expected */
        }

        req.free();
    }

    @Test
    public void testAddExtension()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException {

        Assume.assumeTrue(WolfSSL.certReqEnabled());

        WolfSSLCertRequest req = new WolfSSLCertRequest();
        assertNotNull(req);

        /* Test adding supported extensions by NID */

        /* wolfSSL versions 5.6.3 and earlier did not include code
         * fixes to native wolfSSL allowing this extension support to
         * work. Use a version > 5.6.3 or apply patch from wolfSSL
         * PR 6585 for correct support */
        if (WolfSSL.getLibVersionHex() <= 0x05006003) {
            req.addExtension(WolfSSL.NID_key_usage,
                "digitalSignature,keyAgreement", false);
            req.addExtension(WolfSSL.NID_ext_key_usage,
                "serverAuth,clientAuth", false);
        }
        req.addExtension(WolfSSL.NID_subject_alt_name,
            "my test altName", false);

        /* Adding unsupported NID should throw exception */
        try {
            req.addExtension(123456, "12345", false);
            fail("Unsupported extension NID did not throw exception");
        } catch (WolfSSLException e) {
            /* expected */
        }

        /* Test boolean extension setting */
        req.addExtension(WolfSSL.NID_basic_constraints, true, true);
        req.addExtension(WolfSSL.NID_basic_constraints, false, true);

        /* Test boolean extension with pathLen. If the basicConstraints
         * pathLen overload isn't compiled in, skip the remaining pathLen
         * assertions so they aren't interpreted as passing for the wrong
         * reason (NOT_COMPILED_IN vs. actual input validation). */
        try {
            req.addExtension(WolfSSL.NID_basic_constraints, true, 0, true);
        } catch (WolfSSLException e) {
            if (isNotCompiledIn(e)) {
                Assume.assumeNoException(
                    "basicConstraints pathLen overload not compiled in", e);
            }
            throw e;
        }
        req.addExtension(WolfSSL.NID_basic_constraints, true, 3, true);

        /* Invalid pathLen (< -1) should throw WolfSSLException */
        try {
            req.addExtension(WolfSSL.NID_basic_constraints, true, -2, true);
            fail("Invalid pathLen did not throw exception");
        } catch (WolfSSLException e) {
            /* expected */
        }

        /* pathLen with isCA=false should throw (RFC 5280) */
        try {
            req.addExtension(WolfSSL.NID_basic_constraints, false, 0, true);
            fail("pathLen with isCA=false did not throw");
        } catch (WolfSSLException e) {
            /* expected */
        }

        /* Unsupported NID with pathLen should throw exception */
        try {
            req.addExtension(123456, true, 0, true);
            fail("Unsupported NID did not throw exception");
        } catch (WolfSSLException e) {
            /* expected */
        }

        /* Adding unsupported NID should throw exception */
        try {
            req.addExtension(123456, true, false);
            fail("Unsupported extension NID did not throw exception");
        } catch (WolfSSLException e) {
            /* expected */
        }

        req.free();
    }

    /* Internal helper method, search haystack for needle byte sequence */
    private boolean containsByteSubArray(byte[] haystack, byte[] needle) {

        if (haystack == null || needle == null ||
            needle.length > haystack.length) {
            return false;
        }

        for (int i = 0; i <= haystack.length - needle.length; i++) {
            boolean match = true;
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return true;
            }
        }

        return false;
    }

    /* Internal helper method, build expected DER GeneralName TLV given
     * context-specific tag number and content bytes. Only supports content
     * lengths less than 128 bytes (single byte ASN.1 length) */
    private byte[] buildGeneralNameTLV(int tag, byte[] content) {

        byte[] tlv = new byte[content.length + 2];

        tlv[0] = (byte)(0x80 | tag);
        tlv[1] = (byte)content.length;
        System.arraycopy(content, 0, tlv, 2, content.length);

        return tlv;
    }

    @Test
    public void testAddAltName() throws WolfSSLException, WolfSSLJNIException,
        IOException, CertificateException {

        Assume.assumeTrue(WolfSSL.certReqEnabled());

        WolfSSLCertRequest req = new WolfSSLCertRequest();
        assertNotNull(req);

        /* Set Subject Name */
        WolfSSLX509Name subjectName = GenerateTestSubjectName();
        assertNotNull(subjectName);
        req.setSubjectName(subjectName);

        /* Set Public Key from file */
        req.setPublicKey(cliKeyPubDer, WolfSSL.RSAk,
            WolfSSL.SSL_FILETYPE_ASN1);

        /* Add Subject Alternative Name entries of various types. If
         * altName support is not compiled into native wolfSSL
         * (WOLFSSL_ALT_NAMES), skip this test instead of failing. Only
         * the first call needs to be guarded, if it succeeds support
         * is compiled in for the rest */
        try {
            req.addAltName("alt.wolfssl.com", WolfSSL.ASN_DNS_TYPE);
        } catch (WolfSSLException e) {
            if (isNotCompiledIn(e)) {
                subjectName.free();
                req.free();
                Assume.assumeNoException(
                    "altName support not compiled in (WOLFSSL_ALT_NAMES)", e);
            }
            throw e;
        }
        req.addAltName("test@wolfssl.com", WolfSSL.ASN_RFC822_TYPE);
        req.addAltName("https://www.wolfssl.com", WolfSSL.ASN_URI_TYPE);
        req.addAltName("192.168.1.1", WolfSSL.ASN_IP_TYPE);
        req.addAltName("::1", WolfSSL.ASN_IP_TYPE);

        /* SAN added via addExtension() should combine with entries
         * added via addAltName() */
        req.addExtension(WolfSSL.NID_subject_alt_name,
            "test.wolfssl.com", false);

        /* Invalid IP address string should throw exception */
        try {
            req.addAltName("notanip", WolfSSL.ASN_IP_TYPE);
            fail("Invalid IP address did not throw exception");
        } catch (WolfSSLException e) {
            /* expected */
        }

        /* null name should throw exception */
        try {
            req.addAltName(null, WolfSSL.ASN_DNS_TYPE);
            fail("null altName did not throw exception");
        } catch (WolfSSLException e) {
            /* expected */
        }

        /* Sign CSR */
        req.signRequest(cliKeyDer, WolfSSL.RSAk,
            WolfSSL.SSL_FILETYPE_ASN1, "SHA256");

        byte[] derCsr = req.getDer();
        assertNotNull(derCsr);
        assertTrue(derCsr.length > 0);

        /* Verify GeneralName entries are encoded in the CSR DER with
         * correct types. GeneralName tags from RFC 5280:
         * rfc822Name [1], dNSName [2], URI [6], iPAddress [7] */
        assertTrue("DNS SAN not found in CSR DER",
            containsByteSubArray(derCsr, buildGeneralNameTLV(2,
                "alt.wolfssl.com".getBytes("US-ASCII"))));
        assertTrue("email SAN not found in CSR DER",
            containsByteSubArray(derCsr, buildGeneralNameTLV(1,
                "test@wolfssl.com".getBytes("US-ASCII"))));
        assertTrue("URI SAN not found in CSR DER",
            containsByteSubArray(derCsr, buildGeneralNameTLV(6,
                "https://www.wolfssl.com".getBytes("US-ASCII"))));
        assertTrue("IPv4 SAN not found in CSR DER",
            containsByteSubArray(derCsr, buildGeneralNameTLV(7,
                new byte[] {(byte)192, (byte)168, 1, 1})));
        assertTrue("IPv6 SAN not found in CSR DER",
            containsByteSubArray(derCsr, buildGeneralNameTLV(7,
                new byte[] {0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 1})));
        assertTrue("DNS SAN from addExtension() not found in CSR DER",
            containsByteSubArray(derCsr, buildGeneralNameTLV(2,
                "test.wolfssl.com".getBytes("US-ASCII"))));

        /* Free native memory */
        subjectName.free();
        req.free();

        /* addAltName() after free() should throw IllegalStateException */
        try {
            req.addAltName("alt.wolfssl.com", WolfSSL.ASN_DNS_TYPE);
            fail("addAltName after free did not throw exception");
        } catch (IllegalStateException e) {
            /* expected */
        }
    }

    @Test
    public void testSetVersion()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException {

        Assume.assumeTrue(WolfSSL.certReqEnabled());

        WolfSSLCertRequest req = new WolfSSLCertRequest();
        assertNotNull(req);

        req.setVersion(0);
        req.setVersion(1);

        /* Negative versions should throw exception */
        try {
            req.setVersion(-100);
            fail("Negative version should throw exception");
        } catch (WolfSSLException e) {
            /* expected */
        }

        req.free();
    }

    @Test
    public void testSetPublicKeyFile()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException {

        Assume.assumeTrue(WolfSSL.certReqEnabled());

        WolfSSLCertRequest req = new WolfSSLCertRequest();
        assertNotNull(req);

        /* RSA */
        req.setPublicKey(cliKeyPubDer, WolfSSL.RSAk,
            WolfSSL.SSL_FILETYPE_ASN1);

        /* Test bad key type */
        try {
            req.setPublicKey(cliKeyPubDer, 12345,
                WolfSSL.SSL_FILETYPE_ASN1);
            fail("bad key type should throw exception");
        } catch (WolfSSLException e) {
            /* expected */
        }

        /* Test bad file type */
        try {
            req.setPublicKey(cliKeyPubDer, WolfSSL.RSAk, 12345);
            fail("bad file type should throw exception");
        } catch (WolfSSLException e) {
            /* expected */
        }

        /* Test null file String */
        try {
            req.setPublicKey((String)null, WolfSSL.RSAk,
                WolfSSL.SSL_FILETYPE_ASN1);
            fail("null PublicKey should throw exception");
        } catch (WolfSSLException e) {
            /* expected */
        }

        /* Test file that does not exist */
        try {
            req.setPublicKey("badfile", WolfSSL.RSAk,
                WolfSSL.SSL_FILETYPE_ASN1);
            fail("Bad path to PublicKey should throw exception");
        } catch (WolfSSLException e) {
            /* expected */
        }

        req.free();
    }

    @Test
    public void testSetPublicKeyArray()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException, NoSuchAlgorithmException {

        KeyPairGenerator rsaKpg;
        KeyPairGenerator eccKpg;
        KeyPair rsaKeyPair;
        KeyPair eccKeyPair;
        byte[] rsaPubKeyDer;
        byte[] eccPubKeyDer;

        Assume.assumeTrue(WolfSSL.certReqEnabled());

        WolfSSLCertRequest req = new WolfSSLCertRequest();
        assertNotNull(req);

        /* Generate RSA key pair and get public key bytes (DER encoded). */
        rsaKpg = KeyPairGenerator.getInstance("RSA");
        rsaKpg.initialize(2048);
        rsaKeyPair = rsaKpg.generateKeyPair();
        rsaPubKeyDer = rsaKeyPair.getPublic().getEncoded();

        /* Generate ECC key pair and get public key bytes (DER encoded) */
        eccKpg = KeyPairGenerator.getInstance("EC");
        eccKpg.initialize(256);
        eccKeyPair = eccKpg.generateKeyPair();
        eccPubKeyDer = eccKeyPair.getPublic().getEncoded();

        /* RSA public key DER */
        req.setPublicKey(rsaPubKeyDer, WolfSSL.RSAk,
            WolfSSL.SSL_FILETYPE_ASN1);

        /* ECC public key DER */
        req.setPublicKey(eccPubKeyDer, WolfSSL.ECDSAk,
            WolfSSL.SSL_FILETYPE_ASN1);

        /* Test bad key type */
        try {
            req.setPublicKey(rsaPubKeyDer, 12345,
                WolfSSL.SSL_FILETYPE_ASN1);
            fail("bad key type should throw exception");
        } catch (WolfSSLException e) {
            /* expected */
        }

        /* Test bad file type */
        try {
            req.setPublicKey(rsaPubKeyDer, WolfSSL.RSAk, 12345);
            fail("bad file type should throw exception");
        } catch (WolfSSLException e) {
            /* expected */
        }

        /* Test null file String */
        try {
            req.setPublicKey((byte[])null, WolfSSL.RSAk,
                WolfSSL.SSL_FILETYPE_ASN1);
            fail("null key array should throw exception");
        } catch (WolfSSLException e) {
            /* expected */
        }

        /* Test zero-length byte array */
        byte[] zeroArr = new byte[0];
        try {
            req.setPublicKey(zeroArr, WolfSSL.RSAk,
                WolfSSL.SSL_FILETYPE_ASN1);
            fail("Zero length pub key array should throw exception");
        } catch (WolfSSLException e) {
            /* expected */
        }

        req.free();
    }

    @Test
    public void testSetPublicKeyObject()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException, NoSuchAlgorithmException {

        Assume.assumeTrue(WolfSSL.certReqEnabled());

        WolfSSLCertRequest req = new WolfSSLCertRequest();
        assertNotNull(req);

        /* RSA: Set Public Key from generated java.security.PublicKey */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        PublicKey pubKey = keyPair.getPublic();
        req.setPublicKey(pubKey);

        /* ECC: Set Public Key from generated java.security.PublicKey */
        KeyPairGenerator kpgEcc = KeyPairGenerator.getInstance("EC");
        kpgEcc.initialize(256);
        KeyPair keyPairEcc = kpgEcc.generateKeyPair();
        PublicKey pubKeyEcc = keyPairEcc.getPublic();
        req.setPublicKey(pubKeyEcc);

        /* Test null PublicKey object */
        try {
            req.setPublicKey((PublicKey)null);
            fail("null PublicKey should throw exception");
        } catch (WolfSSLException e) {
            /* expected */
        }

        req.free();
    }

    @Test
    public void testGenCSR_UsingFiles()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException {

        Assume.assumeTrue(WolfSSL.certReqEnabled());

        WolfSSLCertRequest req = new WolfSSLCertRequest();
        assertNotNull(req);

        /* Set Subject Name */
        WolfSSLX509Name subjectName = GenerateTestSubjectName();
        assertNotNull(subjectName);
        req.setSubjectName(subjectName);

        /* Set Public Key from file */
        req.setPublicKey(cliKeyPubDer, WolfSSL.RSAk,
            WolfSSL.SSL_FILETYPE_ASN1);

        /* Set Extensions */
        if (WolfSSL.getLibVersionHex() > 0x05006003) {
            /* Key Usage and Extended Key Usage only work with wolfSSL
             * later than 5.6.3 */
            req.addExtension(WolfSSL.NID_key_usage,
                "digitalSignature,keyEncipherment,dataEncipherment", false);

            req.addExtension(WolfSSL.NID_ext_key_usage,
                "clientAuth,serverAuth", false);
        }
        req.addExtension(WolfSSL.NID_subject_alt_name,
            "test.wolfssl.com", false);
        req.addExtension(WolfSSL.NID_basic_constraints, true, true);

        /* Sign CSR */
        req.signRequest(cliKeyDer, WolfSSL.RSAk,
            WolfSSL.SSL_FILETYPE_ASN1, "SHA256");

        /* Output to DER and PEM */
        byte[] derCsr = req.getDer();
        byte[] pemCsr = req.getPem();

        assertNotNull(derCsr);
        assertTrue(derCsr.length > 0);
        assertNotNull(pemCsr);
        assertTrue(pemCsr.length > 0);

        /* Free native memory */
        subjectName.free();
        req.free();
    }

    @Test
    public void testSignRequestFailureThrows()
        throws WolfSSLException, WolfSSLJNIException, IOException {

        Assume.assumeTrue(WolfSSL.certReqEnabled());

        WolfSSLCertRequest req = new WolfSSLCertRequest();
        assertNotNull(req);

        WolfSSLX509Name subjectName = GenerateTestSubjectName();
        assertNotNull(subjectName);

        try {
            req.setSubjectName(subjectName);

            /* no public key set, native signing fails */
            try {
                req.signRequest(cliKeyDer, WolfSSL.RSAk,
                    WolfSSL.SSL_FILETYPE_ASN1, "SHA256");
                fail("signRequest() should throw when native signing fails");
            } catch (WolfSSLException expected) {
                /* expected */
            }
        } finally {
            subjectName.free();
            req.free();
        }
    }

    @Test
    public void testGenCSR_UsingBuffers()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException {

        Assume.assumeTrue(WolfSSL.certReqEnabled());

        WolfSSLCertRequest req = new WolfSSLCertRequest();
        assertNotNull(req);

        /* Set Subject Name */
        WolfSSLX509Name subjectName = GenerateTestSubjectName();
        assertNotNull(subjectName);
        req.setSubjectName(subjectName);

        /* Set Public Key from file */
        byte[] pubKey = Files.readAllBytes(Paths.get(cliKeyPubDer));
        req.setPublicKey(pubKey, WolfSSL.RSAk, WolfSSL.SSL_FILETYPE_ASN1);

        /* Set Extensions */
        if (WolfSSL.getLibVersionHex() > 0x05006003) {
            /* Key Usage and Extended Key Usage only work with wolfSSL
             * later than 5.6.3 */
            req.addExtension(WolfSSL.NID_key_usage,
                "digitalSignature,keyEncipherment,dataEncipherment", false);
            req.addExtension(WolfSSL.NID_ext_key_usage,
                "clientAuth,serverAuth", false);
        }
        req.addExtension(WolfSSL.NID_subject_alt_name,
            "test.wolfssl.com", false);
        req.addExtension(WolfSSL.NID_basic_constraints, true, true);

        /* Sign CSR */
        byte[] privKey = Files.readAllBytes(Paths.get(cliKeyDer));
        req.signRequest(privKey, WolfSSL.RSAk,
            WolfSSL.SSL_FILETYPE_ASN1, "SHA256");

        /* Output to DER and PEM */
        byte[] derCsr = req.getDer();
        byte[] pemCsr = req.getPem();

        assertNotNull(derCsr);
        assertTrue(derCsr.length > 0);
        assertNotNull(pemCsr);
        assertTrue(pemCsr.length > 0);

        /* Free native memory */
        subjectName.free();
        req.free();
    }

    @Test
    public void testGenCSR_UsingJavaClasses()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException, NoSuchAlgorithmException {

        Assume.assumeTrue(WolfSSL.certReqEnabled());

        WolfSSLCertRequest req = new WolfSSLCertRequest();
        assertNotNull(req);

        /* Set Subject Name */
        WolfSSLX509Name subjectName = GenerateTestSubjectName();
        assertNotNull(subjectName);
        req.setSubjectName(subjectName);

        /* Set Public Key from generated java.security.PublicKey */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        PublicKey pubKey = keyPair.getPublic();
        req.setPublicKey(pubKey);

        /* Set Extensions */
        if (WolfSSL.getLibVersionHex() > 0x05006003) {
            /* Key Usage and Extended Key Usage only work with wolfSSL
             * later than 5.6.3 */
            req.addExtension(WolfSSL.NID_key_usage,
                "digitalSignature,keyEncipherment,dataEncipherment", false);
            req.addExtension(WolfSSL.NID_ext_key_usage,
                "clientAuth,serverAuth", false);
        }
        req.addExtension(WolfSSL.NID_subject_alt_name,
            "test.wolfssl.com", false);
        req.addExtension(WolfSSL.NID_basic_constraints, true, true);

        /* Sign CSR, with java.security.PrivateKey */
        PrivateKey privKey = keyPair.getPrivate();
        req.signRequest(privKey, "SHA256");

        /* Output to DER and PEM */
        byte[] derCsr = req.getDer();
        byte[] pemCsr = req.getPem();

        assertNotNull(derCsr);
        assertTrue(derCsr.length > 0);
        assertNotNull(pemCsr);
        assertTrue(pemCsr.length > 0);

        /* Free native memory */
        subjectName.free();
        req.free();
    }

    /* Utility method if needed for testing, print out CSR array to file */
    private void writeOutCsrFile(byte[] csr, String path)
        throws IOException {
        Files.write(new File(path).toPath(), csr);
    }

    /* setSubjectName() holds the WolfSSLX509Name lock across the native call
     * so a concurrent free() cannot free the pointer mid-call. Races the two
     * operations to check concurrency safety and deadlock-freedom of the added
     * locking, tolerating the expected exceptions when free() wins the race. */
    @Test(timeout = 60000)
    public void testSetSubjectNameFreeRace()
        throws WolfSSLException, WolfSSLJNIException, InterruptedException {

        Assume.assumeTrue(WolfSSL.certReqEnabled());

        final int iterations = 200;
        final AtomicReference<Throwable> failure =
            new AtomicReference<Throwable>();

        for (int i = 0; i < iterations && failure.get() == null; i++) {

            final WolfSSLCertRequest req = new WolfSSLCertRequest();
            final WolfSSLX509Name name = GenerateTestSubjectName();
            final CountDownLatch start = new CountDownLatch(1);

            Thread setter = new Thread(new Runnable() {
                public void run() {
                    try {
                        start.await();
                        req.setSubjectName(name);
                    } catch (IllegalStateException | WolfSSLException e) {
                        /* expected if free() won the race */
                    } catch (Throwable t) {
                        failure.compareAndSet(null, t);
                    }
                }
            });
            Thread freer = new Thread(new Runnable() {
                public void run() {
                    try {
                        start.await();
                        name.free();
                    } catch (Throwable t) {
                        failure.compareAndSet(null, t);
                    }
                }
            });

            setter.start();
            freer.start();
            start.countDown();
            setter.join();
            freer.join();

            name.free();
            req.free();
        }

        if (failure.get() != null) {
            throw new AssertionError(
                "unexpected error during setSubjectName/free race",
                failure.get());
        }
    }
}
