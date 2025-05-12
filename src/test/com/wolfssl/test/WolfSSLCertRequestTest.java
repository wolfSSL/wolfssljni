/* WolfSSLCertRequestTest.java
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

package com.wolfssl.test;

import org.junit.Test;
import org.junit.BeforeClass;
import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

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
        cliKeyPubDer = WolfSSLTestCommon.getPath(cliKeyPubDer);
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

        System.out.print("\taddAttribute()");

        if (!WolfSSL.certReqEnabled()) {
            /* WOLFSSL_CERT_REQ / --enable-certreq not enabled in wolfSSL */
            System.out.println("\t\t\t... skipped");
            return;
        }

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
            req.addAttribute(123456,
                "12345".getBytes());
            System.out.println("\t\t\t... failed");
            fail("Unsupported NID did not throw exception");
        } catch (WolfSSLException e) {
            /* expected */
        }

        req.free();
        System.out.println("\t\t\t... passed");
    }

    @Test
    public void testAddExtension()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException {

        System.out.print("\taddExtension()");

        if (!WolfSSL.certReqEnabled()) {
            /* WOLFSSL_CERT_REQ / --enable-certreq not enabled in wolfSSL */
            System.out.println("\t\t\t... skipped");
            return;
        }

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
            System.out.println("\t\t\t... failed");
            fail("Unsupported extension NID did not throw exception");
        } catch (WolfSSLException e) {
            /* expected */
        }

        /* Test boolean extension setting */
        req.addExtension(WolfSSL.NID_basic_constraints, true, true);
        req.addExtension(WolfSSL.NID_basic_constraints, false, true);

        /* Adding unsupported NID should throw exception */
        try {
            req.addExtension(123456, true, false);
            System.out.println("\t\t\t... failed");
            fail("Unsupported extension NID did not throw exception");
        } catch (WolfSSLException e) {
            /* expected */
        }

        req.free();
        System.out.println("\t\t\t... passed");
    }

    @Test
    public void testSetVersion()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException {

        System.out.print("\tsetVersion()");

        if (!WolfSSL.certReqEnabled()) {
            /* WOLFSSL_CERT_REQ / --enable-certreq not enabled in wolfSSL */
            System.out.println("\t\t\t... skipped");
            return;
        }

        WolfSSLCertRequest req = new WolfSSLCertRequest();
        assertNotNull(req);

        req.setVersion(0);
        req.setVersion(1);

        /* Negative versions should throw exception */
        try {
            req.setVersion(-100);
            System.out.println("\t\t\t... failed");
            fail("Negative version should throw exception");
        } catch (WolfSSLException e) {
            /* expected */
        }

        req.free();
        System.out.println("\t\t\t... passed");
    }

    @Test
    public void testSetPublicKeyFile()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException {

        System.out.print("\tsetPublicKey(file)");

        if (!WolfSSL.certReqEnabled()) {
            /* WOLFSSL_CERT_REQ / --enable-certreq not enabled in wolfSSL */
            System.out.println("\t\t... skipped");
            return;
        }

        WolfSSLCertRequest req = new WolfSSLCertRequest();
        assertNotNull(req);

        /* RSA */
        req.setPublicKey(cliKeyPubDer, WolfSSL.RSAk,
            WolfSSL.SSL_FILETYPE_ASN1);
        req.setPublicKey(cliKeyPem, WolfSSL.RSAk,
            WolfSSL.SSL_FILETYPE_PEM);

        /* ECC */
        req.setPublicKey(cliEccKeyDer, WolfSSL.ECDSAk,
            WolfSSL.SSL_FILETYPE_ASN1);
        req.setPublicKey(cliEccKeyPem, WolfSSL.ECDSAk,
            WolfSSL.SSL_FILETYPE_PEM);

        /* Test bad key type */
        try {
            req.setPublicKey(cliKeyPubDer, 12345,
                WolfSSL.SSL_FILETYPE_ASN1);
            System.out.println("\t\t... failed");
            fail("bad key type should throw exception");
        } catch (WolfSSLException e) {
            /* expected */
        }

        /* Test bad file type */
        try {
            req.setPublicKey(cliKeyPubDer, WolfSSL.RSAk, 12345);
            System.out.println("\t\t... failed");
            fail("bad file type should throw exception");
        } catch (WolfSSLException e) {
            /* expected */
        }

        /* Test null file String */
        try {
            req.setPublicKey((String)null, WolfSSL.RSAk,
                WolfSSL.SSL_FILETYPE_ASN1);
            System.out.println("\t\t... failed");
            fail("null PublicKey should throw exception");
        } catch (WolfSSLException e) {
            /* expected */
        }

        /* Test file that does not exist */
        try {
            req.setPublicKey("badfile", WolfSSL.RSAk,
                WolfSSL.SSL_FILETYPE_ASN1);
            System.out.println("\t\t... failed");
            fail("Bad path to PublicKey should throw exception");
        } catch (WolfSSLException e) {
            /* expected */
        }

        req.free();
        System.out.println("\t\t... passed");
    }

    @Test
    public void testSetPublicKeyArray()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException {

        System.out.print("\tsetPublicKey(array)");

        if (!WolfSSL.certReqEnabled()) {
            /* WOLFSSL_CERT_REQ / --enable-certreq not enabled in wolfSSL */
            System.out.println("\t\t... skipped");
            return;
        }

        WolfSSLCertRequest req = new WolfSSLCertRequest();
        assertNotNull(req);

        byte[] cliKeyRSADer = Files.readAllBytes(Paths.get(cliKeyDer));
        byte[] cliKeyRSAPem = Files.readAllBytes(Paths.get(cliKeyPem));
        byte[] cliKeyECCDer = Files.readAllBytes(Paths.get(cliEccKeyDer));
        byte[] cliKeyECCPem = Files.readAllBytes(Paths.get(cliEccKeyPem));

        /* RSA */
        req.setPublicKey(cliKeyRSADer, WolfSSL.RSAk,
            WolfSSL.SSL_FILETYPE_ASN1);
        req.setPublicKey(cliKeyRSAPem, WolfSSL.RSAk,
            WolfSSL.SSL_FILETYPE_PEM);

        /* ECC */
        req.setPublicKey(cliKeyECCDer, WolfSSL.ECDSAk,
            WolfSSL.SSL_FILETYPE_ASN1);
        req.setPublicKey(cliKeyECCPem, WolfSSL.ECDSAk,
            WolfSSL.SSL_FILETYPE_PEM);

        /* Test bad key type */
        try {
            req.setPublicKey(cliKeyRSADer, 12345,
                WolfSSL.SSL_FILETYPE_ASN1);
            System.out.println("\t\t... failed");
            fail("bad key type should throw exception");
        } catch (WolfSSLException e) {
            /* expected */
        }

        /* Test bad file type */
        try {
            req.setPublicKey(cliKeyRSADer, WolfSSL.RSAk, 12345);
            System.out.println("\t\t... failed");
            fail("bad file type should throw exception");
        } catch (WolfSSLException e) {
            /* expected */
        }

        /* Test null file String */
        try {
            req.setPublicKey((byte[])null, WolfSSL.RSAk,
                WolfSSL.SSL_FILETYPE_ASN1);
            System.out.println("\t\t... failed");
            fail("null key array should throw exception");
        } catch (WolfSSLException e) {
            /* expected */
        }

        /* Test zero-length byte array */
        byte[] zeroArr = new byte[0];
        try {
            req.setPublicKey(zeroArr, WolfSSL.RSAk,
                WolfSSL.SSL_FILETYPE_ASN1);
            System.out.println("\t\t... failed");
            fail("Zero length pub key array should throw exception");
        } catch (WolfSSLException e) {
            /* expected */
        }

        req.free();
        System.out.println("\t\t... passed");
    }

    @Test
    public void testSetPublicKeyObject()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException, NoSuchAlgorithmException {

        System.out.print("\tsetPublicKey(PublicKey)");

        if (!WolfSSL.certReqEnabled()) {
            /* WOLFSSL_CERT_REQ / --enable-certreq not enabled in wolfSSL */
            System.out.println("\t\t... skipped");
            return;
        }

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
            System.out.println("\t\t... failed");
            fail("null PublicKey should throw exception");
        } catch (WolfSSLException e) {
            /* expected */
        }

        req.free();
        System.out.println("\t\t... passed");
    }

    @Test
    public void testGenCSR_UsingFiles()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException {

        System.out.print("\tgen CSR using files");

        if (!WolfSSL.certReqEnabled()) {
            /* WOLFSSL_CERT_REQ / --enable-certreq not enabled in wolfSSL */
            System.out.println("\t\t... skipped");
            return;
        }

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

        System.out.println("\t\t... passed");
    }

    @Test
    public void testGenCSR_UsingBuffers()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException {

        System.out.print("\tgen CSR using buffers");

        if (!WolfSSL.certReqEnabled()) {
            /* WOLFSSL_CERT_REQ / --enable-certreq not enabled in wolfSSL */
            System.out.println("\t\t... skipped");
            return;
        }

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

        System.out.println("\t\t... passed");
    }

    @Test
    public void testGenCSR_UsingJavaClasses()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException, NoSuchAlgorithmException {

        System.out.print("\tgen CSR using Java classes");

        if (!WolfSSL.certReqEnabled()) {
            /* WOLFSSL_CERT_REQ / --enable-certreq not enabled in wolfSSL */
            System.out.println("\t... skipped");
            return;
        }

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

        System.out.println("\t... passed");
    }

    /* Utility method if needed for testing, print out CSR array to file */
    private void writeOutCsrFile(byte[] csr, String path)
        throws IOException {
        Files.write(new File(path).toPath(), csr);
    }
}

