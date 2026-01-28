/* WolfSSLCRLTest.java
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

package com.wolfssl.test;

import org.junit.Test;
import org.junit.BeforeClass;
import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import java.security.PrivateKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Calendar;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLX509Name;
import com.wolfssl.WolfSSLCRL;
import com.wolfssl.WolfSSLCertificate;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLJNIException;

/**
 * @author wolfSSL
 */
public class WolfSSLCRLTest {
    public final static int TEST_FAIL    = -1;
    public final static int TEST_SUCCESS =  0;

    public static String caKeyDer = "examples/certs/ca-key.der";
    public static String caKeyPem = "examples/certs/ca-key.pem";
    public static String caCertPem = "examples/certs/ca-cert.pem";
    public static String clientCertPem = "examples/certs/client-cert.pem";
    public static String clientKeyDer = "examples/certs/client-key.der";
    public static String clientKeyPem = "examples/certs/client-key.pem";
    public static String eccCaKeyPem = "examples/certs/ca-ecc-key.pem";
    public static String eccClientKeyPem = "examples/certs/ecc-client-key.pem";

    @BeforeClass
    public static void setCertPaths() throws WolfSSLException {

        System.out.println("WolfSSLCRL Class");

        try {
            WolfSSL.loadLibrary();
        } catch (UnsatisfiedLinkError ule) {
            fail("failed to load native JNI library");
        }

        caKeyDer = WolfSSLTestCommon.getPath(caKeyDer);
        caKeyPem = WolfSSLTestCommon.getPath(caKeyPem);
        caCertPem = WolfSSLTestCommon.getPath(caCertPem);
        clientCertPem = WolfSSLTestCommon.getPath(clientCertPem);
        clientKeyDer = WolfSSLTestCommon.getPath(clientKeyDer);
        clientKeyPem = WolfSSLTestCommon.getPath(clientKeyPem);
        eccCaKeyPem = WolfSSLTestCommon.getPath(eccCaKeyPem);
        eccClientKeyPem = WolfSSLTestCommon.getPath(eccClientKeyPem);
    }

    /* Internal helper method, generate test IssuerName for CRL generation */
    private WolfSSLX509Name GenerateTestIssuerName() throws WolfSSLException {

        WolfSSLX509Name name = new WolfSSLX509Name();

        name.setCountryName("US");
        name.setStateOrProvinceName("Montana");
        name.setLocalityName("Bozeman");
        name.setCommonName("wolfSSL Test CA");
        name.setEmailAddress("support@wolfssl.com");
        name.setOrganizationName("wolfSSL Inc.");
        name.setOrganizationalUnitName("Development Test");

        return name;
    }

    @Test
    public void testSetVersion()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException {

        System.out.print("\tsetVersion()");

        if (!WolfSSL.CrlGenerationEnabled()) {
            /* CRL generation not enabled in wolfSSL */
            System.out.println("\t\t\t... skipped");
            return;
        }

        WolfSSLCRL crl = new WolfSSLCRL();
        assertNotNull(crl);

        /* Test setting valid versions */
        int ret = crl.setVersion(0);
        assertTrue("setVersion(0) should succeed", ret >= 0);
        ret = crl.setVersion(1);
        assertTrue("setVersion(1) should succeed", ret >= 0);

        /* Verify version was set */
        int version = crl.getVersion();
        assertEquals(1, version);

        /* Negative versions should still work (native handles validation) */
        ret = crl.setVersion(-100);
        /* Native may or may not validate, so just check it doesn't crash */

        crl.free();
        System.out.println("\t\t\t... passed");
    }

    @Test
    public void testSetIssuerName()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException {

        System.out.print("\tsetIssuerName()");

        if (!WolfSSL.CrlGenerationEnabled()) {
            /* CRL generation not enabled in wolfSSL */
            System.out.println("\t\t\t... skipped");
            return;
        }

        WolfSSLCRL crl = new WolfSSLCRL();
        assertNotNull(crl);

        /* Set issuer name */
        WolfSSLX509Name issuerName = GenerateTestIssuerName();
        assertNotNull(issuerName);
        int ret = crl.setIssuerName(issuerName);
        assertTrue("setIssuerName should succeed", ret >= 0);

        /* Test null issuer name */
        try {
            crl.setIssuerName(null);
            System.out.println("\t\t\t... failed");
            fail("null issuer name should throw exception");
        } catch (WolfSSLException e) {
            /* expected */
        }

        /* Free native memory */
        issuerName.free();
        crl.free();
        System.out.println("\t\t\t... passed");
    }

    @Test
    public void testSetLastUpdate()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException {

        System.out.print("\tsetLastUpdate()");

        if (!WolfSSL.CrlGenerationEnabled()) {
            /* CRL generation not enabled in wolfSSL */
            System.out.println("\t\t\t... skipped");
            return;
        }

        WolfSSLCRL crl = new WolfSSLCRL();
        assertNotNull(crl);

        /* Set last update date */
        Date now = new Date();
        int ret = crl.setLastUpdate(now);
        assertEquals(WolfSSL.SSL_SUCCESS, ret);

        /* Verify date was set */
        Date retrieved = crl.getLastUpdate();
        assertNotNull(retrieved);
        /* Allow some tolerance for date comparison */
        long diff = Math.abs(retrieved.getTime() - now.getTime());
        assertTrue("Date should be within 1 second", diff < 1000);

        /* Test null date */
        try {
            crl.setLastUpdate(null);
            System.out.println("\t\t\t... failed");
            fail("null date should throw exception");
        } catch (IllegalArgumentException e) {
            /* expected */
        }

        crl.free();
        System.out.println("\t\t\t... passed");
    }

    @Test
    public void testSetNextUpdate()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException {

        System.out.print("\tsetNextUpdate()");

        if (!WolfSSL.CrlGenerationEnabled()) {
            /* CRL generation not enabled in wolfSSL */
            System.out.println("\t\t\t... skipped");
            return;
        }

        WolfSSLCRL crl = new WolfSSLCRL();
        assertNotNull(crl);

        /* Set next update date */
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_YEAR, 30); /* 30 days from now */
        Date nextUpdate = cal.getTime();
        int ret = crl.setNextUpdate(nextUpdate);
        assertEquals(WolfSSL.SSL_SUCCESS, ret);

        /* Verify date was set */
        Date retrieved = crl.getNextUpdate();
        assertNotNull(retrieved);
        /* Allow some tolerance for date comparison */
        long diff = Math.abs(retrieved.getTime() - nextUpdate.getTime());
        assertTrue("Date should be within 1 second", diff < 1000);

        /* Test null date */
        try {
            crl.setNextUpdate(null);
            System.out.println("\t\t\t... failed");
            fail("null date should throw exception");
        } catch (IllegalArgumentException e) {
            /* expected */
        }

        crl.free();
        System.out.println("\t\t\t... passed");
    }

    @Test
    public void testAddRevoked()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException {

        System.out.print("\taddRevoked()");

        if (!WolfSSL.CrlGenerationEnabled()) {
            /* CRL generation not enabled in wolfSSL */
            System.out.println("\t\t\t... skipped");
            return;
        }

        WolfSSLCRL crl = new WolfSSLCRL();
        assertNotNull(crl);

        /* Add revoked certificate by serial number */
        byte[] serial1 = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        Date revDate1 = new Date();
        int ret = crl.addRevoked(serial1, revDate1);
        assertTrue("addRevoked should succeed", ret >= 0);

        /* Add another revoked certificate */
        byte[] serial2 = new byte[] { 0x05, 0x06, 0x07, 0x08 };
        Date revDate2 = new Date();
        ret = crl.addRevoked(serial2, revDate2);
        assertTrue("addRevoked should succeed", ret >= 0);

        /* Add revoked certificate without revocation date */
        byte[] serial3 = new byte[] { 0x09, 0x0A, 0x0B, 0x0C };
        ret = crl.addRevoked(serial3, null);
        assertTrue("addRevoked should succeed", ret >= 0);

        /* Test null serial number */
        try {
            crl.addRevoked(null, new Date());
            System.out.println("\t\t\t... failed");
            fail("null serial number should throw exception");
        } catch (IllegalArgumentException e) {
            /* expected */
        }

        /* Test empty serial number */
        try {
            crl.addRevoked(new byte[0], new Date());
            System.out.println("\t\t\t... failed");
            fail("empty serial number should throw exception");
        } catch (IllegalArgumentException e) {
            /* expected */
        }

        crl.free();
        System.out.println("\t\t\t... passed");
    }

    @Test
    public void testAddRevokedCert_ByteArray()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException {

        System.out.print("\taddRevokedCert(byte[])");

        if (!WolfSSL.CrlGenerationEnabled()) {
            /* CRL generation not enabled in wolfSSL */
            System.out.println("\t\t... skipped");
            return;
        }

        WolfSSLCRL crl = new WolfSSLCRL();
        assertNotNull(crl);

        /* Load certificate from PEM file and convert to DER */
        WolfSSLCertificate cert = new WolfSSLCertificate(clientCertPem,
            WolfSSL.SSL_FILETYPE_PEM);
        assertNotNull(cert);
        byte[] certDer = cert.getDer();
        assertNotNull(certDer);
        assertTrue(certDer.length > 0);

        /* Add revoked certificate by DER */
        Date revDate = new Date();
        int ret = crl.addRevokedCert(certDer, revDate);
        assertTrue("addRevokedCert should succeed", ret >= 0);

        /* Add revoked certificate without revocation date */
        ret = crl.addRevokedCert(certDer, null);
        assertTrue("addRevokedCert should succeed", ret >= 0);

        /* Test null certificate DER */
        try {
            crl.addRevokedCert((byte[])null, new Date());
            System.out.println("\t\t... failed");
            fail("null certificate DER should throw exception");
        } catch (IllegalArgumentException e) {
            /* expected */
        }

        /* Test empty certificate DER */
        try {
            crl.addRevokedCert(new byte[0], new Date());
            System.out.println("\t\t... failed");
            fail("empty certificate DER should throw exception");
        } catch (IllegalArgumentException e) {
            /* expected */
        }

        crl.free();
        System.out.println("\t\t... passed");
    }

    @Test
    public void testAddRevokedCert_WolfSSLCertificate()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException {

        System.out.print("\taddRevokedCert(WolfSSLCertificate)");

        if (!WolfSSL.CrlGenerationEnabled()) {
            /* CRL generation not enabled in wolfSSL */
            System.out.println("\t... skipped");
            return;
        }

        WolfSSLCRL crl = new WolfSSLCRL();
        assertNotNull(crl);

        /* Load certificate */
        WolfSSLCertificate cert = new WolfSSLCertificate(clientCertPem,
            WolfSSL.SSL_FILETYPE_PEM);
        assertNotNull(cert);

        /* Add revoked certificate */
        Date revDate = new Date();
        int ret = crl.addRevokedCert(cert, revDate);
        assertTrue("addRevokedCert should succeed", ret >= 0);

        /* Add revoked certificate without revocation date */
        WolfSSLCertificate cert2 = new WolfSSLCertificate(clientCertPem,
            WolfSSL.SSL_FILETYPE_PEM);
        ret = crl.addRevokedCert(cert2, null);
        assertTrue("addRevokedCert should succeed", ret >= 0);

        /* Test null certificate */
        try {
            crl.addRevokedCert((WolfSSLCertificate)null, new Date());
            System.out.println("\t... failed");
            fail("null certificate should throw exception");
        } catch (IllegalArgumentException e) {
            /* expected */
        }

        /* Free native memory */
        cert.free();
        cert2.free();
        crl.free();
        System.out.println("\t... passed");
    }

    @Test
    public void testSign_PrivateKey()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException, NoSuchAlgorithmException {

        System.out.print("\tsign(PrivateKey)");

        if (!WolfSSL.CrlGenerationEnabled()) {
            /* CRL generation not enabled in wolfSSL */
            System.out.println("\t\t... skipped");
            return;
        }

        WolfSSLCRL crl = new WolfSSLCRL();
        assertNotNull(crl);

        /* Set issuer name */
        WolfSSLX509Name issuerName = GenerateTestIssuerName();
        crl.setIssuerName(issuerName);

        /* Set dates */
        crl.setLastUpdate(new Date());
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_YEAR, 30);
        crl.setNextUpdate(cal.getTime());

        /* Add revoked certificate */
        byte[] serial = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        crl.addRevoked(serial, new Date());

        /* Sign with RSA key from file */
        byte[] keyBytes = Files.readAllBytes(Paths.get(caKeyDer));
        /* Note: sign() method expects PrivateKey object, not byte array */
        /* We'll test with generated key pair instead */

        /* Generate RSA key pair */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        PrivateKey privKey = keyPair.getPrivate();

        /* Sign CRL */
        int ret = crl.sign(privKey, "SHA256");
        assertTrue("sign should succeed", ret >= 0);

        /* Test null private key */
        try {
            crl.sign(null, "SHA256");
            System.out.println("\t\t... failed");
            fail("null private key should throw exception");
        } catch (IllegalArgumentException e) {
            /* expected */
        }

        /* Free native memory */
        issuerName.free();
        crl.free();
        System.out.println("\t\t... passed");
    }

    @Test
    public void testWriteToFile()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException, NoSuchAlgorithmException {

        System.out.print("\twriteToFile()");

        if (!WolfSSL.CrlGenerationEnabled()) {
            /* CRL generation not enabled in wolfSSL */
            System.out.println("\t\t\t... skipped");
            return;
        }

        WolfSSLCRL crl = new WolfSSLCRL();
        assertNotNull(crl);

        /* Set issuer name */
        WolfSSLX509Name issuerName = GenerateTestIssuerName();
        crl.setIssuerName(issuerName);

        /* Set dates */
        crl.setLastUpdate(new Date());
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_YEAR, 30);
        crl.setNextUpdate(cal.getTime());

        /* Add revoked certificate */
        byte[] serial = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        crl.addRevoked(serial, new Date());

        /* Sign CRL */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        PrivateKey privKey = keyPair.getPrivate();
        crl.sign(privKey, "SHA256");

        /* Write to DER file */
        File tempDer = File.createTempFile("test_crl_", ".der");
        int ret = crl.writeToFile(tempDer.getAbsolutePath(),
            WolfSSL.SSL_FILETYPE_ASN1);
        assertTrue("writeToFile DER should succeed", ret >= 0);
        assertTrue(tempDer.exists());
        assertTrue(tempDer.length() > 0);
        tempDer.delete();

        /* Write to PEM file */
        File tempPem = File.createTempFile("test_crl_", ".pem");
        ret = crl.writeToFile(tempPem.getAbsolutePath(),
            WolfSSL.SSL_FILETYPE_PEM);
        assertTrue("writeToFile PEM should succeed", ret >= 0);
        assertTrue(tempPem.exists());
        assertTrue(tempPem.length() > 0);
        tempPem.delete();

        /* Test null path */
        try {
            crl.writeToFile(null, WolfSSL.SSL_FILETYPE_PEM);
            System.out.println("\t\t\t... failed");
            fail("null path should throw exception");
        } catch (IllegalArgumentException e) {
            /* expected */
        }

        /* Test empty path */
        try {
            crl.writeToFile("", WolfSSL.SSL_FILETYPE_PEM);
            System.out.println("\t\t\t... failed");
            fail("empty path should throw exception");
        } catch (IllegalArgumentException e) {
            /* expected */
        }

        /* Test invalid format */
        try {
            crl.writeToFile("test.der", 12345);
            System.out.println("\t\t\t... failed");
            fail("invalid format should throw exception");
        } catch (IllegalArgumentException e) {
            /* expected */
        }

        /* Free native memory */
        issuerName.free();
        crl.free();
        System.out.println("\t\t\t... passed");
    }

    @Test
    public void testGetDer()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException, NoSuchAlgorithmException {

        System.out.print("\tgetDer()");

        if (!WolfSSL.CrlGenerationEnabled()) {
            /* CRL generation not enabled in wolfSSL */
            System.out.println("\t\t\t... skipped");
            return;
        }

        WolfSSLCRL crl = new WolfSSLCRL();
        assertNotNull(crl);

        /* Set issuer name */
        WolfSSLX509Name issuerName = GenerateTestIssuerName();
        crl.setIssuerName(issuerName);

        /* Set dates */
        crl.setLastUpdate(new Date());
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_YEAR, 30);
        crl.setNextUpdate(cal.getTime());

        /* Add revoked certificate */
        byte[] serial = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        crl.addRevoked(serial, new Date());

        /* Sign CRL */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        PrivateKey privKey = keyPair.getPrivate();
        crl.sign(privKey, "SHA256");

        /* Get DER encoding */
        byte[] der = crl.getDer();
        assertNotNull(der);
        assertTrue(der.length > 0);

        /* Free native memory */
        issuerName.free();
        crl.free();
        System.out.println("\t\t\t... passed");
    }

    @Test
    public void testGetPem()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException, NoSuchAlgorithmException {

        System.out.print("\tgetPem()");

        if (!WolfSSL.CrlGenerationEnabled()) {
            /* CRL generation not enabled in wolfSSL */
            System.out.println("\t\t\t... skipped");
            return;
        }

        WolfSSLCRL crl = new WolfSSLCRL();
        assertNotNull(crl);

        /* Set issuer name */
        WolfSSLX509Name issuerName = GenerateTestIssuerName();
        crl.setIssuerName(issuerName);

        /* Set dates */
        crl.setLastUpdate(new Date());
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_YEAR, 30);
        crl.setNextUpdate(cal.getTime());

        /* Add revoked certificate */
        byte[] serial = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        crl.addRevoked(serial, new Date());

        /* Sign CRL */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        PrivateKey privKey = keyPair.getPrivate();
        crl.sign(privKey, "SHA256");

        /* Get PEM encoding */
        byte[] pem = crl.getPem();
        assertNotNull(pem);
        assertTrue(pem.length > 0);
        /* PEM should contain BEGIN/END markers */
        String pemStr = new String(pem);
        assertTrue(pemStr.contains("BEGIN"));
        assertTrue(pemStr.contains("CRL"));

        /* Free native memory */
        issuerName.free();
        crl.free();
        System.out.println("\t\t\t... passed");
    }

    @Test
    public void testGetVersion()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException {

        System.out.print("\tgetVersion()");

        if (!WolfSSL.CrlGenerationEnabled()) {
            /* CRL generation not enabled in wolfSSL */
            System.out.println("\t\t\t... skipped");
            return;
        }

        WolfSSLCRL crl = new WolfSSLCRL();
        assertNotNull(crl);

        /* Default version should be 2 (v3) */
        int version = crl.getVersion();
        if (version != 2) {
            System.out.println("\t\t\t... failed");
            fail("Default version should be 2 (v3)");
        }

        /* Set version to 1 (v2) */
        crl.setVersion(1);
        version = crl.getVersion();
        if (version != 1) {
            System.out.println("\t\t\t... failed");
            fail("Version should be 1 (v2)");
        }

        crl.free();
        System.out.println("\t\t\t... passed");
    }

    @Test
    public void testGenCRL_UsingFiles()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException, NoSuchAlgorithmException {

        System.out.print("\tgen CRL using files");

        if (!WolfSSL.CrlGenerationEnabled()) {
            /* CRL generation not enabled in wolfSSL */
            System.out.println("\t\t... skipped");
            return;
        }

        WolfSSLCRL crl = new WolfSSLCRL();
        assertNotNull(crl);

        /* Set version */
        crl.setVersion(1);

        /* Set issuer name */
        WolfSSLX509Name issuerName = GenerateTestIssuerName();
        assertNotNull(issuerName);
        crl.setIssuerName(issuerName);

        /* Set dates */
        Date lastUpdate = new Date();
        crl.setLastUpdate(lastUpdate);
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_YEAR, 30);
        Date nextUpdate = cal.getTime();
        crl.setNextUpdate(nextUpdate);

        /* Add revoked certificates by serial number */
        byte[] serial1 = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        Date revDate1 = new Date();
        crl.addRevoked(serial1, revDate1);

        byte[] serial2 = new byte[] { 0x05, 0x06, 0x07, 0x08 };
        Date revDate2 = new Date();
        crl.addRevoked(serial2, revDate2);

        /* Sign CRL with RSA key */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        PrivateKey privKey = keyPair.getPrivate();
        crl.sign(privKey, "SHA256");

        /* Output to DER and PEM */
        byte[] derCrl = crl.getDer();
        byte[] pemCrl = crl.getPem();

        assertNotNull(derCrl);
        assertTrue(derCrl.length > 0);
        assertNotNull(pemCrl);
        assertTrue(pemCrl.length > 0);

        /* Verify version */
        int version = crl.getVersion();
        assertEquals(1, version);

        /* Verify dates */
        Date retrievedLastUpdate = crl.getLastUpdate();
        assertNotNull(retrievedLastUpdate);
        Date retrievedNextUpdate = crl.getNextUpdate();
        assertNotNull(retrievedNextUpdate);

        /* Free native memory */
        issuerName.free();
        crl.free();

        System.out.println("\t\t... passed");
    }

    @Test
    public void testGenCRL_UsingCertificates()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException, NoSuchAlgorithmException {

        System.out.print("\tgen CRL using certificates");

        if (!WolfSSL.CrlGenerationEnabled()) {
            /* CRL generation not enabled in wolfSSL */
            System.out.println("\t... skipped");
            return;
        }

        WolfSSLCRL crl = new WolfSSLCRL();
        assertNotNull(crl);

        /* Set version */
        crl.setVersion(1);

        /* Set issuer name */
        WolfSSLX509Name issuerName = GenerateTestIssuerName();
        assertNotNull(issuerName);
        crl.setIssuerName(issuerName);

        /* Set dates */
        Date lastUpdate = new Date();
        crl.setLastUpdate(lastUpdate);
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_YEAR, 30);
        Date nextUpdate = cal.getTime();
        crl.setNextUpdate(nextUpdate);

        /* Add revoked certificates using WolfSSLCertificate objects */
        WolfSSLCertificate cert1 = new WolfSSLCertificate(clientCertPem,
            WolfSSL.SSL_FILETYPE_PEM);
        Date revDate1 = new Date();
        crl.addRevokedCert(cert1, revDate1);

        /* Sign CRL with RSA key */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        PrivateKey privKey = keyPair.getPrivate();
        crl.sign(privKey, "SHA256");

        /* Output to DER and PEM */
        byte[] derCrl = crl.getDer();
        byte[] pemCrl = crl.getPem();

        assertNotNull(derCrl);
        assertTrue(derCrl.length > 0);
        assertNotNull(pemCrl);
        assertTrue(pemCrl.length > 0);

        /* Free native memory */
        cert1.free();
        issuerName.free();
        crl.free();

        System.out.println("\t... passed");
    }

    @Test
    public void testGenCRL_ECC()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException, NoSuchAlgorithmException {

        System.out.print("\tgen CRL with ECC key");

        if (!WolfSSL.CrlGenerationEnabled()) {
            /* CRL generation not enabled in wolfSSL */
            System.out.println("\t\t... skipped");
            return;
        }

        if (!WolfSSL.EccEnabled()) {
            System.out.println("\t\t... skipped (ECC not enabled)");
            return;
        }

        WolfSSLCRL crl = new WolfSSLCRL();
        assertNotNull(crl);

        /* Set version */
        crl.setVersion(1);

        /* Set issuer name */
        WolfSSLX509Name issuerName = GenerateTestIssuerName();
        assertNotNull(issuerName);
        crl.setIssuerName(issuerName);

        /* Set dates */
        Date lastUpdate = new Date();
        crl.setLastUpdate(lastUpdate);
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_YEAR, 30);
        Date nextUpdate = cal.getTime();
        crl.setNextUpdate(nextUpdate);

        /* Add revoked certificate */
        byte[] serial = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        Date revDate = new Date();
        crl.addRevoked(serial, revDate);

        /* Sign CRL with ECC key */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair keyPair = kpg.generateKeyPair();
        PrivateKey privKey = keyPair.getPrivate();
        crl.sign(privKey, "SHA256");

        /* Output to DER and PEM */
        byte[] derCrl = crl.getDer();
        byte[] pemCrl = crl.getPem();

        assertNotNull(derCrl);
        assertTrue(derCrl.length > 0);
        assertNotNull(pemCrl);
        assertTrue(pemCrl.length > 0);

        /* Free native memory */
        issuerName.free();
        crl.free();

        System.out.println("\t\t... passed");
    }

    @Test
    public void testFree()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException {

        System.out.print("\tfree()");

        if (!WolfSSL.CrlGenerationEnabled()) {
            /* CRL generation not enabled in wolfSSL */
            System.out.println("\t\t\t... skipped");
            return;
        }

        WolfSSLCRL crl = new WolfSSLCRL();
        assertNotNull(crl);

        /* Free should work */
        crl.free();

        /* Operations after free should throw IllegalStateException */
        try {
            crl.setVersion(1);
            System.out.println("\t\t\t... failed");
            fail("setVersion after free should throw exception");
        } catch (IllegalStateException e) {
            /* expected */
        }

        try {
            crl.getVersion();
            System.out.println("\t\t\t... failed");
            fail("getVersion after free should throw exception");
        } catch (IllegalStateException e) {
            /* expected */
        }

        /* Multiple free() calls should be safe */
        crl.free();

        System.out.println("\t\t\t... passed");
    }
}
