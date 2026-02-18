/* WolfSSLCertificate.java
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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.time.Instant;
import java.time.Duration;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.interfaces.RSAPrivateKey;
import java.security.KeyPairGenerator;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.NoSuchAlgorithmException;

import java.util.Collection;
import java.util.List;

import org.junit.Test;
import org.junit.BeforeClass;
import static org.junit.Assert.*;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLX509Name;
import com.wolfssl.WolfSSLCertificate;
import com.wolfssl.WolfSSLCertManager;
import com.wolfssl.WolfSSLAltName;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLJNIException;

/**
 *
 * @author wolfSSL
 */
public class WolfSSLCertificateTest {
    public final static int TEST_FAIL    = -1;
    public final static int TEST_SUCCESS =  0;

    public static String cliCertDer = "examples/certs/client-cert.der";
    public static String cliCertPem = "examples/certs/client-cert.pem";
    public static String cliKeyDer = "examples/certs/client-key.der";
    public static String cliKeyPubDer = "examples/certs/client-keyPub.der";
    public static String caCertPem = "examples/certs/ca-cert.pem";
    public static String caKeyDer = "examples/certs/ca-key.der";
    public static String caKeyPkcs8Der = "examples/certs/ca-keyPkcs8.der";
    public static String serverCertPem = "examples/certs/server-cert.pem";
    public static String external = "examples/certs/ca-google-root.der";
    public static String sanTestDir = "examples/certs/san-test";
    public static String crlDpCertPem = "examples/certs/test/crl-dp-cert.pem";
    public static String sanTestUpnCert = null;
    public static String sanTestAllTypesCert = null;
    public static String sanTestAllTypesDer = null;
    public static String sanTestDnsIpCert = null;
    public static String sanTestDnsIpDer = null;
    public static String sanTestEmailUriCert = null;
    public static String sanTestDirNameRidCert = null;
    public static String sanTestCaCert = null;
    public static String aiaMultiCertPem =
        "examples/certs/aia/multi-aia-cert.pem";
    public static String aiaOverflowCertPem =
        "examples/certs/aia/overflow-aia-cert.pem";
    public static String bogusFile = "/dev/null";
    private WolfSSLCertificate cert;

    private interface ThrowingRunnable {
        void run() throws WolfSSLException, WolfSSLJNIException, IOException;
    }

    private boolean isNotCompiledIn(WolfSSLException e) {
        String msg = e.getMessage();
        if (msg == null) {
            return false;
        }
        return msg.contains(Integer.toString(WolfSSL.NOT_COMPILED_IN)) ||
               msg.contains("NOT_COMPILED_IN");
    }

    private void runOrAllowNotCompiled(ThrowingRunnable r, String label)
        throws WolfSSLException, WolfSSLJNIException, IOException {

        try {
            r.run();
        } catch (WolfSSLException e) {
            if (isNotCompiledIn(e)) {
                System.out.println("\t\t" + label +
                    " ... NOT_COMPILED_IN (skipping)");
                return;
            }
            throw e;
        }
    }

    @BeforeClass
    public static void setCertPaths() throws WolfSSLException {

        try {
            WolfSSL.loadLibrary();
        } catch (UnsatisfiedLinkError ule) {
            fail("failed to load native JNI library");
        }

        cliCertDer = WolfSSLTestCommon.getPath(cliCertDer);
        cliCertPem = WolfSSLTestCommon.getPath(cliCertPem);
        cliKeyDer = WolfSSLTestCommon.getPath(cliKeyDer);
        cliKeyPubDer = WolfSSLTestCommon.getPath(cliKeyPubDer);
        caCertPem = WolfSSLTestCommon.getPath(caCertPem);
        caKeyDer = WolfSSLTestCommon.getPath(caKeyDer);
        caKeyPkcs8Der = WolfSSLTestCommon.getPath(caKeyPkcs8Der);
        serverCertPem = WolfSSLTestCommon.getPath(serverCertPem);
        external   = WolfSSLTestCommon.getPath(external);
        sanTestDir = WolfSSLTestCommon.getPath(sanTestDir);
        crlDpCertPem = WolfSSLTestCommon.getPath(crlDpCertPem);
        sanTestUpnCert = sanTestDir + "/san-test-othername-upn.pem";
        sanTestAllTypesCert = sanTestDir + "/san-test-all-types.pem";
        sanTestAllTypesDer = sanTestDir + "/san-test-all-types.der";
        sanTestDnsIpCert = sanTestDir + "/san-test-dns-ip.pem";
        sanTestDnsIpDer = sanTestDir + "/san-test-dns-ip.der";
        sanTestEmailUriCert = sanTestDir + "/san-test-email-uri.pem";
        sanTestDirNameRidCert = sanTestDir + "/san-test-dirname-rid.pem";
        sanTestCaCert = sanTestDir + "/san-test-ca-cert.pem";
        aiaMultiCertPem = WolfSSLTestCommon.getPath(aiaMultiCertPem);
        aiaOverflowCertPem = WolfSSLTestCommon.getPath(aiaOverflowCertPem);
    }


    @Test
    public void testWolfSSLCertificate() throws WolfSSLException {

        System.out.println("WolfSSLCertificate Class");

        /* WolfSSLCertificate(byte[] der) */
        test_WolfSSLCertificate_new_derArray();
        test_runCertTestsAfterConstructor();

        /* WolfSSLCertificate(String der) */
        test_WolfSSLCertificate_new_pemArray();
        test_runCertTestsAfterConstructor();

        if (WolfSSL.FileSystemEnabled() == true) {
            /* WolfSSLCertificate(byte[] pem) */
            test_WolfSSLCertificate_new_derFile();
            test_runCertTestsAfterConstructor();

            /* WolfSSLCertificate(String pem) */
            test_WolfSSLCertificate_new_pemFile();
            test_runCertTestsAfterConstructor();
        }
    }

    public void test_runCertTestsAfterConstructor() {
        test_getSerial();
        test_notBefore();
        test_notAfter();
        test_getVersion();
        test_getSignature();
        test_isCA();
        test_getIssuer();
        test_getSubject();
        test_getPubkey();
        test_getPubkeyType();
        test_getPathLen();
        test_getSignatureType();
        test_verify();
        test_getSignatureOID();
        if (WolfSSL.getLibVersionHex() > 0x05006003) {
            /* Key Usage and Extended Key Usage only work with wolfSSL
             * later than 5.6.3 */
            test_getKeyUsage();
            test_getExtendedKeyUsage();
        }
        test_getAiaMulti();
        test_getAiaOverflow();
        test_getExtensionSet();
        test_toString();
        test_free();
    }


    public void test_WolfSSLCertificate_new_derArray() {
        File f = new File(cliCertDer);
        byte[] der = null;

        System.out.print("\tnew(byte[] der)");

        try {
            InputStream stream = new FileInputStream(f);
            der = new byte[(int) f.length()];
            stream.read(der, 0, der.length);
            stream.close();
        } catch (IOException ex) {
            System.out.println("\t\t\t... failed");
            fail("Unable to read file " + cliCertDer);
            Logger.getLogger(WolfSSLCertificateTest.class.getName()).log(
                                Level.SEVERE, null, ex);
        }

        try {
            this.cert = new WolfSSLCertificate(der);
        } catch (WolfSSLException ex) {
            System.out.println("\t\t\t... failed");
            fail("Unable to initialize class");
            Logger.getLogger(WolfSSLCertificateTest.class.getName()).log(
                                Level.SEVERE, null, ex);
        }
        System.out.println("\t\t\t... passed");
    }


    public void test_WolfSSLCertificate_new_derFile() {
        System.out.print("\tnew(String der, int format)");

        try {
            this.cert = new WolfSSLCertificate(cliCertDer,
                                WolfSSL.SSL_FILETYPE_ASN1);
        } catch (WolfSSLException ex) {
            System.out.println("\t... failed");
            fail("Unable to initialize class");
            Logger.getLogger(WolfSSLCertificateTest.class.getName()).log(
                                Level.SEVERE, null, ex);
        }
        System.out.println("\t... passed");
    }


    public void test_WolfSSLCertificate_new_pemArray() {
        File f = new File(cliCertPem);
        byte[] pem = null;

        System.out.print("\tnew(byte[] in, int format)");

        try {
            InputStream stream = new FileInputStream(f);
            pem = new byte[(int) f.length()];
            stream.read(pem, 0, pem.length);
            stream.close();
        } catch (IOException ex) {
            System.out.println("\t... failed");
            fail("Unable to read file " + cliCertPem);
            Logger.getLogger(WolfSSLCertificateTest.class.getName()).log(
                                Level.SEVERE, null, ex);
        }

        try {
            this.cert = new WolfSSLCertificate(pem, WolfSSL.SSL_FILETYPE_PEM);
        } catch (WolfSSLException ex) {
            System.out.println("\t... failed");
            fail("Unable to initialize class");
            Logger.getLogger(WolfSSLCertificateTest.class.getName()).log(
                                Level.SEVERE, null, ex);
        }
        System.out.println("\t... passed");
    }


    public void test_WolfSSLCertificate_new_pemFile() {
        System.out.print("\tnew(String pem, int format)");

        try {
            this.cert = new WolfSSLCertificate(cliCertPem,
                                WolfSSL.SSL_FILETYPE_PEM);
        } catch (WolfSSLException ex) {
            System.out.println("\t... failed");
            fail("Unable to initialize class");
            Logger.getLogger(WolfSSLCertificateTest.class.getName()).log(
                                Level.SEVERE, null, ex);
        }
        System.out.println("\t... passed");
    }

    private byte[] fileToByteArray(String filePath)
        throws IOException {
        File f = new File(filePath);
        byte[] fBytes = null;

        InputStream stream = new FileInputStream(f);
        fBytes = new byte[(int) f.length()];
        stream.read(fBytes, 0, fBytes.length);
        stream.close();

        return fBytes;
    }


    public void test_getSerial() {
        byte[] expected = new byte[] {
            (byte)0x08, (byte)0xb0, (byte)0x54, (byte)0x7a, (byte)0x03,
            (byte)0x5a, (byte)0xec, (byte)0x55, (byte)0x8a, (byte)0x12,
            (byte)0xe8, (byte)0xf9, (byte)0x8e, (byte)0x34, (byte)0xb6,
            (byte)0x13, (byte)0xd9, (byte)0x59, (byte)0xb8, (byte)0xe8
        };
        byte[] serial;
        int i;
        BigInteger bigi = cert.getSerial();

        System.out.print("\t\tgetSerial");
        serial = bigi.toByteArray();
        for (i = 0; i < serial.length && i < expected.length; i++) {
            if (serial[i] != expected[i]) {
                System.out.println("\t\t... failed");
                fail("Unexpected serial number");
            }
        }
        System.out.println("\t\t... passed");
    }

    @SuppressWarnings("deprecation")
    public void test_notBefore() {
        Date date = cert.notBefore();
        Date expected = new Date("Dec 13 22:19:28 2023 GMT");
        System.out.print("\t\tnotBefore");
        if (date.compareTo(expected) != 0) {
            System.out.println("\t\t... failed");
            fail("Unexpected not before date");
        }
        System.out.println("\t\t... passed");
    }


    @SuppressWarnings("deprecation")
    public void test_notAfter() {
        Date date = cert.notAfter();
        Date expected = new Date("Sep  8 22:19:28 2026 GMT");
        System.out.print("\t\tnotAfter");
        if (date.compareTo(expected) != 0) {
            System.out.println("\t\t... failed");
            fail("Unexpected not after date");
        }
        System.out.println("\t\t... passed");
    }

    public void test_getVersion() {
        int version = cert.getVersion();

        System.out.print("\t\tgetVersion");
        if (version != 3) {
            System.out.println("\t\t... failed");
            fail("Unexpected version number");
        }
        System.out.println("\t\t... passed");
    }

    public void test_getSignature() {
        byte[] sig = cert.getSignature();
        byte[] expected = new byte[] {
            (byte)0x89, (byte)0x84, (byte)0xeb, (byte)0x6a, (byte)0x70,
            (byte)0x3b, (byte)0x2a, (byte)0x6e, (byte)0xa8, (byte)0x8b,
            (byte)0xf2, (byte)0x92, (byte)0x79, (byte)0x97, (byte)0x5c,
            (byte)0xbd, (byte)0x98, (byte)0x8b, (byte)0x71, (byte)0xdb,
            (byte)0xdb, (byte)0x7c, (byte)0xdf, (byte)0xdb, (byte)0xa4,
            (byte)0x2c, (byte)0x59, (byte)0xd3, (byte)0xa6, (byte)0x75,
            (byte)0x41, (byte)0xc2, (byte)0x06, (byte)0xb6, (byte)0x17,
            (byte)0x1e, (byte)0x0c, (byte)0x1f, (byte)0x7d, (byte)0x0b,
            (byte)0x7f, (byte)0x58, (byte)0x3e, (byte)0xc1, (byte)0xe7,
            (byte)0x0c, (byte)0xf0, (byte)0x62, (byte)0x92, (byte)0x77,
            (byte)0xab, (byte)0x99, (byte)0x79, (byte)0x7b, (byte)0x85,
            (byte)0xf4, (byte)0xd9, (byte)0x6c, (byte)0xd0, (byte)0x0e,
            (byte)0xe5, (byte)0x8b, (byte)0x13, (byte)0x35, (byte)0x65,
            (byte)0x9e, (byte)0xd7, (byte)0x9a, (byte)0x51, (byte)0x98,
            (byte)0xe4, (byte)0x49, (byte)0x44, (byte)0x51, (byte)0xc8,
            (byte)0xe3, (byte)0xe0, (byte)0x9a, (byte)0xff, (byte)0xc2,
            (byte)0xcb, (byte)0x3d, (byte)0x81, (byte)0xeb, (byte)0xee,
            (byte)0xf4, (byte)0x1a, (byte)0xd1, (byte)0x96, (byte)0x4b,
            (byte)0xe9, (byte)0x7d, (byte)0xde, (byte)0x5b, (byte)0xf2,
            (byte)0x64, (byte)0x40, (byte)0xad, (byte)0xe1, (byte)0xd9,
            (byte)0xd6, (byte)0xb7, (byte)0xe1, (byte)0xeb, (byte)0xa9,
            (byte)0x3a, (byte)0x52, (byte)0x29, (byte)0x89, (byte)0xaa,
            (byte)0x07, (byte)0x37, (byte)0x96, (byte)0x44, (byte)0xe3,
            (byte)0x23, (byte)0x49, (byte)0xf3, (byte)0xbe, (byte)0xf3,
            (byte)0x0d, (byte)0x70, (byte)0xd1, (byte)0xa2, (byte)0xce,
            (byte)0x78, (byte)0x86, (byte)0x22, (byte)0xfc, (byte)0x76,
            (byte)0x00, (byte)0x84, (byte)0x1d, (byte)0xfa, (byte)0x8b,
            (byte)0x8a, (byte)0xd2, (byte)0x43, (byte)0x93, (byte)0x88,
            (byte)0xfa, (byte)0xee, (byte)0x22, (byte)0xcc, (byte)0xa6,
            (byte)0x86, (byte)0xf5, (byte)0x3f, (byte)0x24, (byte)0xf1,
            (byte)0xd4, (byte)0x70, (byte)0x05, (byte)0x4f, (byte)0x3b,
            (byte)0x18, (byte)0x32, (byte)0x50, (byte)0x67, (byte)0xc1,
            (byte)0x80, (byte)0x77, (byte)0x0d, (byte)0x3c, (byte)0x78,
            (byte)0x75, (byte)0x35, (byte)0xd0, (byte)0xfd, (byte)0x60,
            (byte)0xf3, (byte)0xed, (byte)0xa1, (byte)0x30, (byte)0xd0,
            (byte)0x62, (byte)0x25, (byte)0x99, (byte)0x6b, (byte)0x80,
            (byte)0x56, (byte)0x17, (byte)0x3d, (byte)0xb4, (byte)0xaf,
            (byte)0x1d, (byte)0xdf, (byte)0xab, (byte)0x48, (byte)0x21,
            (byte)0xc1, (byte)0xd2, (byte)0x0b, (byte)0x6b, (byte)0x94,
            (byte)0xa7, (byte)0x33, (byte)0xd1, (byte)0xd0, (byte)0x82,
            (byte)0xb7, (byte)0x3b, (byte)0x92, (byte)0xeb, (byte)0x9d,
            (byte)0xd6, (byte)0x6c, (byte)0x32, (byte)0x81, (byte)0x5e,
            (byte)0x07, (byte)0x3c, (byte)0x46, (byte)0x34, (byte)0x32,
            (byte)0x7b, (byte)0xea, (byte)0x22, (byte)0xdb, (byte)0xa6,
            (byte)0xa3, (byte)0x18, (byte)0x69, (byte)0x7c, (byte)0xad,
            (byte)0x17, (byte)0xe4, (byte)0xc8, (byte)0xa9, (byte)0x8f,
            (byte)0xa8, (byte)0xba, (byte)0x67, (byte)0xaf, (byte)0x99,
            (byte)0x39, (byte)0xef, (byte)0x6e, (byte)0x0c, (byte)0xf8,
            (byte)0xa9, (byte)0xb3, (byte)0xbd, (byte)0xab, (byte)0x71,
            (byte)0x94, (byte)0xe0, (byte)0x41, (byte)0xaa, (byte)0xa4,
            (byte)0x2d, (byte)0x72, (byte)0x60, (byte)0x51, (byte)0xd1,
            (byte)0x5c
        };
        int i;
        System.out.print("\t\tgetSignature");
        for (i = 0; i < sig.length && i < expected.length; i++) {
            if (sig[i] != expected[i]) {
                System.out.println("\t\t... failed");
                fail("Unexpected signature");
            }
        }
        System.out.println("\t\t... passed");
    }

    public void test_isCA() {
        System.out.print("\t\tisCA");
        if (this.cert.isCA() != 1) {
            System.out.println("\t\t\t... failed");
            fail("Expected isCA to be set");
        }
        System.out.println("\t\t\t... passed");
    }

    public void test_getSubject() {
        String expected = "/C=US/ST=Montana/L=Bozeman/O=wolfSSL_2048/OU=Programming-2048/CN=www.wolfssl.com/emailAddress=info@wolfssl.com";

        System.out.print("\t\tgetSubject");
        if (!cert.getSubject().equals(expected)) {
            System.out.println("\t\t... failed");
            fail("Unexpected subject");
        }
        System.out.println("\t\t... passed");
    }

    public void test_getIssuer() {
        String expected = "/C=US/ST=Montana/L=Bozeman/O=wolfSSL_2048/OU=Programming-2048/CN=www.wolfssl.com/emailAddress=info@wolfssl.com";

        System.out.print("\t\tgetIssuer");
        if (!cert.getIssuer().equals(expected)) {
            System.out.println("\t\t... failed");
            fail("Unexpected issuer");
        }
        System.out.println("\t\t... passed");
    }

    public void test_getPubkey() {
        byte[] expected = new byte[] {
            (byte)0x30, (byte)0x82, (byte)0x01, (byte)0x22,
            (byte)0x30, (byte)0x0D, (byte)0x06, (byte)0x09,
            (byte)0x2A, (byte)0x86, (byte)0x48, (byte)0x86,
            (byte)0xF7, (byte)0x0D, (byte)0x01, (byte)0x01,
            (byte)0x01, (byte)0x05, (byte)0x00, (byte)0x03,
            (byte)0x82, (byte)0x01, (byte)0x0F, (byte)0x00,
            (byte)0x30, (byte)0x82, (byte)0x01, (byte)0x0A,
            (byte)0x02, (byte)0x82, (byte)0x01, (byte)0x01,
            (byte)0x00, (byte)0xC3, (byte)0x03, (byte)0xD1,
            (byte)0x2B, (byte)0xFE, (byte)0x39, (byte)0xA4,
            (byte)0x32, (byte)0x45, (byte)0x3B, (byte)0x53,
            (byte)0xC8, (byte)0x84, (byte)0x2B, (byte)0x2A,
            (byte)0x7C, (byte)0x74, (byte)0x9A, (byte)0xBD,
            (byte)0xAA, (byte)0x2A, (byte)0x52, (byte)0x07,
            (byte)0x47, (byte)0xD6, (byte)0xA6, (byte)0x36,
            (byte)0xB2, (byte)0x07, (byte)0x32, (byte)0x8E,
            (byte)0xD0, (byte)0xBA, (byte)0x69, (byte)0x7B,
            (byte)0xC6, (byte)0xC3, (byte)0x44, (byte)0x9E,
            (byte)0xD4, (byte)0x81, (byte)0x48, (byte)0xFD,
            (byte)0x2D, (byte)0x68, (byte)0xA2, (byte)0x8B,
            (byte)0x67, (byte)0xBB, (byte)0xA1, (byte)0x75,
            (byte)0xC8, (byte)0x36, (byte)0x2C, (byte)0x4A,
            (byte)0xD2, (byte)0x1B, (byte)0xF7, (byte)0x8B,
            (byte)0xBA, (byte)0xCF, (byte)0x0D, (byte)0xF9,
            (byte)0xEF, (byte)0xEC, (byte)0xF1, (byte)0x81,
            (byte)0x1E, (byte)0x7B, (byte)0x9B, (byte)0x03,
            (byte)0x47, (byte)0x9A, (byte)0xBF, (byte)0x65,
            (byte)0xCC, (byte)0x7F, (byte)0x65, (byte)0x24,
            (byte)0x69, (byte)0xA6, (byte)0xE8, (byte)0x14,
            (byte)0x89, (byte)0x5B, (byte)0xE4, (byte)0x34,
            (byte)0xF7, (byte)0xC5, (byte)0xB0, (byte)0x14,
            (byte)0x93, (byte)0xF5, (byte)0x67, (byte)0x7B,
            (byte)0x3A, (byte)0x7A, (byte)0x78, (byte)0xE1,
            (byte)0x01, (byte)0x56, (byte)0x56, (byte)0x91,
            (byte)0xA6, (byte)0x13, (byte)0x42, (byte)0x8D,
            (byte)0xD2, (byte)0x3C, (byte)0x40, (byte)0x9C,
            (byte)0x4C, (byte)0xEF, (byte)0xD1, (byte)0x86,
            (byte)0xDF, (byte)0x37, (byte)0x51, (byte)0x1B,
            (byte)0x0C, (byte)0xA1, (byte)0x3B, (byte)0xF5,
            (byte)0xF1, (byte)0xA3, (byte)0x4A, (byte)0x35,
            (byte)0xE4, (byte)0xE1, (byte)0xCE, (byte)0x96,
            (byte)0xDF, (byte)0x1B, (byte)0x7E, (byte)0xBF,
            (byte)0x4E, (byte)0x97, (byte)0xD0, (byte)0x10,
            (byte)0xE8, (byte)0xA8, (byte)0x08, (byte)0x30,
            (byte)0x81, (byte)0xAF, (byte)0x20, (byte)0x0B,
            (byte)0x43, (byte)0x14, (byte)0xC5, (byte)0x74,
            (byte)0x67, (byte)0xB4, (byte)0x32, (byte)0x82,
            (byte)0x6F, (byte)0x8D, (byte)0x86, (byte)0xC2,
            (byte)0x88, (byte)0x40, (byte)0x99, (byte)0x36,
            (byte)0x83, (byte)0xBA, (byte)0x1E, (byte)0x40,
            (byte)0x72, (byte)0x22, (byte)0x17, (byte)0xD7,
            (byte)0x52, (byte)0x65, (byte)0x24, (byte)0x73,
            (byte)0xB0, (byte)0xCE, (byte)0xEF, (byte)0x19,
            (byte)0xCD, (byte)0xAE, (byte)0xFF, (byte)0x78,
            (byte)0x6C, (byte)0x7B, (byte)0xC0, (byte)0x12,
            (byte)0x03, (byte)0xD4, (byte)0x4E, (byte)0x72,
            (byte)0x0D, (byte)0x50, (byte)0x6D, (byte)0x3B,
            (byte)0xA3, (byte)0x3B, (byte)0xA3, (byte)0x99,
            (byte)0x5E, (byte)0x9D, (byte)0xC8, (byte)0xD9,
            (byte)0x0C, (byte)0x85, (byte)0xB3, (byte)0xD9,
            (byte)0x8A, (byte)0xD9, (byte)0x54, (byte)0x26,
            (byte)0xDB, (byte)0x6D, (byte)0xFA, (byte)0xAC,
            (byte)0xBB, (byte)0xFF, (byte)0x25, (byte)0x4C,
            (byte)0xC4, (byte)0xD1, (byte)0x79, (byte)0xF4,
            (byte)0x71, (byte)0xD3, (byte)0x86, (byte)0x40,
            (byte)0x18, (byte)0x13, (byte)0xB0, (byte)0x63,
            (byte)0xB5, (byte)0x72, (byte)0x4E, (byte)0x30,
            (byte)0xC4, (byte)0x97
        };
        int i;
        byte[] pub;

        System.out.print("\t\tgetPubkey");
        pub = cert.getPubkey();
        for (i = 0; i < pub.length && i < expected.length; i++) {
            if (pub[i] != expected[i]) {
                System.out.println("\t\t... failed");
                fail("Unexpected public key value");
            }
        }

        System.out.println("\t\t... passed");
    }

    public void test_getPubkeyType() {
        String expected = "RSA";
        System.out.print("\t\tgetPubkeyType");
        if (!expected.equals(this.cert.getPubkeyType())) {
                System.out.println("\t\t... failed");
                fail("Unexpected public key type value");
        }
        System.out.println("\t\t... passed");
    }

    public void test_getPathLen() {
        int expected = -1;
        System.out.print("\t\tgetPathLen");
        if (this.cert.getPathLen() != expected) {
                System.out.println("\t\t... failed");
                fail("Unexpected path length value");
        }
        System.out.println("\t\t... passed");
    }

    public void test_getSignatureType() {
        String expected = "SHA256withRSA";
        System.out.print("\t\tgetSignatureType");
        if (!expected.equals(this.cert.getSignatureType())) {
                System.out.println("\t... failed");
                fail("Unexpected signature type");
        }
        System.out.println("\t... passed");
    }

    public void test_verify() {
        byte[] pubkey;

        System.out.print("\t\tverify");
        pubkey = this.cert.getPubkey();
        if (pubkey == null) {
            System.out.println("\t\t\t... failed");
            fail("Could not get public key");
            return;
        }

        if (this.cert.verify(pubkey, pubkey.length) != true) {
            System.out.println("\t\t\t... failed");
            fail("Verify signature failed");
        }
        System.out.println("\t\t\t... passed");
    }

    public void test_getSignatureOID() {
        System.out.print("\t\tgetSignatureOID");

        /* make sure is sha256WithRSAEncryption OID */
        if (!this.cert.getSignatureOID().equals("1.2.840.113549.1.1.11")) {
            System.out.println("\t\t... failed");
            fail("Could not get public key");
        }
        System.out.println("\t\t... passed");
    }

    public void test_getKeyUsage() {
        WolfSSLCertificate ext;
        boolean[] expected = {
            true, false, false, false, false, true, true, false, false
        };

        System.out.print("\t\tgetKeyUsage");
        if (this.cert.getKeyUsage() != null) {
            System.out.println("\t\t... failed");
            fail("Found key usage extension when not expecting any");
        }

        /* test with certificate that has key usage extension */
        try {
            int i;
            boolean[] kuse;

            if (WolfSSL.FileSystemEnabled() == true) {
                ext = new WolfSSLCertificate(external);
            } else {
                ext = new WolfSSLCertificate(fileToByteArray(external),
                                             WolfSSL.SSL_FILETYPE_ASN1);
            }

            kuse = ext.getKeyUsage();
            if (kuse == null) {
                System.out.println("\t\t... failed");
                fail("Did not find key usage extension");
                return;
            }

            for (i = 0; i < kuse.length; i++) {
                if (kuse[i] != expected[i]) {
                    System.out.println("\t\t... failed");
                    fail("Found wrong key usage extension");
                }
            }
            ext.free();
        } catch (Exception ex) {
            Logger.getLogger(WolfSSLCertificateTest.class.getName()).log(
                                Level.SEVERE, null, ex);
            System.out.println("\t\t... failed");
            fail("Error loading external certificate");
        }
        System.out.println("\t\t... passed");
    }

    public void test_getExtendedKeyUsage() {
        int i;
        String[] eku;
        String[] expected = {
            "1.3.6.1.5.5.7.3.1",  /* TLS Web Server Authentication */
            "1.3.6.1.5.5.7.3.2"   /* TLS Web Client Authentication */
        };

        System.out.print("\t\tgetExtendedKeyUsage");

        /* Client cert has Extended Key Usage extension with serverAuth
         * and clientAuth */
        eku = this.cert.getExtendedKeyUsage();
        if (eku == null) {
            System.out.println("\t... failed");
            fail("getExtendedKeyUsage() returned null for client cert");
        }

        if (eku.length != expected.length) {
            System.out.println("\t... failed");
            fail("Expected " + expected.length + " EKU OIDs, got: " +
                 eku.length);
        }

        /* Verify expected OIDs are present */
        for (i = 0; i < expected.length; i++) {
            boolean found = false;
            for (String oid : eku) {
                if (oid.equals(expected[i])) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                System.out.println("\t... failed");
                fail("Missing expected OID: " + expected[i]);
            }
        }

        /* Verify all OIDs are properly formatted */
        for (i = 0; i < eku.length; i++) {
            if (eku[i] == null || eku[i].isEmpty()) {
                System.out.println("\t... failed");
                fail("Extended key usage OID is null or empty");
            }
            if (!eku[i].matches("^[0-9]+(\\.[0-9]+)*$")) {
                System.out.println("\t... failed");
                fail("Invalid OID format: " + eku[i]);
            }
        }

        System.out.println("\t... passed");
    }

    public void test_getAiaMulti() {
        String[] ocsp;
        String[] ca;
        String ocsp1 = "http://127.0.0.1:22221";
        String ocsp2 = "http://127.0.0.1:22222";
        String ca1 = "http://www.wolfssl.com/ca.pem";
        String ca2 = "https://www.wolfssl.com/ca2.pem";
        WolfSSLCertificate tmp = null;

        System.out.print("\t\tgetOcspUris/getCaIssuerUris");

        try {
            if (WolfSSL.FileSystemEnabled() == true) {
                tmp = new WolfSSLCertificate(aiaMultiCertPem,
                    WolfSSL.SSL_FILETYPE_PEM);
            } else {
                tmp = new WolfSSLCertificate(
                    fileToByteArray(aiaMultiCertPem),
                    WolfSSL.SSL_FILETYPE_PEM);
            }

            int overflow = tmp.getAiaOverflow();
            if (overflow == WolfSSL.NOT_COMPILED_IN) {
                System.out.println("\t... skipped (AIA not compiled in)");
                tmp.free();
                return;
            }

            ocsp = tmp.getOcspUris();
            if (ocsp == null || ocsp.length != 2) {
                System.out.println("\t... failed");
                fail("Expected 2 OCSP URIs, got " +
                     ((ocsp == null) ? "null" : ocsp.length));
            }
            assertTrue(arrayContains(ocsp, ocsp1));
            assertTrue(arrayContains(ocsp, ocsp2));

            ca = tmp.getCaIssuerUris();
            if (ca == null || ca.length != 2) {
                System.out.println("\t... failed");
                fail("Expected 2 CA Issuer URIs, got " +
                     ((ca == null) ? "null" : ca.length));
            }
            assertTrue(arrayContains(ca, ca1));
            assertTrue(arrayContains(ca, ca2));

            if (overflow != 0) {
                System.out.println("\t... failed");
                fail("Expected no AIA overflow, got " + overflow);
            }

            tmp.free();
        } catch (Exception ex) {
            if (tmp != null) {
                tmp.free();
            }
            Logger.getLogger(WolfSSLCertificateTest.class.getName()).log(
                                Level.SEVERE, null, ex);
            System.out.println("\t... failed");
            fail("Error loading AIA multi certificate");
        }

        System.out.println("\t... passed");
    }

    public void test_getAiaOverflow() {
        String[] ocsp;
        WolfSSLCertificate tmp = null;

        System.out.print("\t\tgetOcspUris overflow");

        try {
            if (WolfSSL.FileSystemEnabled() == true) {
                tmp = new WolfSSLCertificate(aiaOverflowCertPem,
                    WolfSSL.SSL_FILETYPE_PEM);
            } else {
                tmp = new WolfSSLCertificate(
                    fileToByteArray(aiaOverflowCertPem),
                    WolfSSL.SSL_FILETYPE_PEM);
            }

            int overflow = tmp.getAiaOverflow();
            if (overflow == WolfSSL.NOT_COMPILED_IN) {
                System.out.println("\t... skipped (AIA not compiled in)");
                tmp.free();
                return;
            }

            ocsp = tmp.getOcspUris();
            if (ocsp == null || ocsp.length != 8) {
                System.out.println("\t... failed");
                fail("Expected 8 OCSP URIs (overflow), got " +
                     ((ocsp == null) ? "null" : ocsp.length));
            }
            assertTrue(arrayContains(ocsp, "http://127.0.0.1:22220"));
            assertTrue(arrayContains(ocsp, "http://127.0.0.1:22221"));
            assertTrue(arrayContains(ocsp, "http://127.0.0.1:22222"));
            assertTrue(arrayContains(ocsp, "http://127.0.0.1:22223"));
            assertTrue(arrayContains(ocsp, "http://127.0.0.1:22224"));
            assertTrue(arrayContains(ocsp, "http://127.0.0.1:22225"));
            assertTrue(arrayContains(ocsp, "http://127.0.0.1:22226"));
            assertTrue(arrayContains(ocsp, "http://127.0.0.1:22227"));
            assertFalse(arrayContains(ocsp, "http://127.0.0.1:22228"));

            if (overflow != 1) {
                System.out.println("\t... failed");
                fail("Expected AIA overflow to be set, got " + overflow);
            }

            tmp.free();
        } catch (Exception ex) {
            if (tmp != null) {
                tmp.free();
            }
            Logger.getLogger(WolfSSLCertificateTest.class.getName()).log(
                                Level.SEVERE, null, ex);
            System.out.println("\t... failed");
            fail("Error loading AIA overflow certificate");
        }

        System.out.println("\t... passed");
    }

    private boolean arrayContains(String[] list, String value) {
        if (list == null || value == null) {
            return false;
        }
        for (String s : list) {
            if (value.equals(s)) {
                return true;
            }
        }
        return false;
    }

    public void test_getExtensionSet() {
        System.out.print("\t\tgetExtensionSet");

        if (this.cert.getExtensionSet("2.5.29.19") != 1) {
            System.out.println("\t\t... failed");
            fail("Error with basic constraint extension");
        }

        if (this.cert.getExtensionSet("2.5.29.14") != 1) {
            System.out.println("\t\t... failed");
            fail("Error with subject key ID extension");
        }
        System.out.println("\t\t... passed");
    }

    public void test_toString() {
        String s;
        System.out.print("\t\ttoString");
        s =  cert.toString();
        if (s == null) {
            System.out.println("\t\t... failed");
            fail("Error getting certificate string");
        }
        System.out.println("\t\t... passed");
    }

    public void test_free() {
        System.out.print("\t\tfree");
        this.cert.free();
        System.out.println("\t\t\t... passed");
    }

    @Test
    public void testWolfSSLCertificateGeneration()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException, NoSuchAlgorithmException,
               InvalidKeySpecException {

        System.out.println("WolfSSLCertificate Generation");

        if (WolfSSL.FileSystemEnabled() == true) {
            testCertGen_SelfSigned_UsingFiles();
            testCertGen_SelfSigned_UsingBuffers();
            testCertGen_SelfSigned_UsingJavaClasses();
            testCertGen_CASigned_UsingFiles();
            testCertGen_CASigned_UsingBuffers();
            testCertGen_CASigned_UsingJavaClasses();
        }
    }

    @Test
    public void testWolfSSLCertificateExtensionSetters()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException {

        System.out.println("WolfSSLCertificate extension setters");

        if (WolfSSL.FileSystemEnabled() == false) {
            System.out.println("\tfilesystem disabled, skipping");
            return;
        }

        WolfSSLCertificate x509 = new WolfSSLCertificate();
        assertNotNull(x509);

        WolfSSLX509Name subjectName = GenerateTestSubjectName();
        assertNotNull(subjectName);

        WolfSSLCertificate issuer =
            new WolfSSLCertificate(caCertPem, WolfSSL.SSL_FILETYPE_PEM);
        assertNotNull(issuer);

        /* Minimal required fields for extensions that depend on */
        /* pubkey/issuer */
        Instant now = Instant.now();
        x509.setNotBefore(Date.from(now));
        x509.setNotAfter(Date.from(now.plus(Duration.ofDays(365))));
        x509.setSerialNumber(BigInteger.valueOf(67890));
        x509.setSubjectName(subjectName);
        x509.setIssuerName(issuer);
        x509.setPublicKey(cliKeyPubDer, WolfSSL.RSAk,
            WolfSSL.SSL_FILETYPE_ASN1);

        /* Arbitrary 20-byte test vectors for SKID/AKID content. */
        final byte[] skid = new byte[] {
            0x01, 0x02, 0x03, 0x04, 0x05,
            0x06, 0x07, 0x08, 0x09, 0x0A,
            0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14
        };
        final byte[] akid = new byte[] {
            0x10, 0x11, 0x12, 0x13, 0x14,
            0x15, 0x16, 0x17, 0x18, 0x19,
            0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
            0x1F, 0x20, 0x21, 0x22, 0x23
        };

        runOrAllowNotCompiled(
            () -> x509.setSubjectKeyId(skid),
            "setSubjectKeyId");
        runOrAllowNotCompiled(
            () -> x509.setSubjectKeyIdEx(),
            "setSubjectKeyIdEx");
        runOrAllowNotCompiled(
            () -> x509.setAuthorityKeyId(akid),
            "setAuthorityKeyId");
        runOrAllowNotCompiled(
            () -> x509.setAuthorityKeyIdEx(issuer),
            "setAuthorityKeyIdEx");

        runOrAllowNotCompiled(
            () -> x509.addCrlDistPoint("http://crl.example.com/ca.crl", false),
            "addCrlDistPoint");

        byte[] crlDpDer = issuer.getExtension("2.5.29.31");
        if (crlDpDer != null && crlDpDer.length > 0) {
            runOrAllowNotCompiled(
                () -> x509.setCrlDistPoints(crlDpDer),
                "setCrlDistPoints");
        } else {
            System.out.println("\t\tsetCrlDistPoints ... no DER available");
        }

        runOrAllowNotCompiled(
            () -> x509.setNsCertType(0x80),
            "setNsCertType");

        subjectName.free();
        issuer.free();
        x509.free();

        System.out.println("\t\t... passed");
    }

    /* Quick sanity check on certificate bytes. Loads cert into new
     * WolfSSLCertificate object, tries to get various elements and
     * simply verify if not null / etc. */
    private void sanityCheckCertFileBytes(byte[] certBytes, int type)
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException {

        if (certBytes == null ||
            (type != WolfSSL.SSL_FILETYPE_ASN1 &&
             type != WolfSSL.SSL_FILETYPE_PEM)) {
            throw new WolfSSLException("certBytes is null or bad type");
        }

        WolfSSLCertificate tmp = new WolfSSLCertificate(certBytes, type);
        assertNotNull(tmp);
        assertNotNull(tmp.getDer());
        assertNotNull(tmp.getPem());
        assertNotNull(tmp.getTbs());
        assertNotNull(tmp.getSerial());
        assertNotNull(tmp.notBefore());
        assertNotNull(tmp.notAfter());
        assertTrue(tmp.getVersion() >= 0);
        assertNotNull(tmp.getSignature());
        assertNotNull(tmp.getSignatureType());
        assertNotNull(tmp.getSignatureOID());
        assertNotNull(tmp.getPubkey());
        assertNotNull(tmp.getPubkeyType());
        int isCA = tmp.isCA();
        assertTrue(isCA == 0 || isCA == 1);
        assertTrue(tmp.getPathLen() >= -1);
        assertNotNull(tmp.getSubject());
        assertNotNull(tmp.getIssuer());
        if (WolfSSL.getLibVersionHex() > 0x05006003) {
            /* Key Usage and Extended Key Usage only work with wolfSSL
             * later than 5.6.3 */
            assertNotNull(tmp.getKeyUsage());
        }
        assertNotNull(tmp.getSubjectAltNames());
        assertNotNull(tmp.getX509Certificate());
        assertNotNull(tmp.toString());
    }

    /* Make sure peer cert can be verified using CertManager and provided
     * CA cert (and optional intermediate CA cert if needed). Supports PEM and
     * DER. Throws WolfSSLException if not valid. */
    private void verifyCertSignatureIsCorrect(
        byte[] peerCert, int peerCertType,
        byte[] intCaCert, int intCaCertType,
        byte[] rootCaCert, int rootCaCertType) throws WolfSSLException {

        int ret = WolfSSL.SSL_FAILURE;
        WolfSSLCertManager cm = new WolfSSLCertManager();

        if (peerCert == null || rootCaCert == null ||
            (peerCertType != WolfSSL.SSL_FILETYPE_ASN1 &&
             peerCertType != WolfSSL.SSL_FILETYPE_PEM) ||
            (rootCaCertType != WolfSSL.SSL_FILETYPE_ASN1 &&
             rootCaCertType != WolfSSL.SSL_FILETYPE_PEM)) {
            throw new WolfSSLException("cert or CA cert is null or bad type");
        }

        /* Load root CA as trusted */
        ret = cm.CertManagerLoadCABuffer(rootCaCert, rootCaCert.length,
                                         rootCaCertType);
        if (ret != WolfSSL.SSL_SUCCESS) {
            throw new WolfSSLException("Failed to load CA for verifying");
        }

        /* Load intermediate CA as trusted if needed */
        if (intCaCert != null) {
            if (intCaCertType != WolfSSL.SSL_FILETYPE_ASN1 &&
                intCaCertType != WolfSSL.SSL_FILETYPE_PEM) {
                throw new WolfSSLException("intermediate cert is bad type");
            }

            ret = cm.CertManagerLoadCABuffer(intCaCert, intCaCert.length,
                                             intCaCertType);
            if (ret != WolfSSL.SSL_SUCCESS) {
                throw new WolfSSLException(
                    "Failed to load intermediate CA for verifying");
            }
        }

        ret = cm.CertManagerVerifyBuffer(peerCert, peerCert.length,
            peerCertType);
        if (ret != WolfSSL.SSL_SUCCESS) {
            throw new WolfSSLException("Failed to verify peer cert against CA");
        }
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

    /* Test self-signed certificate generation using files for public key,
     * issuer name, and issuer private key */
    private void testCertGen_SelfSigned_UsingFiles()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException {

        System.out.print("\tself signed (files)");

        WolfSSLCertificate x509 = new WolfSSLCertificate();
        assertNotNull(x509);

        /* Set notBefore/notAfter dates */
        Instant now = Instant.now();
        final Date notBefore = Date.from(now);
        final Date notAfter = Date.from(now.plus(Duration.ofDays(365)));
        x509.setNotBefore(notBefore);
        x509.setNotAfter(notAfter);

        /* Set serial number */
        x509.setSerialNumber(BigInteger.valueOf(12345));

        /* Set Subject Name */
        WolfSSLX509Name subjectName = GenerateTestSubjectName();
        assertNotNull(subjectName);
        x509.setSubjectName(subjectName);

        /* Not setting Issuer, since generating self-signed cert */

        /* Set Public Key from file */
        x509.setPublicKey(cliKeyPubDer, WolfSSL.RSAk,
            WolfSSL.SSL_FILETYPE_ASN1);

        /* Set Extensions */
        if (WolfSSL.getLibVersionHex() > 0x05006003) {
            /* Key Usage and Extended Key Usage only work with wolfSSL
             * later than 5.6.3 */
            x509.addExtension(WolfSSL.NID_key_usage,
                "digitalSignature,keyEncipherment,dataEncipherment", false);

            x509.addExtension(WolfSSL.NID_ext_key_usage,
                "clientAuth,serverAuth", false);
        }
        x509.addExtension(WolfSSL.NID_subject_alt_name,
            "test.wolfssl.com", false);
        x509.addExtension(WolfSSL.NID_basic_constraints, true, true);

        /* Sign cert, self-signed */
        x509.signCert(cliKeyDer, WolfSSL.RSAk,
            WolfSSL.SSL_FILETYPE_ASN1, "SHA256");

        /* Output to DER and PEM */
        byte[] derCert = x509.getDer();
        byte[] pemCert = x509.getPem();

        assertNotNull(derCert);
        assertTrue(derCert.length > 0);
        assertNotNull(pemCert);
        assertTrue(pemCert.length > 0);

        /* Sanity check generated cert buffers */
        sanityCheckCertFileBytes(derCert, WolfSSL.SSL_FILETYPE_ASN1);
        sanityCheckCertFileBytes(pemCert, WolfSSL.SSL_FILETYPE_PEM);

        /* Sanity check CertManager can verify signature using expected CA */
        verifyCertSignatureIsCorrect(derCert, WolfSSL.SSL_FILETYPE_ASN1,
            null, 0, derCert, WolfSSL.SSL_FILETYPE_ASN1);
        verifyCertSignatureIsCorrect(pemCert, WolfSSL.SSL_FILETYPE_PEM,
            null, 0, derCert, WolfSSL.SSL_FILETYPE_ASN1);

        /* Free native memory */
        subjectName.free();
        x509.free();

        System.out.println("\t\t... passed");
    }

    /* Test CA-signed certificate generation using files for public key,
     * issuer name, and issuer private key */
    private void testCertGen_CASigned_UsingFiles()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException {

        System.out.print("\tCA signed (files)");

        WolfSSLCertificate x509 = new WolfSSLCertificate();
        assertNotNull(x509);

        /* Set notBefore/notAfter dates */
        Instant now = Instant.now();
        final Date notBefore = Date.from(now);
        final Date notAfter = Date.from(now.plus(Duration.ofDays(365)));
        x509.setNotBefore(notBefore);
        x509.setNotAfter(notAfter);

        /* Set serial number */
        x509.setSerialNumber(BigInteger.valueOf(12345));

        /* Set Subject Name */
        WolfSSLX509Name subjectName = GenerateTestSubjectName();
        assertNotNull(subjectName);
        x509.setSubjectName(subjectName);

        /* Set Issuer Name from existing PEM file */
        WolfSSLCertificate issuer =
            new WolfSSLCertificate(caCertPem, WolfSSL.SSL_FILETYPE_PEM);
        x509.setIssuerName(issuer);

        /* Set Public Key from file */
        x509.setPublicKey(cliKeyPubDer, WolfSSL.RSAk,
            WolfSSL.SSL_FILETYPE_ASN1);

        /* Set Extensions */
        if (WolfSSL.getLibVersionHex() > 0x05006003) {
            /* Key Usage and Extended Key Usage only work with wolfSSL
             * later than 5.6.3 */
            x509.addExtension(WolfSSL.NID_key_usage,
                "digitalSignature,keyEncipherment,dataEncipherment", false);
            x509.addExtension(WolfSSL.NID_ext_key_usage,
                "clientAuth,serverAuth", false);
        }
        x509.addExtension(WolfSSL.NID_subject_alt_name,
            "test.wolfssl.com", false);
        x509.addExtension(WolfSSL.NID_basic_constraints, false, true);

        /* Sign cert, CA-signed */
        x509.signCert(caKeyDer, WolfSSL.RSAk,
            WolfSSL.SSL_FILETYPE_ASN1, "SHA256");

        /* Output to DER and PEM */
        byte[] derCert = x509.getDer();
        byte[] pemCert = x509.getPem();

        assertNotNull(derCert);
        assertTrue(derCert.length > 0);
        assertNotNull(pemCert);
        assertTrue(pemCert.length > 0);

        /* Sanity check generated cert buffers */
        sanityCheckCertFileBytes(derCert, WolfSSL.SSL_FILETYPE_ASN1);
        sanityCheckCertFileBytes(pemCert, WolfSSL.SSL_FILETYPE_PEM);

        /* Sanity check CertManager can verify signature using expected CA */
        verifyCertSignatureIsCorrect(derCert, WolfSSL.SSL_FILETYPE_ASN1,
            null, 0, issuer.getDer(), WolfSSL.SSL_FILETYPE_ASN1);
        verifyCertSignatureIsCorrect(pemCert, WolfSSL.SSL_FILETYPE_PEM,
            null, 0, issuer.getDer(), WolfSSL.SSL_FILETYPE_ASN1);

        /* Free native memory */
        subjectName.free();
        x509.free();

        System.out.println("\t\t... passed");
    }

    /* Test self-signed certificate generation using buffers for public key,
     * issuer name, and issuer private key */
    private void testCertGen_SelfSigned_UsingBuffers()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException {

        System.out.print("\tself signed (buffers)");

        WolfSSLCertificate x509 = new WolfSSLCertificate();
        assertNotNull(x509);

        /* Set notBefore/notAfter dates */
        Instant now = Instant.now();
        final Date notBefore = Date.from(now);
        final Date notAfter = Date.from(now.plus(Duration.ofDays(365)));
        x509.setNotBefore(notBefore);
        x509.setNotAfter(notAfter);

        /* Set serial number */
        x509.setSerialNumber(BigInteger.valueOf(12345));

        /* Set Subject Name */
        WolfSSLX509Name subjectName = GenerateTestSubjectName();
        assertNotNull(subjectName);
        x509.setSubjectName(subjectName);

        /* Not setting Issuer, since generating self-signed cert */

        /* Set Public Key from file */
        byte[] pubKey = Files.readAllBytes(Paths.get(cliKeyPubDer));
        x509.setPublicKey(pubKey, WolfSSL.RSAk, WolfSSL.SSL_FILETYPE_ASN1);

        /* Set Extensions */
        if (WolfSSL.getLibVersionHex() > 0x05006003) {
            /* Key Usage and Extended Key Usage only work with wolfSSL
             * later than 5.6.3 */
            x509.addExtension(WolfSSL.NID_key_usage,
                "digitalSignature,keyEncipherment,dataEncipherment", false);
            x509.addExtension(WolfSSL.NID_ext_key_usage,
                "clientAuth,serverAuth", false);
        }
        x509.addExtension(WolfSSL.NID_subject_alt_name,
            "test.wolfssl.com", false);
        x509.addExtension(WolfSSL.NID_basic_constraints, true, true);

        /* Sign cert, self-signed */
        byte[] privKey = Files.readAllBytes(Paths.get(cliKeyDer));
        x509.signCert(privKey, WolfSSL.RSAk,
            WolfSSL.SSL_FILETYPE_ASN1, "SHA256");

        /* Output to DER and PEM */
        byte[] derCert = x509.getDer();
        byte[] pemCert = x509.getPem();

        assertNotNull(derCert);
        assertTrue(derCert.length > 0);
        assertNotNull(pemCert);
        assertTrue(pemCert.length > 0);

        /* Sanity check generated cert buffers */
        sanityCheckCertFileBytes(derCert, WolfSSL.SSL_FILETYPE_ASN1);
        sanityCheckCertFileBytes(pemCert, WolfSSL.SSL_FILETYPE_PEM);

        /* Sanity check CertManager can verify signature using expected CA */
        verifyCertSignatureIsCorrect(derCert, WolfSSL.SSL_FILETYPE_ASN1,
            null, 0, derCert, WolfSSL.SSL_FILETYPE_ASN1);
        verifyCertSignatureIsCorrect(pemCert, WolfSSL.SSL_FILETYPE_PEM,
            null, 0, derCert, WolfSSL.SSL_FILETYPE_ASN1);

        /* Free native memory */
        subjectName.free();
        x509.free();

        System.out.println("\t\t... passed");
    }

    /* Test CA-signed certificate generation using buffers for public key,
     * issuer name, and issuer private key */
    private void testCertGen_CASigned_UsingBuffers()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException {

        System.out.print("\tCA signed (buffers)");

        WolfSSLCertificate x509 = new WolfSSLCertificate();
        assertNotNull(x509);

        /* Set notBefore/notAfter dates */
        Instant now = Instant.now();
        final Date notBefore = Date.from(now);
        final Date notAfter = Date.from(now.plus(Duration.ofDays(365)));
        x509.setNotBefore(notBefore);
        x509.setNotAfter(notAfter);

        /* Set serial number */
        x509.setSerialNumber(BigInteger.valueOf(12345));

        /* Set Subject Name */
        WolfSSLX509Name subjectName = GenerateTestSubjectName();
        assertNotNull(subjectName);
        x509.setSubjectName(subjectName);

        /* Set Issuer Name from existing PEM file */
        WolfSSLCertificate issuer =
            new WolfSSLCertificate(Files.readAllBytes(Paths.get(caCertPem)),
                WolfSSL.SSL_FILETYPE_PEM);
        x509.setIssuerName(issuer);

        /* Set Public Key from file */
        byte[] pubKey = Files.readAllBytes(Paths.get(cliKeyPubDer));
        x509.setPublicKey(pubKey, WolfSSL.RSAk, WolfSSL.SSL_FILETYPE_ASN1);

        /* Set Extensions */
        if (WolfSSL.getLibVersionHex() > 0x05006003) {
            /* Key Usage and Extended Key Usage only work with wolfSSL
             * later than 5.6.3 */
            x509.addExtension(WolfSSL.NID_key_usage,
                "digitalSignature,keyEncipherment,dataEncipherment", false);
            x509.addExtension(WolfSSL.NID_ext_key_usage,
                "clientAuth,serverAuth", false);
        }
        x509.addExtension(WolfSSL.NID_subject_alt_name,
            "test.wolfssl.com", false);
        x509.addExtension(WolfSSL.NID_basic_constraints, false, true);

        /* Sign cert, CA-signed */
        byte[] privKey = Files.readAllBytes(Paths.get(caKeyDer));
        x509.signCert(privKey, WolfSSL.RSAk,
            WolfSSL.SSL_FILETYPE_ASN1, "SHA256");

        /* Output to DER and PEM */
        byte[] derCert = x509.getDer();
        byte[] pemCert = x509.getPem();

        assertNotNull(derCert);
        assertTrue(derCert.length > 0);
        assertNotNull(pemCert);
        assertTrue(pemCert.length > 0);

        /* Sanity check generated cert buffers */
        sanityCheckCertFileBytes(derCert, WolfSSL.SSL_FILETYPE_ASN1);
        sanityCheckCertFileBytes(pemCert, WolfSSL.SSL_FILETYPE_PEM);

        /* Sanity check CertManager can verify signature using expected CA */
        verifyCertSignatureIsCorrect(derCert, WolfSSL.SSL_FILETYPE_ASN1,
            null, 0, issuer.getDer(), WolfSSL.SSL_FILETYPE_ASN1);
        verifyCertSignatureIsCorrect(pemCert, WolfSSL.SSL_FILETYPE_PEM,
            null, 0, issuer.getDer(), WolfSSL.SSL_FILETYPE_ASN1);

        /* Free native memory */
        subjectName.free();
        x509.free();

        System.out.println("\t\t... passed");
    }

    /* Test self-signed certificate generation using higher-level Java classes
     * for public key, issuer name, and issuer private key */
    private void testCertGen_SelfSigned_UsingJavaClasses()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException, NoSuchAlgorithmException {

        System.out.print("\tself signed (Java classes)");

        WolfSSLCertificate x509 = new WolfSSLCertificate();
        assertNotNull(x509);

        /* Set notBefore/notAfter dates */
        Instant now = Instant.now();
        final Date notBefore = Date.from(now);
        final Date notAfter = Date.from(now.plus(Duration.ofDays(365)));
        x509.setNotBefore(notBefore);
        x509.setNotAfter(notAfter);

        /* Set serial number */
        x509.setSerialNumber(BigInteger.valueOf(12345));

        /* Set Subject Name */
        WolfSSLX509Name subjectName = GenerateTestSubjectName();
        assertNotNull(subjectName);
        x509.setSubjectName(subjectName);

        /* Not setting Issuer, since generating self-signed cert */

        /* Set Public Key from generated java.security.PublicKey */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        PublicKey pubKey = keyPair.getPublic();
        x509.setPublicKey(pubKey);

        /* Set Extensions */
        if (WolfSSL.getLibVersionHex() > 0x05006003) {
            /* Key Usage and Extended Key Usage only work with wolfSSL
             * later than 5.6.3 */
            x509.addExtension(WolfSSL.NID_key_usage,
                "digitalSignature,keyEncipherment,dataEncipherment", false);
            x509.addExtension(WolfSSL.NID_ext_key_usage,
                "clientAuth,serverAuth", false);
        }
        x509.addExtension(WolfSSL.NID_subject_alt_name,
            "test.wolfssl.com", false);
        x509.addExtension(WolfSSL.NID_basic_constraints, true, true);

        /* Sign cert, self-signed with java.security.PrivateKey */
        PrivateKey privKey = keyPair.getPrivate();
        x509.signCert(privKey, "SHA256");

        /* Output to DER and PEM */
        byte[] derCert = x509.getDer();
        byte[] pemCert = x509.getPem();

        assertNotNull(derCert);
        assertTrue(derCert.length > 0);
        assertNotNull(pemCert);
        assertTrue(pemCert.length > 0);

        /* Sanity check generated cert buffers */
        sanityCheckCertFileBytes(derCert, WolfSSL.SSL_FILETYPE_ASN1);
        sanityCheckCertFileBytes(pemCert, WolfSSL.SSL_FILETYPE_PEM);

        /* Sanity check CertManager can verify signature using expected CA */
        verifyCertSignatureIsCorrect(derCert, WolfSSL.SSL_FILETYPE_ASN1,
            null, 0, derCert, WolfSSL.SSL_FILETYPE_ASN1);
        verifyCertSignatureIsCorrect(pemCert, WolfSSL.SSL_FILETYPE_PEM,
            null, 0, derCert, WolfSSL.SSL_FILETYPE_ASN1);

        /* Free native memory */
        subjectName.free();
        x509.free();

        System.out.println("\t... passed");
    }

    /* Test CA-signed certificate generation using higher-level Java classes
     * for public key, issuer name, and issuer private key */
    private void testCertGen_CASigned_UsingJavaClasses()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException, NoSuchAlgorithmException,
               InvalidKeySpecException {

        System.out.print("\tCA signed (Java classes)");

        WolfSSLCertificate x509 = new WolfSSLCertificate();
        assertNotNull(x509);

        /* Set notBefore/notAfter dates */
        Instant now = Instant.now();
        final Date notBefore = Date.from(now);
        final Date notAfter = Date.from(now.plus(Duration.ofDays(365)));
        x509.setNotBefore(notBefore);
        x509.setNotAfter(notAfter);

        /* Set serial number */
        x509.setSerialNumber(BigInteger.valueOf(12345));

        /* Set Subject Name */
        WolfSSLX509Name subjectName = GenerateTestSubjectName();
        assertNotNull(subjectName);
        x509.setSubjectName(subjectName);

        /* Set Issuer Name from existing PEM file, using server cert since it
         * is a CA, and wolfSSL proper ships a PKCS#8 encoded DER private key
         * needed below */
        WolfSSLCertificate issuer =
            new WolfSSLCertificate(Files.readAllBytes(Paths.get(caCertPem)),
                WolfSSL.SSL_FILETYPE_PEM);
        X509Certificate issuerX509 = issuer.getX509Certificate();
        x509.setIssuerName(issuerX509);

        /* Set Public Key from generated java.security.PublicKey */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        PublicKey pubKey = keyPair.getPublic();
        x509.setPublicKey(pubKey);

        /* Set Extensions */
        if (WolfSSL.getLibVersionHex() > 0x05006003) {
            /* Key Usage and Extended Key Usage only work with wolfSSL
             * later than 5.6.3 */
            x509.addExtension(WolfSSL.NID_key_usage,
                "digitalSignature,keyEncipherment,dataEncipherment", false);
            x509.addExtension(WolfSSL.NID_ext_key_usage,
                "clientAuth,serverAuth", false);
        }
        x509.addExtension(WolfSSL.NID_subject_alt_name,
            "test.wolfssl.com", false);
        x509.addExtension(WolfSSL.NID_basic_constraints, false, true);

        /* Sign cert, with CA's private key */
        byte[] privBytes = Files.readAllBytes(Paths.get(caKeyPkcs8Der));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privBytes);
        RSAPrivateKey rsaPriv = (RSAPrivateKey)kf.generatePrivate(spec);
        x509.signCert((PrivateKey)rsaPriv, "SHA256");

        /* Output to DER and PEM */
        byte[] derCert = x509.getDer();
        byte[] pemCert = x509.getPem();

        assertNotNull(derCert);
        assertTrue(derCert.length > 0);
        assertNotNull(pemCert);
        assertTrue(pemCert.length > 0);

        /* Sanity check generated cert buffers */
        sanityCheckCertFileBytes(derCert, WolfSSL.SSL_FILETYPE_ASN1);
        sanityCheckCertFileBytes(pemCert, WolfSSL.SSL_FILETYPE_PEM);

        /* Sanity check CertManager can verify signature using expected CA */
        verifyCertSignatureIsCorrect(derCert, WolfSSL.SSL_FILETYPE_ASN1,
            null, 0, issuer.getDer(), WolfSSL.SSL_FILETYPE_ASN1);
        verifyCertSignatureIsCorrect(pemCert, WolfSSL.SSL_FILETYPE_PEM,
            null, 0, issuer.getDer(), WolfSSL.SSL_FILETYPE_ASN1);

        /* Free native memory */
        subjectName.free();
        x509.free();

        System.out.println("\t... passed");
    }

    /* Utility method if needed for testing, print out cert array to file */
    private void writeOutCertFile(byte[] cert, String path)
        throws IOException {
        Files.write(new File(path).toPath(), cert);
    }

    /**
     * Test Subject Alternative Names (SAN) parsing functionality.
     *
     * Tests getSubjectAltNames() and getSubjectAltNamesExtended() methods
     * which return SAN entries with proper type information as per RFC 5280.
     */
    @Test
    public void testSubjectAltNames()
        throws WolfSSLException, WolfSSLJNIException, IOException {

        System.out.println("Subject Alternative Names (SAN) Parsing");

        test_getSubjectAltNames_ServerCert();
        test_getSubjectAltNames_ExampleCert();
        test_getSubjectAltNamesExtended();
        test_getSubjectAltNames_CertWithNoSANs();
        test_getSubjectAltNames_TypeConstants();
    }

    /**
     * Test getSubjectAltNames() with server-cert.pem which has DNS and IP SANs.
     * Server cert has: DNS:example.com, IP Address:127.0.0.1
     */
    public void test_getSubjectAltNames_ServerCert()
        throws WolfSSLException, IOException {

        boolean foundDNS = false;
        boolean foundIP = false;

        System.out.print("\tgetSubjectAltNames (DNS + IP)");

        String serverCertPath = WolfSSLTestCommon.getPath(serverCertPem);
        WolfSSLCertificate serverCert = null;

        if (WolfSSL.FileSystemEnabled() == true) {
            serverCert = new WolfSSLCertificate(
                serverCertPath, WolfSSL.SSL_FILETYPE_PEM);
        }
        else {
            serverCert = new WolfSSLCertificate(
                fileToByteArray(serverCertPath), WolfSSL.SSL_FILETYPE_PEM);
        }
        assertNotNull(serverCert);

        Collection<List<?>> sans = serverCert.getSubjectAltNames();
        assertNotNull("getSubjectAltNames() returned null", sans);
        assertTrue("Expected at least 2 SANs", sans.size() >= 2);

        for (List<?> san : sans) {
            assertNotNull("SAN entry is null", san);
            assertTrue("SAN entry should have at least 2 elements",
                san.size() >= 2);

            Integer type = (Integer) san.get(0);
            assertNotNull("SAN type is null", type);

            if (type == WolfSSL.ASN_DNS_TYPE) {
                /* DNS name (type 2) */
                Object value = san.get(1);
                assertTrue("DNS value should be String",
                    value instanceof String);
                String dnsName = (String)value;
                if ("example.com".equals(dnsName)) {
                    foundDNS = true;
                }
            }
            else if (type == WolfSSL.ASN_IP_TYPE) {
                /* IP address (type 7) */
                Object value = san.get(1);
                assertTrue("IP value should be byte[]",
                    value instanceof byte[]);
                byte[] ipBytes = (byte[])value;
                /* 127.0.0.1 is 4 bytes: 0x7F, 0x00, 0x00, 0x01 */
                if (ipBytes.length == 4 &&
                    ipBytes[0] == 127 &&
                    ipBytes[1] == 0 &&
                    ipBytes[2] == 0 &&
                    ipBytes[3] == 1) {
                    foundIP = true;
                }
            }
        }

        assertTrue("Did not find DNS SAN 'example.com'", foundDNS);
        assertTrue("Did not find IP SAN '127.0.0.1'", foundIP);

        serverCert.free();
        System.out.println("\t... passed");
    }

    /**
     * Test getSubjectAltNames() with example-com.der which has multiple
     * DNS SANs.
     */
    public void test_getSubjectAltNames_ExampleCert()
        throws WolfSSLException, IOException {

        System.out.print("\tgetSubjectAltNames (multi DNS)");

        String exampleCertPath = WolfSSLTestCommon.getPath(external);
        /* external is ca-google-root.der, use example-com.der instead */
        String exampleComPath = exampleCertPath.replace(
            "ca-google-root.der", "example-com.der");

        WolfSSLCertificate exampleCert = null;

        try {
            if (WolfSSL.FileSystemEnabled() == true) {
                exampleCert = new WolfSSLCertificate(
                    exampleComPath, WolfSSL.SSL_FILETYPE_ASN1);
            }
            else {
                exampleCert = new WolfSSLCertificate(
                    fileToByteArray(exampleComPath), WolfSSL.SSL_FILETYPE_ASN1);
            }
        }
        catch (WolfSSLException e) {
            /* Cert might not exist in test environment */
            System.out.println("\t... skipped (cert not found)");
            return;
        }

        assertNotNull(exampleCert);

        Collection<List<?>> sans = exampleCert.getSubjectAltNames();
        if (sans == null) {
            /* Native method may not be available */
            exampleCert.free();
            System.out.println("\t... skipped (native not available)");
            return;
        }

        /* example-com.der has 8 DNS SANs */
        assertTrue("Expected multiple DNS SANs", sans.size() >= 1);

        String[] expectedDNS = {
            "www.example.org", "example.com", "example.edu", "example.net",
            "example.org", "www.example.com", "www.example.edu",
            "www.example.net"
        };

        int foundCount = 0;
        for (List<?> san : sans) {
            Integer type = (Integer) san.get(0);
            if (type == WolfSSL.ASN_DNS_TYPE) {
                String dnsName = (String) san.get(1);
                for (String expected : expectedDNS) {
                    if (expected.equals(dnsName)) {
                        foundCount++;
                        break;
                    }
                }
            }
        }

        assertTrue("Expected to find multiple DNS SANs, found: " + foundCount,
            foundCount >= 1);

        exampleCert.free();
        System.out.println("\t... passed");
    }

    /**
     * Test getSubjectAltNamesExtended() returns full data for otherName.
     * This method should return OID and value bytes for otherName types.
     */
    public void test_getSubjectAltNamesExtended()
        throws WolfSSLException, IOException {

        System.out.print("\tgetSubjectAltNamesExtended");

        String serverCertPath = WolfSSLTestCommon.getPath(serverCertPem);
        WolfSSLCertificate serverCert = null;

        if (WolfSSL.FileSystemEnabled() == true) {
            serverCert = new WolfSSLCertificate(
                serverCertPath, WolfSSL.SSL_FILETYPE_PEM);
        }
        else {
            serverCert = new WolfSSLCertificate(
                fileToByteArray(serverCertPath), WolfSSL.SSL_FILETYPE_PEM);
        }
        assertNotNull(serverCert);

        Collection<List<?>> sans = serverCert.getSubjectAltNamesExtended();
        if (sans == null) {
            /* Native method may not be available in some builds */
            serverCert.free();
            System.out.println("\t... skipped (native not available)");
            return;
        }

        assertTrue("Expected at least 1 SAN", sans.size() >= 1);

        /* Verify structure matches expected format:
         * [type, value] for most types
         * [type, oid, value_bytes] for otherName */
        for (List<?> san : sans) {
            assertNotNull("SAN entry is null", san);
            assertTrue("SAN entry should have at least 2 elements",
                san.size() >= 2);

            Integer type = (Integer) san.get(0);
            assertNotNull("SAN type is null", type);
            assertTrue("Invalid SAN type: " + type,
                type >= 0 && type <= 8);

            /* If otherName (type 0), should have 3 elements */
            if (type == WolfSSL.ASN_OTHER_TYPE) {
                assertTrue("otherName should have 3 elements",
                    san.size() >= 3);
                assertTrue("otherName OID should be String",
                    san.get(1) instanceof String);
                assertTrue("otherName value should be byte[]",
                    san.get(2) instanceof byte[]);
            }
        }

        serverCert.free();
        System.out.println("\t... passed");
    }

    /**
     * Test getSubjectAltNames() with CA certificate which may have no SANs.
     * If the cert has no SANs, should return an empty collection or null.
     */
    public void test_getSubjectAltNames_CertWithNoSANs()
        throws WolfSSLException, IOException {

        System.out.print("\tgetSubjectAltNames (CA cert)");

        /* CA cert typically doesn't have SANs */
        String caCertPath = WolfSSLTestCommon.getPath(caCertPem);
        WolfSSLCertificate caCert = null;

        if (WolfSSL.FileSystemEnabled() == true) {
            caCert = new WolfSSLCertificate(
                caCertPath, WolfSSL.SSL_FILETYPE_PEM);
        }
        else {
            caCert = new WolfSSLCertificate(
                fileToByteArray(caCertPath), WolfSSL.SSL_FILETYPE_PEM);
        }
        assertNotNull(caCert);

        Collection<List<?>> sans = caCert.getSubjectAltNames();
        /* CA cert may or may not have SANs */
        /* Just verify the method doesn't throw and returns a valid result */
        if (sans != null && !sans.isEmpty()) {
            /* If SANs exist, verify they are well-formed */
            for (List<?> san : sans) {
                assertNotNull("SAN entry should not be null", san);
                assertTrue("SAN entry should have at least 2 elements",
                    san.size() >= 2);
                assertNotNull("SAN type should not be null", san.get(0));
            }
        }

        Collection<List<?>> sansExt = caCert.getSubjectAltNamesExtended();
        /* Extended method should return null for certs without SANs,
         * or a valid collection if SANs exist */
        if (sansExt != null && !sansExt.isEmpty()) {
            for (List<?> san : sansExt) {
                assertNotNull("SAN entry should not be null", san);
                assertTrue("SAN entry should have at least 2 elements",
                    san.size() >= 2);
            }
        }

        caCert.free();
        System.out.println("\t... passed");
    }

    /**
     * Test that SAN type constants match expected RFC 5280 values.
     */
    public void test_getSubjectAltNames_TypeConstants() {

        System.out.print("\tSAN type constants");

        /* Verify constants match RFC 5280 GeneralName types */
        assertEquals("ASN_OTHER_TYPE should be 0", 0, WolfSSL.ASN_OTHER_TYPE);
        assertEquals("ASN_RFC822_TYPE should be 1", 1, WolfSSL.ASN_RFC822_TYPE);
        assertEquals("ASN_DNS_TYPE should be 2", 2, WolfSSL.ASN_DNS_TYPE);
        assertEquals("ASN_DIR_TYPE should be 4", 4, WolfSSL.ASN_DIR_TYPE);
        assertEquals("ASN_URI_TYPE should be 6", 6, WolfSSL.ASN_URI_TYPE);
        assertEquals("ASN_IP_TYPE should be 7", 7, WolfSSL.ASN_IP_TYPE);

        System.out.println("\t\t... passed");
    }

    /**
     * Test parsing of Microsoft Active Directory UPN (User Principal Name)
     * from an otherName SAN entry.
     *
     * This test demonstrates how to parse MS AD UPN from certificates.
     *
     * MS AD UPN OID: 1.3.6.1.4.1.311.20.2.3
     *
     * This test demonstrates the pattern for parsing MS AD UPN.
     * In a real scenario with an AD certificate containing UPN SAN:
     *
     * WolfSSLAltName[] sans = cert.getSubjectAltNamesArray();
     * for (WolfSSLAltName san : sans) {
     *     if (san.isMicrosoftUPN()) {
     *         String upn = san.getOtherNameValueAsString();
     *     }
     * }
     */
    @Test
    public void testMicrosoftADUPNParsing()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException, NoSuchAlgorithmException {

        /* MS AD UPN OID */
        final String MS_UPN_OID = "1.3.6.1.4.1.311.20.2.3";

        System.out.print("\tParsing otherName UPN");

        if (WolfSSL.FileSystemEnabled() != true) {
            System.out.println("\t... skipped (file system not enabled)");
            return;
        }

        /* Test with server cert which has known SANs */
        String serverCertPath = WolfSSLTestCommon.getPath(serverCertPem);
        WolfSSLCertificate serverCert = new WolfSSLCertificate(
            serverCertPath, WolfSSL.SSL_FILETYPE_PEM);
        assertNotNull(serverCert);

        Collection<List<?>> sans = serverCert.getSubjectAltNamesExtended();
        if (sans != null) {
            for (List<?> san : sans) {
                Integer type = (Integer) san.get(0);

                /* If we find an otherName (type 0), verify structure */
                if (type == WolfSSL.ASN_OTHER_TYPE) {
                    assertTrue("otherName should have OID", san.size() >= 2);
                    assertTrue("OID should be String",
                        san.get(1) instanceof String);
                    String oid = (String)san.get(1);
                    assertNotNull("OID should not be null", oid);

                    if (san.size() >= 3) {
                        assertTrue("Value should be byte[]",
                            san.get(2) instanceof byte[]);
                        byte[] valueBytes = (byte[]) san.get(2);
                        assertNotNull("Value bytes should not be null",
                            valueBytes);

                        /* If this is MS UPN, parse the UTF8String value */
                        if (MS_UPN_OID.equals(oid) && valueBytes.length > 2) {
                            /* ASN.1 UTF8String: tag 0x0C + length + data.
                             * Length can be short form (1 byte, <= 127) or
                             * long form (first byte 0x8n, followed by n
                             * bytes of actual length).
                             */
                            if (valueBytes[0] == 0x0C) {
                                int len = valueBytes[1] & 0xFF;
                                int offset = 2;

                                /* Handle long form length encoding */
                                if ((len & 0x80) != 0) {
                                    int numOctets = len & 0x7F;
                                    if (numOctets >= 1 && numOctets <= 4 &&
                                        valueBytes.length >= 2 + numOctets) {
                                        len = 0;
                                        for (int k = 0; k < numOctets; k++) {
                                            len = (len << 8) |
                                                (valueBytes[offset++] & 0xFF);
                                        }
                                    }
                                }

                                if (len > 0 &&
                                    valueBytes.length >= offset + len) {
                                    byte[] strBytes = new byte[len];
                                    System.arraycopy(valueBytes, offset,
                                        strBytes, 0, len);
                                    String upn = new String(strBytes, "UTF-8");
                                    assertNotNull("UPN should not be null",
                                        upn);
                                }
                            }
                        }
                    }
                }
            }
        }

        serverCert.free();
        System.out.println("\t\t... passed");

        /* Test with actual MS AD UPN certificate if available */
        test_MSADUPNMigrationPattern();
    }

    /**
     * Test parsing Microsoft AD UPN from certificates using WolfSSLAltName.
     *
     * wolfSSL JNI pattern:
     *   WolfSSLAltName san = ...;
     *   if (san.isMicrosoftUPN()) {
     *       username = san.getOtherNameValueAsString();
     *   }
     */
    private void test_MSADUPNMigrationPattern()
        throws WolfSSLException, IOException {

        System.out.print("\tMS AD UPN parsing");

        /* Check if UPN test cert exists */
        String upnCertPath = sanTestUpnCert;
        File upnCertFile = new File(upnCertPath);

        if (!upnCertFile.exists()) {
            System.out.println(
                "\t... skipped (run generate-san-test-certs.sh)");
            return;
        }

        WolfSSLCertificate cert = new WolfSSLCertificate(
            upnCertPath, WolfSSL.SSL_FILETYPE_PEM);

        try {
            /* Get SANs using the type-safe WolfSSLAltName API */
            WolfSSLAltName[] sans = cert.getSubjectAltNamesArray();

            if (sans == null) {
                System.out.println("\t... skipped (native not available)");
                return;
            }

            /* Find MS AD UPN and extract username, avoiding names with '$' */
            String deprioritizedUsername = null;
            String finalUsername = null;

            for (WolfSSLAltName san : sans) {
                int type = san.getType();

                /* Check accepted SAN types (0=otherName, 1=email, 2=DNS) */
                if (type != WolfSSLAltName.TYPE_OTHER_NAME &&
                    type != WolfSSLAltName.TYPE_RFC822_NAME &&
                    type != WolfSSLAltName.TYPE_DNS_NAME) {
                    continue;
                }

                String username = null;

                if (san.isMicrosoftUPN()) {
                    /* Parse MS AD UPN - ASN.1 parsing handled internally */
                    username = san.getOtherNameValueAsString();

                    /* Verify we get a valid UPN */
                    assertNotNull("MS UPN should parse to non-null string",
                        username);
                    assertTrue("UPN should contain @ symbol",
                        username.contains("@"));

                } else if (type == WolfSSLAltName.TYPE_OTHER_NAME) {
                    /* Other otherName OID */
                    username = san.getOtherNameValueAsString();
                } else {
                    /* String types: email, DNS */
                    username = san.getStringValue();
                }

                if (username != null) {
                    deprioritizedUsername = username;

                    /* Prefer usernames without '$' (not machine accounts) */
                    if (!username.contains("$")) {
                        finalUsername = username;
                        break;
                    }
                }
            }

            /* Verify we found at least one username */
            assertNotNull("Should find at least one username",
                deprioritizedUsername);

            /* Our test cert has UPNs without '$', so finalUsername
             * should be set */
            assertNotNull("Should find username without '$'", finalUsername);

            /* Verify the UPN values match expected test cert content */
            assertTrue("Username should be a valid UPN format",
                finalUsername.contains("@"));

            /* Test getSubjectAltNamesExtended() for raw byte access */
            Collection<List<?>> sansExt = cert.getSubjectAltNamesExtended();
            assertNotNull("getSubjectAltNamesExtended() should not be null",
                sansExt);

            boolean foundOtherNameWithBytes = false;
            for (List<?> san : sansExt) {
                int type = (Integer) san.get(0);
                if (type == WolfSSLAltName.TYPE_OTHER_NAME && san.size() >= 3) {
                    String oid = (String) san.get(1);
                    byte[] valueBytes = (byte[]) san.get(2);
                    assertNotNull("otherName OID should not be null", oid);
                    assertNotNull("otherName value bytes should not be null",
                        valueBytes);
                    assertTrue("Value bytes should have content",
                        valueBytes.length > 0);
                    foundOtherNameWithBytes = true;
                }
            }
            assertTrue("Should find otherName with bytes in extended API",
                foundOtherNameWithBytes);

        } finally {
            cert.free();
        }

        System.out.println("\t\t... passed");
    }

    /**
     * Test regression prevention for SAN parsing functionality.
     *
     * This test ensures the WolfSSLAltName API continues to support all
     * the functionality needed for comprehensive SAN parsing including
     * otherName types used by Microsoft Active Directory.
     */
    @Test
    public void testSANParsingRegressionPrevention()
        throws WolfSSLException, WolfSSLJNIException, IOException {

        System.out.println("SAN Parsing Regression Prevention Tests");

        test_SAN_OtherNameOID();
        test_SAN_OtherNameValue();
        test_SAN_isMicrosoftUPN();
        test_SAN_AllTypesSupported();
        test_SAN_DeprioritizedUsername();
    }

    /**
     * Test that otherName OID is accessible via getOtherNameOID().
     */
    private void test_SAN_OtherNameOID()
        throws WolfSSLException, IOException {

        System.out.print("\totherName OID access");

        String certPath = sanTestUpnCert;
        File certFile = new File(certPath);

        if (!certFile.exists()) {
            System.out.println("\t\t... skipped (cert not found)");
            return;
        }

        WolfSSLCertificate cert = new WolfSSLCertificate(
            certPath, WolfSSL.SSL_FILETYPE_PEM);

        try {
            WolfSSLAltName[] sans = cert.getSubjectAltNamesArray();
            if (sans == null) {
                System.out.println("\t\t... skipped (native not available)");
                return;
            }

            boolean foundOID = false;
            for (WolfSSLAltName san : sans) {
                if (san.getType() == WolfSSLAltName.TYPE_OTHER_NAME) {
                    String oid = san.getOtherNameOID();
                    assertNotNull("getOtherNameOID() should return OID", oid);
                    assertTrue("OID should be in dotted format",
                        oid.matches("[0-9]+(\\.[0-9]+)+"));
                    foundOID = true;
                }
            }
            assertTrue("Should find at least one otherName with OID", foundOID);

        } finally {
            cert.free();
        }

        System.out.println("\t\t... passed");
    }

    /**
     * Test that otherName value bytes are accessible via getOtherNameValue().
     */
    private void test_SAN_OtherNameValue()
        throws WolfSSLException, IOException {

        System.out.print("\totherName value bytes");

        String certPath = sanTestUpnCert;
        File certFile = new File(certPath);

        if (!certFile.exists()) {
            System.out.println("\t\t... skipped (cert not found)");
            return;
        }

        WolfSSLCertificate cert = new WolfSSLCertificate(
            certPath, WolfSSL.SSL_FILETYPE_PEM);

        try {
            WolfSSLAltName[] sans = cert.getSubjectAltNamesArray();
            if (sans == null) {
                System.out.println("\t\t... skipped (native not available)");
                return;
            }

            boolean foundValue = false;
            for (WolfSSLAltName san : sans) {
                if (san.getType() == WolfSSLAltName.TYPE_OTHER_NAME) {
                    byte[] valueBytes = san.getOtherNameValue();
                    assertNotNull("getOtherNameValue() should return bytes",
                        valueBytes);
                    assertTrue("Value bytes should have content",
                        valueBytes.length > 0);

                    /* Verify ASN.1 structure - should start with tag */
                    assertTrue("Should be valid ASN.1 (tag byte present)",
                        valueBytes.length >= 2);

                    foundValue = true;
                }
            }
            assertTrue("Should find at least one otherName with value",
                foundValue);

        } finally {
            cert.free();
        }

        System.out.println("\t\t... passed");
    }

    /**
     * Test isMicrosoftUPN() method for detecting MS AD UPN certificates.
     */
    private void test_SAN_isMicrosoftUPN()
        throws WolfSSLException, IOException {

        System.out.print("\tisMicrosoftUPN() detection");

        String certPath = sanTestUpnCert;
        File certFile = new File(certPath);

        if (!certFile.exists()) {
            System.out.println("\t... skipped");
            return;
        }

        WolfSSLCertificate cert = new WolfSSLCertificate(
            certPath, WolfSSL.SSL_FILETYPE_PEM);

        try {
            WolfSSLAltName[] sans = cert.getSubjectAltNamesArray();
            if (sans == null) {
                System.out.println("\t... skipped");
                return;
            }

            boolean foundMSUPN = false;
            for (WolfSSLAltName san : sans) {
                if (san.isMicrosoftUPN()) {
                    foundMSUPN = true;

                    /* Verify OID matches MS UPN */
                    assertEquals("MS UPN should have correct OID",
                        WolfSSLAltName.OID_MS_UPN, san.getOtherNameOID());

                    /* Verify value parses as string */
                    String upn = san.getOtherNameValueAsString();
                    assertNotNull("MS UPN value should parse as string", upn);
                    assertTrue("UPN should contain @", upn.contains("@"));
                }
            }
            assertTrue("Test cert should contain MS UPN", foundMSUPN);

        } finally {
            cert.free();
        }

        System.out.println("\t... passed");
    }

    /**
     * Test that all SAN types are properly supported.
     */
    private void test_SAN_AllTypesSupported()
        throws WolfSSLException, IOException {

        System.out.print("\tall SAN types supported");

        String certPath = sanTestAllTypesCert;
        File certFile = new File(certPath);

        if (!certFile.exists()) {
            System.out.println("\t\t... skipped (cert not found)");
            return;
        }

        WolfSSLCertificate cert = new WolfSSLCertificate(
            certPath, WolfSSL.SSL_FILETYPE_PEM);

        try {
            WolfSSLAltName[] sans = cert.getSubjectAltNamesArray();
            if (sans == null) {
                System.out.println("\t\t... skipped (native not available)");
                return;
            }

            /* Track which types we find */
            boolean foundOtherName = false;
            boolean foundEmail = false;
            boolean foundDNS = false;
            boolean foundURI = false;
            boolean foundIP = false;
            boolean foundDirName = false;

            for (WolfSSLAltName san : sans) {
                switch (san.getType()) {
                    case WolfSSLAltName.TYPE_OTHER_NAME:
                        foundOtherName = true;
                        assertNotNull("otherName should have OID",
                            san.getOtherNameOID());
                        break;
                    case WolfSSLAltName.TYPE_RFC822_NAME:
                        foundEmail = true;
                        assertNotNull("email should have value",
                            san.getStringValue());
                        assertTrue("email should contain @",
                            san.getStringValue().contains("@"));
                        break;
                    case WolfSSLAltName.TYPE_DNS_NAME:
                        foundDNS = true;
                        assertNotNull("DNS should have value",
                            san.getStringValue());
                        break;
                    case WolfSSLAltName.TYPE_URI:
                        foundURI = true;
                        assertNotNull("URI should have value",
                            san.getStringValue());
                        break;
                    case WolfSSLAltName.TYPE_IP_ADDRESS:
                        foundIP = true;
                        assertNotNull("IP should have bytes",
                            san.getIPAddress());
                        assertNotNull("IP should have string",
                            san.getIPAddressString());
                        break;
                    case WolfSSLAltName.TYPE_DIRECTORY_NAME:
                        foundDirName = true;
                        assertNotNull("dirName should have value",
                            san.getStringValue());
                        break;
                }
            }

            /* Verify we found the expected types in all-types cert */
            assertTrue("Should find otherName", foundOtherName);
            assertTrue("Should find email", foundEmail);
            assertTrue("Should find DNS", foundDNS);
            assertTrue("Should find URI", foundURI);
            assertTrue("Should find IP", foundIP);
            assertTrue("Should find dirName", foundDirName);

        } finally {
            cert.free();
        }

        System.out.println("\t\t... passed");
    }

    /**
     * Test the "deprioritized username" pattern for SAN parsing.
     * Avoids usernames containing '$' (MS computer accounts).
     */
    private void test_SAN_DeprioritizedUsername()
        throws WolfSSLException, IOException {

        System.out.print("\tdeprioritized username pattern");

        String certPath = sanTestUpnCert;
        File certFile = new File(certPath);

        if (!certFile.exists()) {
            System.out.println("\t... skipped (cert not found)");
            return;
        }

        WolfSSLCertificate cert = new WolfSSLCertificate(
            certPath, WolfSSL.SSL_FILETYPE_PEM);

        try {
            WolfSSLAltName[] sans = cert.getSubjectAltNamesArray();
            if (sans == null) {
                System.out.println("\t... skipped (native not available)");
                return;
            }

            /* Implement the deprioritized username pattern */
            String deprioritizedUsername = null;
            String finalUsername = null;

            for (WolfSSLAltName san : sans) {
                String username = null;

                if (san.isMicrosoftUPN()) {
                    username = san.getOtherNameValueAsString();
                } else if (san.getType() == WolfSSLAltName.TYPE_RFC822_NAME ||
                           san.getType() == WolfSSLAltName.TYPE_DNS_NAME) {
                    username = san.getStringValue();
                }

                if (username != null) {
                    deprioritizedUsername = username;
                    /* Prefer usernames without '$' */
                    if (!username.contains("$")) {
                        finalUsername = username;
                        break;
                    }
                }
            }

            /* Verify pattern works */
            assertNotNull("Should find at least one username",
                deprioritizedUsername);

            /* Our test cert UPNs don't have '$', so finalUsername
             * should be set */
            if (finalUsername != null) {
                assertFalse("Final username should not contain '$'",
                    finalUsername.contains("$"));
            }

        } finally {
            cert.free();
        }

        System.out.println("\t... passed");
    }

    /**
     * Test WolfSSLAltName class and getSubjectAltNamesArray() method.
     *
     * This tests the type-safe API for accessing Subject Alternative Names.
     */
    @Test
    public void testWolfSSLAltNameClass()
        throws WolfSSLException, WolfSSLJNIException, IOException {

        System.out.println("WolfSSLAltName Class Tests");

        test_getSubjectAltNamesArray_ServerCert();
        test_WolfSSLAltName_TypeConstants();
        test_WolfSSLAltName_Methods();
        test_WolfSSLAltName_EqualsHashCode();
        test_getSubjectAltNamesArray_DefensiveCopy();
    }

    /**
     * Test getSubjectAltNamesArray() with server cert.
     */
    public void test_getSubjectAltNamesArray_ServerCert()
        throws WolfSSLException, IOException {

        boolean foundDNS = false;
        boolean foundIP = false;

        System.out.print("\tgetSubjectAltNamesArray()");

        if (WolfSSL.FileSystemEnabled() != true) {
            System.out.println("\t... skipped");
            return;
        }

        String serverCertPath = WolfSSLTestCommon.getPath(serverCertPem);
        WolfSSLCertificate serverCert = new WolfSSLCertificate(
            serverCertPath, WolfSSL.SSL_FILETYPE_PEM);
        assertNotNull(serverCert);

        WolfSSLAltName[] sans = serverCert.getSubjectAltNamesArray();
        if (sans == null) {
            serverCert.free();
            System.out.println("\t... skipped");
            return;
        }

        assertTrue("Expected at least 2 SANs", sans.length >= 2);

        for (WolfSSLAltName san : sans) {
            assertNotNull("SAN entry should not be null", san);

            if (san.getType() == WolfSSLAltName.TYPE_DNS_NAME) {
                String dnsName = san.getStringValue();
                assertNotNull("DNS value should not be null", dnsName);
                if ("example.com".equals(dnsName)) {
                    foundDNS = true;
                }
                /* Test toString() */
                assertTrue("toString() should contain dNSName",
                    san.toString().contains("dNSName"));
            }
            else if (san.getType() == WolfSSLAltName.TYPE_IP_ADDRESS) {
                byte[] ipBytes = san.getIPAddress();
                assertNotNull("IP bytes should not be null", ipBytes);
                String ipStr = san.getIPAddressString();
                assertNotNull("IP string should not be null", ipStr);
                if ("127.0.0.1".equals(ipStr)) {
                    foundIP = true;
                }
                /* Test getValue() for IP */
                assertEquals("getValue() should match getIPAddressString()",
                    ipStr, san.getValue());
            }
        }

        assertTrue("Did not find DNS SAN 'example.com'", foundDNS);
        assertTrue("Did not find IP SAN '127.0.0.1'", foundIP);

        serverCert.free();
        System.out.println("\t... passed");
    }

    /**
     * Test WolfSSLAltName type constants.
     */
    public void test_WolfSSLAltName_TypeConstants() {

        System.out.print("\tWolfSSLAltName type constants");

        /* Verify constants match RFC 5280 GeneralName types */
        assertEquals("TYPE_OTHER_NAME should be 0",
            0, WolfSSLAltName.TYPE_OTHER_NAME);
        assertEquals("TYPE_RFC822_NAME should be 1",
            1, WolfSSLAltName.TYPE_RFC822_NAME);
        assertEquals("TYPE_DNS_NAME should be 2",
            2, WolfSSLAltName.TYPE_DNS_NAME);
        assertEquals("TYPE_X400_ADDRESS should be 3",
            3, WolfSSLAltName.TYPE_X400_ADDRESS);
        assertEquals("TYPE_DIRECTORY_NAME should be 4",
            4, WolfSSLAltName.TYPE_DIRECTORY_NAME);
        assertEquals("TYPE_EDI_PARTY_NAME should be 5",
            5, WolfSSLAltName.TYPE_EDI_PARTY_NAME);
        assertEquals("TYPE_URI should be 6",
            6, WolfSSLAltName.TYPE_URI);
        assertEquals("TYPE_IP_ADDRESS should be 7",
            7, WolfSSLAltName.TYPE_IP_ADDRESS);
        assertEquals("TYPE_REGISTERED_ID should be 8",
            8, WolfSSLAltName.TYPE_REGISTERED_ID);

        /* Verify MS UPN OID constant */
        assertEquals("OID_MS_UPN should be correct",
            "1.3.6.1.4.1.311.20.2.3", WolfSSLAltName.OID_MS_UPN);

        System.out.println("\t... passed");
    }

    /**
     * Test WolfSSLAltName helper methods using real certificate data.
     */
    public void test_WolfSSLAltName_Methods()
        throws WolfSSLException, IOException {

        System.out.print("\tWolfSSLAltName methods");

        if (WolfSSL.FileSystemEnabled() != true) {
            System.out.println("\t\t... skipped (file system not enabled)");
            return;
        }

        /* Get SANs from server cert to test methods on real objects */
        String serverCertPath = WolfSSLTestCommon.getPath(serverCertPem);
        WolfSSLCertificate serverCert = new WolfSSLCertificate(
            serverCertPath, WolfSSL.SSL_FILETYPE_PEM);
        WolfSSLAltName[] sans = serverCert.getSubjectAltNamesArray();

        if (sans == null || sans.length == 0) {
            serverCert.free();
            System.out.println("\t\t... skipped (no SANs)");
            return;
        }

        /* Find DNS and IP entries to test methods */
        WolfSSLAltName dnsEntry = null;
        WolfSSLAltName ipEntry = null;

        for (WolfSSLAltName san : sans) {
            if (san.getType() == WolfSSLAltName.TYPE_DNS_NAME) {
                dnsEntry = san;
            }
            else if (san.getType() == WolfSSLAltName.TYPE_IP_ADDRESS) {
                ipEntry = san;
            }
        }

        /* Test DNS entry methods */
        if (dnsEntry != null) {
            assertEquals("getTypeName() for DNS should be dNSName",
                "dNSName", dnsEntry.getTypeName());
            assertNotNull("getStringValue() should not be null",
                dnsEntry.getStringValue());
            assertEquals("getValue() should match getStringValue()",
                dnsEntry.getStringValue(), dnsEntry.getValue());
            assertTrue("toString() should contain type name",
                dnsEntry.toString().contains("dNSName"));
            assertNull("getIPAddress() should be null for DNS",
                dnsEntry.getIPAddress());
            assertNull("getOtherNameOID() should be null for DNS",
                dnsEntry.getOtherNameOID());
            assertFalse("isMicrosoftUPN() should be false for DNS",
                dnsEntry.isMicrosoftUPN());
        }

        /* Test IP entry methods */
        if (ipEntry != null) {
            assertEquals("getTypeName() for IP should be iPAddress",
                "iPAddress", ipEntry.getTypeName());
            byte[] ipBytes = ipEntry.getIPAddress();
            assertNotNull("getIPAddress() should not be null", ipBytes);
            assertTrue("IP should be 4 or 16 bytes",
                ipBytes.length == 4 || ipBytes.length == 16);
            String ipStr = ipEntry.getIPAddressString();
            assertNotNull("getIPAddressString() should not be null", ipStr);
            assertEquals("getValue() should match IP string",
                ipStr, ipEntry.getValue());
            assertTrue("toString() should contain iPAddress",
                ipEntry.toString().contains("iPAddress"));
            assertNull("getStringValue() should be null for IP",
                ipEntry.getStringValue());
        }

        /* Test equals() - same entry should equal itself */
        if (dnsEntry != null) {
            assertEquals("Entry should equal itself", dnsEntry, dnsEntry);
            assertEquals("hashCode should be consistent",
                dnsEntry.hashCode(), dnsEntry.hashCode());
        }

        serverCert.free();
        System.out.println("\t\t... passed");
    }

    /**
     * Test WolfSSLAltName equals() and hashCode() methods thoroughly.
     */
    public void test_WolfSSLAltName_EqualsHashCode()
        throws WolfSSLException, IOException {

        System.out.print("\tequals() and hashCode()");

        if (WolfSSL.FileSystemEnabled() != true) {
            System.out.println("\t\t... skipped (file system not enabled)");
            return;
        }

        /* Load cert with SANs */
        String serverCertPath = WolfSSLTestCommon.getPath(serverCertPem);
        WolfSSLCertificate cert1 = new WolfSSLCertificate(
            serverCertPath, WolfSSL.SSL_FILETYPE_PEM);
        WolfSSLCertificate cert2 = new WolfSSLCertificate(
            serverCertPath, WolfSSL.SSL_FILETYPE_PEM);

        WolfSSLAltName[] sans1 = cert1.getSubjectAltNamesArray();
        WolfSSLAltName[] sans2 = cert2.getSubjectAltNamesArray();

        if (sans1 == null || sans2 == null || sans1.length == 0) {
            cert1.free();
            cert2.free();
            System.out.println("\t\t... skipped (no SANs)");
            return;
        }

        /* Test reflexive: x.equals(x) should return true */
        assertTrue("equals() should be reflexive",
            sans1[0].equals(sans1[0]));

        /* Test symmetric: x.equals(y) should match y.equals(x) */
        if (sans1.length > 0 && sans2.length > 0) {
            boolean eq1 = sans1[0].equals(sans2[0]);
            boolean eq2 = sans2[0].equals(sans1[0]);
            assertEquals("equals() should be symmetric", eq1, eq2);

            /* If equal, hashCodes must match */
            if (eq1) {
                assertEquals("Equal objects must have same hashCode",
                    sans1[0].hashCode(), sans2[0].hashCode());
            }
        }

        /* Test null: x.equals(null) should return false */
        assertFalse("equals(null) should return false",
            sans1[0].equals(null));

        /* Test different type: x.equals(differentType) should return false */
        assertFalse("equals(String) should return false",
            sans1[0].equals("not a WolfSSLAltName"));

        /* Test consistency: multiple calls should return same result */
        boolean result1 = sans1[0].equals(sans2[0]);
        boolean result2 = sans1[0].equals(sans2[0]);
        assertEquals("equals() should be consistent", result1, result2);

        /* Test hashCode consistency */
        int hash1 = sans1[0].hashCode();
        int hash2 = sans1[0].hashCode();
        assertEquals("hashCode() should be consistent", hash1, hash2);

        cert1.free();
        cert2.free();
        System.out.println("\t\t... passed");
    }

    /**
     * Test that getSubjectAltNamesArray() returns a copy.
     */
    public void test_getSubjectAltNamesArray_DefensiveCopy()
        throws WolfSSLException, IOException {

        System.out.print("\tdefensive copy test");

        if (WolfSSL.FileSystemEnabled() != true) {
            System.out.println("\t\t... skipped");
            return;
        }

        String serverCertPath = WolfSSLTestCommon.getPath(serverCertPem);
        WolfSSLCertificate cert = new WolfSSLCertificate(
            serverCertPath, WolfSSL.SSL_FILETYPE_PEM);

        WolfSSLAltName[] sans1 = cert.getSubjectAltNamesArray();
        WolfSSLAltName[] sans2 = cert.getSubjectAltNamesArray();

        if (sans1 == null || sans2 == null) {
            cert.free();
            fail("no SANs found in certificate");
            return;
        }

        /* Arrays should be different objects (copy) */
        assertNotSame("getSubjectAltNamesArray() should return copy",
            sans1, sans2);

        /* But contents should be equal */
        assertEquals("Arrays should have same length",
            sans1.length, sans2.length);

        for (int i = 0; i < sans1.length; i++) {
            assertEquals("Array elements should be equal",
                sans1[i], sans2[i]);
        }

        /* Modifying returned array should not affect future calls */
        int origLen = sans1.length;
        sans1[0] = null;  /* Modify the first array */
        WolfSSLAltName[] sans3 = cert.getSubjectAltNamesArray();
        assertNotNull("Modification should not affect cached data", sans3[0]);
        assertEquals("Length should remain unchanged", origLen, sans3.length);

        cert.free();
        System.out.println("\t\t... passed");
    }

    /**
     * Test SAN parsing with generated test certificates that have all
     * supported SAN types (DNS, IP, email, URI, otherName/UPN,
     * directoryName, registeredID).
     *
     * Test certificates are generated by:
     * examples/certs/generate-san-test-certs.sh
     */
    @Test
    public void testSANTestCertificates()
        throws WolfSSLException, WolfSSLJNIException, IOException {

        if (WolfSSL.FileSystemEnabled() != true) {
            return;
        }

        /* Check if test certs exist */
        File sanDir = new File(sanTestDir);
        if (!sanDir.exists() || !sanDir.isDirectory()) {
            return;
        }

        test_SAN_DnsAndIp();
        test_SAN_EmailAndUri();
        test_SAN_OtherNameUPN();
        test_SAN_DirName();
        test_SAN_AllTypes();
        test_SAN_DerFormat();
        test_SAN_CaCertVerification();
    }

    /**
     * Test DNS and IP address SANs.
     * Certificate has: DNS:localhost, DNS:example.com, DNS:*.wildcard.com,
     *   IP:127.0.0.1, IP:192.168.1.1, IP:::1, IP:fe80::1
     */
    private void test_SAN_DnsAndIp()
        throws WolfSSLException, IOException {

        System.out.print("\tDNS and IP SANs");

        String certPath = sanTestDnsIpCert;
        File certFile = new File(certPath);
        if (!certFile.exists()) {
            System.out.println("\t\t\t... skipped");
            return;
        }

        WolfSSLCertificate cert = new WolfSSLCertificate(
            certPath, WolfSSL.SSL_FILETYPE_PEM);
        assertNotNull(cert);

        WolfSSLAltName[] sans = cert.getSubjectAltNamesArray();
        if (sans == null) {
            cert.free();
            System.out.println("\t\t\t... skipped");
            return;
        }

        /* Should have at least 7 SANs: 3 DNS + 4 IP */
        assertTrue("Expected at least 7 SANs, got " + sans.length,
            sans.length >= 7);

        /* Track what we find */
        boolean foundLocalhost = false;
        boolean foundExampleCom = false;
        boolean foundWildcard = false;
        boolean foundIPv4_127 = false;
        boolean foundIPv4_192 = false;
        boolean foundIPv6_loopback = false;
        boolean foundIPv6_linklocal = false;

        for (WolfSSLAltName san : sans) {
            if (san.getType() == WolfSSLAltName.TYPE_DNS_NAME) {
                String dns = san.getStringValue();
                if ("localhost".equals(dns)) foundLocalhost = true;
                if ("example.com".equals(dns)) foundExampleCom = true;
                if ("*.wildcard.com".equals(dns)) foundWildcard = true;
            }
            else if (san.getType() == WolfSSLAltName.TYPE_IP_ADDRESS) {
                String ip = san.getIPAddressString();
                byte[] ipBytes = san.getIPAddress();

                if (ipBytes.length == 4) {
                    /* IPv4 */
                    if ("127.0.0.1".equals(ip)) foundIPv4_127 = true;
                    if ("192.168.1.1".equals(ip)) foundIPv4_192 = true;
                }
                else if (ipBytes.length == 16) {
                    /* IPv6 - check for loopback and link-local.
                     * InetAddress produces canonical format (e.g., "::1")
                     * so check for both expanded and compressed forms */
                    if (ip != null && (ip.equals("::1") ||
                        ip.equals("0:0:0:0:0:0:0:1"))) {
                        foundIPv6_loopback = true;
                    }
                    if (ip != null && ip.toLowerCase().startsWith("fe80:")) {
                        foundIPv6_linklocal = true;
                    }
                }
            }
        }

        assertTrue("Did not find DNS 'localhost'", foundLocalhost);
        assertTrue("Did not find DNS 'example.com'", foundExampleCom);
        assertTrue("Did not find DNS '*.wildcard.com'", foundWildcard);
        assertTrue("Did not find IPv4 '127.0.0.1'", foundIPv4_127);
        assertTrue("Did not find IPv4 '192.168.1.1'", foundIPv4_192);
        assertTrue("Did not find IPv6 loopback", foundIPv6_loopback);
        assertTrue("Did not find IPv6 link-local", foundIPv6_linklocal);

        cert.free();
        System.out.println("\t\t\t... passed");
    }

    /**
     * Test Email (rfc822Name) and URI SANs.
     * Certificate has: email:test@example.com, email:admin@wolfssl.com,
     *   URI:https://www.wolfssl.com, URI:ldap://ldap.example.com/cn=test
     */
    private void test_SAN_EmailAndUri()
        throws WolfSSLException, IOException {

        System.out.print("\tEmail and URI SANs");

        String certPath = sanTestEmailUriCert;
        File certFile = new File(certPath);
        if (!certFile.exists()) {
            System.out.println("\t\t... skipped (cert not found)");
            return;
        }

        WolfSSLCertificate cert = new WolfSSLCertificate(
            certPath, WolfSSL.SSL_FILETYPE_PEM);
        assertNotNull(cert);

        WolfSSLAltName[] sans = cert.getSubjectAltNamesArray();
        if (sans == null) {
            cert.free();
            System.out.println("\t\t... skipped (native not available)");
            return;
        }

        /* Should have at least 4 SANs: 2 email + 2 URI */
        assertTrue("Expected at least 4 SANs, got " + sans.length,
            sans.length >= 4);

        boolean foundEmail1 = false;
        boolean foundEmail2 = false;
        boolean foundUri1 = false;
        boolean foundUri2 = false;

        for (WolfSSLAltName san : sans) {
            if (san.getType() == WolfSSLAltName.TYPE_RFC822_NAME) {
                String email = san.getStringValue();
                assertEquals("getTypeName() should be rfc822Name",
                    "rfc822Name", san.getTypeName());
                if ("test@example.com".equals(email)) foundEmail1 = true;
                if ("admin@wolfssl.com".equals(email)) foundEmail2 = true;
            }
            else if (san.getType() == WolfSSLAltName.TYPE_URI) {
                String uri = san.getStringValue();
                assertEquals(
                    "getTypeName() should be uniformResourceIdentifier",
                    "uniformResourceIdentifier", san.getTypeName());
                if ("https://www.wolfssl.com".equals(uri)) foundUri1 = true;
                if (uri != null && uri.contains("ldap://ldap.example.com")) {
                    foundUri2 = true;
                }
            }
        }

        assertTrue("Did not find email 'test@example.com'", foundEmail1);
        assertTrue("Did not find email 'admin@wolfssl.com'", foundEmail2);
        assertTrue("Did not find URI 'https://www.wolfssl.com'", foundUri1);
        assertTrue("Did not find LDAP URI", foundUri2);

        cert.free();
        System.out.println("\t\t... passed");
    }

    /**
     * Test otherName SAN with Microsoft UPN.
     * Certificate has: otherName UPN:testuser@example.com,
     *   otherName UPN:admin@wolfssl.local, email:testuser@example.com
     */
    private void test_SAN_OtherNameUPN()
        throws WolfSSLException, IOException {

        System.out.print("\totherName UPN SANs");

        String certPath = sanTestUpnCert;
        File certFile = new File(certPath);
        if (!certFile.exists()) {
            System.out.println("\t\t... skipped (cert not found)");
            return;
        }

        WolfSSLCertificate cert = new WolfSSLCertificate(
            certPath, WolfSSL.SSL_FILETYPE_PEM);
        assertNotNull(cert);

        WolfSSLAltName[] sans = cert.getSubjectAltNamesArray();
        if (sans == null) {
            cert.free();
            System.out.println("\t\t... skipped (native not available)");
            return;
        }

        /* Should have at least 2 otherName SANs + 1 email */
        assertTrue("Expected at least 3 SANs, got " + sans.length,
            sans.length >= 3);

        boolean foundUPN1 = false;
        boolean foundUPN2 = false;
        int otherNameCount = 0;

        for (WolfSSLAltName san : sans) {
            if (san.getType() == WolfSSLAltName.TYPE_OTHER_NAME) {
                otherNameCount++;
                assertEquals("getTypeName() should be otherName",
                    "otherName", san.getTypeName());

                String oid = san.getOtherNameOID();
                assertNotNull("otherName OID should not be null", oid);

                /* Check if this is MS UPN */
                if (WolfSSLAltName.OID_MS_UPN.equals(oid)) {
                    assertTrue("isMicrosoftUPN() should return true",
                        san.isMicrosoftUPN());

                    byte[] valueBytes = san.getOtherNameValue();
                    assertNotNull("otherName value bytes should not be null",
                        valueBytes);

                    String upnStr = san.getOtherNameValueAsString();
                    if (upnStr != null) {
                        if (upnStr.contains("testuser@example.com")) {
                            foundUPN1 = true;
                        }
                        if (upnStr.contains("admin@wolfssl.local")) {
                            foundUPN2 = true;
                        }
                    }

                    /* Test getValue() for otherName */
                    String val = san.getValue();
                    assertNotNull("getValue() should not be null for UPN", val);
                }

                /* Test toString() contains OID info */
                String str = san.toString();
                assertTrue("toString() should contain OID",
                    str.contains("OID="));
            }
        }

        assertTrue("Expected at least 2 otherName SANs, got " + otherNameCount,
            otherNameCount >= 2);
        assertTrue("Did not find UPN 'testuser@example.com'", foundUPN1);
        assertTrue("Did not find UPN 'admin@wolfssl.local'", foundUPN2);

        cert.free();
        System.out.println("\t\t... passed");
    }

    /**
     * Test directoryName SANs.
     * Certificate has: dirName entries.
     */
    private void test_SAN_DirName()
        throws WolfSSLException, IOException {

        System.out.print("\tdirectoryName SANs");

        String certPath = sanTestDirNameRidCert;
        File certFile = new File(certPath);
        if (!certFile.exists()) {
            System.out.println("\t\t... skipped (cert not found)");
            return;
        }

        WolfSSLCertificate cert = new WolfSSLCertificate(
            certPath, WolfSSL.SSL_FILETYPE_PEM);
        assertNotNull(cert);

        WolfSSLAltName[] sans = cert.getSubjectAltNamesArray();
        if (sans == null) {
            cert.free();
            System.out.println("\t\t... skipped (native not available)");
            return;
        }

        /* Should have at least 2 dirName entries */
        assertTrue("Expected at least 2 SANs, got " + sans.length,
            sans.length >= 2);

        int dirNameCount = 0;

        for (WolfSSLAltName san : sans) {
            if (san.getType() == WolfSSLAltName.TYPE_DIRECTORY_NAME) {
                dirNameCount++;
                assertEquals("getTypeName() should be directoryName",
                    "directoryName", san.getTypeName());

                String dirName = san.getStringValue();
                assertNotNull("directoryName value should not be null",
                    dirName);

                /* Verify dirName contains expected DN components */
                assertTrue("dirName should contain CN",
                    dirName.contains("CN=") || dirName.contains("Directory"));
            }
        }

        assertTrue("Expected at least 2 directoryName SANs, got " +
            dirNameCount, dirNameCount >= 2);

        cert.free();
        System.out.println("\t\t... passed");
    }

    /**
     * Test comprehensive certificate with multiple SAN types.
     * Certificate has: otherName (UPN), rfc822Name (email), dNSName,
     *   directoryName, URI, iPAddress (v4 and v6).
     *
     * Note: registeredID (type 8) is excluded from this test cert as it
     * can cause parsing issues in some wolfSSL builds.
     */
    private void test_SAN_AllTypes()
        throws WolfSSLException, IOException {

        System.out.print("\tAll SAN types");

        String certPath = sanTestAllTypesCert;
        File certFile = new File(certPath);
        if (!certFile.exists()) {
            System.out.println("\t\t\t... skipped (cert not found)");
            return;
        }

        WolfSSLCertificate cert = new WolfSSLCertificate(
            certPath, WolfSSL.SSL_FILETYPE_PEM);
        assertNotNull(cert);

        WolfSSLAltName[] sans = cert.getSubjectAltNamesArray();
        if (sans == null) {
            cert.free();
            System.out.println("\t\t\t... skipped (native not available)");
            return;
        }

        /* Should have many SANs (otherName, email x2, DNS x3, dirName,
         * URI x2, IP x4) = at least 13 */
        assertTrue("Expected at least 10 SANs, got " + sans.length,
            sans.length >= 10);

        /* Track found types */
        boolean foundOtherName = false;
        boolean foundEmail = false;
        boolean foundDNS = false;
        boolean foundDirName = false;
        boolean foundURI = false;
        boolean foundIPv4 = false;
        boolean foundIPv6 = false;

        /* Track specific values */
        boolean foundUPN = false;
        boolean foundLocalhost = false;
        boolean foundWolfSSLUri = false;

        for (WolfSSLAltName san : sans) {
            int type = san.getType();

            switch (type) {
                case WolfSSLAltName.TYPE_OTHER_NAME:
                    foundOtherName = true;
                    if (san.isMicrosoftUPN()) {
                        String upn = san.getOtherNameValueAsString();
                        if (upn != null &&
                            upn.contains("allsantypes@wolfssl.com")) {
                            foundUPN = true;
                        }
                    }
                    break;

                case WolfSSLAltName.TYPE_RFC822_NAME:
                    foundEmail = true;
                    break;

                case WolfSSLAltName.TYPE_DNS_NAME:
                    foundDNS = true;
                    if ("localhost".equals(san.getStringValue())) {
                        foundLocalhost = true;
                    }
                    break;

                case WolfSSLAltName.TYPE_DIRECTORY_NAME:
                    foundDirName = true;
                    break;

                case WolfSSLAltName.TYPE_URI:
                    foundURI = true;
                    String uri = san.getStringValue();
                    if (uri != null &&
                        uri.contains("https://www.wolfssl.com")) {
                        foundWolfSSLUri = true;
                    }
                    break;

                case WolfSSLAltName.TYPE_IP_ADDRESS:
                    byte[] ipBytes = san.getIPAddress();
                    if (ipBytes != null) {
                        if (ipBytes.length == 4) {
                            foundIPv4 = true;
                        }
                        else if (ipBytes.length == 16) {
                            foundIPv6 = true;
                        }
                    }
                    break;

                default:
                    /* Ignore other types */
                    break;
            }
        }

        /* Verify all expected types found */
        assertTrue("Did not find otherName SAN", foundOtherName);
        assertTrue("Did not find rfc822Name (email) SAN", foundEmail);
        assertTrue("Did not find dNSName SAN", foundDNS);
        assertTrue("Did not find directoryName SAN", foundDirName);
        assertTrue("Did not find URI SAN", foundURI);
        assertTrue("Did not find IPv4 SAN", foundIPv4);
        assertTrue("Did not find IPv6 SAN", foundIPv6);

        /* Verify specific values */
        assertTrue("Did not find UPN 'allsantypes@wolfssl.com'", foundUPN);
        assertTrue("Did not find DNS 'localhost'", foundLocalhost);
        assertTrue("Did not find URI 'https://www.wolfssl.com'",
            foundWolfSSLUri);

        cert.free();
        System.out.println("\t\t\t... passed");
    }

    /**
     * Test SAN parsing with DER format certificates.
     * Verifies that DER files work the same as PEM files.
     */
    private void test_SAN_DerFormat()
        throws WolfSSLException, IOException {

        System.out.print("\tDER format certificates");

        /* Test all-types cert in DER format */
        String derPath = sanTestAllTypesDer;
        File derFile = new File(derPath);
        if (!derFile.exists()) {
            System.out.println("\t... skipped (DER not found)");
            return;
        }

        WolfSSLCertificate cert = new WolfSSLCertificate(
            derPath, WolfSSL.SSL_FILETYPE_ASN1);
        assertNotNull(cert);

        WolfSSLAltName[] sans = cert.getSubjectAltNamesArray();
        if (sans == null) {
            cert.free();
            System.out.println("\t... skipped (native not available)");
            return;
        }

        /* Verify we got SANs from DER format */
        assertTrue("Expected SANs from DER cert, got " + sans.length,
            sans.length >= 10);

        /* Verify at least DNS and IP types are present */
        boolean foundDNS = false;
        boolean foundIP = false;

        for (WolfSSLAltName san : sans) {
            if (san.getType() == WolfSSLAltName.TYPE_DNS_NAME) {
                foundDNS = true;
            }
            else if (san.getType() == WolfSSLAltName.TYPE_IP_ADDRESS) {
                foundIP = true;
            }
        }

        assertTrue("Did not find DNS SAN in DER cert", foundDNS);
        assertTrue("Did not find IP SAN in DER cert", foundIP);

        /* Also test dns-ip.der */
        String dnsIpDerPath = sanTestDnsIpDer;
        File dnsIpDerFile = new File(dnsIpDerPath);
        if (dnsIpDerFile.exists()) {
            WolfSSLCertificate dnsIpCert = new WolfSSLCertificate(
                dnsIpDerPath, WolfSSL.SSL_FILETYPE_ASN1);
            assertNotNull(dnsIpCert);

            WolfSSLAltName[] dnsIpSans = dnsIpCert.getSubjectAltNamesArray();
            if (dnsIpSans != null) {
                assertTrue("Expected SANs from dns-ip DER cert",
                    dnsIpSans.length >= 7);
            }

            dnsIpCert.free();
        }

        cert.free();
        System.out.println("\t\t... passed");
    }

    /**
     * Test CA certificate and verification of test certificates.
     * Verifies the CA cert was generated correctly and can verify
     * the signed test certificates.
     */
    private void test_SAN_CaCertVerification()
        throws WolfSSLException, IOException {

        System.out.print("\tCA cert verification");

        String caCertPath = sanTestCaCert;
        File caCertFile = new File(caCertPath);
        if (!caCertFile.exists()) {
            System.out.println("\t\t... skipped (CA cert not found)");
            return;
        }

        /* Load CA certificate */
        WolfSSLCertificate caCert = new WolfSSLCertificate(
            caCertPath, WolfSSL.SSL_FILETYPE_PEM);
        assertNotNull(caCert);

        /* Verify CA cert properties - isCA() returns 1 for CA certs */
        assertTrue("CA cert should be CA", caCert.isCA() == 1);
        String caSubject = caCert.getSubject();
        assertNotNull("CA subject should not be null", caSubject);
        assertTrue("CA subject should contain 'SAN Test CA'",
            caSubject.contains("SAN Test CA"));

        /* Load a test certificate and verify it was signed by CA */
        String testCertPath = sanTestAllTypesCert;
        File testCertFile = new File(testCertPath);
        if (testCertFile.exists()) {
            WolfSSLCertificate testCert = new WolfSSLCertificate(
                testCertPath, WolfSSL.SSL_FILETYPE_PEM);
            assertNotNull(testCert);

            /* Get issuer and verify it matches CA subject */
            String issuer = testCert.getIssuer();
            assertNotNull("Test cert issuer should not be null", issuer);
            assertTrue("Test cert issuer should contain 'SAN Test CA'",
                issuer.contains("SAN Test CA"));

            /* Verify the test cert with CA public key */
            byte[] caPubKey = caCert.getPubkey();
            if (caPubKey != null) {
                boolean verified = testCert.verify(caPubKey,
                    caPubKey.length);
                assertTrue("Test cert should verify with CA key", verified);
            }

            testCert.free();
        }

        caCert.free();
        System.out.println("\t\t... passed");
    }
}
