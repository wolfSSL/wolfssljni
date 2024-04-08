/* WolfSSLCertificate.java
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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
import java.security.cert.CertificateFactory;
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

import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import static org.junit.Assert.*;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLX509Name;
import com.wolfssl.WolfSSLCertificate;
import com.wolfssl.WolfSSLCertManager;
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
    public static String bogusFile = "/dev/null";
    private WolfSSLCertificate cert;

    @BeforeClass
    public static void setCertPaths() throws WolfSSLException {

        try {
            WolfSSL.loadLibrary();
        } catch (UnsatisfiedLinkError ule) {
            fail("failed to load native JNI library");
        }

        cliCertDer = WolfSSLTestCommon.getPath(cliCertDer);
        cliCertPem = WolfSSLTestCommon.getPath(cliCertPem);
        cliKeyPubDer = WolfSSLTestCommon.getPath(cliKeyPubDer);
        caCertPem = WolfSSLTestCommon.getPath(caCertPem);
        caKeyDer = WolfSSLTestCommon.getPath(caKeyDer);
        external   = WolfSSLTestCommon.getPath(external);
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
        }
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
                ext = new WolfSSLCertificate(this.external);
            } else {
                ext = new WolfSSLCertificate(fileToByteArray(this.external),
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
}

