/* X509v3CertificateGeneration.java
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

import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Instant;
import java.time.Duration;
import java.util.Date;
import java.math.BigInteger;

import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.interfaces.RSAPrivateKey;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLCertificate;
import com.wolfssl.WolfSSLX509Name;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLJNIException;

/**
 * Example application that demonstrates X509v3 certifiate generation
 * including various combinations:
 *
 * Self-signed certificate using files as input for certs/keys
 * Self-signed certificate using arrays as input for certs/keys
 * Self-signed certificate using generated certs and keys
 *
 * CA-signed certificate using files as input for certs/keys
 * CA-signed certificate using arrays as input for certs/keys
 * CA-signed certificate using generated certs and keys
 *
 * Each sub-example is contained in a separate method.
 *
 * When run, generated certificates are written out to PEM and DER files,
 * with location specified by variables at the top of this class.
 */
public class X509v3CertificateGeneration {

    private static String CERT_DIR = "../certs/";
    private static String GEN_DIR = CERT_DIR + "generated/";
    private static String CERT_DIR_FROM_ROOT = "./exammples/certs/generated/";

    /* Existing certs/keys used for cert gen example with files */
    private static String caCertPem       = CERT_DIR + "ca-cert.pem";
    private static String caKeyDer        = CERT_DIR + "ca-key.der";
    private static String caKeyPkcs8Der   = CERT_DIR + "ca-keyPkcs8.der";
    private static String clientKeyDer    = CERT_DIR + "client-key.der";
    private static String clientKeyPubDer = CERT_DIR + "client-keyPub.der";

    /* Generated self-signed certificate locations.
     * Generated self-signed certs have isCA Basic Constraint set true
     * in these examples. */
    private static String selfSignedUsingFilesDer =
        GEN_DIR + "self-signed-using-files.der";
    private static String selfSignedUsingFilesPem =
        GEN_DIR + "self-signed-using-files.pem";
    private static String selfSignedUsingArraysDer =
        GEN_DIR + "self-signed-using-arrays.der";
    private static String selfSignedUsingArraysPem =
        GEN_DIR + "self-signed-using-arrays.pem";
    private static String selfSignedUsingGeneratedKeysDer =
        GEN_DIR + "self-signed-generated-keys.der";
    private static String selfSignedUsingGeneratedKeysPem =
        GEN_DIR + "self-signed-generated-keys.pem";

    /* Generated CA-signed certificate locations.
     * Generated CA-signed certs have isCA Basic Constraint set false
     * in these examples. */
    private static String caSignedUsingFilesDer =
        GEN_DIR + "ca-signed-using-files.der";
    private static String caSignedUsingFilesPem =
        GEN_DIR + "ca-signed-using-files.pem";
    private static String caSignedUsingArraysDer =
        GEN_DIR + "ca-signed-using-arrays.der";
    private static String caSignedUsingArraysPem =
        GEN_DIR + "ca-signed-using-arrays.pem";
    private static String caSignedUsingGeneratedKeysDer =
        GEN_DIR + "ca-signed-generated-keys.der";
    private static String caSignedUsingGeneratedKeysPem =
        GEN_DIR + "ca-signed-generated-keys.pem";

    /* Example Extension values */
    private static String test_KEY_USAGE =
        "digitalSignature,keyEncipherment,dataEncipherment";
    private static String test_EXT_KEY_USAGE =
        "clientAuth,serverAuth";
    private static String test_ALT_NAME =
        "alt.example.com";

    private void writeFile(String path, byte[] bytes)
        throws IOException {

        File genDir = new File(GEN_DIR);
        if (!genDir.exists()) {
            genDir.mkdir();
        }
        Files.write(new File(path).toPath(), bytes);
    }

    private WolfSSLX509Name generateTestSubjectName()
        throws WolfSSLException {

        WolfSSLX509Name subjectName = new WolfSSLX509Name();
        subjectName.setCountryName("US");
        subjectName.setStateOrProvinceName("Montana");
        subjectName.setStreetAddress("12345 Test Address");
        subjectName.setLocalityName("Bozeman");
        subjectName.setSurname("Test Surname");
        subjectName.setCommonName("example.com");
        subjectName.setEmailAddress("support@example.com");
        subjectName.setOrganizationName("wolfSSL Inc.");
        subjectName.setOrganizationalUnitName("Test and Development");
        subjectName.setPostalCode("59715");
        subjectName.setUserId("TestUserID");

        return subjectName;
    }

    /**
     * Generate example certificate using the following files as input
     * to the certificate generation process:
     *
     * clientKeyPubDer - Existing client public key in DER format
     * clientKeyDer    - Existing client private key in DER format
     *
     * Generates and writes certificate out to the following paths in
     * both PEM and DER format (see variable values above):
     *     selfSignedUsingFilesDer (DER format)
     *     selfSignedUsingFilesPem (PEM format)
     *
     * @throws WolfSSLException if error occurs during certificate generation
     *         process.
     * @throws WolfSSLJNIException if native JNI error occurs
     * @throws IOException on error writing to output file locations
     */
    public void generateSelfSignedUsingFiles()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException {

        System.out.print("\nGenerating self-signed cert using files");

        /* Create new certificate object */
        WolfSSLCertificate x509 = new WolfSSLCertificate();

        /* Set notBefore/notAfter validity dates */
        Instant now = Instant.now();
        final Date notBefore = Date.from(now);
        final Date notAfter = Date.from(now.plus(Duration.ofDays(365)));
        x509.setNotBefore(notBefore);
        x509.setNotAfter(notAfter);

        /* Set serial number */
        x509.setSerialNumber(BigInteger.valueOf(12345));

        /* Set Subject Name */
        WolfSSLX509Name subjectName = generateTestSubjectName();
        x509.setSubjectName(subjectName);

        /* Not setting Issuer, since generating self-signed cert */

        /* Set Public Key from existing public key DER file */
        x509.setPublicKey(clientKeyPubDer, WolfSSL.RSAk,
                WolfSSL.SSL_FILETYPE_ASN1);

        /* Add Extensions */
        x509.addExtension(WolfSSL.NID_key_usage, test_KEY_USAGE, false);
        x509.addExtension(WolfSSL.NID_ext_key_usage, test_EXT_KEY_USAGE, false);
        x509.addExtension(WolfSSL.NID_subject_alt_name, test_ALT_NAME, false);
        x509.addExtension(WolfSSL.NID_basic_constraints, true, true);

        /* Sign certificate, self-signed using existing client key DER */
        x509.signCert(clientKeyDer, WolfSSL.RSAk,
                WolfSSL.SSL_FILETYPE_ASN1, "SHA256");

        /* Output to DER and PEM files */
        byte[] derCert = x509.getDer();
        byte[] pemCert = x509.getPem();

        /* Write out generated certs to files */
        writeFile(selfSignedUsingFilesDer, derCert);
        writeFile(selfSignedUsingFilesPem, pemCert);

        /* Test converting to X509Certificate */
        X509Certificate tmpX509 = x509.getX509Certificate();

        System.out.println("... ");
        System.out.println("    " + CERT_DIR_FROM_ROOT +
                Paths.get(selfSignedUsingFilesDer).getFileName());
        System.out.println("    " + CERT_DIR_FROM_ROOT +
                Paths.get(selfSignedUsingFilesPem).getFileName());

        /* Free native memory */
        subjectName.free();
        x509.free();
    }

    /**
     * Generate example certificate using the following files in array format
     * as input to the certificate generation process:
     *
     * clientKeyPubDer - Existing client public key in DER format
     * clientKeyDer    - Existing client private key in DER format
     *
     * Generates and writes certificate out to the following paths in
     * both PEM and DER format (see variable values above):
     *     selfSignedUsingArraysDer (DER format)
     *     selfSignedUsingArraysPem (PEM format)
     *
     * @throws WolfSSLException if error occurs during certificate generation
     *         process.
     * @throws WolfSSLJNIException if native JNI error occurs
     * @throws IOException on error writing to output file locations
     */
    public void generateSelfSignedUsingArrays()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException {

        System.out.print("\nGenerating self-signed cert using arrays");

        /* Create new certificate object */
        WolfSSLCertificate x509 = new WolfSSLCertificate();

        /* Set notBefore/notAfter validity dates */
        Instant now = Instant.now();
        final Date notBefore = Date.from(now);
        final Date notAfter = Date.from(now.plus(Duration.ofDays(365)));
        x509.setNotBefore(notBefore);
        x509.setNotAfter(notAfter);

        /* Set serial number */
        x509.setSerialNumber(BigInteger.valueOf(12345));

        /* Set Subject Name */
        WolfSSLX509Name subjectName = generateTestSubjectName();
        x509.setSubjectName(subjectName);

        /* Not setting Issuer, since generating self-signed cert */

        /* Set Public Key from existing public key DER file */
        byte[] pubKey = Files.readAllBytes(Paths.get(clientKeyPubDer));
        x509.setPublicKey(pubKey, WolfSSL.RSAk, WolfSSL.SSL_FILETYPE_ASN1);

        /* Add Extensions */
        x509.addExtension(WolfSSL.NID_key_usage, test_KEY_USAGE, false);
        x509.addExtension(WolfSSL.NID_ext_key_usage, test_EXT_KEY_USAGE, false);
        x509.addExtension(WolfSSL.NID_subject_alt_name, test_ALT_NAME, false);
        x509.addExtension(WolfSSL.NID_basic_constraints, true, true);

        /* Sign certificate, self-signed using existing client key DER */
        byte[] privKey = Files.readAllBytes(Paths.get(clientKeyDer));
        x509.signCert(privKey, WolfSSL.RSAk,
                WolfSSL.SSL_FILETYPE_ASN1, "SHA256");

        /* Output to DER and PEM files */
        byte[] derCert = x509.getDer();
        byte[] pemCert = x509.getPem();

        /* Write out generated certs to files */
        writeFile(selfSignedUsingArraysDer, derCert);
        writeFile(selfSignedUsingArraysPem, pemCert);

        /* Test converting to X509Certificate */
        X509Certificate tmpX509 = x509.getX509Certificate();

        System.out.println("... ");
        System.out.println("    " + CERT_DIR_FROM_ROOT +
                Paths.get(selfSignedUsingArraysDer).getFileName());
        System.out.println("    " + CERT_DIR_FROM_ROOT +
                Paths.get(selfSignedUsingArraysPem).getFileName());

        /* Free native memory */
        subjectName.free();
        x509.free();
    }

    /**
     * Generate example certificate using generated keys for the certificate
     * public and private key, to be used in the certificate generation
     * process.
     *
     * Generates and writes certificate out to the following paths in
     * both PEM and DER format (see variable values above):
     *     selfSignedUsingGeneratedKeysDer (DER format)
     *     selfSignedUsingGeneratedKeysPem (PEM format)
     *
     * @throws WolfSSLException if error occurs during certificate generation
     *         process.
     * @throws WolfSSLJNIException if native JNI error occurs
     * @throws IOException on error writing to output file locations
     */
    public void generateSelfSignedUsingGeneratedKeys()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException, NoSuchAlgorithmException {

        System.out.print("\nGenerating self-signed cert with generated keys");

        /* Create new certificate object */
        WolfSSLCertificate x509 = new WolfSSLCertificate();

        /* Set notBefore/notAfter validity dates */
        Instant now = Instant.now();
        final Date notBefore = Date.from(now);
        final Date notAfter = Date.from(now.plus(Duration.ofDays(365)));
        x509.setNotBefore(notBefore);
        x509.setNotAfter(notAfter);

        /* Set serial number */
        x509.setSerialNumber(BigInteger.valueOf(12345));

        /* Set Subject Name */
        WolfSSLX509Name subjectName = generateTestSubjectName();
        x509.setSubjectName(subjectName);

        /* Not setting Issuer, since generating self-signed cert */

        /* Set Public Key from generated java.security.PublicKey */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        PublicKey pubKey = keyPair.getPublic();
        x509.setPublicKey(pubKey);

        /* Add Extensions */
        x509.addExtension(WolfSSL.NID_key_usage, test_KEY_USAGE, false);
        x509.addExtension(WolfSSL.NID_ext_key_usage, test_EXT_KEY_USAGE, false);
        x509.addExtension(WolfSSL.NID_subject_alt_name, test_ALT_NAME, false);
        x509.addExtension(WolfSSL.NID_basic_constraints, true, true);

        /* Sign certificate, self-signed with java.security.PrivateKey */
        PrivateKey privKey = keyPair.getPrivate();
        x509.signCert(privKey, "SHA256");

        /* Output to DER and PEM files */
        byte[] derCert = x509.getDer();
        byte[] pemCert = x509.getPem();

        /* Write out generated certs to files */
        writeFile(selfSignedUsingGeneratedKeysDer, derCert);
        writeFile(selfSignedUsingGeneratedKeysPem, pemCert);

        /* Test converting to X509Certificate */
        X509Certificate tmpX509 = x509.getX509Certificate();

        System.out.println("... ");
        System.out.println("    " + CERT_DIR_FROM_ROOT +
                Paths.get(selfSignedUsingGeneratedKeysDer).getFileName());
        System.out.println("    " + CERT_DIR_FROM_ROOT +
                Paths.get(selfSignedUsingGeneratedKeysPem).getFileName());

        /* Free native memory */
        subjectName.free();
        x509.free();
    }

    /**
     * -----------------------------------------------------------------------
     * Below are examples of CA-signed certificate generation
     * -----------------------------------------------------------------------
     */

    /**
     * Generate example CA-signed certificate using the following files as
     * input to the certificate generation process:
     *
     * caCertPem       - Existing CA certificate in PEM format
     * clientKeyPubDer - Existing client public key in DER format
     * clientKeyDer    - Existing client private key in DER format
     *
     * Generates and writes certificate out to the following paths in
     * both PEM and DER format (see variable values above):
     *     caSignedUsingFilesDer (DER format)
     *     caSignedUsingFilesPem (PEM format)
     *
     * @throws WolfSSLException if error occurs during certificate generation
     *         process.
     * @throws WolfSSLJNIException if native JNI error occurs
     * @throws IOException on error writing to output file locations
     */
    public void generateCASignedUsingFiles()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException {

        System.out.print("\nGenerating CA-signed cert using files");

        /* Create new certificate object */
        WolfSSLCertificate x509 = new WolfSSLCertificate();

        /* Set notBefore/notAfter validity dates */
        Instant now = Instant.now();
        final Date notBefore = Date.from(now);
        final Date notAfter = Date.from(now.plus(Duration.ofDays(365)));
        x509.setNotBefore(notBefore);
        x509.setNotAfter(notAfter);

        /* Set serial number */
        x509.setSerialNumber(BigInteger.valueOf(12345));

        /* Set Subject Name */
        WolfSSLX509Name subjectName = generateTestSubjectName();
        x509.setSubjectName(subjectName);

        /* Set Issuer Name from existing cert file wrapped in
         * WolfSSLCertificate object */
        WolfSSLCertificate issuer = new WolfSSLCertificate(caCertPem,
            WolfSSL.SSL_FILETYPE_PEM);
        x509.setIssuerName(issuer);

        /* Set Public Key from existing public key DER file */
        x509.setPublicKey(clientKeyPubDer, WolfSSL.RSAk,
                WolfSSL.SSL_FILETYPE_ASN1);

        /* Add Extensions */
        x509.addExtension(WolfSSL.NID_key_usage, test_KEY_USAGE, false);
        x509.addExtension(WolfSSL.NID_ext_key_usage, test_EXT_KEY_USAGE, false);
        x509.addExtension(WolfSSL.NID_subject_alt_name, test_ALT_NAME, false);
        x509.addExtension(WolfSSL.NID_basic_constraints, true, true);

        /* Sign certificate, CA-signed using existing CA key DER */
        x509.signCert(caKeyDer, WolfSSL.RSAk,
                WolfSSL.SSL_FILETYPE_ASN1, "SHA256");

        /* Output to DER and PEM files */
        byte[] derCert = x509.getDer();
        byte[] pemCert = x509.getPem();

        /* Write out generated certs to files */
        writeFile(caSignedUsingFilesDer, derCert);
        writeFile(caSignedUsingFilesPem, pemCert);

        /* Test converting to X509Certificate */
        X509Certificate tmpX509 = x509.getX509Certificate();

        System.out.println("... ");
        System.out.println("    " + CERT_DIR_FROM_ROOT +
                Paths.get(caSignedUsingFilesDer).getFileName());
        System.out.println("    " + CERT_DIR_FROM_ROOT +
                Paths.get(caSignedUsingFilesPem).getFileName());

        /* Free native memory */
        subjectName.free();
        x509.free();
    }

    /**
     * Generate example CA-signed certificate using the following files in
     * array format as input to the certificate generation process:
     *
     * caCertPem       - Existing CA certificate in PEM format
     * clientKeyPubDer - Existing client public key in DER format
     * clientKeyDer    - Existing client private key in DER format
     *
     * Generates and writes certificate out to the following paths in
     * both PEM and DER format (see variable values above):
     *     caSignedUsingArraysDer (DER format)
     *     caSignedUsingArraysPem (PEM format)
     *
     * @throws WolfSSLException if error occurs during certificate generation
     *         process.
     * @throws WolfSSLJNIException if native JNI error occurs
     * @throws IOException on error writing to output file locations
     */
    public void generateCASignedUsingArrays()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException {

        System.out.print("\nGenerating CA-signed cert using arrays");

        /* Create new certificate object */
        WolfSSLCertificate x509 = new WolfSSLCertificate();

        /* Set notBefore/notAfter validity dates */
        Instant now = Instant.now();
        final Date notBefore = Date.from(now);
        final Date notAfter = Date.from(now.plus(Duration.ofDays(365)));
        x509.setNotBefore(notBefore);
        x509.setNotAfter(notAfter);

        /* Set serial number */
        x509.setSerialNumber(BigInteger.valueOf(12345));

        /* Set Subject Name */
        WolfSSLX509Name subjectName = generateTestSubjectName();
        x509.setSubjectName(subjectName);

        /* Set Issuer Name from existing cert file ready into a byte array and
         * wrapped in WolfSSLCertificate object */
        WolfSSLCertificate issuer = new WolfSSLCertificate(
            Files.readAllBytes(Paths.get(caCertPem)),
            WolfSSL.SSL_FILETYPE_PEM);
        x509.setIssuerName(issuer);

        /* Set Public Key from existing public key DER file */
        byte[] pubKey = Files.readAllBytes(Paths.get(clientKeyPubDer));
        x509.setPublicKey(pubKey, WolfSSL.RSAk, WolfSSL.SSL_FILETYPE_ASN1);

        /* Add Extensions */
        x509.addExtension(WolfSSL.NID_key_usage, test_KEY_USAGE, false);
        x509.addExtension(WolfSSL.NID_ext_key_usage, test_EXT_KEY_USAGE, false);
        x509.addExtension(WolfSSL.NID_subject_alt_name, test_ALT_NAME, false);
        x509.addExtension(WolfSSL.NID_basic_constraints, true, true);

        /* Sign certificate, self-signed using existing client key DER */
        byte[] privKey = Files.readAllBytes(Paths.get(caKeyDer));
        x509.signCert(privKey, WolfSSL.RSAk,
                WolfSSL.SSL_FILETYPE_ASN1, "SHA256");

        /* Output to DER and PEM files */
        byte[] derCert = x509.getDer();
        byte[] pemCert = x509.getPem();

        /* Write out generated certs to files */
        writeFile(caSignedUsingArraysDer, derCert);
        writeFile(caSignedUsingArraysPem, pemCert);

        /* Test converting to X509Certificate */
        X509Certificate tmpX509 = x509.getX509Certificate();

        System.out.println("... ");
        System.out.println("    " + CERT_DIR_FROM_ROOT +
                Paths.get(caSignedUsingArraysDer).getFileName());
        System.out.println("    " + CERT_DIR_FROM_ROOT +
                Paths.get(caSignedUsingArraysPem).getFileName());

        /* Free native memory */
        subjectName.free();
        x509.free();
    }

    /**
     * Generate example CA-signed certificate using generated keys for the
     * certificate public and private key, to be used in the certificate
     * generation process.
     *
     * Generates and writes certificate out to the following paths in
     * both PEM and DER format (see variable values above):
     *     caSignedUsingGeneratedKeysDer (DER format)
     *     caSignedUsingGeneratedKeysPem (PEM format)
     *
     * @throws WolfSSLException if error occurs during certificate generation
     *         process.
     * @throws WolfSSLJNIException if native JNI error occurs
     * @throws IOException on error writing to output file locations
     */
    public void generateCASignedUsingGeneratedKeys()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException, NoSuchAlgorithmException,
               InvalidKeySpecException {

        System.out.print("\nGenerating CA-signed cert with generated keys");

        /* Create new certificate object */
        WolfSSLCertificate x509 = new WolfSSLCertificate();

        /* Set notBefore/notAfter validity dates */
        Instant now = Instant.now();
        final Date notBefore = Date.from(now);
        final Date notAfter = Date.from(now.plus(Duration.ofDays(365)));
        x509.setNotBefore(notBefore);
        x509.setNotAfter(notAfter);

        /* Set serial number */
        x509.setSerialNumber(BigInteger.valueOf(12345));

        /* Set Subject Name */
        WolfSSLX509Name subjectName = generateTestSubjectName();
        x509.setSubjectName(subjectName);

        /* Set Issuer Name from existing cert file wrapped in
         * WolfSSLCertificate object */
        WolfSSLCertificate issuer = new WolfSSLCertificate(caCertPem,
            WolfSSL.SSL_FILETYPE_PEM);
        X509Certificate issuerX509 = issuer.getX509Certificate();
        x509.setIssuerName(issuerX509);

        /* Set Public Key from generated java.security.PublicKey */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        PublicKey pubKey = keyPair.getPublic();
        x509.setPublicKey(pubKey);

        /* Add Extensions */
        x509.addExtension(WolfSSL.NID_key_usage, test_KEY_USAGE, false);
        x509.addExtension(WolfSSL.NID_ext_key_usage, test_EXT_KEY_USAGE, false);
        x509.addExtension(WolfSSL.NID_subject_alt_name, test_ALT_NAME, false);
        x509.addExtension(WolfSSL.NID_basic_constraints, true, true);

        /* Sign certificate, using CA's private key */
        byte[] privBytes = Files.readAllBytes(Paths.get(caKeyPkcs8Der));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privBytes);
        RSAPrivateKey rsaPriv = (RSAPrivateKey)kf.generatePrivate(spec);
        x509.signCert((PrivateKey)rsaPriv, "SHA256");

        /* Output to DER and PEM files */
        byte[] derCert = x509.getDer();
        byte[] pemCert = x509.getPem();

        /* Write out generated certs to files */
        writeFile(caSignedUsingGeneratedKeysDer, derCert);
        writeFile(caSignedUsingGeneratedKeysPem, pemCert);

        /* Test converting to X509Certificate */
        X509Certificate tmpX509 = x509.getX509Certificate();

        System.out.println("... ");
        System.out.println("    " + CERT_DIR_FROM_ROOT +
                Paths.get(caSignedUsingGeneratedKeysDer).getFileName());
        System.out.println("    " + CERT_DIR_FROM_ROOT +
                Paths.get(caSignedUsingGeneratedKeysPem).getFileName());

        /* Free native memory */
        subjectName.free();
        x509.free();
    }

    public void run(String[] args) {

        int ret = 0;

        try {
            /* Initialize and load native wolfSSL library, enable debugging */
            WolfSSL.loadLibrary();
            WolfSSL sslLib = new WolfSSL();

            /* Enable debugging if desired */
            /* sslLib.debuggingON(); */

            System.out.println(
                "wolfSSL JNI X509v3 Certificate Generation Example");

            /* Generate self-signed example certificates */
            generateSelfSignedUsingFiles();
            generateSelfSignedUsingArrays();
            generateSelfSignedUsingGeneratedKeys();

            /* Generate CA-signed example certificates */
            generateCASignedUsingFiles();
            generateCASignedUsingArrays();
            generateCASignedUsingGeneratedKeys();

        } catch (WolfSSLException | WolfSSLJNIException |
                 IOException | CertificateException |
                 NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();

            /* exit with error */
            System.exit(1);
        }

    } /* end run() */

    public static void main(String[] args) {
        new X509v3CertificateGeneration().run(args);
    }

} /* end X509v3CertificateGeneration */

