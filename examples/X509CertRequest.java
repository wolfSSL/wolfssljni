/* X509CertRequest.java
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

import java.io.File;
import java.io.IOException;

import java.nio.file.Files;
import java.nio.file.Paths;

import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateException;
import java.security.NoSuchAlgorithmException;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLCertRequest;
import com.wolfssl.WolfSSLX509Name;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLJNIException;

/**
 * Example application that demonstrates X509 Certificate Signing Request (CSR)
 * generation including various combinations.
 *
 *     CSR using files as input for certs/keys
 *     CSR using arrays as input for certs/keys
 *     CSR using generated certs and keys
 *
 * Each sub-example is contained in a separate method.
 *
 * When run, generated certificates are written out to PEM and DER files,
 * with location specified by variables at the top of this class.
 *
 */
public class X509CertRequest {

    private static String CERT_DIR = "../certs/";
    private static String GEN_DIR = CERT_DIR + "generated/";
    private static String CERT_DIR_FROM_ROOT = "./exammples/certs/generated/";

    /* Existing certs/keys used for CSR gen example with files */
    private static String clientKeyDer    = CERT_DIR + "client-key.der";
    private static String clientKeyPubDer = CERT_DIR + "client-keyPub.der";

    /* Generated certificate signing request (CSR) locations. */
    private static String csrUsingFilesDer =
        GEN_DIR + "csr-using-files.der";
    private static String csrUsingFilesPem =
        GEN_DIR + "csr-using-files.pem";
    private static String csrUsingArraysDer =
        GEN_DIR + "csr-using-arrays.der";
    private static String csrUsingArraysPem =
        GEN_DIR + "csr-using-arrays.pem";
    private static String csrUsingGeneratedKeysDer =
        GEN_DIR + "csr-generated-keys.der";
    private static String csrUsingGeneratedKeysPem =
        GEN_DIR + "csr-generated-keys.pem";

    /* Example Extension values */
    private static String test_KEY_USAGE =
        "digitalSignature,keyEncipherment,dataEncipherment";
    private static String test_EXT_KEY_USAGE =
        "clientAuth,serverAuth";
    private static String test_ALT_NAME =
        "alt.example.com";

    /* Example Attribute values */
    private static String test_CHALLENGE_PASSWORD =
        "12345!@#$%";

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
     * Generate example Certificate Signing Request (CSR) using the following
     * files as input to the CSR generation process:
     *
     * clientKeyPubDer - Existing client public key in DER format
     * clientKeyDer    - Existing client private key in DER format
     *
     * Generates and writes CSR out to the following paths in
     * both PEM and DER format (see variable values above):
     *     csrUsingFilesDer (DER format)
     *     csrUsingFilesPem (PEM format)
     *
     * @throws WolfSSLException if error occurs during CSR generation process.
     * @throws WolfSSLJNIException if native JNI error occurs
     * @throws IOException on error writing to output file locations
     */
    public void generateCSRUsingFiles()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException {

        System.out.print("\nGenerating CSR using files");

        /* Create new CSR object */
        WolfSSLCertRequest req = new WolfSSLCertRequest();

        /* Set Subject Name */
        WolfSSLX509Name subjectName = generateTestSubjectName();
        req.setSubjectName(subjectName);

        /* Set Public Key from existing public key DER file */
        req.setPublicKey(clientKeyPubDer, WolfSSL.RSAk,
                WolfSSL.SSL_FILETYPE_ASN1);

        /* Add Attributes */
        req.addAttribute(WolfSSL.NID_pkcs9_challengePassword,
                test_CHALLENGE_PASSWORD.getBytes());

        /* Add Extensions */
        req.addExtension(WolfSSL.NID_key_usage, test_KEY_USAGE, false);
        req.addExtension(WolfSSL.NID_ext_key_usage, test_EXT_KEY_USAGE, false);
        req.addExtension(WolfSSL.NID_subject_alt_name, test_ALT_NAME, false);
        req.addExtension(WolfSSL.NID_basic_constraints, true, true);

        /* Sign CSR, using existing client key DER */
        req.signRequest(clientKeyDer, WolfSSL.RSAk,
                WolfSSL.SSL_FILETYPE_ASN1, "SHA256");

        /* Output to DER and PEM files */
        byte[] derCsr = req.getDer();
        byte[] pemCsr = req.getPem();

        /* Write out generated CSRs to files */
        writeFile(csrUsingFilesDer, derCsr);
        writeFile(csrUsingFilesPem, pemCsr);

        System.out.println("... ");
        System.out.println("    " + CERT_DIR_FROM_ROOT +
                Paths.get(csrUsingFilesDer).getFileName());
        System.out.println("    " + CERT_DIR_FROM_ROOT +
                Paths.get(csrUsingFilesPem).getFileName());

        /* Free native memory */
        subjectName.free();
        req.free();
    }

    /**
     * Generate example Certificate Signing Request (CSR) using the following
     * files in array format as input to the CSR generation process:
     *
     * clientKeyPubDer - Existing client public key in DER format
     * clientKeyDer    - Existing client private key in DER format
     *
     * Generates and writes CSR out to the following paths in
     * both PEM and DER format (see variable values above):
     *     csrUsingArraysDer (DER format)
     *     csrUsingArraysPem (PEM format)
     *
     * @throws WolfSSLException if error occurs during CSR generation process.
     * @throws WolfSSLJNIException if native JNI error occurs
     * @throws IOException on error writing to output file locations
     */
    public void generateCSRUsingArrays()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException {

        System.out.print("\nGenerating CSR using arrays");

        /* Create new CSR object */
        WolfSSLCertRequest req = new WolfSSLCertRequest();

        /* Set Subject Name */
        WolfSSLX509Name subjectName = generateTestSubjectName();
        req.setSubjectName(subjectName);

        /* Set Public Key from existing public key DER file */
        byte[] pubKey = Files.readAllBytes(Paths.get(clientKeyPubDer));
        req.setPublicKey(pubKey, WolfSSL.RSAk, WolfSSL.SSL_FILETYPE_ASN1);

        /* Add Attributes */
        req.addAttribute(WolfSSL.NID_pkcs9_challengePassword,
                test_CHALLENGE_PASSWORD.getBytes());

        /* Add Extensions */
        req.addExtension(WolfSSL.NID_key_usage, test_KEY_USAGE, false);
        req.addExtension(WolfSSL.NID_ext_key_usage, test_EXT_KEY_USAGE, false);
        req.addExtension(WolfSSL.NID_subject_alt_name, test_ALT_NAME, false);
        req.addExtension(WolfSSL.NID_basic_constraints, true, true);

        /* Sign CSR, using existing client key DER */
        byte[] privKey = Files.readAllBytes(Paths.get(clientKeyDer));
        req.signRequest(privKey, WolfSSL.RSAk,
                WolfSSL.SSL_FILETYPE_ASN1, "SHA256");

        /* Output to DER and PEM files */
        byte[] derCsr = req.getDer();
        byte[] pemCsr = req.getPem();

        /* Write out generated CSRs to files */
        writeFile(csrUsingArraysDer, derCsr);
        writeFile(csrUsingArraysPem, pemCsr);

        System.out.println("... ");
        System.out.println("    " + CERT_DIR_FROM_ROOT +
                Paths.get(csrUsingArraysDer).getFileName());
        System.out.println("    " + CERT_DIR_FROM_ROOT +
                Paths.get(csrUsingArraysPem).getFileName());

        /* Free native memory */
        subjectName.free();
        req.free();
    }

    /**
     * Generate example Certificate Signing Request (CSR) using generated keys
     * for the CSR public and private signgin key, to be used in the CSR
     * generation process.
     *
     * Generates and writes CSR out to the following paths in
     * both PEM and DER format (see variable values above):
     *     csrUsingGeneratedKeysDer (DER format)
     *     csrUsingGeneratedKeysPem (PEM format)
     *
     * @throws WolfSSLException if error occurs during CSR generation process.
     * @throws WolfSSLJNIException if native JNI error occurs
     * @throws IOException on error writing to output file locations
     */
    public void generateCSRUsingGeneratedKeys()
        throws WolfSSLException, WolfSSLJNIException, IOException,
               CertificateException, NoSuchAlgorithmException {

        System.out.print("\nGenerating CSR with generated keys");

        /* Create new CSR object */
        WolfSSLCertRequest req = new WolfSSLCertRequest();

        /* Set Subject Name */
        WolfSSLX509Name subjectName = generateTestSubjectName();
        req.setSubjectName(subjectName);

        /* Set Public Key from generated java.security.PublicKey */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        PublicKey pubKey = keyPair.getPublic();
        req.setPublicKey(pubKey);

        /* Add Attributes */
        req.addAttribute(WolfSSL.NID_pkcs9_challengePassword,
                test_CHALLENGE_PASSWORD.getBytes());

        /* Add Extensions */
        req.addExtension(WolfSSL.NID_key_usage, test_KEY_USAGE, false);
        req.addExtension(WolfSSL.NID_ext_key_usage, test_EXT_KEY_USAGE, false);
        req.addExtension(WolfSSL.NID_subject_alt_name, test_ALT_NAME, false);
        req.addExtension(WolfSSL.NID_basic_constraints, true, true);

        /* Sign CSR, with java.security.PrivateKey */
        PrivateKey privKey = keyPair.getPrivate();
        req.signRequest(privKey, "SHA256");

        /* Output to DER and PEM files */
        byte[] derCsr = req.getDer();
        byte[] pemCsr = req.getPem();

        /* Write out generated CSRs to files */
        writeFile(csrUsingGeneratedKeysDer, derCsr);
        writeFile(csrUsingGeneratedKeysPem, pemCsr);

        System.out.println("... ");
        System.out.println("    " + CERT_DIR_FROM_ROOT +
                Paths.get(csrUsingGeneratedKeysDer).getFileName());
        System.out.println("    " + CERT_DIR_FROM_ROOT +
                Paths.get(csrUsingGeneratedKeysPem).getFileName());

        /* Free native memory */
        subjectName.free();
        req.free();
    }

    public void run(String[] args) {

        int ret = 0;

        try {
            /* Initialize and load native wolfSSL library, enable debugging */
            WolfSSL.loadLibrary();
            WolfSSL sslLib = new WolfSSL();

            /* Enable debugging if desired */
            //sslLib.debuggingON();

            System.out.println(
                "wolfSSL JNI Certificate Signing Request Generation Example");

            if (!WolfSSL.certReqEnabled()) {
                System.out.println("ERROR: Native wolfSSL must be compiled " +
                    "with --enable-certreq or WOLFSSL_CERT_REQ to use this " +
                    "example");

                /* exit with error */
                System.exit(1);
            }

            /* Generate example Certificate Signing Request files */
            generateCSRUsingFiles();
            generateCSRUsingArrays();
            generateCSRUsingGeneratedKeys();

        } catch (WolfSSLException | WolfSSLJNIException |
                 IOException | CertificateException |
                 NoSuchAlgorithmException e) {
            e.printStackTrace();

            /* exit with error */
            System.exit(1);
        }

    } /* end run() */

    public static void main(String[] args) {
        new X509CertRequest().run(args);
    }

} /* end X509CertRequest */


