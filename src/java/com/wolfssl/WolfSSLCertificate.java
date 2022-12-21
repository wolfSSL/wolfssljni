/* WolfSSLCertificate.java
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
package com.wolfssl;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import java.math.BigInteger;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.logging.Level;
import java.util.logging.Logger;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;

/**
 * WolfSSLCertificate class, wraps native wolfSSL WOLFSSL_X509 functionality.
 */
public class WolfSSLCertificate {

    private boolean active = false;
    private long x509Ptr = 0;

    /* Does this WolfSSLCertificate own the internal WOLFSSL_X509 pointer?
     * If not, don't try to free native memory on free(). */
    private boolean weOwnX509Ptr = false;

    /* lock around active state */
    private static final Object stateLock = new Object();

    /* cache alt names once retrieved once */
    private Collection<List<?>> altNames = null;

    static native byte[] X509_get_der(long x509);
    static native byte[] X509_get_tbs(long x509);
    static native void X509_free(long x509);
    static native int X509_get_serial_number(long x509, byte[] out);
    static native String X509_notBefore(long x509);
    static native String X509_notAfter(long x509);
    static native int X509_version(long x509);
    static native byte[] X509_get_signature(long x509);
    static native String X509_get_signature_type(long x509);
    static native String X509_get_signature_OID(long x509);
    static native byte[] X509_print(long x509);
    static native int X509_get_isCA(long x509);
    static native String X509_get_subject_name(long x509);
    static native String X509_get_issuer_name(long x509);
    static native byte[] X509_get_pubkey(long x509);
    static native String X509_get_pubkey_type(long x509);
    static native int X509_get_pathLength(long x509);
    static native int X509_verify(long x509, byte[] pubKey, int pubKeySz);
    static native boolean[] X509_get_key_usage(long x509);
    static native byte[] X509_get_extension(long x509, String oid);
    static native int X509_is_extension_set(long x509, String oid);
    static native String X509_get_next_altname(long x509);
    static native long X509_load_certificate_buffer(byte[] buf, int format);
    static native long X509_load_certificate_file(String path, int format);

    /**
     * Create new WolfSSLCertificate from DER-encoded byte array.
     *
     * @param der ASN.1/DER encoded X.509 certificate
     *
     * @throws WolfSSLException if input is null, input array length is 0,
     *                          or native API call fails.
     */
    public WolfSSLCertificate(byte[] der) throws WolfSSLException {

        if (der == null || der.length == 0) {
            throw new WolfSSLException(
                "Input array must not be null or zero length");
        }

        x509Ptr = X509_load_certificate_buffer(der, WolfSSL.SSL_FILETYPE_ASN1);
        if (x509Ptr == 0) {
            throw new WolfSSLException("Failed to create WolfSSLCertificate");
        }

        /* x509Ptr has been allocated natively, mark as owned */
        this.weOwnX509Ptr = true;

        synchronized (stateLock) {
            this.active = true;
        }
    }

    /**
     * Create WolfSSLCertificate from byte array in specified format.
     *
     * @param in X.509 certificate byte array in format specified
     * @param format format of certificate, either WolfSSL.SSL_FILETYPE_ASN1
     *               or WolfSSL.SSL_FILETYPE_PEM
     *
     * @throws WolfSSLException if in array is null, input array length is 0,
     *                          format does not match valid options, or
     *                          native API call fails.
     */
    public WolfSSLCertificate(byte[] in, int format) throws WolfSSLException {

        if (in == null || in.length == 0) {
            throw new WolfSSLException(
                "Input array must not be null or zero length");
        }

        if ((format != WolfSSL.SSL_FILETYPE_ASN1) &&
            (format != WolfSSL.SSL_FILETYPE_PEM)) {
            throw new WolfSSLException(
                "Input format must be WolfSSL.SSL_FILETYPE_ASN1 or " +
                "WolfSSL.SSL_FILETYPE_PEM");
        }

        x509Ptr = X509_load_certificate_buffer(in, format);
        if (x509Ptr == 0) {
            throw new WolfSSLException("Failed to create WolfSSLCertificate");
        }

        /* x509Ptr has been allocated natively, mark as owned */
        this.weOwnX509Ptr = true;

        synchronized (stateLock) {
            this.active = true;
        }
    }

    /**
     * Create WolfSSLCertificate from specified ASN.1/DER X.509 file.
     *
     * @param fileName path to X.509 certificate file in ASN.1/DER format
     *
     * @throws WolfSSLException if fileName is null or native API
     *                          call fails with error.
     */
    public WolfSSLCertificate(String fileName) throws WolfSSLException {

        if (fileName == null) {
            throw new WolfSSLException("Input filename cannot be null");
        }

        x509Ptr = X509_load_certificate_file(fileName,
                                             WolfSSL.SSL_FILETYPE_ASN1);
        if (x509Ptr == 0) {
            throw new WolfSSLException("Failed to create WolfSSLCertificate");
        }

        /* x509Ptr has been allocated natively, mark as owned */
        this.weOwnX509Ptr = true;

        synchronized (stateLock) {
            this.active = true;
        }
    }

    /**
     * Create WolfSSLCertificate from specified X.509 file in specified
     * format.
     *
     * @param fileName path to X.509 certificate file
     * @param format format of certificate file, either
     *               WolfSSL.SSL_FILETYPE_ASN1 or
     *               WolfSSL.SSL_FILETYPE_PEM
     *
     * @throws WolfSSLException if input fileName is null, format is not
     *                          valid, or native API call fails.
     */
    public WolfSSLCertificate(String fileName, int format)
            throws WolfSSLException {

        if (fileName == null) {
            throw new WolfSSLException("Input filename cannot be null");
        }

        if ((format != WolfSSL.SSL_FILETYPE_ASN1) &&
            (format != WolfSSL.SSL_FILETYPE_PEM)) {
            throw new WolfSSLException(
                "Input format must be WolfSSL.SSL_FILETYPE_ASN1 or " +
                "WolfSSL.SSL_FILETYPE_PEM");
        }

        x509Ptr = X509_load_certificate_file(fileName, format);
        if (x509Ptr == 0) {
            throw new WolfSSLException("Failed to create WolfSSLCertificate");
        }

        /* x509Ptr has been allocated natively, mark as owned */
        this.weOwnX509Ptr = true;

        synchronized (stateLock) {
            this.active = true;
        }
    }

    /**
     * Create WolfSSLCertificate from pre existing native pointer.
     *
     * @param x509 pre existing native pointer to WOLFSSL_X509 structure.
     *
     * @throws WolfSSLException if input pointer is invalid
     */
    public WolfSSLCertificate(long x509) throws WolfSSLException {

        if (x509 == 0) {
            throw new WolfSSLException("Input pointer may not be 0/NULL");
        }
        x509Ptr = x509;

        /* x509Ptr has NOT been allocated natively, do not mark as owned.
         * Original owner is responsible for freeing. */
        this.weOwnX509Ptr = false;

        synchronized (stateLock) {
            this.active = true;
        }
    }

    /**
     * Get ASN.1/DER encoding of this X.509 certificate
     *
     * @return DER encoded array of certificate or null if not available.
     */
    public byte[] getDer() {

        synchronized (stateLock) {
            if (this.active == true) {
                return X509_get_der(this.x509Ptr);
            }
        }

        return null;
    }

    /**
     * Get buffer that is To Be Signed (Tbs)
     *
     * @return byte array to be signed
     */
    public byte[] getTbs() {

        synchronized (stateLock) {
            if (this.active == true) {
                return X509_get_tbs(this.x509Ptr);
            }
        }

        return null;
    }

    /**
     * Get X.509 serial number as BigInteger
     *
     * @return serial number as BigInteger, or null if not available
     */
    public BigInteger getSerial() {
        byte[] out = new byte[32];
        int sz;

        synchronized (stateLock) {
            if (this.active == false) {
                return null;
            }

            sz = X509_get_serial_number(this.x509Ptr, out);
            if (sz <= 0) {
                return null;
            }
            else {
                byte[] serial = Arrays.copyOf(out, sz);
                return new BigInteger(serial);
            }
        }
    }

    /**
     * Get X.509 validity notBefore date
     *
     * @return notBefore date as Date object, or null if not available
     */
    public Date notBefore() {
        String nb;

        synchronized (stateLock) {
            if (this.active == false) {
                return null;
            }

            nb  = X509_notBefore(this.x509Ptr);
            if (nb != null) {
                SimpleDateFormat format =
                        new SimpleDateFormat("MMM dd HH:mm:ss yyyy zzz");
                try {
                    return format.parse(nb);
                } catch (ParseException ex) {
                    /* error case parsing date */
                }
            }
        }
        return null;
    }

    /**
     * Get X.509 validity notAfter date
     *
     * @return notAfter date as Date object, or null if not available
     */
    public Date notAfter() {
        String nb;

        synchronized (stateLock) {
            if (this.active == false) {
                return null;
            }

            nb = X509_notAfter(this.x509Ptr);
            if (nb != null) {
                SimpleDateFormat format =
                        new SimpleDateFormat("MMM dd HH:mm:ss yyyy zzz");
                try {
                    return format.parse(nb);
                } catch (ParseException ex) {
                    /* error case parsing date */
                }
            }
        }
        return null;
    }

    /**
     * Get X.509 version
     *
     * @return version of X.509 certificate
     */
    public int getVersion() {

        synchronized (stateLock) {
            if (this.active == true) {
                return X509_version(this.x509Ptr);
            }
        }

        return 0;
    }

    /**
     * Get signature from X.509 certificate
     *
     * @return byte array with signature from X.509 certificate, or null
     */
    public byte[] getSignature() {

        synchronized (stateLock) {
            if (this.active == true) {
                return X509_get_signature(this.x509Ptr);
            }
        }

        return null;
    }

    /**
     * Get signature type from X.509 certificate
     *
     * @return signature type String, or null
     */
    public String getSignatureType() {

        synchronized (stateLock) {
            if (this.active == true) {
                return X509_get_signature_type(this.x509Ptr);
            }
        }

        return null;
    }

    /**
     * Get X.509 signature algorithm OID
     *
     * @return algorithm OID of signature, or null
     */
    public String getSignatureOID() {

        synchronized (stateLock) {
            if (this.active == true) {
                return X509_get_signature_OID(this.x509Ptr);
            }
        }

        return null;
    }

    /**
     * Get public key from X.509 certificate
     *
     * @return certificate public key, byte array. Or null.
     */
    public byte[] getPubkey() {

        synchronized (stateLock) {
            if (this.active == true) {
                return X509_get_pubkey(this.x509Ptr);
            }
        }

        return null;
    }

    /**
     * Get public key type of certificate
     *
     * @return public key type String, or null
     */
    public String getPubkeyType() {

        synchronized (stateLock) {
            if (this.active == true) {
                return X509_get_pubkey_type(this.x509Ptr);
            }
        }

        return null;
    }

    /**
     * Get certificate isCA value
     *
     * @return X.509 isCA value
     */
    public int isCA() {

        synchronized (stateLock) {
            if (this.active == true) {
                return X509_get_isCA(this.x509Ptr);
            }
        }

        return 0;
    }

    /**
     * Get certificate path length
     *
     * @return path length, or -1 if not set
     */
    public int getPathLen() {

        synchronized (stateLock) {
            if (this.active == true) {
                return X509_get_pathLength(this.x509Ptr);
            }
        }

        return 0;
    }

    /**
     * Get certificate Subject
     *
     * @return X.509 Subject String, or null
     */
    public String getSubject() {

        synchronized (stateLock) {
            if (this.active == true) {
                return X509_get_subject_name(this.x509Ptr);
            }
        }

        return null;
    }

    /**
     * Get certificate Issuer
     *
     * @return X.509 Issuer String, or null
     */
    public String getIssuer() {

        synchronized (stateLock) {
            if (this.active == true) {
                return X509_get_issuer_name(this.x509Ptr);
            }
        }

        return null;
    }

    /**
     * Verify signature in certificate with provided public key
     *
     * @param pubKey public key, ASN.1/DER formatted
     * @param pubKeySz size of public key array, bytes
     *
     * @return true if verified, otherwise false
     */
    public boolean verify(byte[] pubKey, int pubKeySz) {
        int ret;

        synchronized (stateLock) {
            if (this.active == false) {
                return false;
            }

            ret  = X509_verify(this.x509Ptr, pubKey, pubKeySz);
            if (ret == WolfSSL.SSL_SUCCESS) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get array of key usage values set in certificate
     *
     * Array returned will represent the following key usages (true/false):
     *    [0] = KEYUSE_DIGITAL_SIG
     *    [1] = KEYUSE_CONTENT_COMMIT
     *    [2] = KEYUSE_KEY_ENCIPHER
     *    [3] = KEYUSE_DATA_ENCIPHER
     *    [4] = KEYUSE_KEY_AGREE
     *    [5] = KEYUSE_KEY_CERT_SIGN
     *    [6] = KEYUSE_CRL_SIGN
     *    [7] = KEYUSE_ENCIPHER_ONLY
     *    [8] = KEYUSE_DECIPHER_ONLY
     *
     * @return arrray of key usages set for certificate, or null
     */
    public boolean[] getKeyUsage() {

        synchronized (stateLock) {
            if (this.active == true) {
                return X509_get_key_usage(this.x509Ptr);
            }
        }

        return null;
    }

    /**
     * Get DER encoded extension value from a specified OID
     *
     * @param oid OID value of extension to retreive value for
     *
     * @return DER encoded extension value, or null
     */
    public byte[] getExtension(String oid) {

        synchronized (stateLock) {
            if (oid == null || this.active == false) {
                return null;
            }
            return X509_get_extension(this.x509Ptr, oid);
        }
    }

    /**
     * Poll if certificate extension is set for this certificate
     *
     * @param oid OID value of extension to poll for
     *
     * @return 1 if extension OID is set but not critical,
     *         2 if extension OID is set and is critical,
     *         0 if not set,
     *         otherwise negative value on error
     */
    public int getExtensionSet(String oid) {

        synchronized (stateLock) {
            if (this.active == false) {
                return 0;
            }
            return X509_is_extension_set(this.x509Ptr, oid);
        }
    }

    /**
     * Returns an immutable Collection of subject alternative names from this
     * certificate's SubjectAltName extension.
     *
     * Each collection item is a List containing two objects:
     *     [0] = Integer representing type of name, 0-8 (ex: 2 == dNSName)
     *     [1] = String representing altname entry.
     *
     * Note: this currently returns all altNames as dNSName types, with the
     * second list element being a String.
     *
     * @return immutable Collection of subject alternative names, or null
     */
    public Collection<List<?>> getSubjectAltNames() {

        synchronized (stateLock) {
            if (this.active == false) {
                throw new IllegalStateException("Object has been freed");
            }

            if (this.altNames != null) {
                /* already gathered, return cached version */
                return this.altNames;
            }

            Collection<List<?>> names = new ArrayList<List<?>>();

            String nextAltName = X509_get_next_altname(this.x509Ptr);
            while (nextAltName != null) {
                Object[] entry = new Object[2];
                entry[0] = 2; // Only return dNSName type for now
                entry[1] = nextAltName;
                List<?> entryList = Arrays.asList(entry);

                names.add(Collections.unmodifiableList(entryList));
                nextAltName = X509_get_next_altname(this.x509Ptr);
            }

            /* cache altNames collection for later use */
            this.altNames = Collections.unmodifiableCollection(names);
        }

        return this.altNames;
    }

    /**
     * Returns X509Certificate object based on this certificate.
     *
     * @return X509Certificate object
     * @throws CertificateException on error
     * @throws IOException on error closing ByteArrayInputStream
     */
    public X509Certificate getX509Certificate()
        throws CertificateException, IOException {

        X509Certificate cert = null;
        InputStream in = null;

        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        synchronized (stateLock) {
            if (this.active == false) {
                throw new CertificateException("Object has been freed");
            }

            try {
                in = new ByteArrayInputStream(this.getDer());
                cert = (X509Certificate)cf.generateCertificate(in);
                in.close();

            } catch (Exception e) {
                if (in != null) {
                    in.close();
                    throw e;
                }
            }
        }

        return cert;
    }

    @Override
    public String toString() {

        byte[] x509Text;

        synchronized (stateLock) {
            if (this.active == false) {
                return super.toString();
            }

            x509Text = X509_print(this.x509Ptr);
            if (x509Text != null) {
                /* let Java do the modified UTF-8 conversion */
                return new String(x509Text, Charset.forName("UTF-8"));
            }
        }

        return super.toString();
    }

    /**
     * Frees an X509.
     *
     * @throws IllegalStateException WolfSSLCertificate has been freed
     */
    public synchronized void free() throws IllegalStateException {

        synchronized (stateLock) {
            if (this.active == false) {
                /* already freed, just return */
                return;
            }

            /* set this.altNames to null so GC can free */
            this.altNames = null;

            /* only free native resources if we own pointer */
            if (this.weOwnX509Ptr == true) {
                /* free native resources */
                X509_free(this.x509Ptr);
            }

            /* free Java resources */
            this.active = false;
            this.x509Ptr = 0;
        }
    }

    @SuppressWarnings("deprecation")
    @Override
    protected void finalize() throws Throwable
    {
        this.free();
        super.finalize();
    }
}
