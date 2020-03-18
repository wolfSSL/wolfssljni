/* WolfSSLCertificate.java
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
package com.wolfssl;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
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

public class WolfSSLCertificate {

    private boolean active = false;
    private long x509Ptr = 0;

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
    static native String X509_print(long x509);
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

    public WolfSSLCertificate(byte[] der) throws WolfSSLException {

        if (der == null || der.length == 0) {
            throw new WolfSSLException(
                "Input array must not be null or zero length");
        }

        x509Ptr = X509_load_certificate_buffer(der, WolfSSL.SSL_FILETYPE_ASN1);
        if (x509Ptr <= 0) {
            throw new WolfSSLException("Failed to create WolfSSLCertificate");
        }

        this.active = true;
    }

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
        if (x509Ptr <= 0) {
            throw new WolfSSLException("Failed to create WolfSSLCertificate");
        }

        this.active = true;
    }

    public WolfSSLCertificate(String fileName) throws WolfSSLException {

        if (fileName == null) {
            throw new WolfSSLException("Input filename cannot be null");
        }

        x509Ptr = X509_load_certificate_file(fileName,
                                             WolfSSL.SSL_FILETYPE_ASN1);
        if (x509Ptr <= 0) {
            throw new WolfSSLException("Failed to create WolfSSLCertificate");
        }

        this.active = true;
    }

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
        if (x509Ptr <= 0) {
            throw new WolfSSLException("Failed to create WolfSSLCertificate");
        }

        this.active = true;
    }

    public WolfSSLCertificate(long x509) throws WolfSSLException {

        if (x509 <= 0) {
            throw new WolfSSLException("Input pointer may not be <= 0");
        }
        x509Ptr = x509;
        this.active = true;
    }

    /* return DER encoding of certificate */
    public byte[] getDer() {

        if (this.active == true) {
            return X509_get_der(this.x509Ptr);
        }

        return null;
    }

    /* return the buffer that is To Be Signed */
    public byte[] getTbs() {

        if (this.active == true) {
            return X509_get_tbs(this.x509Ptr);
        }

        return null;
    }

    public BigInteger getSerial() {
        byte[] out = new byte[32];
        int sz;

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

    public Date notBefore() {
        String nb;

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
        return null;
    }

    public Date notAfter() {
        String nb;

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
        return null;
    }

    public int getVersion() {

        if (this.active == true) {
            return X509_version(this.x509Ptr);
        }

        return 0;
    }

    public byte[] getSignature() {

        if (this.active == true) {
            return X509_get_signature(this.x509Ptr);
        }

        return null;
    }

    public String getSignatureType() {

        if (this.active == true) {
            return X509_get_signature_type(this.x509Ptr);
        }

        return null;
    }

    public String getSignatureOID() {

        if (this.active == true) {
            return X509_get_signature_OID(this.x509Ptr);
        }

        return null;
    }

    public byte[] getPubkey() {

        if (this.active == true) {
            return X509_get_pubkey(this.x509Ptr);
        }

        return null;
    }

    public String getPubkeyType() {

        if (this.active == true) {
            return X509_get_pubkey_type(this.x509Ptr);
        }

        return null;
    }

    public int isCA() {

        if (this.active == true) {
            return X509_get_isCA(this.x509Ptr);
        }

        return 0;
    }

    /* if not set -1 is returned */
    public int getPathLen() {

        if (this.active == true) {
            return X509_get_pathLength(this.x509Ptr);
        }

        return 0;
    }

    public String getSubject() {

        if (this.active == true) {
            return X509_get_subject_name(this.x509Ptr);
        }

        return null;
    }

    public String getIssuer() {

        if (this.active == true) {
            return X509_get_issuer_name(this.x509Ptr);
        }

        return null;
    }

    /* returns WOLFSSL_SUCCESS on successful verification */
    public boolean verify(byte[] pubKey, int pubKeySz) {
        int ret;

        if (this.active == false) {
            return false;
        }

        ret  = X509_verify(this.x509Ptr, pubKey, pubKeySz);
        if (ret == WolfSSL.SSL_SUCCESS) {
            return true;
        }
        return false;
    }

    public boolean[] getKeyUsage() {

        if (this.active == true) {
            return X509_get_key_usage(this.x509Ptr);
        }

        return null;
    }

    /* gets the DER encoded extension value from an OID passed in */
    public byte[] getExtension(String oid) {
        if (oid == null || this.active == false) {
            return null;
        }
        return X509_get_extension(this.x509Ptr, oid);
    }

    /* returns 1 if extension OID is set but not critical
     * returns 2 if extension OID is set and is critical
     * return  0 if not set
     * return negative value on error
     */
    public int getExtensionSet(String oid) {
        if (this.active == false) {
            return 0;
        }
        return X509_is_extension_set(this.x509Ptr, oid);
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

        return cert;
    }

    @Override
    public String toString() {
        return X509_print(this.x509Ptr);
    }

    /**
     * Frees an X509.
     *
     * @throws IllegalStateException WolfSSLCertificate has been freed
     */
    public void free() throws IllegalStateException {

        if (this.active == false)
            throw new IllegalStateException("Object has been freed");

        /* set this.altNames to null so GC can free */
        this.altNames = null;

        /* free native resources */
        X509_free(this.x509Ptr);

        /* free Java resources */
        this.active = false;
        this.x509Ptr = 0;
    }

    @SuppressWarnings("deprecation")
    @Override
    protected void finalize() throws Throwable
    {
        if (this.active == true) {
            try {
                this.free();
            } catch (IllegalStateException e) {
                /* already freed */
            }
            this.active = false;
        }
        super.finalize();
    }
}
