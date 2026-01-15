/* WolfSSLCRL.java
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

package com.wolfssl;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;

/**
 * WolfSSLCRL class, wraps native wolfSSL WOLFSSL_X509_CRL functionality.
 */
public class WolfSSLCRL implements Serializable {

    private static final long serialVersionUID = 1L;

    /** Flag if this class is active or not */
    private boolean active = false;

    /** Internal pointer for native WOLFSSL_X509_CRL */
    private long crlPtr = 0;

    /** Does this WolfSSLCRL own the internal WOLFSSL_X509_CRL pointer? */
    private boolean weOwnCrlPtr = false;

    /** lock around active state */
    private transient final Object stateLock = new Object();

    /** lock around native WOLFSSL_X509_CRL pointer use */
    private transient final Object crlLock = new Object();

    /* From wolfssl/wolfcrypt/asn.h and wolfssl/wolfcrypt/asn_public.h */
    private static final int ASN_UTC_TIME = 0x17;
    private static final int ASN_GENERALIZED_TIME = 0x18;
    private static final int CTC_DATE_SIZE = 32;
    private static final int ASN1_TIME_STRUCT_SIZE = CTC_DATE_SIZE + 8;
    private static final int ASN1_UTC_YEAR_MIN = 1950;
    private static final int ASN1_UTC_YEAR_MAX = 2049;
    private static final int EVP_PKEY_RSA = 16;
    private static final int EVP_PKEY_EC  = 18;

    /* Native method declarations */
    static native long X509_CRL_new();
    static native void X509_CRL_free(long crl);
    static native int X509_CRL_set_version(long crl, int version);
    static native int X509_CRL_set_issuer_name(long crl, long x509NamePtr);
    static native int X509_CRL_set_lastUpdate(long crl, byte[] time);
    static native int X509_CRL_set_nextUpdate(long crl, byte[] time);
    static native int X509_CRL_add_revoked(long crl, byte[] serial,
        byte[] revDate, int dateFmt);
    static native int X509_CRL_add_revoked_cert(long crl, byte[] certDer,
        byte[] revDate, int dateFmt);
    static native int X509_CRL_sign(long crl, int keyType, byte[] keyBytes,
        int format, String digestAlg);
    static native int write_X509_CRL(long crl, String path, int format);
    static native byte[] X509_CRL_print(long crl);
    static native int X509_CRL_version(long crl);
    static native String X509_CRL_get_lastUpdate(long crl);
    static native String X509_CRL_get_nextUpdate(long crl);
    static native byte[] X509_CRL_get_der(long crl);
    static native byte[] X509_CRL_get_pem(long crl);

    private static final class Asn1TimeData {
        private final byte[] paddedData;
        private final int length;
        private final int type;

        private Asn1TimeData(byte[] paddedData, int length, int type) {
            this.paddedData = paddedData;
            this.length = length;
            this.type = type;
        }
    }

    private static Asn1TimeData buildAsn1TimeData(Date date) {
        if (date == null) {
            throw new IllegalArgumentException("Date is null");
        }

        Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"),
            Locale.US);
        cal.setTime(date);
        int year = cal.get(Calendar.YEAR);
        boolean useUtcTime = (year >= ASN1_UTC_YEAR_MIN &&
            year <= ASN1_UTC_YEAR_MAX);

        String pattern = useUtcTime ? "yyMMddHHmmss'Z'" :
            "yyyyMMddHHmmss'Z'";
        int type = useUtcTime ? ASN_UTC_TIME : ASN_GENERALIZED_TIME;

        SimpleDateFormat format = new SimpleDateFormat(pattern, Locale.US);
        format.setTimeZone(TimeZone.getTimeZone("UTC"));
        byte[] timeBytes = format.format(date).getBytes(
            StandardCharsets.US_ASCII);

        if (timeBytes.length > CTC_DATE_SIZE) {
            throw new IllegalArgumentException(
                "ASN.1 time exceeds max size: " + timeBytes.length);
        }

        byte[] padded = new byte[CTC_DATE_SIZE];
        System.arraycopy(timeBytes, 0, padded, 0, timeBytes.length);

        return new Asn1TimeData(padded, timeBytes.length, type);
    }

    private static byte[] buildAsn1TimeStruct(Date date) {
        Asn1TimeData timeData = buildAsn1TimeData(date);
        ByteBuffer buffer = ByteBuffer.allocate(ASN1_TIME_STRUCT_SIZE)
            .order(ByteOrder.nativeOrder());
        buffer.put(timeData.paddedData);
        buffer.position(CTC_DATE_SIZE);
        buffer.putInt(timeData.length);
        buffer.putInt(timeData.type);
        return buffer.array();
    }

    /**
     * Create new empty WolfSSLCRL object, for CRL generation.
     *
     * @throws WolfSSLException if native API call fails.
     */
    public WolfSSLCRL() throws WolfSSLException {

        crlPtr = X509_CRL_new();
        if (crlPtr == 0) {
            throw new WolfSSLException("Failed to create WolfSSLCRL");
        }

        this.weOwnCrlPtr = true;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
            WolfSSLDebug.INFO, crlPtr,
            () -> "creating new WolfSSLCRL");

        synchronized (stateLock) {
            this.active = true;
        }
    }

    /**
     * Create new WolfSSLCRL from DER-encoded byte array.
     *
     * @param der ASN.1/DER encoded CRL
     *
     * @throws WolfSSLException if CRL loading is not implemented.
     */
    public WolfSSLCRL(byte[] der) throws WolfSSLException {
        throw new WolfSSLException("CRL loading from DER not implemented yet");
    }

    /**
     * Create WolfSSLCRL from file in specified format.
     *
     * @param filePath path to CRL file
     * @param format format of CRL, either WolfSSL.SSL_FILETYPE_ASN1 or
     *               WolfSSL.SSL_FILETYPE_PEM
     *
     * @throws WolfSSLException if CRL loading is not implemented.
     */
    public WolfSSLCRL(String filePath, int format) throws WolfSSLException {
        throw new WolfSSLException("CRL loading from file not implemented yet");
    }

    /**
     * Verifies that the current WolfSSLCRL object is active.
     *
     * @throws IllegalStateException if object has been freed
     */
    private void confirmObjectIsActive()
        throws IllegalStateException {

        synchronized (stateLock) {
            if (this.active == false) {
                throw new IllegalStateException(
                    "WolfSSLCRL object has been freed");
            }
        }
    }

    /**
     * Set CRL version (0 = v1, 1 = v2).
     *
     * @param version CRL version
     *
     * @return native wolfSSL return code
     * @throws IllegalStateException if WolfSSLCRL has been freed.
     */
    public int setVersion(int version) throws IllegalStateException {
        confirmObjectIsActive();
        synchronized (crlLock) {
            return X509_CRL_set_version(this.crlPtr, version);
        }
    }

    /**
     * Set CRL issuer name from WolfSSLX509Name.
     *
     * @param name WolfSSLX509Name to set as issuer
     *
     * @return native wolfSSL return code
     * @throws IllegalStateException if WolfSSLCRL has been freed.
     * @throws WolfSSLException if name is null.
     */
    public int setIssuerName(WolfSSLX509Name name)
        throws IllegalStateException, WolfSSLException {

        if (name == null) {
            throw new WolfSSLException("Issuer name is null");
        }

        confirmObjectIsActive();

        synchronized (crlLock) {
            return X509_CRL_set_issuer_name(this.crlPtr,
                name.getNativeX509NamePtr());
        }
    }

    /**
     * Set CRL last update date.
     *
     * @param date Date to set as last update time
     *
     * @return native wolfSSL return code (WolfSSL.SSL_SUCCESS on success)
     *
     * @throws IllegalStateException if WolfSSLCRL has been freed.
     * @throws IllegalArgumentException if date is null.
     */
    public int setLastUpdate(Date date) {
        if (date == null) {
            throw new IllegalArgumentException("LastUpdate date is null");
        }

        confirmObjectIsActive();

        byte[] asnTime = buildAsn1TimeStruct(date);
        synchronized (crlLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.crlPtr,
                () -> "entered setLastUpdate(" + date + ")");
            int ret = X509_CRL_set_lastUpdate(this.crlPtr, asnTime);
            return (ret == 0) ? WolfSSL.SSL_FAILURE : WolfSSL.SSL_SUCCESS;
        }
    }

    /**
     * Set CRL next update date.
     *
     * @param date Date to set as next update time
     *
     * @return native wolfSSL return code (WolfSSL.SSL_SUCCESS on success)
     *
     * @throws IllegalStateException if WolfSSLCRL has been freed.
     * @throws IllegalArgumentException if date is null.
     */
    public int setNextUpdate(Date date) {
        if (date == null) {
            throw new IllegalArgumentException("NextUpdate date is null");
        }

        confirmObjectIsActive();

        byte[] asnTime = buildAsn1TimeStruct(date);
        synchronized (crlLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.crlPtr,
                () -> "entered setNextUpdate(" + date + ")");
            int ret = X509_CRL_set_nextUpdate(this.crlPtr, asnTime);
            return (ret == 0) ? WolfSSL.SSL_FAILURE : WolfSSL.SSL_SUCCESS;
        }
    }

    /**
     * Add revoked certificate entry to CRL by serial number.
     *
     * @param serialNumber Serial number of revoked certificate
     * @param revocationDate Date when certificate was revoked, or null
     *
     * @return native wolfSSL return code
     *
     * @throws IllegalStateException if WolfSSLCRL has been freed.
     * @throws IllegalArgumentException if serialNumber is null or empty.
     */
    public int addRevoked(byte[] serialNumber, Date revocationDate) {
        if (serialNumber == null || serialNumber.length == 0) {
            throw new IllegalArgumentException(
                "Serial number is null or empty");
        }

        confirmObjectIsActive();

        byte[] revDateBytes = null;
        int dateFmt = 0;
        if (revocationDate != null) {
            Asn1TimeData timeData = buildAsn1TimeData(revocationDate);
            revDateBytes = timeData.paddedData;
            dateFmt = timeData.type;
        }

        synchronized (crlLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.crlPtr,
                () -> "entered addRevoked(serial: " + serialNumber.length +
                ", revocationDate: " + revocationDate + ")");
            return X509_CRL_add_revoked(this.crlPtr, serialNumber,
                revDateBytes, dateFmt);
        }
    }

    /**
     * Add revoked certificate entry to CRL from DER-encoded certificate.
     *
     * @param certDer DER-encoded certificate to add as revoked
     * @param revocationDate Date when certificate was revoked, or null
     *
     * @return native wolfSSL return code
     *
     * @throws IllegalStateException if WolfSSLCRL has been freed.
     * @throws IllegalArgumentException if certDer is null or empty.
     */
    public int addRevokedCert(byte[] certDer, Date revocationDate) {
        if (certDer == null || certDer.length == 0) {
            throw new IllegalArgumentException(
                "Certificate DER is null or empty");
        }

        confirmObjectIsActive();

        byte[] revDateBytes = null;
        int dateFmt = 0;
        if (revocationDate != null) {
            Asn1TimeData timeData = buildAsn1TimeData(revocationDate);
            revDateBytes = timeData.paddedData;
            dateFmt = timeData.type;
        }

        synchronized (crlLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.crlPtr,
                () -> "entered addRevokedCert(der: " + certDer.length +
                ", revocationDate: " + revocationDate + ")");
            return X509_CRL_add_revoked_cert(this.crlPtr, certDer,
                revDateBytes, dateFmt);
        }
    }

    /**
     * Add revoked certificate entry to CRL from WolfSSLCertificate object.
     *
     * @param cert WolfSSLCertificate object to add as revoked
     * @param revocationDate Date when certificate was revoked, or null
     *
     * @return native wolfSSL return code
     *
     * @throws IllegalStateException if WolfSSLCRL has been freed or if
     *         certificate DER encoding fails.
     * @throws IllegalArgumentException if cert is null.
     */
    public int addRevokedCert(WolfSSLCertificate cert, Date revocationDate) {
        if (cert == null) {
            throw new IllegalArgumentException("Certificate is null");
        }

        confirmObjectIsActive();

        synchronized (crlLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.crlPtr,
                () -> "entered addRevokedCert(cert, revocationDate: " +
                revocationDate + ")");
        }

        byte[] certDer = null;
        try {
            certDer = cert.getDer();
        }
        catch (WolfSSLJNIException ex) {
            throw new IllegalStateException(
                "Failed to get certificate DER", ex);
        }

        if (certDer == null || certDer.length == 0) {
            throw new IllegalStateException("Certificate DER is empty");
        }

        return addRevokedCert(certDer, revocationDate);
    }

    /**
     * Sign CRL with private key from PrivateKey object.
     *
     * @param key java.security.PrivateKey object containing private key,
     *        must be of type RSAPrivateKey or ECPrivateKey
     * @param digestAlg Message digest algorithm to use for signature
     *        generation. Options include the following, but native algorithm
     *        must be compiled into wolfSSL to be available:
     *            "MD4", "MD5", "SHA1", "SHA224", "SHA256", "SHA384",
     *            "SHA512", "SHA3_224", "SHA3_256", "SHA3_384", "SHA3_512"
     *
     * @return native wolfSSL return code (WolfSSL.SSL_SUCCESS on success)
     *
     * @throws IllegalStateException if WolfSSLCRL has been freed.
     * @throws IllegalArgumentException if key is null, unsupported key type,
     *         or key does not support encoding.
     */
    public int sign(PrivateKey key, String digestAlg) {
        int ret = 0;
        int evpKeyType;
        byte[] encodedKey = null;

        confirmObjectIsActive();

        synchronized (crlLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.crlPtr,
                () -> "entered sign(" + key + ", digestAlg: " + digestAlg +
                ")");
        }

        if (key == null) {
            throw new IllegalArgumentException("Key object is null");
        }

        if (key instanceof RSAPrivateKey) {
            evpKeyType = EVP_PKEY_RSA;
        }
        else if (key instanceof ECPrivateKey) {
            evpKeyType = EVP_PKEY_EC;
        }
        else {
            throw new IllegalArgumentException(
                "PrivateKey must be of type RSAPrivateKey or ECPrivateKey");
        }

        /* Get DER encoded key */
        encodedKey = key.getEncoded();
        if (encodedKey == null) {
            throw new IllegalArgumentException(
                "PrivateKey does not support encoding");
        }

        synchronized (crlLock) {
            ret = X509_CRL_sign(this.crlPtr, evpKeyType, encodedKey,
                WolfSSL.SSL_FILETYPE_ASN1, digestAlg);
        }

        return ret;
    }

    /**
     * Write CRL to file in specified format.
     *
     * @param path path to file where CRL should be written
     * @param format format of CRL, either WolfSSL.SSL_FILETYPE_ASN1 or
     *               WolfSSL.SSL_FILETYPE_PEM
     *
     * @return native wolfSSL return code (WolfSSL.SSL_SUCCESS on success)
     *
     * @throws IllegalStateException if WolfSSLCRL has been freed.
     * @throws IllegalArgumentException if path is null or empty, or format
     *         is invalid.
     */
    public int writeToFile(String path, int format) {
        if (path == null || path.length() == 0) {
            throw new IllegalArgumentException("Path is null or empty");
        }

        if (format != WolfSSL.SSL_FILETYPE_ASN1 &&
            format != WolfSSL.SSL_FILETYPE_PEM) {
            throw new IllegalArgumentException(
                "Invalid file format, must be PEM or DER");
        }

        confirmObjectIsActive();

        synchronized (crlLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.crlPtr,
                () -> "entered writeToFile(" + path + ", format: " + format +
                ")");

            return write_X509_CRL(this.crlPtr, path, format);
        }
    }

    /**
     * Get ASN.1/DER encoding of this CRL.
     *
     * @return DER encoded array of CRL or null if not available.
     *
     * @throws IllegalStateException if WolfSSLCRL has been freed.
     * @throws WolfSSLJNIException if native JNI error occurs.
     */
    public byte[] getDer() throws IllegalStateException, WolfSSLJNIException {
        confirmObjectIsActive();
        synchronized (crlLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.crlPtr, () -> "entered getDer()");
            return X509_CRL_get_der(this.crlPtr);
        }
    }

    /**
     * Get PEM encoding of this CRL.
     *
     * @return PEM encoded array of CRL or null if not available.
     *
     * @throws IllegalStateException if WolfSSLCRL has been freed.
     * @throws WolfSSLJNIException if native JNI error occurs.
     */
    public byte[] getPem() throws IllegalStateException, WolfSSLJNIException {
        confirmObjectIsActive();
        synchronized (crlLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.crlPtr, () -> "entered getPem()");
            return X509_CRL_get_pem(this.crlPtr);
        }
    }

    /**
     * Get CRL version.
     *
     * @return version of CRL (0 = v1, 1 = v2)
     *
     * @throws IllegalStateException if WolfSSLCRL has been freed.
     */
    public int getVersion() {
        confirmObjectIsActive();

        synchronized (crlLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.crlPtr, () -> "entered getVersion()");

            return X509_CRL_version(this.crlPtr);
        }
    }

    /**
     * Get CRL last update date.
     *
     * @return last update date as Date object, or null if not available
     *         or if date parsing fails.
     *
     * @throws IllegalStateException if WolfSSLCRL has been freed.
     */
    public Date getLastUpdate() {
        String date;

        confirmObjectIsActive();

        synchronized (crlLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.crlPtr,
                () -> "entered getLastUpdate()");

            date = X509_CRL_get_lastUpdate(this.crlPtr);
        }

        if (date != null) {
            SimpleDateFormat format =
                new SimpleDateFormat("MMM dd HH:mm:ss yyyy zzz");
            try {
                return format.parse(date);
            } catch (ParseException ex) {
                /* error case parsing date */
            }
        }

        return null;
    }

    /**
     * Get CRL next update date.
     *
     * @return next update date as Date object, or null if not available
     *         or if date parsing fails.
     *
     * @throws IllegalStateException if WolfSSLCRL has been freed.
     */
    public Date getNextUpdate() {
        String date;

        confirmObjectIsActive();

        synchronized (crlLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.Component.JNI,
                WolfSSLDebug.INFO, this.crlPtr,
                () -> "entered getNextUpdate()");

            date = X509_CRL_get_nextUpdate(this.crlPtr);
        }

        if (date != null) {
            SimpleDateFormat format =
                new SimpleDateFormat("MMM dd HH:mm:ss yyyy zzz");
            try {
                return format.parse(date);
            } catch (ParseException ex) {
                /* error case parsing date */
            }
        }

        return null;
    }

    @Override
    public String toString() {
        byte[] crlText = null;
        synchronized (stateLock) {
            if (this.active == false) {
                return super.toString();
            }
            synchronized (crlLock) {
                crlText = X509_CRL_print(this.crlPtr);
            }
            if (crlText != null) {
                /* let Java do the modified UTF-8 conversion */
                return new String(crlText, Charset.forName("UTF-8"));
            } else { 
                System.out.println("toString: crlText == null");
            }
        }
        return super.toString();
    }

    /**
     * Free native CRL resources.
     */
    public synchronized void free() {
        synchronized (stateLock) {
            if (!this.active) {
                return;
            }
            this.active = false;
        }

        if (this.weOwnCrlPtr) {
            synchronized (crlLock) {
                X509_CRL_free(this.crlPtr);
                this.crlPtr = 0;
                this.weOwnCrlPtr = false;
            }
        }
    }

    @SuppressWarnings("deprecation")
    @Override
    protected void finalize() throws Throwable {
        this.free();
        super.finalize();
    }
}
