/* WolfSSLCertificate.java
 *
 * Copyright (C) 2006-2018 wolfSSL Inc.
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
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

public class WolfSSLCertificate {
        
    private boolean active = false;
    private long x509Ptr = 0;
    
    static native long d2i_X509(byte[] der, int len);
    static native byte[] X509_get_der(long x509);
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
    
    public WolfSSLCertificate(byte[] der) throws WolfSSLException {
        x509Ptr = d2i_X509(der, der.length);
        if (x509Ptr == 0) {
            throw new WolfSSLException("Failed to create SSL Context");
        }
        this.active = true;
    }
    
    public WolfSSLCertificate(String fileName) throws WolfSSLException {
        File f = new File(fileName);
        byte[] der = null;
        
        try {
            der = Files.readAllBytes(f.toPath());
        } catch (IOException ex) {
            Logger.getLogger(WolfSSLCertificate.class.getName()).log(Level.SEVERE, null, ex);
            throw new WolfSSLException("Failed to create SSL Context");
        }
        

        x509Ptr = d2i_X509(der, der.length);
        if (x509Ptr == 0) {
            throw new WolfSSLException("Failed to create SSL Context");
        }
        this.active = true;
    }
    
    
    /* return DER encoding of certificate */
    public byte[] getDer() {
        return X509_get_der(this.x509Ptr);
    }
    
    public BigInteger getSerial() {
        byte[] out = new byte[32];
        int sz = X509_get_serial_number(this.x509Ptr, out);
        if (sz <= 0) {
            return null;
        }
        else {
            byte[] serial = Arrays.copyOf(out, sz);
            return new BigInteger(serial);
        }
    }
    
    public Date notBefore() {
        String nb = X509_notBefore(this.x509Ptr);

        if (nb != null) {
            SimpleDateFormat format =
                    new SimpleDateFormat("MMM dd HH:mm:ss yyyy zzz");
            try {
                return format.parse(nb);
            } catch (ParseException ex) {
                Logger.getLogger(WolfSSLCertificate.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return null;
    }
    
        
    public Date notAfter() {
        String nb = X509_notAfter(this.x509Ptr);

        if (nb != null) {
            SimpleDateFormat format =
                    new SimpleDateFormat("MMM dd HH:mm:ss yyyy zzz");
            try {
                return format.parse(nb);
            } catch (ParseException ex) {
                Logger.getLogger(WolfSSLCertificate.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return null;
    }
    
    public int getVersion() {
        return X509_version(this.x509Ptr);
    }
    
    public byte[] getSignature() {
        return X509_get_signature(this.x509Ptr);
    }
    
    public String getSignatureType() {
        return X509_get_signature_type(this.x509Ptr);
    }
    
    public String getSignatureOID() {
        return X509_get_signature_OID(this.x509Ptr);
    }
    
    public byte[] getPubkey() {
        return X509_get_pubkey(this.x509Ptr);
    }
        
    public String getPubkeyType() {
        return X509_get_pubkey_type(this.x509Ptr);
    }
    
    public int isCA() {
        return X509_get_isCA(this.x509Ptr);
    }
    
    /* if not set -1 is returned */
    public int getPathLen() {
        return X509_get_pathLength(this.x509Ptr);
    }
    
    public String getSubject() {
        return X509_get_subject_name(this.x509Ptr);
    }
    
    public String getIssuer() {
        return X509_get_issuer_name(this.x509Ptr);
    }

    /* returns WOLFSSL_SUCCESS on successful verification */
    public boolean verify(byte[] pubKey, int pubKeySz) {
        int ret = X509_verify(this.x509Ptr, pubKey, pubKeySz);
        if (ret == WolfSSL.SSL_SUCCESS) {
            return true;
        }
        return false;
    }
    
    public boolean[] getKeyUsage() {
        return X509_get_key_usage(this.x509Ptr);
    }
    
    /* gets the DER encoded extension value from an OID passed in */
    public byte[] getExtension(String oid) {
        if (oid == null) {
            return null;
        }
        return X509_get_extension(this.x509Ptr, oid);
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

        /* free native resources */
        X509_free(this.x509Ptr);

        /* free Java resources */
        this.active = false;
    }
}
