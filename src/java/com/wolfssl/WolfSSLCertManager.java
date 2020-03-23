/* WolfSSLCertManager.java
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

import java.util.Enumeration;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateEncodingException;
import com.wolfssl.WolfSSLException;

/**
 * CertManager class which wraps the native WolfSSL embedded SSL library.
 * This class contains library init and cleanup methods, general callback
 * methods, as well as error codes and general wolfSSL codes.
 *
 * @author  wolfSSL
 * @version 1.1, February 2019
 */
public class WolfSSLCertManager {
    private boolean active = false;
    private long cmPtr = 0;

    static native long CertManagerNew();
    static native void CertManagerFree(long cm);
    static native int CertManagerLoadCA(long cm, String f, String d);
    static native int CertManagerLoadCABuffer(long cm, byte[] in, long sz,
                                              int format);
    static native int CertManagerVerifyBuffer(long cm, byte[] in, long sz,
                                              int format);

    public WolfSSLCertManager() throws WolfSSLException {
        cmPtr = CertManagerNew();
        if (cmPtr == 0) {
            throw new WolfSSLException("Failed to create WolfSSLCertManager");
        }
        this.active = true;
    }

    public int CertManagerLoadCA(String f, String d) {
        if (this.active == false)
            throw new IllegalStateException("Object has been freed");

        return CertManagerLoadCA(this.cmPtr, f, d);
    }

    public int CertManagerLoadCABuffer(byte[] in, long sz, int format) {
        if (this.active == false)
            throw new IllegalStateException("Object has been freed");

        return CertManagerLoadCABuffer(this.cmPtr, in, sz, format);
    }

    /**
     * Loads KeyStore certificates into WolfSSLCertManager object.
     *
     * @param  ks - input KeyStore from which to load CA certs
     * @throws WolfSSLException on exception working with KeyStore
     * @return WolfSSL.SSL_SUCCESS if at least one cert was loaded
     *         successfully, otherwise WolfSSL.SSL_FAILURE.
     */
    public int CertManagerLoadCAKeyStore(KeyStore ks) throws WolfSSLException {
        int ret = 0;
        int loadedCerts = 0;

        if (this.active == false) {
            throw new IllegalStateException("Object has been freed");
        }

        if (ks == null) {
            throw new WolfSSLException("Input KeyStore is null");
        }

        try {
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String name = aliases.nextElement();
                X509Certificate cert = null;

                if (ks.isKeyEntry(name)) {
                    Certificate[] chain = ks.getCertificateChain(name);
                    if (chain != null) {
                        cert = (X509Certificate) chain[0];
                    }
                } else {
                    cert = (X509Certificate) ks.getCertificate(name);
                }

                if (cert != null && cert.getBasicConstraints() >= 0) {
                    ret = CertManagerLoadCABuffer(cert.getEncoded(),
                            cert.getEncoded().length,
                            WolfSSL.SSL_FILETYPE_ASN1);

                    if (ret == WolfSSL.SSL_SUCCESS) {
                        loadedCerts++;
                    }
                }
            }
        } catch (KeyStoreException | CertificateEncodingException ex) {
            throw new WolfSSLException(ex);
        }

        if (loadedCerts > 0) {
            return WolfSSL.SSL_SUCCESS;
        } else {
            return WolfSSL.SSL_FAILURE;
        }
    }

    public int CertManagerVerifyBuffer(byte[] in, long sz, int format) {
        if (this.active == false)
            throw new IllegalStateException("Object has been freed");

        return CertManagerVerifyBuffer(this.cmPtr, in, sz, format);
    }

    /**
     * Frees CertManager object
     *
     * @throws IllegalStateException WolfSSLContext has been freed
     * @see         WolfSSLSession#freeSSL()
     */
    public void free() throws IllegalStateException {

        if (this.active == false)
            throw new IllegalStateException("Object has been freed");

        /* free native resources */
        CertManagerFree(this.cmPtr);

        /* free Java resources */
        this.active = false;
        this.cmPtr = 0;
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
