/* WolfSSLTrustX509.java
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

package com.wolfssl.provider.jsse;

import com.wolfssl.WolfSSL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.X509TrustManager;

import com.wolfssl.WolfSSLCertManager;
import com.wolfssl.WolfSSLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.HashSet;
import java.util.Set;

/**
 * wolfSSL implementation of X509TrustManager
 *
 * @author wolfSSL
 */
public class WolfSSLTrustX509 implements X509TrustManager {
    private KeyStore store = null;
    private Set<X509Certificate> CAs = null;

    public WolfSSLTrustX509(KeyStore in) {
        this.store = in;
        LoadCAsFromStore();
    }

    /* Loads all CAs from the key store into the cert manager structure */
    private int LoadCAsFromStore() {
        try {
            /* Store the alias of all CAs */
            Enumeration<String> aliases = store.aliases();
            CAs = new HashSet<X509Certificate>();
            while (aliases.hasMoreElements()) {
                String name = aliases.nextElement();
                X509Certificate cert = null;

                if (store.isKeyEntry(name)) {
                    Certificate[] chain = store.getCertificateChain(name);
                    if (chain != null)
                        cert = (X509Certificate) chain[0];
                }
                else {
                    cert = (X509Certificate) store.getCertificate(name);
                }

                if (cert != null && cert.getBasicConstraints() >= 0) {
                    CAs.add(cert);
                }
            }
        } catch (KeyStoreException ex) {
            Logger.getLogger(WolfSSLTrustX509.class.getName()).log(
                    Level.SEVERE, null, ex);
        }
        return WolfSSL.SSL_SUCCESS;
    }

    /**
     * Verify cert chain using WolfSSLCertManager, throw CertificateException
     * on error/failure. Do all loading and verification in one function to
     * avoid holding native resources at the object/class level. */
    private void certManagerVerify(X509Certificate[] certs, String type)
        throws CertificateException {

        int ret = WolfSSL.SSL_FAILURE;
        WolfSSLCertManager cm = null;

        if (certs == null || certs.length == 0 || type.length() == 0) {
            throw new CertificateException();
        }

        /* create new WolfSSLCertManager */
        try {
            cm = new WolfSSLCertManager();
        } catch (WolfSSLException e) {
            throw new CertificateException(
                "Failed to create native WolfSSLCertManager");
        }

        /* load trusted certs from KeyStore */
        try {
            ret = cm.CertManagerLoadCAKeyStore(this.store);
        } catch (WolfSSLException e) {
            cm.free();
            throw new CertificateException(
                "Failed to load trusted certs into WolfSSLCertManager");
        }

        /* verify chain */
        for (int i = 0; i < certs.length; i++) {
            byte[] encoded = certs[i].getEncoded();
            ret = cm.CertManagerLoadCABuffer(encoded, encoded.length,
                    WolfSSL.SSL_FILETYPE_ASN1);
            if (ret != WolfSSL.SSL_SUCCESS) {
                cm.free();
                throw new CertificateException();
            }
        }

        cm.free();
    }

    @Override
    public void checkClientTrusted(X509Certificate[] certs, String type)
            throws CertificateException {

            certManagerVerify(certs, type);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] certs, String type)
        throws CertificateException {

        certManagerVerify(certs, type);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        if (CAs != null) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "accepted issuer array size = " + CAs.size());
            return CAs.toArray(new X509Certificate[CAs.size()]);
        }
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "accepted issuer array is null");
        return null;
    }

    @SuppressWarnings("deprecation")
    @Override
    protected void finalize() throws Throwable {
        this.store = null;
        this.CAs = null;
        super.finalize();
    }
}

