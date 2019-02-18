/* WolfSSLTrustX509.java
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

package com.wolfssl.provider.jsse;

import com.wolfssl.WolfSSL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.X509TrustManager;

import com.wolfssl.WolfSSLCertManager;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSL;
import java.security.cert.CertificateEncodingException;

public class WolfSSLTrustX509 implements X509TrustManager {
    private KeyStore store;
    private List<String> CAs;
    private WolfSSLCertManager cm;
    
    public WolfSSLTrustX509(KeyStore in) {
        this.store = in;
        CAs = new ArrayList<String>();
        try {
            this.cm  = new WolfSSLCertManager();
            LoadCAsFromStore();
        } catch (WolfSSLException ex) {
            Logger.getLogger(WolfSSLTrustX509.class.getName()).log(Level.SEVERE, null, ex);
        }


    }

    /* Loads all CAs from the key store into the cert manager structure */
    private int LoadCAsFromStore() {
        try {
            /* Store the alias of all CAs */
            Enumeration<String> aliases = store.aliases();
            while (aliases.hasMoreElements()) {
                String name = aliases.nextElement();
                X509Certificate cert = (X509Certificate) store.getCertificate(name);
                if (cert.getBasicConstraints() >= 0) {
                    int ret = this.cm.CertManagerLoadCABuffer(cert.getEncoded(),
                            cert.getEncoded().length, WolfSSL.SSL_FILETYPE_ASN1);
                    if (ret == WolfSSL.SSL_SUCCESS) {
                        this.CAs.add(name);
                    }
                }
            }
        } catch (KeyStoreException ex) {
            Logger.getLogger(WolfSSLTrustX509.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateEncodingException ex) {
            Logger.getLogger(WolfSSLTrustX509.class.getName()).log(Level.SEVERE, null, ex);
        }

        return WolfSSL.SSL_SUCCESS;
    }
    
    public void checkClientTrusted(X509Certificate[] certs, String type)
            throws CertificateException, IllegalArgumentException {
        if (certs.length == 0 || type.length() == 0) {
            throw new IllegalArgumentException();
        }
        
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public void checkServerTrusted(X509Certificate[] certs, String type) throws CertificateException {
        int i;
        
        if (certs.length == 0 || type.length() == 0) {
            throw new IllegalArgumentException();
        }

        for (i = 0; i < certs.length; i++) {
            int ret = this.cm.CertManagerVerifyBuffer(certs[i].getEncoded(),
                    certs[i].getEncoded().length, WolfSSL.SSL_FILETYPE_ASN1);
            if (ret != WolfSSL.SSL_SUCCESS) {
                throw new CertificateException();
            }
        }
    }

    public X509Certificate[] getAcceptedIssuers() {
        X509Certificate ret[];
        
        ret = new X509Certificate[CAs.size()];
        if (CAs.size() > 0) {
            int i;
            for (i = 0; i < CAs.size(); i++) {
                try {
                    ret[i] = (X509Certificate)store.getCertificate(CAs.get(i));
                } catch (KeyStoreException ex) {
                    Logger.getLogger(WolfSSLTrustX509.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }
        return ret;
    }
    
    
}