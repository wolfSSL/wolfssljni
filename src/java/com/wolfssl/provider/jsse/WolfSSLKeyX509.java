/* WolfSSLKeyX509.java
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

import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509KeyManager;


public class WolfSSLKeyX509 implements X509KeyManager{
    private KeyStore store;
    private char[] password;
    
    public WolfSSLKeyX509(KeyStore in, char[] password) {
        this.store = in;
        this.password = password;
    }
    
    private String[] getAliases(String type, Principal[] issuers) {
        Enumeration<String> aliases = null;
        int i;
        ArrayList<String> ret = new ArrayList<String>();
        
        try {
            aliases = this.store.aliases();
        } catch (KeyStoreException ex) {
            Logger.getLogger(WolfSSLKeyX509.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }

        while (aliases.hasMoreElements()) {
            String current = aliases.nextElement();
            X509Certificate cert = null;
            try {
                cert = (X509Certificate)this.store.getCertificate(current);
            } catch (KeyStoreException ex) {
                Logger.getLogger(WolfSSLKeyX509.class.getName()).log(Level.SEVERE, null, ex);
            }
            
            /* if issuers is null than it does not matter which issuer */
            if (issuers == null) {
                ret.add(current);
            }
            else {
                for (i = 0; i < issuers.length; i++) {
                    if (cert != null && cert.getIssuerDN().equals(issuers[i])) {
                        ret.add(current);
                    }
                }
            }
        }
        
        return ret.toArray(new String[0]);
    }
    
    public String[] getClientAliases(String type, Principal[] issuers) {
        return getAliases(type, issuers);
    }

    public String chooseClientAlias(String[] type, Principal[] issuers, Socket sock) {
        int i;
        
        if (type == null) {
            return null;
        }
        
        if (sock != null) {
            throw new UnsupportedOperationException("Not supported yet.");
        }
        
        for (i = 0; i < type.length; i++) {
            String[] all = getAliases(type[i], issuers);
            if (all != null) {
                return all[0];
            }
        }
        return null;
    }

    public String[] getServerAliases(String type, Principal[] issuers) {
        return getAliases(type, issuers);
    }

    public String chooseServerAlias(String type, Principal[] issuers, Socket sock) {
        String[] all = getAliases(type, issuers);
        if (sock != null) {
            if (sock.isConnected() == true) {
                SSLSocket ssl = (SSLSocket)sock;
                //String proto = ssl.getApplicationProtocol();
            }
        }
        return all[0];
    }

    public X509Certificate[] getCertificateChain(String alias) {
        X509Certificate[] ret = null;
        try {
            Certificate[] certs = this.store.getCertificateChain(alias);
            if (certs != null) {
                int i;
                ret = new X509Certificate[certs.length];
                for (i = 0; i < certs.length; i++) {
                    ret[i] = (X509Certificate)certs[i];
                }
            }
        } catch (KeyStoreException ex) {
            Logger.getLogger(WolfSSLKeyX509.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        if (ret == null) {
            try {
                Certificate cert = (X509Certificate)this.store.getCertificate(alias);
                if (cert != null) {
                    ret    = new X509Certificate[1];
                    ret[0] = (X509Certificate)cert;
                }
            } catch (KeyStoreException ex) {
                Logger.getLogger(WolfSSLKeyX509.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return ret;
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        PrivateKey key = null;

        try {
            key = (PrivateKey)store.getKey(alias, password);
        } catch (Exception e) {
           /* @TODO unable to get key */
        }
        return key;
    }
    
}
