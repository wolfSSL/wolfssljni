/* WolfSSLTrustManager.java
 *
 * Copyright (C) 2006-2019 wolfSSL Inc.
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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;

/**
 * wolfSSL implemenation of TrustManagerFactorySpi
 *
 * @author wolfSSL
 */
public class WolfSSLTrustManager extends TrustManagerFactorySpi {
    private KeyStore store;

    @Override
    protected void engineInit(KeyStore in) throws KeyStoreException {
        KeyStore certs = in;
        if (in == null) {
            String pass = System.getProperty("javax.net.ssl.trustStorePassword");
            String file = System.getProperty("javax.net.ssl.trustStore");
            char passAr[] = null;
            InputStream stream = null;

            try {
                if (pass != null) {
                    passAr = pass.toCharArray();
                }
                certs = KeyStore.getInstance("JKS");
                if (file == null) {
                    String home = System.getenv("JAVA_HOME");
                    if (home != null) {
                        File f = new File(home.concat("lib/security/jssecacerts"));
                        if (f.exists()) {
                            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                    "Loading certs from " + home.concat("lib/security/jssecacerts"));
                            stream = new FileInputStream(f);
                            certs.load(stream, passAr);
                        }
                        else {
                            f = new File(home.concat("lib/security/cacerts"));
                            if (f.exists()) {
                                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                        "Loading certs from " + home.concat("lib/security/cacerts"));
                                stream = new FileInputStream(f);
                                certs.load(stream, passAr);
                            }
                            else {
                                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                        "Using Anonymous cipher suite");
                            }
                        }
                    }
                }
                else {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            "Loading certs from " + file);
                    stream = new FileInputStream(file);
                    certs.load(stream, passAr);
                }
            } catch (FileNotFoundException ex) {
                Logger.getLogger(WolfSSLTrustManager.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IOException ex) {
                Logger.getLogger(WolfSSLTrustManager.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(WolfSSLTrustManager.class.getName()).log(Level.SEVERE, null, ex);
            } catch (CertificateException ex) {
                Logger.getLogger(WolfSSLTrustManager.class.getName()).log(Level.SEVERE, null, ex);
            }

            if (stream != null) {
                try {
                    stream.close();
                } catch (IOException e) {
                    throw new KeyStoreException("Unable to close stream");
                }
            }
        }
        this.store = certs;
    }

    @Override
    protected void engineInit(ManagerFactoryParameters arg0) throws InvalidAlgorithmParameterException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    protected TrustManager[] engineGetTrustManagers() {
        /* array of WolfSSLX509Trust objects to use */
        TrustManager[] tm = {new WolfSSLTrustX509(this.store)};
        return tm;
    }
}
