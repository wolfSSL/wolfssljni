/* WolfSSLKeyManager.java
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


package com.wolfssl.provider.jsse;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;
import com.wolfssl.WolfSSLCertificate;
import com.wolfssl.WolfSSLException;

/**
 * WolfSSL KeyManagerFactory implementation
 */
public class WolfSSLKeyManager extends KeyManagerFactorySpi {
    private char[] pswd;
    private KeyStore store;

    /** Default WolfSSLKeyManager constructor */
    public WolfSSLKeyManager() { }

    @Override
    protected void engineInit(KeyStore store, char[] password)
            throws KeyStoreException, NoSuchAlgorithmException,
            UnrecoverableKeyException {

        this.pswd = password;
        KeyStore certs = store;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entering engineInit(KeyStore store, char[] password)");

        /* If no KeyStore passed in, try to load from system property values */
        if (store == null) {
            String pass = System.getProperty("javax.net.ssl.keyStorePassword");
            String file = System.getProperty("javax.net.ssl.keyStore");
            String type = System.getProperty("javax.net.ssl.keyStoreType");
            String vmVendor = System.getProperty("java.vm.vendor");
            InputStream stream = null;

            try {
                if (file != null) {
                    if (pass != null) {
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            "javax.net.ssl.keyStorePassword system property " +
                            "set, using password");
                        this.pswd = pass.toCharArray();
                    } else {
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            "javax.net.ssl.keyStorePassword system property " +
                            "not set");
                    }

                    /* We default to use a JKS KeyStore type if not set at the
                     * system level, except on Android we use BKS */
                    try {
                        if (type != null && type != "") {
                            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                "javax.net.ssl.keyStoreType system property " +
                                "set: " + type);
                            certs = KeyStore.getInstance(type);
                        } else {
                            if (vmVendor != null &&
                                    vmVendor.equals("The Android Project")) {
                                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                    "Detected Android VM, " +
                                    "using BKS KeyStore type");
                                certs = KeyStore.getInstance("BKS");
                            } else {
                                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                "javax.net.ssl.keyStoreType system property " +
                                "not set, using type: JKS");
                                certs = KeyStore.getInstance("JKS");
                            }
                        }
                    } catch (KeyStoreException kse) {
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.ERROR,
                            "Unsupported KeyStore type: " + type);
                        throw kse;
                    }

                    try {
                        /* initialize KeyStore, loading certs below will
                         * overwrite if needed, otherwise Android needs
                         * this to be initialized here */
                        certs.load(null, null);

                    } catch (Exception e) {
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.ERROR,
                           "Error initializing KeyStore with load(null, null)");
                        throw e;
                    }

                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            "Loading certs from " + file);
                    stream = new FileInputStream(file);
                    certs.load(stream, this.pswd);
                    stream.close();
                }

            } catch (FileNotFoundException ex) {
                throw new KeyStoreException(ex);
            } catch (IOException ex) {
                throw new KeyStoreException(ex);
            } catch (NoSuchAlgorithmException ex) {
                throw new KeyStoreException(ex);
            } catch (CertificateException ex) {
                throw new KeyStoreException(ex);
            }
        }
        this.store = certs;
    }

    @Override
    protected void engineInit(ManagerFactoryParameters arg0)
        throws InvalidAlgorithmParameterException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entering engineInit(ManagerFactoryParameters arg0)");

        throw new UnsupportedOperationException(
                "KeyManagerFactory.init(ManagerFactoryParameters) not " +
                "supported yet");
    }

    @Override
    protected KeyManager[] engineGetKeyManagers() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered engineGetKeyManagers()");

        KeyManager[] km = {new WolfSSLKeyX509(this.store, this.pswd)};
        return km;
    }
}

