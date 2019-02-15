/* WolfSSLParameters.java
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

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.security.SecureRandom;

import java.lang.IllegalArgumentException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

/**
 * Helper class used to store common settings, objects, etc.
 */
public class WolfSSLParameters {

    static enum TLS_VERSION {
        INVALID,
        TLSv1,
        TLSv1_1,
        TLSv1_2,
        TLSv1_3,
        SSLv23
    };
    
    private TLS_VERSION currentVersion = TLS_VERSION.INVALID;

    private X509KeyManager km = null;
    private X509TrustManager tm = null;
    private SecureRandom sr = null;
    
    protected WolfSSLParameters(KeyManager[] keyman, TrustManager[] trustman,
        SecureRandom random, TLS_VERSION version)
        throws IllegalArgumentException, KeyManagementException {

        if (version == TLS_VERSION.INVALID) {
            throw new IllegalArgumentException("Invalid SSL/TLS version");
        }

        initKeyManager(keyman);
        initTrustManager(trustman);
        initSecureRandom(random);

        this.currentVersion = version;
    }

    /**
     * Initialize key manager.
     * The first instance of X509KeyManager found will be used. If null is
     * passed in, installed security providers with be searched for highest
     * priority implementation of the required factory.
     */
    private void initKeyManager(KeyManager[] managers)
        throws KeyManagementException {

        if (managers == null || managers.length == 0) {

            try {
                /* use key managers from installed security providers */
                KeyManagerFactory kmFactory = KeyManagerFactory.getInstance(
                    KeyManagerFactory.getDefaultAlgorithm());
                managers = kmFactory.getKeyManagers();

            } catch (NoSuchAlgorithmException nsae) {
                throw new KeyManagementException(nsae);
            }
        }

        for (int i = 0; i < managers.length; i++) {
            if (managers[i] instanceof X509KeyManager) {
                km = (X509KeyManager)managers[i];
                break;
            }
        }
        
        if (km == null) {
            throw new KeyManagementException("No X509KeyManager found " +
                    "in KeyManager array");
        }
    }

    /**
     * Initialize trust manager.
     * The first instance of X509TrustManager found will be used. If null is
     * passed in, installed security providers with be searched for highest
     * priority implementation of the required factory.
     */
    private void initTrustManager(TrustManager[] managers)
        throws KeyManagementException {

        if (managers == null || managers.length == 0) {

            try {
                /* use trust managers from installed security providers */
                TrustManagerFactory tmFactory = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
                managers = tmFactory.getTrustManagers();

            } catch (NoSuchAlgorithmException nsae) {
                throw new KeyManagementException(nsae);
            }
        }

        for (int i = 0; i < managers.length; i++) {
            if (managers[i] instanceof X509TrustManager) {
                tm = (X509TrustManager)managers[i];
                break;
            }
        }
        
        if (tm == null) {
            throw new KeyManagementException("No X509TrustManager found " +
                    "in TrustManager array");
        }
    }

    /**
     * Initialize secure random.
     * If SecureRandom passed in is null, default implementation will
     * be used.
     */
    private void initSecureRandom(SecureRandom random) {

        if (random == null) {
            random = new SecureRandom();
        }
        sr = random;
    }
    

    protected X509KeyManager getX509KeyManager() {
        return this.km;
    }

    protected X509TrustManager getX509TrustManager() {
        return this.tm;
    }

    protected SecureRandom getSecureRandom() {
        return this.sr;
    }

    protected TLS_VERSION getProtocolVersion() {
        return this.currentVersion;
    }
}

