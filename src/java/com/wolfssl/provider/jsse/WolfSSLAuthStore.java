/* WolfSSLAuthStore.java
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
import com.wolfssl.WolfSSLSession;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.security.KeyStore;
import java.security.SecureRandom;

import java.lang.IllegalArgumentException;
import java.security.KeyStoreException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Helper class used to store common settings, objects, etc.
 */
public class WolfSSLAuthStore {

    static enum TLS_VERSION {
        INVALID,
        TLSv1,
        TLSv1_1,
        TLSv1_2,
        TLSv1_3,
        SSLv23
    }

    private TLS_VERSION currentVersion = TLS_VERSION.INVALID;

    private X509KeyManager km = null;
    private X509TrustManager tm = null;
    private SecureRandom sr = null;
    private String alias = null;
    private SessionStore<Integer, WolfSSLImplementSSLSession> store;

    /**
     * @param keyman key manager to use
     * @param trustman trust manager to use
     * @param random secure random
     * @param version TLS protocol version to use
     * @throws IllegalArgumentException when bad values are passed in
     * @throws KeyManagementException in the case that getting keys fails
     */
    protected WolfSSLAuthStore(KeyManager[] keyman, TrustManager[] trustman,
        SecureRandom random, TLS_VERSION version)
        throws IllegalArgumentException, KeyManagementException {

        if (version == TLS_VERSION.INVALID) {
            throw new IllegalArgumentException("Invalid SSL/TLS version");
        }

        initKeyManager(keyman);
        initTrustManager(trustman);
        initSecureRandom(random);

        this.currentVersion = version;
        store = new SessionStore<Integer, WolfSSLImplementSSLSession>(10);
        //@TODO set max size correctly
    }

    /**
     * Initialize key manager.
     * The first instance of X509KeyManager found will be used. If null is
     * passed in, installed security providers with be searched for highest
     * priority implementation of the required factory.
     */
    private void initKeyManager(KeyManager[] in)
        throws KeyManagementException {
        KeyManager[] managers = in;
        if (managers == null || managers.length == 0) {
            try {
                /* use key managers from installed security providers */
                KeyManagerFactory kmFactory = KeyManagerFactory.getInstance(
                    KeyManagerFactory.getDefaultAlgorithm());
                kmFactory.init(null, null);
                managers = kmFactory.getKeyManagers();

            } catch (NoSuchAlgorithmException nsae) {
                throw new KeyManagementException(nsae);
            } catch (KeyStoreException kse) {
                throw new KeyManagementException(kse);
            } catch (UnrecoverableKeyException uke) {
                throw new KeyManagementException(uke);
            }
        }

        if (managers != null) {
            for (int i = 0; i < managers.length; i++) {
                if (managers[i] instanceof X509KeyManager) {
                    km = (X509KeyManager)managers[i];
                    break;
                }
            }
        }
    }

    /**
     * Initialize trust manager.
     * The first instance of X509TrustManager found will be used. If null is
     * passed in, installed security providers with be searched for highest
     * priority implementation of the required factory.
     */
    private void initTrustManager(TrustManager[] in)
        throws KeyManagementException {
        TrustManager[] managers = in;
        if (managers == null || managers.length == 0) {

            try {
                /* use trust managers from installed security providers */
                TrustManagerFactory tmFactory = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
                tmFactory.init((KeyStore)null);
                managers = tmFactory.getTrustManagers();

            } catch (NoSuchAlgorithmException nsae) {
                throw new KeyManagementException(nsae);
            } catch (KeyStoreException kse) {
                throw new KeyManagementException(kse);
            }
        }

        if (managers != null) {
            for (int i = 0; i < managers.length; i++) {
                if (managers[i] instanceof X509TrustManager) {
                    tm = (X509TrustManager)managers[i];
                    break;
                }
            }
        }
    }

    /**
     * Initialize secure random.
     * If SecureRandom passed in is null, default implementation will
     * be used.
     */
    private void initSecureRandom(SecureRandom random) {

        if (random == null) {
            sr = new SecureRandom();
        }
        sr = random;
    }


    /**
     * @return get the key manager used
     */
    protected X509KeyManager getX509KeyManager() {
        return this.km;
    }

    /**
     * @return get the trust manager used
     */
    protected X509TrustManager getX509TrustManager() {
        return this.tm;
    }

    /**
     * @return get secure random
     */
    protected SecureRandom getSecureRandom() {
        return this.sr;
    }

    /**
     * @return get the current protocol version set
     */
    protected TLS_VERSION getProtocolVersion() {
        return this.currentVersion;
    }

    /**
     * @param in alias to set for certificate used
     */
    protected void setCertAlias(String in) {
        this.alias = in;
    }

    /**
     * @return alias name
     */
    protected String getCertAlias() {
        return this.alias;
    }

    /** Returns either an existing session to use or creates a new session. Can
     * return null on error case or the case where session could not be created.
     * @param ssl WOLFSSL class to set in session
     * @param port port number connecting to
     * @param host host connecting to
     * @param clientMode if is client side then true
     * @return a new or reused SSLSession on success, null on failure
     */
    protected WolfSSLImplementSSLSession getSession(WolfSSLSession ssl,
        int port, String host, boolean clientMode) {

        WolfSSLImplementSSLSession ses;
        String toHash;

        if (ssl == null) {
            return null;
        }

        /* server mode, or client mode with no host */
        if (clientMode == false || host == null) {
            return this.getSession(ssl);
        }
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "attempting to look up session (" +
                "host: " + host + ", port: " + port + ")");

        /* check if is in table */
        toHash = host.concat(Integer.toString(port));
        ses = store.get(toHash.hashCode());
        if (ses == null) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "session not found in cache table, creating new");
            /* not found in stored sessions create a new one */
            ses = new WolfSSLImplementSSLSession(ssl, port, host, this);
        }
        else {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "session found in cache, trying to resume");
            ses.resume(ssl);
        }
        return ses;
    }

    /** Returns a new session, does not check/save for resumption
     * @param ssl WOLFSSL class to reference with new session
     * @return a new SSLSession on success
     */
    protected WolfSSLImplementSSLSession getSession(WolfSSLSession ssl) {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "creating new session");
        return new WolfSSLImplementSSLSession(ssl, this);
    }

    /**
     * Add the session for possible resumption
     * @param session the session to add to stored session map
     * @return SSL_SUCCESS on success
     */
    protected int addSession(WolfSSLImplementSSLSession session) {
        String toHash;

        if (session.getPeerHost() != null) {
            /* register into session table for resumption */
            session.fromTable = true;
            toHash = session.getPeerHost().concat(Integer.toString(
                     session.getPeerPort()));
            store.put(toHash.hashCode(), session);


            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "stored session in cache table (host: " +
                    session.getPeerHost() + ", port: " +
                    session.getPeerPort() + ")");
        }

        return WolfSSL.SSL_SUCCESS;
    }

    private class SessionStore<K, V> extends LinkedHashMap<K, V> {
        /**
         * user defined ID
         */
        private static final long serialVersionUID = 1L;
        private final int maxSz;

        /**
         * @param in max size of hash map before oldest entry is overwritten
         */
        protected SessionStore(int in) {
            maxSz = in;
        }

        @Override
        protected boolean removeEldestEntry(Map.Entry<K, V> oldest) {
            return size() > maxSz;
        }
    }
}

