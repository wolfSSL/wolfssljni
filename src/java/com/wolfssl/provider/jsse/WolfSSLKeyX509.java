/* WolfSSLKeyX509.java
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

package com.wolfssl.provider.jsse;

import java.net.Socket;
import java.security.AccessController;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.Arrays;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import com.wolfssl.WolfSSLDebug;

/**
 * wolfSSL implementation of X509KeyManager, extends X509ExtendedKeyManager
 * for implementation of chooseEngineClientAlias() and
 * chooseEngineServerAlias().
 *
 * @author wolfSSL
 */
public class WolfSSLKeyX509 extends X509ExtendedKeyManager {

    /* Security property to control caching behavior. When set to "true",
     * disables KeyStore entry caching and reverts to calling KeyStore
     * methods directly for each operation. */
    private static final String DISABLE_CACHE_PROPERTY =
        "wolfjsse.X509KeyManager.disableCache";

    /* Reference to original KeyStore for non-cached operations */
    private final KeyStore keyStore;
    private final char[] keyStorePassword;

    /* Cache behavior determined once at construction time */
    private final boolean cacheDisabled;

    /* Cache for KeyStore entries to avoid concurrent access issues. Prior
     * to the addition of these caches, WolfSSLKeyX509 called down directly
     * to the underlying KeyStore for each operation. Since the KeyStore
     * operations are synchronized, concurrent threads accessing this
     * KeyManager can queue up in that scenario and hurt performance.
     * These caches are only used if caching has not been disabled via
     * Security property. */
    private final Map<String, X509Certificate> certificateCache;
    private final Map<String, X509Certificate[]> certificateChainCache;
    private final Map<String, PrivateKey> privateKeyCache;
    private final Set<String> aliasSet;

    /**
     * Create new WolfSSLKeyX509 object
     *
     * @param store input KeyStore to cache entries from
     * @param password input KeyStore password
     * @throws KeyStoreException if unable to populate cache from KeyStore
     */
    public WolfSSLKeyX509(KeyStore store, char[] password)
        throws KeyStoreException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "creating new WolfSSLKeyX509 object");

        /* Check Security property once at construction time.
         * Use doPrivileged for SecurityManager compatibility. */
        @SuppressWarnings("removal")
        String disableCacheValue = AccessController.doPrivileged(
            new PrivilegedAction<String>() {
                public String run() {
                    return Security.getProperty(DISABLE_CACHE_PROPERTY);
                }
            }
        );
        this.cacheDisabled = "true".equalsIgnoreCase(disableCacheValue);

        if (this.cacheDisabled) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "KeyStore caching disabled via " +
                DISABLE_CACHE_PROPERTY + " Security property, " +
                "using direct KeyStore access");

            this.keyStore = store;
            this.keyStorePassword =
                (password != null) ? password.clone() : null;

            this.certificateCache = null;
            this.certificateChainCache = null;
            this.privateKeyCache = null;
            this.aliasSet = null;

        } else {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "KeyStore caching enabled, populating caches");

            this.keyStore = null;
            this.keyStorePassword = null;

            /* Initialize cache data structures */
            this.certificateCache = new HashMap<String, X509Certificate>();
            this.certificateChainCache =
                new HashMap<String, X509Certificate[]>();
            this.privateKeyCache = new HashMap<String, PrivateKey>();
            this.aliasSet = new LinkedHashSet<String>();

            /* Populate caches from KeyStore */
            populateCache(store, password);
        }
    }

    /**
     * Populate internal caches with all entries from KeyStore
     *
     * @param store KeyStore to read entries from
     * @param password KeyStore password to access private keys
     * @throws KeyStoreException if unable to read from KeyStore
     */
    private void populateCache(KeyStore store, char[] password)
        throws KeyStoreException {

        if (store == null) {
            return;
        }

        Enumeration<String> aliases = store.aliases();

        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            aliasSet.add(alias);

            try {
                /* Cache individual certificate */
                Certificate cert = store.getCertificate(alias);
                if (cert instanceof X509Certificate) {
                    certificateCache.put(alias, (X509Certificate)cert);
                }

                /* Cache certificate chain */
                Certificate[] certChain = store.getCertificateChain(alias);
                if (certChain != null) {
                    int x509Cnt = 0;

                    /* Count X509Certificate entries */
                    for (int i = 0; i < certChain.length; i++) {
                        if (certChain[i] instanceof X509Certificate) {
                            x509Cnt++;
                        }
                    }

                    /* Store X509Certificate chain */
                    if (x509Cnt > 0) {
                        int idx = 0;
                        X509Certificate[] x509Chain =
                            new X509Certificate[x509Cnt];

                        for (int i = 0; i < certChain.length; i++) {
                            if (certChain[i] instanceof X509Certificate) {
                                x509Chain[idx++] = (X509Certificate)certChain[i];
                            }
                        }
                        certificateChainCache.put(alias, x509Chain);
                    }
                }

                /* Cache private key */
                PrivateKey key = (PrivateKey)store.getKey(alias, password);
                if (key != null) {
                    privateKeyCache.put(alias, key);
                }

            } catch (Exception e) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.ERROR,
                    () -> "Error caching entry for alias: " + alias + ", " + e);
                /* Continue processing other aliases */
            }
        }

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "Cached " + aliasSet.size() + " aliases from KeyStore");
    }


    /**
     * Return array of aliases from KeyStore that matches provided
     * type and issuers array (non-cached version).
     *
     * Returns:
     * null - if no alias matches found in KeyStore.
     * String[] - aliases, if found that match type and/or issuers
     */
    private String[] getAliasesFromKeyStore(String type, Principal[] issuers)
        throws KeyStoreException {

        int i;
        ArrayList<String> ret = new ArrayList<String>();

        if (keyStore == null) {
            return null;
        }

        Enumeration<String> aliases = keyStore.aliases();

        /* loop through each KeyStore alias */
        while (aliases.hasMoreElements()) {
            String current = aliases.nextElement();
            Certificate cert = keyStore.getCertificate(current);

            if (!(cert instanceof X509Certificate)) {
                continue;
            }

            X509Certificate x509cert = (X509Certificate)cert;

            if (type != null &&
                !x509cert.getPublicKey().getAlgorithm().equals(type)) {
                /* different public key type, skip */
                continue;
            }

            /* if issuers is null then it does not matter which issuer */
            if (issuers == null) {
                ret.add(current);
            }
            else {
                /* search through issuers for matching issuer name */
                for (i = 0; i < issuers.length; i++) {
                    String certIssuer = x509cert.getIssuerDN().getName();
                    String issuerName = issuers[i].getName();

                    /* normalize spaces after commas, needed on some JDKs */
                    certIssuer = certIssuer.replaceAll(", ", ",");
                    issuerName = issuerName.replaceAll(", ", ",");

                    if (certIssuer.equals(issuerName)) {
                        /* matched issuer, add alias and continue on */
                        ret.add(current);
                        break;
                    }
                }
            }
        }

        if (ret.size() == 0) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "No aliases found in KeyStore that match type " +
                "and/or issuer");
            return null;
        }

        return ret.toArray(new String[0]);
    }

    /**
     * Return array of aliases that matches provided type and issuers array.
     * Uses either cached entries or direct KeyStore access based on Security
     * property configuration.
     *
     * Returns:
     * null - if no alias matches found.
     * String[] - aliases, if found that match type and/or issuers
     */
    private String[] getAliases(String type, Principal[] issuers) {

        /* Check if caching is disabled, use direct KeyStore access */
        if (this.cacheDisabled) {
            try {
                return getAliasesFromKeyStore(type, issuers);
            } catch (KeyStoreException e) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.ERROR,
                    () -> "Error accessing KeyStore directly: " +
                    e.getMessage());
                return null;
            }
        }

        /* Use cached entries */
        int i;
        ArrayList<String> ret = new ArrayList<String>();

        /* loop through each cached alias */
        for (String current : aliasSet) {
            X509Certificate cert = certificateCache.get(current);

            if (type != null && cert != null &&
                !cert.getPublicKey().getAlgorithm().equals(type)) {
                /* different public key type, skip */
                continue;
            }

            /* if issuers is null then it does not matter which issuer */
            if (issuers == null) {
                ret.add(current);
            }
            else {
                if (cert != null) {
                    /* search through issuers for matching issuer name */
                    for (i = 0; i < issuers.length; i++) {
                        String certIssuer = cert.getIssuerDN().getName();
                        String issuerName = issuers[i].getName();

                        /* normalize spaces after commas, needed on some JDKs */
                        certIssuer = certIssuer.replaceAll(", ", ",");
                        issuerName = issuerName.replaceAll(", ", ",");

                        if (certIssuer.equals(issuerName)) {
                            /* matched issuer, add alias and continue on */
                            ret.add(current);
                            break;
                        }
                    }
                }
            }
        }

        if (ret.size() == 0) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "No aliases found in cache that match type " +
                "and/or issuer");
            return null;
        }

        return ret.toArray(new String[0]);
    }

    @Override
    public String[] getClientAliases(String type, Principal[] issuers) {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered getClientAliases()");

        return getAliases(type, issuers);
    }

    /* Note: Socket argument not used by wolfJSSE to choose aliases */
    @Override
    public String chooseClientAlias(String[] type, Principal[] issuers,
        Socket sock) {

        int i;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered chooseClientAlias()");

        if (type == null) {
            return null;
        }

        for (i = 0; i < type.length; i++) {
            String[] all = getAliases(type[i], issuers);
            if (all != null) {
                /* Find first alias that has a private key, skip cert-only
                 * entries (trustedCertEntry) which have no private key */
                for (String alias : all) {
                    PrivateKey key = getPrivateKey(alias);
                    if (key != null) {
                        final String selectedAlias = alias;
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            () -> "chooseClientAlias() returning alias " +
                            "with private key: " + selectedAlias);
                        return alias;
                    }
                }
            }
        }
        return null;
    }

    /* Note: Engine argument not yet used by wolfJSSE to choose aliases */
    @Override
    public String chooseEngineClientAlias(String[] type, Principal[] issuers,
        SSLEngine engine) {

        int i;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered chooseEngineClientAlias()");

        if (type == null) {
            return null;
        }

        for (i = 0; i < type.length; i++) {
            String[] all = getAliases(type[i], issuers);
            if (all != null) {
                /* Find first alias that has a private key, skip cert-only
                 * entries (trustedCertEntry) which have no private key */
                for (String alias : all) {
                    PrivateKey key = getPrivateKey(alias);
                    if (key != null) {
                        final String selectedAlias = alias;
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            () -> "chooseEngineClientAlias() returning " +
                            "alias with private key: " + selectedAlias);
                        return alias;
                    }
                }
            }
        }
        return null;
    }

    @Override
    public String[] getServerAliases(String type, Principal[] issuers) {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered getServerAliases(), type: " + type);

        return getAliases(type, issuers);
    }

    @Override
    public String chooseServerAlias(String type, Principal[] issuers,
        Socket sock) {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered chooseServerAlias(), type: " + type);

        if (type == null || type.isEmpty()) {
            return null;
        }

        /* For now using same behavior as chooseClientAlias() */
        return chooseClientAlias(new String[] {type}, issuers, sock);
    }

    @Override
    public String chooseEngineServerAlias(String type, Principal[] issuers,
        SSLEngine engine) {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered chooseEngineServerAlias(), type: " + type);

        if (type == null || type.isEmpty()) {
            return null;
        }

        /* For now, using same behavior as chooseEngineClientAlias() */
        return chooseEngineClientAlias(new String[] {type}, issuers, engine);
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered getCertificateChain(), alias: " + alias);

        if (alias == null) {
            return null;
        }

        /* Check if caching is disabled, use direct KeyStore access */
        if (this.cacheDisabled) {
            try {
                if (keyStore == null) {
                    return null;
                }

                Certificate[] certChain = keyStore.getCertificateChain(alias);
                if (certChain == null) {
                    return null;
                }

                /* Convert to X509Certificate array */
                int x509Cnt = 0;
                for (int i = 0; i < certChain.length; i++) {
                    if (certChain[i] instanceof X509Certificate) {
                        x509Cnt++;
                    }
                }

                if (x509Cnt == 0) {
                    return null;
                }

                X509Certificate[] x509Chain = new X509Certificate[x509Cnt];
                int idx = 0;
                for (int i = 0; i < certChain.length; i++) {
                    if (certChain[i] instanceof X509Certificate) {
                        x509Chain[idx++] = (X509Certificate)certChain[i];
                    }
                }

                return x509Chain;

            } catch (KeyStoreException e) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.ERROR,
                    () -> "Error accessing certificate chain from KeyStore: " +
                    e.getMessage());
                return null;
            }
        }

        /* Return cached certificate chain */
        return certificateChainCache.get(alias);
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered getPrivateKey(), alias: " + alias);

        if (alias == null) {
            return null;
        }

        /* Check if caching is disabled, use direct KeyStore access */
        if (this.cacheDisabled) {
            try {
                if (keyStore == null || keyStorePassword == null) {
                    return null;
                }

                return (PrivateKey)keyStore.getKey(alias, keyStorePassword);

            } catch (Exception e) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.ERROR,
                    () -> "Error accessing private key from KeyStore: " +
                    e.getMessage());
                return null;
            }
        }

        /* Return cached private key */
        return privateKeyCache.get(alias);
    }

    /**
     * Clear sensitive data when object is garbage collected
     */
    @Override
    protected void finalize() throws Throwable {
        try {
            /* Clear KeyStore password if present */
            if (keyStorePassword != null) {
                Arrays.fill(keyStorePassword, (char)0);
            }

            /* Clear cached private keys */
            if (privateKeyCache != null) {
                privateKeyCache.clear();
            }

            /* Free WolfSSLX509 certificates if present */
            if (certificateCache != null) {
                for (X509Certificate cert : certificateCache.values()) {
                    if (cert instanceof WolfSSLX509) {
                        ((WolfSSLX509)cert).free();
                    }
                }
                certificateCache.clear();
            }

            /* Free WolfSSLX509 certificate chains if present */
            if (certificateChainCache != null) {
                for (X509Certificate[] chain : certificateChainCache.values()) {
                    if (chain != null) {
                        for (X509Certificate cert : chain) {
                            if (cert instanceof WolfSSLX509) {
                                ((WolfSSLX509)cert).free();
                            }
                        }
                    }
                }
                certificateChainCache.clear();
            }

            if (aliasSet != null) {
                aliasSet.clear();
            }

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "WolfSSLKeyX509 finalized, sensitive data cleared");

        } finally {
            super.finalize();
        }
    }
}

