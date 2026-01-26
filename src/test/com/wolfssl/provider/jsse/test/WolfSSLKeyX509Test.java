/* WolfSSLKeyX509Test.java
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

package com.wolfssl.provider.jsse.test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.security.KeyStore;
import java.security.Principal;
import java.security.Provider;
import java.security.Security;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;
import java.security.KeyStoreException;
import java.security.KeyManagementException;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509ExtendedKeyManager;

import org.junit.BeforeClass;
import org.junit.Test;

import com.wolfssl.WolfSSLException;
import com.wolfssl.provider.jsse.WolfSSLProvider;

public class WolfSSLKeyX509Test {

    private static WolfSSLTestFactory tf;
    private String provider = "wolfJSSE";

    @BeforeClass
    public static void testProviderInstallationAtRuntime()
        throws NoSuchProviderException, WolfSSLException {

        System.out.println("WolfSSLKeyX509 Class");

        /* Install wolfJSSE provider at runtime */
        Security.insertProviderAt(new WolfSSLProvider(), 1);

        Provider p = Security.getProvider("wolfJSSE");
        assertNotNull(p);

        try {
            tf = new WolfSSLTestFactory();
        } catch (WolfSSLException e) {
            e.printStackTrace();
            throw e;
        }
    }

    @Test
    public void testGetClientAliases()
        throws NoSuchAlgorithmException, KeyStoreException,
               KeyManagementException, CertificateException, IOException,
               NoSuchProviderException, UnrecoverableKeyException {

        KeyManager[] list;
        X509KeyManager km;
        X509Certificate[] chain;
        String[] alias;

        System.out.print("\tTesting getClientAliases");

        list = tf.createKeyManager("SunX509", tf.allJKS, provider);
        km = (X509KeyManager) list[0];
        alias = km.getClientAliases("RSA", null);
        if (alias == null) {
            error("\t... failed");
            fail("failed to get client aliases");
            return;
        }

        if (alias.length != 6) {
            error("\t... failed");
            fail("unexpected number of alias found");
        }

        /* Try getting chain with null alias, should return null */
        chain = km.getCertificateChain(null);
        if (chain != null) {
            error("\t... failed");
            fail("did not return null chain with null alias");
            return;
        }

        /* Try getting chain with client alias */
        chain = km.getCertificateChain("client");
        if (chain == null || chain.length < 1) {
            error("\t... failed");
            fail("failed to get client certificate");
            return;
        }

        alias = km.getClientAliases("RSA",
            new Principal[] { chain[0].getIssuerDN() });

        if (alias == null || alias.length != 1) {
            error("\t... failed");
            fail("failed to get client aliases");
            return;
        }

        if (!alias[0].equals("client")) {
            error("\t... failed");
            fail("unexpected alias found");
        }

        alias = km.getClientAliases("EC", null);
        if (alias == null) {
            error("\t... failed");
            fail("failed to get client aliases");
            return;
        }

        if (alias.length != 3) {
            error("\t... failed");
            fail("unexpected number of alias found");
        }

        pass("\t... passed");
    }

    @Test
    public void testChooseClientAlias()
        throws NoSuchAlgorithmException, KeyStoreException,
               KeyManagementException, CertificateException, IOException,
               NoSuchProviderException, UnrecoverableKeyException {

        KeyManager[] km = null;
        X509KeyManager x509km = null;
        String alias = null;

        System.out.print("\tTesting chooseClientAlias");

        km = tf.createKeyManager("SunX509", tf.allJKS, provider);
        if (km == null) {
            error("\t... failed");
            fail("failed to create KeyManager[]");
        }

        if (!(km[0] instanceof X509KeyManager)) {
            error("\t... failed");
            fail("KeyManager[0] is not of type X509KeyManager");
        }

        x509km = (X509KeyManager) km[0];
        if (x509km == null) {
            error("\t... failed");
            fail("failed to get X509KeyManager");
        }

        /* All null args, expect null return */
        alias = x509km.chooseClientAlias(null, null, null);
        if (alias != null) {
            error("\t... failed");
            fail("expected null alias with all null args, got: " + alias);
        }

        /* RSA type, null issuers and socket */
        alias = x509km.chooseClientAlias(new String[] { "RSA" }, null, null);

        if (alias != null) {
            /* Note: this is very dependent on the contents and ordering of
             * all.jks. If that file is re-generated or changed, this test may
             * need to be updated */
            if (!alias.equals("client") && !alias.equals("ca")) {
                error("\t... failed");
                fail("expected 'client' alias for RSA type from allJKS, got: " + alias);
            }
        }

        /* EC type, null issuers and socket */
        alias = x509km.chooseClientAlias(new String[] { "EC" }, null, null);

        if (alias != null) {
            /* Note: this is very dependent on the contents and ordering of
             * all.jks. If that file is re-generated or changed, this test may
             * need to be updated */
            if (!alias.equals("server-ecc") && !alias.equals("ca-ecc")) {
                error("\t... failed");
                fail("expected 'server-ecc' alias for EC type from allJKS, got: " + alias);
            }
        }

        pass("\t... passed");
    }

    @Test
    public void testEngineChooseClientAlias()
        throws NoSuchAlgorithmException, KeyStoreException,
               KeyManagementException, CertificateException, IOException,
               NoSuchProviderException, UnrecoverableKeyException {

        KeyManager[] km = null;
        X509ExtendedKeyManager x509km = null;
        String alias = null;

        System.out.print("\tTesting chooseEngineClientAlias");

        km = tf.createKeyManager("SunX509", tf.allJKS, provider);
        if (km == null) {
            error("\t... failed");
            fail("failed to create KeyManager[]");
        }

        if (!(km[0] instanceof X509ExtendedKeyManager)) {
            error("\t... failed");
            fail("KeyManager[0] is not of type X509ExtendedKeyManager");
        }

        x509km = (X509ExtendedKeyManager) km[0];
        if (x509km == null) {
            error("\t... failed");
            fail("failed to get X509ExtendedKeyManager");
        }

        /* All null args, expect null return */
        alias = x509km.chooseEngineClientAlias(null, null, null);
        if (alias != null) {
            error("\t... failed");
            fail("expected null alias with all null args, got: " + alias);
        }

        /* RSA type, null issuers and socket */
        alias = x509km.chooseEngineClientAlias(new String[] { "RSA" },
                                               null, null);
        if (alias != null) {
            /* Note: this is very dependent on the contents and ordering of
             * all.jks. If that file is re-generated or changed, this test may
             * need to be updated */
            if (!alias.equals("client") && !alias.equals("ca")) {
                error("\t... failed");
                fail("expected 'client' alias for RSA type from allJKS, got: " + alias);
            }
        }

        /* EC type, null issuers and socket */
        alias = x509km.chooseEngineClientAlias(new String[] { "EC" },
                                               null, null);
        if (alias != null) {
            /* Note: this is very dependent on the contents and ordering of
             * all.jks. If that file is re-generated or changed, this test may
             * need to be updated */
            if (!alias.equals("server-ecc") && !alias.equals("ca-ecc")) {
                error("\t... failed");
                fail("expected 'server-ecc' alias for EC type from allJKS, got: " + alias);
            }
        }

        /* Currently SSLEngine argument is not used by wolfJSSE, if this
         * behavior changes, add tests here */

        pass("\t... passed");
    }

    @Test
    public void testGetServerAliases()
        throws NoSuchAlgorithmException, KeyStoreException,
               KeyManagementException, CertificateException, IOException,
               NoSuchProviderException, UnrecoverableKeyException {

        KeyManager[] list;
        X509KeyManager km;
        String[] alias;

        System.out.print("\tTesting getServerAliases");

        list = tf.createKeyManager("SunX509", tf.allJKS, provider);
        km = (X509KeyManager) list[0];
        alias = km.getServerAliases("RSA", null);
        if (alias == null) {
            error("\t... failed");
            fail("failed to get server aliases");
            return;
        }

        if (alias.length != 6) {
            error("\t... failed");
            fail("unexpected number of alias found");
        }

        alias = km.getServerAliases("EC", null);
        if (alias == null) {
            error("\t... failed");
            fail("failed to get server aliases");
            return;
        }

        if (alias.length != 3) {
            error("\t... failed");
            fail("unexpected number of alias found");
        }

        /* should be no ECC keys in RSA key store */
        list = tf.createKeyManager("SunX509", tf.serverRSAJKS, provider);
        km = (X509KeyManager) list[0];
        alias = km.getServerAliases("EC", null);
        if (alias != null) {
            error("\t... failed");
            fail("failed to get server aliases");
        }

        pass("\t... passed");
    }

    @Test
    public void testChooseServerAlias()
        throws NoSuchAlgorithmException, KeyStoreException,
               KeyManagementException, CertificateException, IOException,
               NoSuchProviderException, UnrecoverableKeyException {

        KeyManager[] km = null;
        X509KeyManager x509km = null;
        String alias = null;

        System.out.print("\tTesting chooseServerAlias");

        km = tf.createKeyManager("SunX509", tf.allJKS, provider);
        if (km == null) {
            error("\t... failed");
            fail("failed to create KeyManager[]");
        }

        if (!(km[0] instanceof X509KeyManager)) {
            error("\t... failed");
            fail("KeyManager[0] is not of type X509KeyManager");
        }

        x509km = (X509KeyManager) km[0];
        if (x509km == null) {
            error("\t... failed");
            fail("failed to get X509KeyManager");
        }

        /* All null args, expect null return */
        alias = x509km.chooseServerAlias(null, null, null);
        if (alias != null) {
            error("\t... failed");
            fail("expected null alias with all null args, got: " + alias);
        }

        /* RSA type, null issuers and socket */
        alias = x509km.chooseServerAlias("RSA", null, null);

        if (alias != null) {
            /* Note: this is very dependent on the contents and ordering of
             * all.jks. If that file is re-generated or changed, this test may
             * need to be updated */
            if (!alias.equals("client") && !alias.equals("ca")) {
                error("\t... failed");
                fail("expected 'client' alias for RSA type from allJKS, got: " + alias);
            }
        }

        /* EC type, null issuers and socket */
        alias = x509km.chooseServerAlias("EC", null, null);

        if (alias != null) {
            /* Note: this is very dependent on the contents and ordering of
             * all.jks. If that file is re-generated or changed, this test may
             * need to be updated */
            if (!alias.equals("server-ecc") && !alias.equals("ca-ecc")) {
                error("\t... failed");
                fail("expected 'server-ecc' alias for EC type from allJKS, got: " + alias);
            }
        }

        pass("\t... passed");
    }

    @Test
    public void testChooseEngineServerAlias()
        throws NoSuchAlgorithmException, KeyStoreException,
               KeyManagementException, CertificateException, IOException,
               NoSuchProviderException, UnrecoverableKeyException {

        KeyManager[] km = null;
        X509ExtendedKeyManager x509km = null;
        String alias = null;

        System.out.print("\tTesting chooseEngineServerAlias");

        km = tf.createKeyManager("SunX509", tf.allJKS, provider);
        if (km == null) {
            error("\t... failed");
            fail("failed to create KeyManager[]");
        }

        if (!(km[0] instanceof X509ExtendedKeyManager)) {
            error("\t... failed");
            fail("KeyManager[0] is not of type X509ExtendedKeyManager");
        }

        x509km = (X509ExtendedKeyManager) km[0];
        if (x509km == null) {
            error("\t... failed");
            fail("failed to get X509ExtendedKeyManager");
        }

        /* All null args, expect null return */
        alias = x509km.chooseEngineServerAlias(null, null, null);
        if (alias != null) {
            error("\t... failed");
            fail("expected null alias with all null args, got: " + alias);
        }

        /* RSA type, null issuers and socket */
        alias = x509km.chooseEngineServerAlias("RSA", null, null);

        if (alias != null) {
            /* Note: this is very dependent on the contents and ordering of
             * all.jks. If that file is re-generated or changed, this test may
             * need to be updated */
            if (!alias.equals("client") && !alias.equals("ca")) {
                error("\t... failed");
                fail("expected 'client' alias for RSA type from allJKS, got: " + alias);
            }
        }

        /* EC type, null issuers and socket */
        alias = x509km.chooseEngineServerAlias("EC", null, null);

        if (alias != null) {
            /* Note: this is very dependent on the contents and ordering of
             * all.jks. If that file is re-generated or changed, this test may
             * need to be updated */
            if (!alias.equals("server-ecc") && !alias.equals("ca-ecc")) {
                error("\t... failed");
                fail("expected 'server-ecc' alias for EC type from allJKS, got: " + alias);
            }
        }

        /* Currently SSLSocket argument is not used by wolfJSSE, if this
         * behavior changes, add tests here */

        pass("\t... passed");
    }

    @Test
    public void testConstructorWithInvalidKeyStore()
        throws NoSuchAlgorithmException, KeyStoreException,
               KeyManagementException, CertificateException, IOException,
               NoSuchProviderException, UnrecoverableKeyException {

        System.out.print("\tTesting with invalid KeyStore");

        /* Test with null KeyStore - should not throw exception */
        try {
            com.wolfssl.provider.jsse.WolfSSLKeyX509 km =
                new com.wolfssl.provider.jsse.WolfSSLKeyX509(null, null);
            /* Should succeed with empty cache */
        } catch (Exception e) {
            error("\t... failed");
            fail("Constructor should handle null KeyStore gracefully: " + e);
        }

        pass("\t... passed");
    }

    @Test
    public void testCacheConsistencyWithKeyStore()
        throws NoSuchAlgorithmException, KeyStoreException,
               KeyManagementException, CertificateException, IOException,
               NoSuchProviderException, UnrecoverableKeyException {

        KeyManager[] list;
        X509KeyManager km;
        String[] aliases;

        System.out.print("\tTesting cache consistency");

        /* Create KeyManager with cached WolfSSLKeyX509 */
        list = tf.createKeyManager("SunX509", tf.allJKS, provider);
        km = (X509KeyManager) list[0];

        /* Test that cached aliases match what we expect */
        aliases = km.getClientAliases("RSA", null);
        if (aliases == null || aliases.length == 0) {
            error("\t... failed");
            fail("No RSA client aliases found in cache");
        }

        /* Test certificate chain consistency */
        for (String alias : aliases) {
            if (alias != null) {
                X509Certificate[] chain = km.getCertificateChain(alias);
                if (chain == null) {
                    error("\t... failed");
                    fail("Certificate chain missing from cache for alias: " + alias);
                }
            }
        }

        /* Test private key consistency */
        for (String alias : aliases) {
            if (alias != null) {
                /* Private key may be null for some aliases, that's expected */
                km.getPrivateKey(alias);
            }
        }

        pass("\t... passed");
    }

    @Test
    public void testEmptyKeyStoreCache()
        throws NoSuchAlgorithmException, KeyStoreException,
               KeyManagementException, CertificateException, IOException,
               NoSuchProviderException, UnrecoverableKeyException {

        System.out.print("\tTesting empty KeyStore cache");

        try {
            /* Create empty KeyStore */
            KeyStore emptyStore = KeyStore.getInstance("JKS");
            emptyStore.load(null, null);

            /* Create WolfSSLKeyX509 with empty KeyStore */
            com.wolfssl.provider.jsse.WolfSSLKeyX509 km =
                new com.wolfssl.provider.jsse.WolfSSLKeyX509(emptyStore, null);

            /* Test methods with empty cache */
            String[] aliases = km.getClientAliases("RSA", null);
            if (aliases != null) {
                error("\t... failed");
                fail("Expected null aliases from empty KeyStore");
            }

            aliases = km.getServerAliases("RSA", null);
            if (aliases != null) {
                error("\t... failed");
                fail("Expected null server aliases from empty KeyStore");
            }

            String alias = km.chooseClientAlias(new String[] {"RSA"}, null, null);
            if (alias != null) {
                error("\t... failed");
                fail("Expected null client alias from empty KeyStore");
            }

            alias = km.chooseServerAlias("RSA", null, null);
            if (alias != null) {
                error("\t... failed");
                fail("Expected null server alias from empty KeyStore");
            }

        } catch (Exception e) {
            error("\t... failed");
            fail("Empty KeyStore test failed: " + e);
        }

        pass("\t... passed");
    }

    @Test
    public void testNullKeyStoreCache()
        throws NoSuchAlgorithmException, KeyStoreException,
               KeyManagementException, CertificateException, IOException,
               NoSuchProviderException, UnrecoverableKeyException {

        System.out.print("\tTesting null KeyStore cache");

        try {
            /* Create WolfSSLKeyX509 with null KeyStore */
            com.wolfssl.provider.jsse.WolfSSLKeyX509 km =
                new com.wolfssl.provider.jsse.WolfSSLKeyX509(null, null);

            /* Test methods with null KeyStore */
            String[] aliases = km.getClientAliases("RSA", null);
            if (aliases != null) {
                error("\t... failed");
                fail("Expected null aliases from null KeyStore");
            }

            aliases = km.getServerAliases("RSA", null);
            if (aliases != null) {
                error("\t... failed");
                fail("Expected null server aliases from null KeyStore");
            }

            String alias = km.chooseClientAlias(new String[] {"RSA"}, null, null);
            if (alias != null) {
                error("\t... failed");
                fail("Expected null client alias from null KeyStore");
            }

            alias = km.chooseServerAlias("RSA", null, null);
            if (alias != null) {
                error("\t... failed");
                fail("Expected null server alias from null KeyStore");
            }

            X509Certificate[] chain = km.getCertificateChain("nonexistent");
            if (chain != null) {
                error("\t... failed");
                fail("Expected null certificate chain from null KeyStore");
            }

            java.security.PrivateKey key = km.getPrivateKey("nonexistent");
            if (key != null) {
                error("\t... failed");
                fail("Expected null private key from null KeyStore");
            }

        } catch (Exception e) {
            error("\t... failed");
            fail("Null KeyStore test failed: " + e);
        }

        pass("\t... passed");
    }

    @Test
    public void testCertificateChainCaching()
        throws NoSuchAlgorithmException, KeyStoreException,
               KeyManagementException, CertificateException, IOException,
               NoSuchProviderException, UnrecoverableKeyException {

        KeyManager[] list;
        X509KeyManager km;
        X509Certificate[] chain1, chain2;

        System.out.print("\tTesting cert chain caching");

        list = tf.createKeyManager("SunX509", tf.allJKS, provider);
        km = (X509KeyManager) list[0];

        /* Get certificate chain twice to test caching */
        chain1 = km.getCertificateChain("client");
        chain2 = km.getCertificateChain("client");

        if (chain1 == null) {
            error("\t... failed");
            fail("Certificate chain should not be null for 'client' alias");
        }

        if (chain2 == null) {
            error("\t... failed");
            fail("Second certificate chain retrieval should not be null");
        }

        /* Test that both retrievals return the same cached object */
        if (chain1 != chain2) {
            error("\t... failed");
            fail("Certificate chain caching failed - different objects returned");
        }

        /* Test with non-existent alias */
        X509Certificate[] nullChain = km.getCertificateChain("nonexistent");
        if (nullChain != null) {
            error("\t... failed");
            fail("Expected null certificate chain for non-existent alias");
        }

        /* Test with null alias */
        nullChain = km.getCertificateChain(null);
        if (nullChain != null) {
            error("\t... failed");
            fail("Expected null certificate chain for null alias");
        }

        pass("\t... passed");
    }

    @Test
    public void testPrivateKeyCaching()
        throws NoSuchAlgorithmException, KeyStoreException,
               KeyManagementException, CertificateException, IOException,
               NoSuchProviderException, UnrecoverableKeyException {

        KeyManager[] list;
        X509KeyManager km;
        java.security.PrivateKey key1, key2;

        System.out.print("\tTesting private key caching");

        list = tf.createKeyManager("SunX509", tf.allJKS, provider);
        km = (X509KeyManager) list[0];

        /* Get private key twice to test caching */
        key1 = km.getPrivateKey("client");
        key2 = km.getPrivateKey("client");

        if (key1 == null) {
            error("\t... failed");
            fail("Private key should not be null for 'client' alias");
        }

        if (key2 == null) {
            error("\t... failed");
            fail("Second private key retrieval should not be null");
        }

        /* Test that both retrievals return the same cached object */
        if (key1 != key2) {
            error("\t... failed");
            fail("Private key caching failed - different objects returned");
        }

        /* Test with non-existent alias */
        java.security.PrivateKey nullKey = km.getPrivateKey("nonexistent");
        if (nullKey != null) {
            error("\t... failed");
            fail("Expected null private key for non-existent alias");
        }

        /* Test with null alias */
        nullKey = km.getPrivateKey(null);
        if (nullKey != null) {
            error("\t... failed");
            fail("Expected null private key for null alias");
        }

        pass("\t... passed");
    }

    @Test
    public void testCacheDisabledSecurityProperty()
        throws NoSuchAlgorithmException, KeyStoreException,
               KeyManagementException, CertificateException, IOException,
               NoSuchProviderException, UnrecoverableKeyException {

        System.out.print("\tTesting cache disabled");

        /* Save original property value */
        String originalValue =
            Security.getProperty("wolfjsse.X509KeyManager.disableCache");

        try {
            /* Test with caching disabled */
            Security.setProperty(
                "wolfjsse.X509KeyManager.disableCache", "true");

            /* Create KeyManager with caching disabled */
            KeyStore ks = KeyStore.getInstance("JKS");
            java.io.FileInputStream fis =
                new java.io.FileInputStream(tf.allJKS);
            ks.load(fis, "wolfSSL test".toCharArray());
            fis.close();

            com.wolfssl.provider.jsse.WolfSSLKeyX509 km =
                new com.wolfssl.provider.jsse.WolfSSLKeyX509(
                    ks, "wolfSSL test".toCharArray());

            /* Test that operations work with caching disabled */
            String[] aliases = km.getClientAliases("RSA", null);
            if (aliases == null || aliases.length == 0) {
                error("\t\t... failed");
                fail("No RSA client aliases found with caching disabled");
            }

            /* Test certificate chain retrieval */
            X509Certificate[] chain = km.getCertificateChain("client");
            if (chain == null) {
                error("\t\t... failed");
                fail("Certificate chain should not be null with " +
                     "caching disabled");
            }

            /* Test private key retrieval */
            java.security.PrivateKey key = km.getPrivateKey("client");
            if (key == null) {
                error("\t\t... failed");
                fail("Private key should not be null with caching disabled");
            }

            /* Test alias selection */
            String selectedAlias =
                km.chooseClientAlias(new String[] {"RSA"}, null, null);
            if (selectedAlias == null) {
                error("\t\t... failed");
                fail("Should be able to choose client alias with " +
                     "caching disabled");
            }

        } finally {
            /* Restore original property value */
            if (originalValue != null) {
                Security.setProperty(
                    "wolfjsse.X509KeyManager.disableCache", originalValue);
            } else {
                /* Remove property if it wasn't set originally */
                Security.setProperty(
                    "wolfjsse.X509KeyManager.disableCache", "");
            }
        }

        pass("\t\t... passed");
    }

    @Test
    public void testCacheEnabledSecurityProperty()
        throws NoSuchAlgorithmException, KeyStoreException,
               KeyManagementException, CertificateException, IOException,
               NoSuchProviderException, UnrecoverableKeyException {

        System.out.print("\tTesting cache enabled");

        /* Save original property value */
        String originalValue =
            Security.getProperty("wolfjsse.X509KeyManager.disableCache");

        try {
            /* Test with caching explicitly enabled */
            Security.setProperty(
                "wolfjsse.X509KeyManager.disableCache", "false");

            /* Create KeyManager with caching enabled */
            KeyStore ks = KeyStore.getInstance("JKS");
            java.io.FileInputStream fis =
                new java.io.FileInputStream(tf.allJKS);
            ks.load(fis, "wolfSSL test".toCharArray());
            fis.close();

            com.wolfssl.provider.jsse.WolfSSLKeyX509 km =
                new com.wolfssl.provider.jsse.WolfSSLKeyX509(
                    ks, "wolfSSL test".toCharArray());

            /* Test that operations work with caching enabled */
            String[] aliases = km.getClientAliases("RSA", null);
            if (aliases == null || aliases.length == 0) {
                error("\t\t... failed");
                fail("No RSA client aliases found with caching enabled");
            }

            /* Test certificate chain retrieval and caching */
            X509Certificate[] chain1 = km.getCertificateChain("client");
            X509Certificate[] chain2 = km.getCertificateChain("client");
            if (chain1 == null || chain2 == null) {
                error("\t\t... failed");
                fail("Certificate chains should not be null " +
                     "with caching enabled");
            }

            /* With caching enabled, should return same cached object */
            if (chain1 != chain2) {
                error("\t\t... failed");
                fail("Certificate chain caching failed - different " +
                     "objects returned");
            }

            /* Test private key retrieval and caching */
            java.security.PrivateKey key1 = km.getPrivateKey("client");
            java.security.PrivateKey key2 = km.getPrivateKey("client");
            if (key1 == null || key2 == null) {
                error("\t\t... failed");
                fail("Private keys should not be null with caching enabled");
            }

            /* With caching enabled, should return same cached object */
            if (key1 != key2) {
                error("\t\t... failed");
                fail("Private key caching failed - different objects returned");
            }

        } finally {
            /* Restore original property value */
            if (originalValue != null) {
                Security.setProperty(
                    "wolfjsse.X509KeyManager.disableCache", originalValue);
            } else {
                /* Remove property if it wasn't set originally */
                Security.setProperty(
                    "wolfjsse.X509KeyManager.disableCache", "");
            }
        }

        pass("\t\t... passed");
    }

    @Test
    public void testDefaultCachingBehavior()
        throws NoSuchAlgorithmException, KeyStoreException,
               KeyManagementException, CertificateException, IOException,
               NoSuchProviderException, UnrecoverableKeyException {

        System.out.print("\tTesting default cache behavior");

        /* Save original property value */
        String originalValue = Security.getProperty(
            "wolfjsse.X509KeyManager.disableCache");

        try {
            /* Clear property to test default behavior */
            Security.setProperty("wolfjsse.X509KeyManager.disableCache", "");

            /* Create KeyManager with default behavior
             * (should be caching enabled) */
            KeyStore ks = KeyStore.getInstance("JKS");
            java.io.FileInputStream fis =
                new java.io.FileInputStream(tf.allJKS);
            ks.load(fis, "wolfSSL test".toCharArray());
            fis.close();

            com.wolfssl.provider.jsse.WolfSSLKeyX509 km =
                new com.wolfssl.provider.jsse.WolfSSLKeyX509(
                    ks, "wolfSSL test".toCharArray());

            /* Test that operations work with default behavior */
            String[] aliases = km.getClientAliases("RSA", null);
            if (aliases == null || aliases.length == 0) {
                error("\t... failed");
                fail("No RSA client aliases found with default behavior");
            }

            /* Test that caching works by default (same objects returned) */
            X509Certificate[] chain1 = km.getCertificateChain("client");
            X509Certificate[] chain2 = km.getCertificateChain("client");
            if (chain1 == null || chain2 == null) {
                error("\t... failed");
                fail("Certificate chains should not be null " +
                     "with default behavior");
            }

            /* Default behavior should be caching enabled */
            if (chain1 != chain2) {
                error("\t... failed");
                fail("Default behavior should enable caching - " +
                     "different objects returned");
            }

        } finally {
            /* Restore original property value */
            if (originalValue != null) {
                Security.setProperty(
                    "wolfjsse.X509KeyManager.disableCache", originalValue);
            } else {
                /* Remove property if it wasn't set originally */
                Security.setProperty(
                    "wolfjsse.X509KeyManager.disableCache", "");
            }
        }

        pass("\t... passed");
    }

    @Test
    public void testCaseInsensitiveSecurityProperty()
        throws NoSuchAlgorithmException, KeyStoreException,
               KeyManagementException, CertificateException, IOException,
               NoSuchProviderException, UnrecoverableKeyException {

        System.out.print("\tCase insensitive cache disable");

        /* Save original property value */
        String originalValue = Security.getProperty(
            "wolfjsse.X509KeyManager.disableCache");

        try {
            /* Test different case variations of "true" */
            String[] trueVariations = {"true", "TRUE", "True", "tRuE"};

            for (String trueValue : trueVariations) {
                Security.setProperty(
                    "wolfjsse.X509KeyManager.disableCache", trueValue);

                KeyStore ks = KeyStore.getInstance("JKS");
                java.io.FileInputStream fis =
                    new java.io.FileInputStream(tf.allJKS);
                ks.load(fis, "wolfSSL test".toCharArray());
                fis.close();

                com.wolfssl.provider.jsse.WolfSSLKeyX509 km =
                    new com.wolfssl.provider.jsse.WolfSSLKeyX509(
                        ks, "wolfSSL test".toCharArray());

                /* Should work with any case variation of "true" */
                String[] aliases = km.getClientAliases("RSA", null);
                if (aliases == null || aliases.length == 0) {
                    error("\t... failed");
                    fail("No RSA client aliases found with '" +
                         trueValue + "'");
                }
            }

            /* Test values that should NOT disable caching */
            String[] falseVariations = {"false", "FALSE", "False", "0",
                "no", "disabled", "random"};

            for (String falseValue : falseVariations) {
                Security.setProperty(
                    "wolfjsse.X509KeyManager.disableCache", falseValue);

                KeyStore ks = KeyStore.getInstance("JKS");
                java.io.FileInputStream fis =
                    new java.io.FileInputStream(tf.allJKS);
                ks.load(fis, "wolfSSL test".toCharArray());
                fis.close();

                com.wolfssl.provider.jsse.WolfSSLKeyX509 km =
                    new com.wolfssl.provider.jsse.WolfSSLKeyX509(
                        ks, "wolfSSL test".toCharArray());

                /* Should have caching enabled (same objects returned) */
                X509Certificate[] chain1 = km.getCertificateChain("client");
                X509Certificate[] chain2 = km.getCertificateChain("client");
                if (chain1 == null || chain2 == null) {
                    error("\t... failed");
                    fail("Certificate chains should not be null with '" +
                         falseValue + "'");
                }

                if (chain1 != chain2) {
                    error("\t... failed");
                    fail("Caching should be enabled with '" +
                         falseValue + "' - different objects returned");
                }
            }

        } finally {
            /* Restore original property value */
            if (originalValue != null) {
                Security.setProperty(
                    "wolfjsse.X509KeyManager.disableCache", originalValue);
            } else {
                /* Remove property if it wasn't set originally */
                Security.setProperty(
                    "wolfjsse.X509KeyManager.disableCache", "");
            }
        }

        pass("\t... passed");
    }

    @Test
    public void testNullKeyStoreWithCachingDisabled()
        throws NoSuchAlgorithmException, KeyStoreException,
               KeyManagementException, CertificateException, IOException,
               NoSuchProviderException, UnrecoverableKeyException {

        System.out.print("\tnull KeyStore with no caching");

        /* Save original property value */
        String originalValue = Security.getProperty(
            "wolfjsse.X509KeyManager.disableCache");

        try {
            /* Test with caching disabled and null KeyStore */
            Security.setProperty(
                "wolfjsse.X509KeyManager.disableCache", "true");

            com.wolfssl.provider.jsse.WolfSSLKeyX509 km =
                new com.wolfssl.provider.jsse.WolfSSLKeyX509(null, null);

            /* Test that all operations return null gracefully */
            String[] aliases = km.getClientAliases("RSA", null);
            if (aliases != null) {
                error("\t... failed");
                fail("Expected null aliases with null KeyStore and " +
                     "caching disabled");
            }

            X509Certificate[] chain = km.getCertificateChain("client");
            if (chain != null) {
                error("\t... failed");
                fail("Expected null certificate chain with null " +
                     "KeyStore and caching disabled");
            }

            java.security.PrivateKey key = km.getPrivateKey("client");
            if (key != null) {
                error("\t... failed");
                fail("Expected null private key with null KeyStore " +
                     "and caching disabled");
            }

            String alias = km.chooseClientAlias(new String[] {"RSA"},
                null, null);
            if (alias != null) {
                error("\t... failed");
                fail("Expected null alias with null KeyStore and " +
                     "caching disabled");
            }

        } finally {
            /* Restore original property value */
            if (originalValue != null) {
                Security.setProperty(
                    "wolfjsse.X509KeyManager.disableCache", originalValue);
            } else {
                /* Remove property if it wasn't set originally */
                Security.setProperty(
                    "wolfjsse.X509KeyManager.disableCache", "");
            }
        }

        pass("\t... passed");
    }

    /* Test that chooseAlias methods return aliases with private keys */
    @Test
    public void testChooseAliasSkipsCertOnlyEntries()
        throws NoSuchAlgorithmException, KeyStoreException,
               KeyManagementException, CertificateException, IOException,
               NoSuchProviderException, UnrecoverableKeyException {

        System.out.print("\tTesting chooseAlias skips cert-only");

        KeyManager[] km = tf.createKeyManager("SunX509", tf.allJKS, provider);
        X509ExtendedKeyManager x509km = (X509ExtendedKeyManager) km[0];
        String alias;

        alias = x509km.chooseClientAlias(new String[] { "RSA" }, null, null);
        if (alias != null && x509km.getPrivateKey(alias) == null) {
            fail("chooseClientAlias returned alias without private key");
        }

        alias = x509km.chooseEngineClientAlias(
            new String[] { "RSA" }, null, null);
        if (alias != null && x509km.getPrivateKey(alias) == null) {
            fail("chooseEngineClientAlias returned alias without private key");
        }

        pass("\t... passed");
    }

    private void pass(String msg) {
        WolfSSLTestFactory.pass(msg);
    }

    private void error(String msg) {
        WolfSSLTestFactory.fail(msg);
    }
}
