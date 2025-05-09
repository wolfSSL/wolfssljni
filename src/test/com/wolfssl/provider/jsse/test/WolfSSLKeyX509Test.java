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

    private void pass(String msg) {
        WolfSSLTestFactory.pass(msg);
    }

    private void error(String msg) {
        WolfSSLTestFactory.fail(msg);
    }
 }
