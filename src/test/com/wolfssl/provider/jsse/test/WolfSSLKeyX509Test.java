/* WolfSSLKeyX509Test.java
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

package com.wolfssl.provider.jsse.test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.X509KeyManager;

import org.junit.BeforeClass;
import org.junit.Test;

import com.wolfssl.WolfSSLException;
import com.wolfssl.provider.jsse.WolfSSLProvider;

public class WolfSSLKeyX509Test {

    private static WolfSSLTestFactory tf;
    private String provider = "wolfJSSE";
    private javax.security.cert.X509Certificate[] certs;

    @BeforeClass
    public static void testProviderInstallationAtRuntime()
        throws NoSuchProviderException {

        System.out.println("WolfSSLKeyX509 Class");

        /* install wolfJSSE provider at runtime */
        Security.insertProviderAt(new WolfSSLProvider(), 1);

        Provider p = Security.getProvider("wolfJSSE");
        assertNotNull(p);

        try {
            tf = new WolfSSLTestFactory();
        } catch (WolfSSLException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    @Test
    public void testgetClientAliases() {
        KeyManager[] list;
        X509KeyManager km;
        X509Certificate[] chain;
        String[] alias;
        String str;
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

        chain = km.getCertificateChain("client");
        if (chain == null || chain.length < 1) {
            error("\t... failed");
            fail("failed to get client certificate");
            return;
        }

        alias = km.getClientAliases("RSA", new Principal[] { chain[0].getIssuerDN() });
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

        str = km.chooseClientAlias(null, null, null);
        if (str != null) {
            error("\t... failed");
            fail("unexpected alias found");
        }

        pass("\t... passed");
    }

    @Test
    public void testgetServerAliases() {
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
        list = tf.createKeyManager("SunX509", tf.rsaJKS, provider);
        km = (X509KeyManager) list[0];
        alias = km.getServerAliases("EC", null);
        if (alias != null) {
            error("\t... failed");
            fail("failed to get server aliases");
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
