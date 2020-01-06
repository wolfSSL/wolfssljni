/* WolfSSLContextTest.java
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

package com.wolfssl.test;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import static org.junit.Assert.*;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLContext;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLPskClientCallback;
import com.wolfssl.WolfSSLPskServerCallback;
import com.wolfssl.WolfSSLSession;

public class WolfSSLContextTest {

    public final static int TEST_FAIL    = -1;
    public final static int TEST_SUCCESS =  0;

    public static String cliCert = "examples/certs/client-cert.pem";
    public static String cliKey  = "examples/certs/client-key.pem";
    public static String caCert  = "examples/certs/ca-cert.pem";
    public final static String bogusFile = "/dev/null";

    WolfSSLContext ctx;

    @Test
    public void testWolfSSLContext() throws WolfSSLException {

        System.out.println("WolfSSLContext Class");
        
        cliCert = WolfSSLTestCommon.getPath(cliCert);
        cliKey = WolfSSLTestCommon.getPath(cliKey);
        caCert = WolfSSLTestCommon.getPath(caCert);
        
        test_WolfSSLContext_new(WolfSSL.SSLv23_ServerMethod());
        test_WolfSSLContext_useCertificateFile();
        test_WolfSSLContext_usePrivateKeyFile();
        test_WolfSSLContext_loadVerifyLocations();
        test_WolfSSLContext_setPskClientCb();
        test_WolfSSLContext_setPskServerCb();
        test_WolfSSLContext_usePskIdentityHint();
        test_WolfSSLContext_free();

    }

    public void test_WolfSSLContext_new(long method) {

        if (method != 0)
        {
            System.out.print("\tWolfSSLContext()");

            /* test failure case */
            try {

                ctx = new WolfSSLContext(0);

            } catch (WolfSSLException e) {

                /* now test success case */
                try {
                    ctx = new WolfSSLContext(method);
                } catch (WolfSSLException we) {
                    System.out.println("\t\t... failed");
                    fail("failed to create WolfSSLContext object");
                }

                System.out.println("\t\t... passed");
                return;
            }

            System.out.println("\t\t... failed");
            fail("failure case improperly succeeded, WolfSSLContext()");
        }
    }

    public void test_WolfSSLContext_useCertificateFile() {

        System.out.print("\tuseCertificateFile()");

        test_ucf(null, null, 9999, WolfSSL.SSL_FAILURE,
                 "useCertificateFile(null, null, 9999)");

        test_ucf(ctx, bogusFile, WolfSSL.SSL_FILETYPE_PEM, WolfSSL.SSL_FAILURE,
                 "useCertificateFile(ctx, bogusFile, SSL_FILETYPE_PEM)");

        test_ucf(ctx, cliCert, 9999, WolfSSL.SSL_FAILURE,
                 "useCertificateFile(ctx, cliCert, 9999)");

        test_ucf(ctx, cliCert, WolfSSL.SSL_FILETYPE_PEM,
                 WolfSSL.SSL_SUCCESS,
                 "useCertificateFile(ctx, cliCert, SSL_FILETYPE_PEM)");

        System.out.println("\t\t... passed");
    }

    /* helper for testing WolfSSLContext.useCertificateFile() */
    public void test_ucf(WolfSSLContext sslCtx, String filePath, int type,
                        int cond, String name) {

        int result;

        try {

            result = sslCtx.useCertificateFile(filePath, type);
            if (result != cond)
            {
                System.out.println("\t\t... failed");
                fail(name + " failed");
            }

        } catch (NullPointerException e) {

            /* correctly handle NULL pointer */
            if (sslCtx == null) {
                return;
            }
        }

        return;
    }

    public void test_WolfSSLContext_usePrivateKeyFile() {

        System.out.print("\tusePrivateKeyFile()");

        test_upkf(null, null, 9999, WolfSSL.SSL_FAILURE,
                 "usePrivateKeyFile(null, null, 9999)");

        test_upkf(ctx, bogusFile, WolfSSL.SSL_FILETYPE_PEM,
                  WolfSSL.SSL_FAILURE,
                 "usePrivateKeyFile(ctx, bogusFile, SSL_FILETYPE_PEM)");

        test_upkf(ctx, cliKey, 9999, WolfSSL.SSL_FAILURE,
                 "usePrivateKeyFile(ctx, cliKey, 9999)");

        test_upkf(ctx, cliKey, WolfSSL.SSL_FILETYPE_PEM, WolfSSL.SSL_SUCCESS,
                 "usePrivateKeyFile(ctx, cliKey, SSL_FILETYPE_PEM)");

        System.out.println("\t\t... passed");
    }

    /* helper for testing WolfSSLContext.usePrivateKeyFile() */
    public void test_upkf(WolfSSLContext sslCtx, String filePath, int type,
                        int cond, String name) {

        int result;

        try {

            result = sslCtx.usePrivateKeyFile(filePath, type);
            if (result != cond)
            {
                System.out.println("\t\t... failed");
                fail(name + " failed");
            }

        } catch (NullPointerException e) {

            /* correctly handle NULL pointer */
            if (sslCtx == null) {
                return;
            }
        }

        return;
    }

    public void test_WolfSSLContext_loadVerifyLocations() {

        System.out.print("\tloadVerifyLocations()");

        test_lvl(null, null, null, WolfSSL.SSL_FAILURE,
                "loadVerifyLocations(null, null, null)");

        test_lvl(ctx, null, null, WolfSSL.SSL_FAILURE,
                "loadVerifyLocations(ctx, null, null)");

        test_lvl(null, caCert, null, WolfSSL.SSL_FAILURE,
                "loadVerifyLocations(null, caCert, null)");

        test_lvl(ctx, caCert, null, WolfSSL.SSL_SUCCESS,
                "loadVerifyLocations(ctx, caCert, 0)");

        System.out.println("\t\t... passed");
    }

    /* helper for testing WolfSSLContext.loadVerifyLocations() */
    public void test_lvl(WolfSSLContext sslCtx, String filePath,
                         String dirPath, int cond, String name) {

        int result;

        try {

            result = sslCtx.loadVerifyLocations(filePath, dirPath);
            if (result != cond)
            {
                System.out.println("\t\t... failed");
                fail(name + " failed");
            }

        } catch (NullPointerException e) {

            /* correctly handle NULL pointer */
            if (sslCtx == null) {
                return;
            }
        }

        return;
    }

    class TestPskClientCb implements WolfSSLPskClientCallback
    {
        public long pskClientCallback(WolfSSLSession ssl, String hint,
                StringBuffer identity, long idMaxLen, byte[] key,
                long keyMaxLen) {

            /* set the client identity */
            if (identity.length() != 0)
                return 0;
            identity.append("Client_identity");

            /* set the client key, max key size is key.length */
            key[0] = 26;
            key[1] = 43;
            key[2] = 60;
            key[3] = 77;

            /* return size of key */
            return 4;
        }
    }

    public void test_WolfSSLContext_setPskClientCb() {
        System.out.print("\tsetPskClientCb()");
        try {
            TestPskClientCb pskClientCb = new TestPskClientCb();
            ctx.setPskClientCb(pskClientCb);
        } catch (Exception e) {
            if (!e.getMessage().equals("wolfSSL not compiled with PSK " +
                        "support")) {
                System.out.println("\t\t... failed");
                e.printStackTrace();
            }
        }
        System.out.println("\t\t... passed");
    }

    class TestPskServerCb implements WolfSSLPskServerCallback
    {
        public long pskServerCallback(WolfSSLSession ssl, String identity,
                byte[] key, long keyMaxLen) {

            /* check the client identity */
            if (!identity.equals("Client_identity"))
                return 0;

            /* set the server key, max key size is key.length */
            key[0] = 26;
            key[1] = 43;
            key[2] = 60;
            key[3] = 77;

            /* return size of key */
            return 4;
        }
    }

    public void test_WolfSSLContext_setPskServerCb() {
        System.out.print("\tsetPskServerCb()");
        try {
            TestPskServerCb pskServerCb = new TestPskServerCb();
            ctx.setPskServerCb(pskServerCb);
        } catch (Exception e) {
            if (!e.getMessage().equals("wolfSSL not compiled with PSK " +
                        "support")) {
                System.out.println("\t\t... failed");
                e.printStackTrace();
            }
        }
        System.out.println("\t\t... passed");
    }

    public void test_WolfSSLContext_usePskIdentityHint() {
        System.out.print("\tusePskIdentityHint()");
        try {
            int ret = ctx.usePskIdentityHint("wolfssl hint");
            if (ret != WolfSSL.SSL_SUCCESS &&
                ret != WolfSSL.NOT_COMPILED_IN) {
                System.out.println("\t\t... failed");
                fail("usePskIdentityHint failed");
            }
        } catch (IllegalStateException e) {
            System.out.println("\t\t... failed");
            e.printStackTrace();
        }
        System.out.println("\t\t... passed");
    }

    public void test_WolfSSLContext_free() {

        System.out.print("\tfree()");
        ctx.free();
        System.out.println("\t\t\t\t... passed");
    }
}

