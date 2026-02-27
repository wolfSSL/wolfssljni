/* WolfSSLContextTest.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

package com.wolfssl.test;

import org.junit.Test;
import org.junit.BeforeClass;
import static org.junit.Assert.*;

import java.io.IOException;
import java.net.Socket;
import java.net.ServerSocket;
import java.nio.ByteBuffer;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLContext;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLJNIException;
import com.wolfssl.WolfSSLPskClientCallback;
import com.wolfssl.WolfSSLPskServerCallback;
import com.wolfssl.WolfSSLSession;
import com.wolfssl.WolfSSLRsaSignCallback;
import com.wolfssl.WolfSSLRsaVerifyCallback;
import com.wolfssl.WolfSSLRsaPssSignCallback;
import com.wolfssl.WolfSSLRsaPssVerifyCallback;
import com.wolfssl.WolfCryptRSA;

public class WolfSSLContextTest {

    public final static int TEST_FAIL    = -1;
    public final static int TEST_SUCCESS =  0;

    public static String cliCert    = "examples/certs/client-cert.pem";
    public static String cliKey     = "examples/certs/client-key.pem";
    public static String svrCert    = "examples/certs/server-cert.pem";
    public static String svrKey     = "examples/certs/server-key.pem";
    public static String svrCertEcc = "examples/certs/server-ecc.pem";
    public static String caCert     = "examples/certs/ca-cert.pem";
    public static String dhParams   = "examples/certs/dh2048.pem";
    public final static String bogusFile = "/dev/null";

    WolfSSLContext ctx;

    @BeforeClass
    public static void loadLibrary() {
        try {
            WolfSSL.loadLibrary();
        } catch (UnsatisfiedLinkError ule) {
            fail("failed to load native JNI library");
        }
    }

    @Test
    public void testWolfSSLContext() throws WolfSSLException {

        System.out.println("WolfSSLContext Class");

        cliCert = WolfSSLTestCommon.getPath(cliCert);
        cliKey = WolfSSLTestCommon.getPath(cliKey);
        svrCert = WolfSSLTestCommon.getPath(svrCert);
        svrKey = WolfSSLTestCommon.getPath(svrKey);
        svrCertEcc = WolfSSLTestCommon.getPath(svrCertEcc);
        caCert = WolfSSLTestCommon.getPath(caCert);
        dhParams = WolfSSLTestCommon.getPath(dhParams);

        test_WolfSSLContext_new(WolfSSL.SSLv23_ServerMethod());
        test_WolfSSLContext_useCertificateFile();
        test_WolfSSLContext_usePrivateKeyFile();
        test_WolfSSLContext_loadVerifyLocations();
        test_WolfSSLContext_setPskClientCb();
        test_WolfSSLContext_setPskServerCb();
        test_WolfSSLContext_usePskIdentityHint();
        test_WolfSSLContext_useSecureRenegotiation();
        test_WolfSSLContext_useSupportedCurves();
        test_WolfSSLContext_setGroups();
        test_WolfSSLContext_set1SigAlgsList();
        test_WolfSSLContext_setMinRSAKeySize();
        test_WolfSSLContext_setMinECCKeySize();
        test_WolfSSLContext_rsaCbHandshake();
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

        if (WolfSSL.FileSystemEnabled() == true) {
            test_ucf(ctx, bogusFile, WolfSSL.SSL_FILETYPE_PEM,
                     WolfSSL.SSL_FAILURE,
                     "useCertificateFile(ctx, bogusFile, SSL_FILETYPE_PEM)");

            test_ucf(ctx, cliCert, 9999, WolfSSL.SSL_FAILURE,
                     "useCertificateFile(ctx, cliCert, 9999)");

            test_ucf(ctx, cliCert, WolfSSL.SSL_FILETYPE_PEM,
                     WolfSSL.SSL_SUCCESS,
                     "useCertificateFile(ctx, cliCert, SSL_FILETYPE_PEM)");
        }

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

        if (WolfSSL.FileSystemEnabled() == true) {
            test_upkf(ctx, bogusFile, WolfSSL.SSL_FILETYPE_PEM,
                      WolfSSL.SSL_FAILURE,
                     "usePrivateKeyFile(ctx, bogusFile, SSL_FILETYPE_PEM)");

            test_upkf(ctx, cliKey, 9999, WolfSSL.SSL_FAILURE,
                     "usePrivateKeyFile(ctx, cliKey, 9999)");

            test_upkf(ctx, cliKey, WolfSSL.SSL_FILETYPE_PEM,
                     WolfSSL.SSL_SUCCESS,
                     "usePrivateKeyFile(ctx, cliKey, SSL_FILETYPE_PEM)");
        }

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

        if (WolfSSL.FileSystemEnabled() == true ) {
            test_lvl(ctx, null, null, WolfSSL.SSL_FAILURE,
                    "loadVerifyLocations(ctx, null, null)");

            test_lvl(null, caCert, null, WolfSSL.SSL_FAILURE,
                    "loadVerifyLocations(null, caCert, null)");

            test_lvl(ctx, caCert, null, WolfSSL.SSL_SUCCESS,
                    "loadVerifyLocations(ctx, caCert, 0)");
        }

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

    public void test_WolfSSLContext_useSecureRenegotiation() {
        System.out.print("\tuseSecureRenegotiation()");
        try {
            int ret = ctx.useSecureRenegotiation();
            if (ret != WolfSSL.SSL_SUCCESS &&
                ret != WolfSSL.NOT_COMPILED_IN) {
                System.out.println("\t... failed");
                fail("useSecureRenegotiation failed");
            }
        } catch (IllegalStateException e) {
            System.out.println("\t... failed");
            e.printStackTrace();
        }
        System.out.println("\t... passed");
    }

    public void test_WolfSSLContext_useSupportedCurves() {

        int ret;
        String[] singleEccSecp256r1 = new String[] { "secp256r1" };
        String[] allEccCurves =  new String[] {
            "secp160k1", "secp160r1", "secp160r2", "secp192k1", "secp192r1",
            "secp224k1", "secp224r1", "secp256k1", "secp256r1", "secp384r1",
            "secp521r1"
        };
        String[] x25519Curve = new String[] { "x25519" };
        String[] x448Curve = new String[] { "x448" };

        System.out.print("\tuseSupportedCurves()");
        try {
            ret = ctx.useSupportedCurves(singleEccSecp256r1);
            if (ret != WolfSSL.SSL_SUCCESS &&
                ret != WolfSSL.NOT_COMPILED_IN) {
                System.out.println("\t\t... failed");
                fail("useSupportedCurves(singleEccSecp256r1) failed");
            }
            ret = ctx.useSupportedCurves(allEccCurves);
            if (ret != WolfSSL.SSL_SUCCESS &&
                ret != WolfSSL.NOT_COMPILED_IN) {
                System.out.println("\t\t... failed");
                fail("useSupportedCurves(allEccCurves) failed");
            }
            if (WolfSSL.Curve25519Enabled()) {
                ret = ctx.useSupportedCurves(x25519Curve);
                if (ret != WolfSSL.SSL_SUCCESS &&
                    ret != WolfSSL.NOT_COMPILED_IN) {
                    System.out.println("\t\t... failed");
                    fail("useSupportedCurves(x25519Curve) failed");
                }
            }
            if (WolfSSL.Curve448Enabled()) {
                ret = ctx.useSupportedCurves(x448Curve);
                if (ret != WolfSSL.SSL_SUCCESS &&
                    ret != WolfSSL.NOT_COMPILED_IN) {
                    System.out.println("\t\t... failed");
                    fail("useSupportedCurves(x448Curve) failed");
                }
            }
            System.out.println("\t\t... passed");

        } catch (IllegalStateException e) {
            System.out.println("\t\t... failed");
            fail("useSupportedCurves failed");
            e.printStackTrace();
        }
    }

    public void test_WolfSSLContext_setGroups() {

        int ret;
        int[] singleItem = { WolfSSL.WOLFSSL_ECC_SECP256R1 };
        int[] twoItems = {
            WolfSSL.WOLFSSL_ECC_SECP256R1,
            WolfSSL.WOLFSSL_ECC_SECP256R1
        };
        int[] tooLong = new int[50];
        int[] badGroups = { 0xDEAD, 0xBEEF };

        System.out.print("\tsetGroups()");
        try {
            ret = ctx.setGroups(null);
            if (ret != WolfSSL.NOT_COMPILED_IN &&
                ret == WolfSSL.SSL_SUCCESS) {
                System.out.println("\t\t\t... failed");
                fail("setGroups() should fail with null arg");
            }
            if (WolfSSL.EccEnabled()) {
                ret = ctx.setGroups(singleItem);
                if (ret != WolfSSL.NOT_COMPILED_IN &&
                    ret != WolfSSL.SSL_SUCCESS) {
                    System.out.println("\t\t\t... failed");
                    fail("setGroups() failed with WOLFSSL_ECC_SECP256R1");
                }
                ret = ctx.setGroups(twoItems);
                if (ret != WolfSSL.NOT_COMPILED_IN &&
                    ret != WolfSSL.SSL_SUCCESS) {
                    System.out.println("\t\t\t... failed");
                    fail("setGroups() failed with two entries");
                }
            }
            ret = ctx.setGroups(tooLong);
            if (ret != WolfSSL.NOT_COMPILED_IN &&
                ret != WolfSSL.BAD_FUNC_ARG) {
                System.out.println("\t\t\t... failed");
                fail("setGroups() should fail with too long array");
            }
            ret = ctx.setGroups(badGroups);
            if (ret != WolfSSL.NOT_COMPILED_IN &&
                ret != WolfSSL.BAD_FUNC_ARG) {
                System.out.println("\t\t\t... failed");
                fail("setGroups() should fail with bad/invalid values");
            }

            System.out.println("\t\t\t... passed");

        } catch (IllegalStateException e) {
            System.out.println("\t\t\t... failed");
            e.printStackTrace();
            fail("setGroups() failed");
        }
    }

    public void test_WolfSSLContext_set1SigAlgsList() {

        int ret;

        System.out.print("\tset1SigAlgsList()");
        try {
            /* Expected failure, null list */
            ret = ctx.set1SigAlgsList(null);
            if (ret != WolfSSL.NOT_COMPILED_IN &&
                ret != WolfSSL.SSL_FAILURE) {
                System.out.println("\t\t... failed");
                fail("set1SigAlgsList() should fail with null list");
            }

            /* Expected failure, empty list */
            ret = ctx.set1SigAlgsList("");
            if (ret != WolfSSL.NOT_COMPILED_IN &&
                ret != WolfSSL.SSL_FAILURE) {
                System.out.println("\t\t... failed");
                fail("set1SigAlgsList() should fail with empty list");
            }

            if (WolfSSL.RsaEnabled()) {
                ret = ctx.set1SigAlgsList("RSA");
                if (ret != WolfSSL.NOT_COMPILED_IN &&
                    ret != WolfSSL.SSL_FAILURE) {
                    System.out.println("\t\t... failed");
                    fail("set1SigAlgsList() should fail without hash");
                }

                if (WolfSSL.Sha256Enabled()) {
                    ret = ctx.set1SigAlgsList("RSA+SHA256");
                    if (ret != WolfSSL.NOT_COMPILED_IN &&
                        ret != WolfSSL.SSL_SUCCESS) {
                        System.out.println("\t\t... failed");
                        fail("set1SigAlgsList() should pass with given list");
                    }

                    ret = ctx.set1SigAlgsList("RSA:RSA+SHA256");
                    if (ret != WolfSSL.NOT_COMPILED_IN &&
                        ret != WolfSSL.SSL_FAILURE) {
                        System.out.println("\t\t... failed");
                        fail("set1SigAlgsList() should fail without hash");
                    }

                    if (WolfSSL.Sha512Enabled()) {
                        ret = ctx.set1SigAlgsList("RSA+SHA256:RSA+SHA512");
                        if (ret != WolfSSL.NOT_COMPILED_IN &&
                            ret != WolfSSL.SSL_SUCCESS) {
                            System.out.println("\t\t... failed");
                            fail("set1SigAlgsList() should pass");
                        }
                    }
                }
            }

            if (WolfSSL.EccEnabled()) {
                ret = ctx.set1SigAlgsList("ECDSA");
                if (ret != WolfSSL.NOT_COMPILED_IN &&
                    ret != WolfSSL.SSL_FAILURE) {
                    System.out.println("\t\t... failed");
                    fail("set1SigAlgsList() should fail without hash");
                }

                if (WolfSSL.Sha256Enabled()) {
                    ret = ctx.set1SigAlgsList("ECDSA+SHA256");
                    if (ret != WolfSSL.NOT_COMPILED_IN &&
                        ret != WolfSSL.SSL_SUCCESS) {
                        System.out.println("\t\t... failed");
                        fail("set1SigAlgsList() should pass with given list");
                    }

                    ret = ctx.set1SigAlgsList("ECDSA:ECDSA+SHA256");
                    if (ret != WolfSSL.NOT_COMPILED_IN &&
                        ret != WolfSSL.SSL_FAILURE) {
                        System.out.println("\t\t... failed");
                        fail("set1SigAlgsList() should fail without hash");
                    }

                    if (WolfSSL.Sha512Enabled()) {
                        ret = ctx.set1SigAlgsList("ECDSA+SHA256:ECDSA+SHA512");
                        if (ret != WolfSSL.NOT_COMPILED_IN &&
                            ret != WolfSSL.SSL_SUCCESS) {
                            System.out.println("\t\t... failed");
                            fail("set1SigAlgsList() should pass");
                        }
                    }
                }
            }

            System.out.println("\t\t... passed");

        } catch (IllegalStateException e) {
            System.out.println("\t\t... failed");
            e.printStackTrace();
            fail("set1SigAlgsList() failed");
        }
    }

    public void test_WolfSSLContext_setMinRSAKeySize() {

        int ret = 0;

        System.out.print("\tsetMinKeyRSASize()");

        try {
            /* negative size key length should fail */
            ret = ctx.setMinRSAKeySize(-1);
            if (ret != WolfSSL.BAD_FUNC_ARG) {
                System.out.println("\t\t... failed");
                fail("setMinRSAKeySize should fail with negative key size");
            }

            /* key length not % 8 should fail */
            ret = ctx.setMinRSAKeySize(1023);
            if (ret != WolfSSL.BAD_FUNC_ARG) {
                System.out.println("\t\t... failed");
                fail("setMinRSAKeySize should fail with non % 8 size");
            }

            /* valid key length should succeed */
            ret = ctx.setMinRSAKeySize(1024);
            if (ret != WolfSSL.SSL_SUCCESS) {
                System.out.println("\t\t... failed");
                fail("setMinRSAKeySize did not pass as expected");
            }

            /* loading of key larger than set size should pass */
            ret = ctx.useCertificateFile(cliCert, WolfSSL.SSL_FILETYPE_PEM);
            if (ret != WolfSSL.SSL_SUCCESS) {
                System.out.println("\t\t... failed");
                fail("setMinRSAKeySize did not pass as expected (1024 limit)");
            }

            /* set min key size to something very large for next test. Below
             * we test ctx.useCertificateFile(), but that API will only fail
             * based on key size limitations when peer verification is
             * enabled, set SSL_VERIFY_PEER here. */
            ctx.setVerify(WolfSSL.SSL_VERIFY_PEER, null);
            ret = ctx.setMinRSAKeySize(8192);
            if (ret != WolfSSL.SSL_SUCCESS) {
                System.out.println("\t\t... failed");
                fail("setMinRSAKeySize did not pass as expected for 8192");
            }

            /* loading of key smaller than set size should fail */
            ret = ctx.useCertificateFile(cliCert, WolfSSL.SSL_FILETYPE_PEM);
            if (ret == WolfSSL.SSL_SUCCESS) {
                System.out.println("\t\t... failed");
                fail("setMinRSAKeySize did not fail as expected with limit");
            }

        } catch (IllegalStateException e) {
            System.out.println("\t\t... failed");
            e.printStackTrace();
        }

        System.out.println("\t\t... passed");
    }

    public void test_WolfSSLContext_setMinECCKeySize() {

        int ret = 0;

        System.out.print("\tsetMinECCKeySize()");

        try {
            /* negative size key length should fail */
            ret = ctx.setMinECCKeySize(-1);
            if (ret != WolfSSL.BAD_FUNC_ARG) {
                System.out.println("\t\t... failed");
                fail("setMinECCKeySize should fail with negative key size");
            }

            /* valid key length should succeed */
            ret = ctx.setMinECCKeySize(128);
            if (ret != WolfSSL.SSL_SUCCESS) {
                System.out.println("\t\t... failed");
                fail("setMinECCKeySize did not pass as expected");
            }

            /* loading of key larger than set size should pass */
            ret = ctx.useCertificateFile(svrCertEcc, WolfSSL.SSL_FILETYPE_PEM);
            if (ret != WolfSSL.SSL_SUCCESS) {
                System.out.println("\t\t... failed");
                fail("setMinECCKeySize did not pass as expected (128 limit)");
            }

            /* set min key size to something very large for next test */
            ret = ctx.setMinECCKeySize(512);
            if (ret != WolfSSL.SSL_SUCCESS) {
                System.out.println("\t\t... failed");
                fail("setMinECCKeySize did not pass as expected for 521");
            }

            /* loading of key smaller than set size should fail */
            ret = ctx.useCertificateFile(svrCertEcc, WolfSSL.SSL_FILETYPE_PEM);
            if (ret == WolfSSL.SSL_SUCCESS) {
                System.out.println("\t\t... failed");
                fail("setMinECCKeySize did not fail as expected with limit");
            }

        } catch (IllegalStateException e) {
            System.out.println("\t\t... failed");
            e.printStackTrace();
        }

        System.out.println("\t\t... passed");
    }

    public void test_WolfSSLContext_setMinDHKeySize() {

        int ret = 0;

        System.out.print("\tsetMinDHKeySize()");

        try {
            /* key length > 16000 fail */
            ret = ctx.setMinDHKeySize(17000);
            if (ret != WolfSSL.BAD_FUNC_ARG) {
                System.out.println("\t\t... failed");
                fail("setMinDHKeySize should fail with key size too large");
            }

            /* key length not % 8 should fail */
            ret = ctx.setMinECCKeySize(1023);
            if (ret != WolfSSL.BAD_FUNC_ARG) {
                System.out.println("\t\t... failed");
                fail("setMinDHKeySize should fail with non % 8 size");
            }

            /* valid key length should succeed */
            ret = ctx.setMinDHKeySize(1024);
            if (ret != WolfSSL.SSL_SUCCESS) {
                System.out.println("\t\t... failed");
                fail("setMinDHKeySize did not pass as expected");
            }

            /* loading params larger than min size should pass */
            ret = ctx.setTmpDHFile(dhParams, WolfSSL.SSL_FILETYPE_PEM);
            if (ret != WolfSSL.SSL_SUCCESS) {
                System.out.println("\t\t... failed");
                fail("setMinDHKeySize did not pass as expected (1024 limit)");
            }

            /* set min key size to something very large for next test */
            ret = ctx.setMinECCKeySize(8192);
            if (ret != WolfSSL.SSL_SUCCESS) {
                System.out.println("\t\t... failed");
                fail("setMinDHKeySize did not pass as expected for 8192");
            }

            /* loading of key smaller than set size should fail */
            ret = ctx.setTmpDHFile(dhParams, WolfSSL.SSL_FILETYPE_PEM);
            if (ret == WolfSSL.SSL_SUCCESS) {
                System.out.println("\t\t... failed");
                fail("setMinDHKeySize did not fail as expected with limit");
            }

        } catch (IllegalStateException | WolfSSLJNIException e) {
            System.out.println("\t\t... failed");
            e.printStackTrace();
        }

        System.out.println("\t\t... passed");
    }

    /* Context object shared between RSA sign/verify callbacks, tracks whether
     * callback was invoked during handshake */
    class TestRsaCbCtx
    {
        public boolean called = false;
    }

    class TestRsaSignCb implements WolfSSLRsaSignCallback
    {
        public int rsaSignCallback(WolfSSLSession ssl, ByteBuffer in, long inSz,
            ByteBuffer out, int[] outSz, ByteBuffer keyDer, long keySz,
            Object ctx) {

            TestRsaCbCtx myCtx = (TestRsaCbCtx)ctx;
            myCtx.called = true;

            WolfCryptRSA rsa = new WolfCryptRSA();
            return rsa.doSign(in, inSz, out, outSz, keyDer, keySz);
        }
    }

    class TestRsaVerifyCb implements WolfSSLRsaVerifyCallback
    {
        public int rsaVerifyCallback(WolfSSLSession ssl, ByteBuffer sig,
            long sigSz, ByteBuffer out, long outSz, ByteBuffer keyDer,
            long keySz, Object ctx) {

            TestRsaCbCtx myCtx = (TestRsaCbCtx)ctx;
            myCtx.called = true;

            WolfCryptRSA rsa = new WolfCryptRSA();
            return rsa.doVerify(sig, sigSz, out, outSz, keyDer, keySz);
        }
    }

    class TestRsaPssSignCb implements WolfSSLRsaPssSignCallback
    {
        public int rsaPssSignCallback(WolfSSLSession ssl, ByteBuffer in,
            long inSz, ByteBuffer out, int[] outSz, int hash, int mgf,
            ByteBuffer keyDer, long keySz, Object ctx) {

            TestRsaCbCtx myCtx = (TestRsaCbCtx)ctx;
            myCtx.called = true;

            WolfCryptRSA rsa = new WolfCryptRSA();
            return rsa.doPssSign(in, inSz, out, outSz, hash, mgf, keyDer,
                keySz);
        }
    }

    class TestRsaPssVerifyCb implements WolfSSLRsaPssVerifyCallback
    {
        public int rsaPssVerifyCallback(WolfSSLSession ssl, ByteBuffer sig,
            long sigSz, ByteBuffer out, long outSz, int hash, int mgf,
            ByteBuffer keyDer, long keySz, Object ctx) {

            TestRsaCbCtx myCtx = (TestRsaCbCtx)ctx;
            myCtx.called = true;

            WolfCryptRSA rsa = new WolfCryptRSA();
            return rsa.doPssVerify(sig, sigSz, out, outSz, hash, mgf, keyDer,
                keySz);
        }
    }

    /**
     * Helper to create and configure a WolfSSLContext with cert, key, and CA
     * for handshake tests.
     */
    private WolfSSLContext createCtx(String certPath, String keyPath,
        String caPath, long method) throws Exception {

        int ret;
        WolfSSLContext c = new WolfSSLContext(method);

        ret = c.useCertificateChainFile(certPath);
        if (ret != WolfSSL.SSL_SUCCESS) {
            c.free();
            throw new Exception("Failed to load cert: " + certPath);
        }

        ret = c.usePrivateKeyFile(keyPath, WolfSSL.SSL_FILETYPE_PEM);
        if (ret != WolfSSL.SSL_SUCCESS) {
            c.free();
            throw new Exception("Failed to load key: " + keyPath);
        }

        ret = c.loadVerifyLocations(caPath, null);
        if (ret != WolfSSL.SSL_SUCCESS) {
            c.free();
            throw new Exception("Failed to load CA: " + caPath);
        }

        return c;
    }

    public void test_WolfSSLContext_rsaCbHandshake() {

        System.out.print("\trsaCbHandshake()");

        if (!WolfSSL.RsaEnabled() || !WolfSSL.FileSystemEnabled()) {
            System.out.println("\t\t... skipped");
            return;
        }

        /* TLS 1.2 handshake with RSA PK callbacks */
        rsaCbHandshakeTls12();

        /* TLS 1.3 handshake with RSA-PSS PK callbacks */
        if (WolfSSL.TLSv13Enabled() && WolfSSL.RsaPssEnabled()) {
            rsaCbHandshakeTls13();
        }

        System.out.println("\t\t... passed");
    }

    private void rsaCbHandshakeTls12() {

        WolfSSLContext srvCtx = null;
        WolfSSLContext cliCtx = null;
        ServerSocket srvSocket = null;
        ExecutorService es = null;
        Socket cliSock = null;
        WolfSSLSession cliSes = null;

        try {
            srvCtx = createCtx(svrCert, svrKey, caCert,
                WolfSSL.TLSv1_2_ServerMethod());
            cliCtx = createCtx(cliCert, cliKey, caCert,
                WolfSSL.TLSv1_2_ClientMethod());

            /* Register server-side RSA sign + sign check */
            TestRsaSignCb signCb = new TestRsaSignCb();
            TestRsaVerifyCb signCheckCb = new TestRsaVerifyCb();
            srvCtx.setRsaSignCb(signCb);
            srvCtx.setRsaSignCheckCb(signCheckCb);

            /* Register client-side RSA verify */
            TestRsaVerifyCb verifyCb = new TestRsaVerifyCb();
            cliCtx.setRsaVerifyCb(verifyCb);

            /* Register RSA-PSS callbacks in case rsa_pss_sa_algo is used
             * as sig algo in TLS 1.2 */
            if (WolfSSL.RsaPssEnabled()) {
                TestRsaPssSignCb pssSignCb = new TestRsaPssSignCb();
                TestRsaPssVerifyCb pssSrvChk = new TestRsaPssVerifyCb();
                TestRsaPssVerifyCb pssCliChk = new TestRsaPssVerifyCb();
                srvCtx.setRsaPssSignCb(pssSignCb);
                srvCtx.setRsaPssSignCheckCb(pssSrvChk);
                cliCtx.setRsaPssSignCheckCb(pssCliChk);
            }

            /* Context objects to track invocation */
            final TestRsaCbCtx srvSignCtx = new TestRsaCbCtx();
            final TestRsaCbCtx srvVerifyCtx = new TestRsaCbCtx();
            final TestRsaCbCtx cliVerifyCtx = new TestRsaCbCtx();

            srvSocket = new ServerSocket(0);
            srvSocket.setSoTimeout(10000);
            final int port = srvSocket.getLocalPort();
            final ServerSocket fSrvSock = srvSocket;
            final WolfSSLContext fSrvCtx = srvCtx;

            final CountDownLatch ready = new CountDownLatch(1);

            es = Executors.newSingleThreadExecutor();
            Future<Void> srvFuture = es.submit(new Callable<Void>() {
                @Override
                public Void call() throws Exception {
                    int ret;
                    int err;
                    Socket srv = null;
                    WolfSSLSession srvSes = null;
                    try {
                        ready.countDown();
                        srv = fSrvSock.accept();
                        srvSes = new WolfSSLSession(fSrvCtx);
                        srvSes.setRsaSignCtx(srvSignCtx);
                        srvSes.setRsaVerifyCtx(srvVerifyCtx);
                        ret = srvSes.setFd(srv);
                        if (ret != WolfSSL.SSL_SUCCESS) {
                            throw new Exception("srv setFd fail: " + ret);
                        }
                        do {
                            ret = srvSes.accept();
                            err = srvSes.getError(ret);
                        } while (
                            ret != WolfSSL.SSL_SUCCESS &&
                            (err == WolfSSL.SSL_ERROR_WANT_READ ||
                             err == WolfSSL.SSL_ERROR_WANT_WRITE));
                        if (ret != WolfSSL.SSL_SUCCESS) {
                            throw new Exception("srv accept fail: " + ret);
                        }
                        srvSes.shutdownSSL();

                    } finally {
                        if (srvSes != null) {
                            srvSes.freeSSL();
                        }
                        if (srv != null) {
                            srv.close();
                        }
                        fSrvSock.close();
                    }
                    return null;
                }
            });

            if (!ready.await(2, TimeUnit.SECONDS)) {
                fail("Server did not become ready within timeout");
            }

            cliSock = new Socket("localhost", port);
            cliSes = new WolfSSLSession(cliCtx);
            cliSes.setRsaVerifyCtx(cliVerifyCtx);

            int ret = cliSes.setFd(cliSock);
            if (ret != WolfSSL.SSL_SUCCESS) {
                fail("cli setFd fail: " + ret);
            }

            int err;
            do {
                ret = cliSes.connect();
                err = cliSes.getError(ret);
            } while (ret != WolfSSL.SSL_SUCCESS &&
                (err == WolfSSL.SSL_ERROR_WANT_READ ||
                 err == WolfSSL.SSL_ERROR_WANT_WRITE));
            if (ret != WolfSSL.SSL_SUCCESS) {
                fail("TLS 1.2 RSA CB connect fail: " + ret);
            }

            cliSes.shutdownSSL();
            cliSes.freeSSL();
            cliSock.close();

            /* Check server thread for errors */
            es.shutdown();
            srvFuture.get(5, TimeUnit.SECONDS);

            /* Verify callbacks were invoked */
            assertTrue("RSA sign cb not called", srvSignCtx.called);
            assertTrue("RSA sign check cb not called", srvVerifyCtx.called);
            if (!WolfSSL.RsaPssEnabled()) {
                assertTrue("RSA verify (cli) cb not called",
                    cliVerifyCtx.called);
            }

        } catch (WolfSSLJNIException e) {
            /* PK callbacks may not be compiled in */
            if (e.getMessage() != null &&
                e.getMessage().contains("PK Callback")) {
                return;
            }
            System.out.println("\t\t... failed");
            fail("TLS 1.2 RSA CB handshake: " + e.getMessage());

        } catch (ExecutionException e) {
            System.out.println("\t\t... failed");
            fail("TLS 1.2 RSA CB server: " + e.getCause().getMessage());

        } catch (Exception e) {
            System.out.println("\t\t... failed");
            fail("TLS 1.2 RSA CB handshake: " + e.getMessage());

        } finally {
            if (cliSes != null) {
                try { cliSes.freeSSL(); }
                catch (Exception e) { /* ignore */ }
            }
            if (cliSock != null) {
                try { cliSock.close(); }
                catch (IOException e) { /* ignore */ }
            }
            if (srvSocket != null && !srvSocket.isClosed()) {
                try { srvSocket.close(); }
                catch (IOException e) { /* ignore */ }
            }
            if (cliCtx != null) cliCtx.free();
            if (srvCtx != null) srvCtx.free();
            if (es != null) {
                es.shutdownNow();
            }
        }
    }

    private void rsaCbHandshakeTls13() {

        WolfSSLContext srvCtx = null;
        WolfSSLContext cliCtx = null;
        ServerSocket srvSocket = null;
        ExecutorService es = null;
        Socket cliSock = null;
        WolfSSLSession cliSes = null;

        try {
            srvCtx = createCtx(svrCert, svrKey, caCert,
                WolfSSL.TLSv1_3_ServerMethod());
            cliCtx = createCtx(cliCert, cliKey, caCert,
                WolfSSL.TLSv1_3_ClientMethod());

            /* Server: RSA-PSS sign + sign check */
            TestRsaPssSignCb pssSignCb = new TestRsaPssSignCb();
            TestRsaPssVerifyCb pssSrvChkCb = new TestRsaPssVerifyCb();
            srvCtx.setRsaPssSignCb(pssSignCb);
            srvCtx.setRsaPssSignCheckCb(pssSrvChkCb);

            /* Context objects to track invocation */
            final TestRsaCbCtx srvSignCtx = new TestRsaCbCtx();
            final TestRsaCbCtx srvVerifyCtx = new TestRsaCbCtx();

            srvSocket = new ServerSocket(0);
            srvSocket.setSoTimeout(10000);
            final int port = srvSocket.getLocalPort();
            final ServerSocket fSrvSock = srvSocket;
            final WolfSSLContext fSrvCtx = srvCtx;

            final CountDownLatch ready = new CountDownLatch(1);

            es = Executors.newSingleThreadExecutor();
            Future<Void> srvFuture = es.submit(new Callable<Void>() {
                @Override
                public Void call() throws Exception {
                    int ret;
                    int err;
                    Socket srv = null;
                    WolfSSLSession srvSes = null;
                    try {
                        ready.countDown();
                        srv = fSrvSock.accept();
                        srvSes = new WolfSSLSession(fSrvCtx);
                        srvSes.setRsaSignCtx(srvSignCtx);
                        srvSes.setRsaVerifyCtx(srvVerifyCtx);
                        ret = srvSes.setFd(srv);
                        if (ret != WolfSSL.SSL_SUCCESS) {
                            throw new Exception("srv setFd fail: " + ret);
                        }
                        do {
                            ret = srvSes.accept();
                            err = srvSes.getError(ret);
                        } while (ret != WolfSSL.SSL_SUCCESS &&
                            (err == WolfSSL.SSL_ERROR_WANT_READ ||
                             err == WolfSSL.SSL_ERROR_WANT_WRITE));
                        if (ret != WolfSSL.SSL_SUCCESS) {
                            throw new Exception("srv accept fail: " + ret);
                        }
                        srvSes.shutdownSSL();

                    } finally {
                        if (srvSes != null) {
                            srvSes.freeSSL();
                        }
                        if (srv != null) {
                            srv.close();
                        }
                        fSrvSock.close();
                    }
                    return null;
                }
            });

            if (!ready.await(2, TimeUnit.SECONDS)) {
                fail("Server did not become ready within timeout");
            }

            cliSock = new Socket("localhost", port);
            cliSes = new WolfSSLSession(cliCtx);

            int ret = cliSes.setFd(cliSock);
            if (ret != WolfSSL.SSL_SUCCESS) {
                fail("cli setFd fail: " + ret);
            }

            int err;
            do {
                ret = cliSes.connect();
                err = cliSes.getError(ret);
            } while (ret != WolfSSL.SSL_SUCCESS &&
                (err == WolfSSL.SSL_ERROR_WANT_READ ||
                 err == WolfSSL.SSL_ERROR_WANT_WRITE));
            if (ret != WolfSSL.SSL_SUCCESS) {
                fail("TLS 1.3 PSS CB connect fail: " + ret);
            }

            cliSes.shutdownSSL();
            cliSes.freeSSL();
            cliSock.close();

            /* Check server thread for errors */
            es.shutdown();
            srvFuture.get(5, TimeUnit.SECONDS);

            /* Verify server-side callbacks were invoked. Client-side PSS peer
             * verify uses internal wolfSSL code (no setRsaPssVerifyCb in
             * JNI yet). */
            assertTrue("PSS sign cb not called", srvSignCtx.called);
            assertTrue("PSS sign check cb not called", srvVerifyCtx.called);

        } catch (WolfSSLJNIException e) {
            /* PK callbacks may not be compiled in */
            if (e.getMessage() != null &&
                e.getMessage().contains("PK Callback")) {
                return;
            }
            System.out.println("\t\t... failed");
            fail("TLS 1.3 PSS CB handshake: " + e.getMessage());

        } catch (ExecutionException e) {
            System.out.println("\t\t... failed");
            fail("TLS 1.3 PSS CB server: " + e.getCause().getMessage());

        } catch (Exception e) {
            System.out.println("\t\t... failed");
            fail("TLS 1.3 PSS CB handshake: " + e.getMessage());

        } finally {
            if (cliSes != null) {
                try { cliSes.freeSSL(); }
                catch (Exception e) { /* ignore */ }
            }
            if (cliSock != null) {
                try { cliSock.close(); }
                catch (IOException e) { /* ignore */ }
            }
            if (srvSocket != null && !srvSocket.isClosed()) {
                try { srvSocket.close(); }
                catch (IOException e) { /* ignore */ }
            }
            if (cliCtx != null) cliCtx.free();
            if (srvCtx != null) srvCtx.free();
            if (es != null) {
                es.shutdownNow();
            }
        }
    }

    public void test_WolfSSLContext_free() {

        System.out.print("\tfree()");
        ctx.free();
        System.out.println("\t\t\t\t... passed");
    }
}

