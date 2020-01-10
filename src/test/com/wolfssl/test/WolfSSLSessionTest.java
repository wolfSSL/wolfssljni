/* WolfSSLSessionTest.java
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

import java.net.Socket;
import java.net.UnknownHostException;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLContext;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLJNIException;
import com.wolfssl.WolfSSLPskClientCallback;
import com.wolfssl.WolfSSLPskServerCallback;
import com.wolfssl.WolfSSLSession;

public class WolfSSLSessionTest {

    public final static int TEST_FAIL    = -1;
    public final static int TEST_SUCCESS =  0;

    public static String cliCert = "./examples/certs/client-cert.pem";
    public static String cliKey  = "./examples/certs/client-key.pem";
    public static String caCert  = "./examples/certs/ca-cert.pem";
    public static String bogusFile = "/dev/null";

    public final static String exampleHost = "www.example.com";
    public final static int examplePort = 443;

    WolfSSLContext ctx;
    WolfSSLSession ssl;

    @Test
    public void testWolfSSLSession() throws WolfSSLException {

        ctx = new WolfSSLContext(WolfSSL.SSLv23_ClientMethod());

        System.out.println("WolfSSLSession Class");

        cliCert = WolfSSLTestCommon.getPath(cliCert);
        cliKey = WolfSSLTestCommon.getPath(cliKey);
        caCert = WolfSSLTestCommon.getPath(caCert);
        
        test_WolfSSLSession_new();
        test_WolfSSLSession_useCertificateFile();
        test_WolfSSLSession_usePrivateKeyFile();
        test_WolfSSLSession_useCertificateChainFile();
        test_WolfSSLSession_setPskClientCb();
        test_WolfSSLSession_setPskServerCb();
        test_WolfSSLSession_usePskIdentityHint();
        test_WolfSSLSession_getPskIdentityHint();
        test_WolfSSLSession_getPskIdentity();
        test_WolfSSLSession_timeout();
        test_WolfSSLSession_status();
        test_WolfSSLSession_freeSSL();
        test_WolfSSLSession_UseAfterFree();
    }

    public void test_WolfSSLSession_new() {

        try {
            System.out.print("\tWolfSSLSession()");
            ssl = new WolfSSLSession(ctx);
        } catch (WolfSSLException we) {
            System.out.println("\t... failed");
            fail("failed to create WolfSSLSession object");
        }

        System.out.println("\t\t... passed");
    }

    public void test_WolfSSLSession_useCertificateFile() {

        System.out.print("\tuseCertificateFile()");

        test_ucf("useCertificateFile", null, null, 9999, WolfSSL.SSL_FAILURE,
                 "useCertificateFile(null, null, 9999)");

        test_ucf("useCertificateFile", ssl, bogusFile,
                 WolfSSL.SSL_FILETYPE_PEM, WolfSSL.SSL_FAILURE,
                 "useCertificateFile(ssl, bogusFile, SSL_FILETYPE_PEM)");

        test_ucf("useCertificateFile", ssl, cliCert, 9999,
                 WolfSSL.SSL_FAILURE,
                 "useCertificateFile(ssl, cliCert, 9999)");

        test_ucf("useCertificateFile", ssl, cliCert,
                 WolfSSL.SSL_FILETYPE_PEM,
                 WolfSSL.SSL_SUCCESS,
                 "useCertificateFile(ssl, cliCert, SSL_FILETYPE_PEM)");

        System.out.println("\t\t... passed");
    }

    public void test_WolfSSLSession_useCertificateChainFile() {

        System.out.print("\tuseCertificateChainFile()");

        test_ucf("useCertificateChainFile", null, null, 0,
                 WolfSSL.SSL_FAILURE,
                 "useCertificateChainFile(null, null)");

        test_ucf("useCertificateChainFile", ssl, bogusFile, 0,
                 WolfSSL.SSL_FAILURE,
                 "useCertificateChainFile(ssl, bogusFile)");

        test_ucf("useCertificateChainFile", ssl, cliCert, 0,
                 WolfSSL.SSL_SUCCESS,
                 "useCertificateChainFile(ssl, cliCert)");

        System.out.println("\t... passed");
    }

    /* helper for testing WolfSSLSession.useCertificateFile() */
    public void test_ucf(String func, WolfSSLSession ssl, String filePath,
            int type, int cond, String name) {

        int result = WolfSSL.SSL_FAILURE;

        try {

            if (func.equals("useCertificateFile")) {
                result = ssl.useCertificateFile(filePath, type);
            } else if (func.equals("useCertificateChainFile")) {
                result = ssl.useCertificateChainFile(filePath);
            } else {
                fail(name + " failed");
            }

            if ((result != cond) && (result != WolfSSL.NOT_COMPILED_IN))
            {
                if (func.equals("useCertificateFile")) {
                    System.out.println("\t\t... failed");
                } else {
                    System.out.println("\t... failed");
                }
                fail(name + " failed");
            }

        } catch (NullPointerException e) {

            /* correctly handle NULL pointer */
            if (ssl == null) {
                return;
            }
        }

        return;
    }

    public void test_WolfSSLSession_usePrivateKeyFile() {

        System.out.print("\tusePrivateKeyFile()");

        test_upkf(null, null, 9999, WolfSSL.SSL_FAILURE,
                 "usePrivateKeyFile(null, null, 9999)");

        test_upkf(ssl, bogusFile, WolfSSL.SSL_FILETYPE_PEM,
                  WolfSSL.SSL_FAILURE,
                 "usePrivateKeyFile(ssl, bogusFile, SSL_FILETYPE_PEM)");

        test_upkf(ssl, cliKey, 9999, WolfSSL.SSL_FAILURE,
                 "usePrivateKeyFile(ssl, cliKey, 9999)");

        test_upkf(ssl, cliKey, WolfSSL.SSL_FILETYPE_PEM, WolfSSL.SSL_SUCCESS,
                 "usePrivateKeyFile(ssl, cliKey, SSL_FILETYPE_PEM)");

        System.out.println("\t\t... passed");
    }

    /* helper for testing WolfSSLSession.usePrivateKeyFile() */
    public void test_upkf(WolfSSLSession ssl, String filePath, int type,
                        int cond, String name) {

        int result;

        try {

            result = ssl.usePrivateKeyFile(filePath, type);
            if ((result != cond) && (result != WolfSSL.NOT_COMPILED_IN))
            {
                System.out.println("\t\t... failed");
                fail(name + " failed");
            }

        } catch (NullPointerException e) {

            /* correctly handle NULL pointer */
            if (ssl == null) {
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

    public void test_WolfSSLSession_setPskClientCb() {
        System.out.print("\tsetPskClientCb()");
        try {
            TestPskClientCb pskClientCb = new TestPskClientCb();
            ssl.setPskClientCb(pskClientCb);
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

    public void test_WolfSSLSession_setPskServerCb() {
        System.out.print("\tsetPskServerCb()");
        try {
            TestPskServerCb pskServerCb = new TestPskServerCb();
            ssl.setPskServerCb(pskServerCb);
        } catch (Exception e) {
            if (!e.getMessage().equals("wolfSSL not compiled with PSK " +
                        "support")) {
                System.out.println("\t\t... failed");
                e.printStackTrace();
            }
        }
        System.out.println("\t\t... passed");
    }

    public void test_WolfSSLSession_usePskIdentityHint() {
        System.out.print("\tusePskIdentityHint()");
        try {
            int ret = ssl.usePskIdentityHint("wolfssl hint");
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

    public void test_WolfSSLSession_getPskIdentityHint() {
        System.out.print("\tgetPskIdentityHint()");
        try {
            String hint = ssl.getPskIdentityHint();
            if (hint != null && !hint.equals("wolfssl hint")) {
                System.out.println("\t\t... failed");
                fail("getPskIdentityHint failed");
            }
        } catch (IllegalStateException e) {
            System.out.println("\t\t... failed");
            e.printStackTrace();
        }
        System.out.println("\t\t... passed");
    }

    public void test_WolfSSLSession_getPskIdentity() {
        System.out.print("\tgetPskIdentity()");
        try {
            String identity = ssl.getPskIdentity();
        } catch (IllegalStateException e) {
            System.out.println("\t\t... failed");
            e.printStackTrace();
        }
        System.out.println("\t\t... passed");
    }
    
    public void test_WolfSSLSession_timeout() {

        System.out.print("\ttimeout()");
        ssl.setTimeout(5);
        if (ssl.getTimeout() != 5) {
            System.out.println("\t\t\t... failed");
        }
        System.out.println("\t\t\t... passed");
    }

    public void test_WolfSSLSession_status() {

        System.out.print("\tstatus()");
        if (ssl.handshakeDone() == true) {
            System.out.println("\t\t\t... failed");
        }
        System.out.println("\t\t\t... passed");
    }
    
    public void test_WolfSSLSession_freeSSL() {

        System.out.print("\tfreeSSL()");

        try {
            ssl.freeSSL();
        } catch (WolfSSLJNIException e) {
            System.out.println("\t\t\t... failed");
            e.printStackTrace();
        }
        System.out.println("\t\t\t... passed");
    }

    public void test_WolfSSLSession_UseAfterFree() {

        int ret;
        WolfSSL sslLib = null;
        WolfSSLContext sslCtx = null;
        WolfSSLSession ssl = null;
        Socket sock = null;

        System.out.print("\tTesting use after free");

        try {

            /* setup library, context, session, socket */
            sslLib = new WolfSSL();
            sslCtx = new WolfSSLContext(WolfSSL.TLSv1_2_ClientMethod());
            sslCtx.setVerify(WolfSSL.SSL_VERIFY_NONE, null);
            ssl = new WolfSSLSession(sslCtx);

            sock = new Socket(exampleHost, examplePort);
            ret = ssl.setFd(sock);
            if (ret != WolfSSL.SSL_SUCCESS) {
                ssl.freeSSL();
                sslCtx.free();
                fail("Failed to set file descriptor");
            }

            /* successful connection test */
            ret = ssl.connect();
            if (ret != WolfSSL.SSL_SUCCESS) {
                ssl.freeSSL();
                sslCtx.free();
                fail("Failed WolfSSL.connect() to " + exampleHost);
            }

            ssl.freeSSL();
            sslCtx.free();

        } catch (UnknownHostException e) {
            /* skip if no Internet connection */
            System.out.println("\t\t... skipped");
            return;

        } catch (Exception e) {
            System.out.println("\t\t... failed");
            e.printStackTrace();
            return;
        }

        try {
            /* this should fail, use after free */
            ret = ssl.connect();
        } catch (IllegalStateException ise) {
            System.out.println("\t\t... passed");
            return;
        }

        /* fail here means WolfSSLSession was used after free without
         * exception thrown */
        System.out.println("\t\t... failed");
        fail("WolfSSLSession was able to be used after freed");
    }
}

