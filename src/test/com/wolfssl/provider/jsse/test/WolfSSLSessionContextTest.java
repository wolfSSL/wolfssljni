/* WolfSSLServerSocketFactoryTest.java
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

package com.wolfssl.provider.jsse.test;

import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.Enumeration;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import java.security.Security;
import java.security.Provider;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;

import com.wolfssl.WolfSSLException;
import com.wolfssl.provider.jsse.WolfSSLProvider;


public class WolfSSLSessionContextTest {
    public final static char[] jksPass = "wolfSSL test".toCharArray();
    public final static String engineProvider = "wolfJSSE";
    private static WolfSSLTestFactory tf;

    private SSLContext ctx = null;

    @BeforeClass
    public static void testProviderInstallationAtRuntime()
        throws NoSuchProviderException {

        System.out.println("WolfSSLSessionContext Class");

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
    public void testGetSessionTimeout()
        throws NoSuchProviderException, NoSuchAlgorithmException {
        SSLEngine server;
        SSLEngine client;
        int ret;
        SSLSessionContext sesCtx;

        /* create new SSLEngine */
        System.out.print("\tTesting getSessionTimeout");

        this.ctx = tf.createSSLContext("TLS", engineProvider);
        if (this.ctx == null) {
            error("\t... failed");
            fail("unable to make a context");
        }

        server = this.ctx.createSSLEngine();
        if (server == null)     {
            error("\t... failed");
            fail("failed to create an engine");
        }

        server.setUseClientMode(false);
        server.setNeedClientAuth(false);
        sesCtx = server.getSession().getSessionContext();
        if (sesCtx != null)     {
            error("\t... failed");
            fail("session context should be null before connection is made");
        }

        client = this.ctx.createSSLEngine("wolfSSL begin handshake test", 11111);
        client.setUseClientMode(true);

        try {
            server.beginHandshake();
            client.beginHandshake();
        } catch (SSLException e) {
            error("\t... failed");
            fail("failed to begin handshake");
        }

        ret = tf.testConnection(server, client, null, null, "Test in/out bound");
        if (ret != 0) {
            error("\t... failed");
            fail("failed to create engine");
        }
        sesCtx = server.getSession().getSessionContext();
        if (sesCtx == null)     {
            error("\t... failed");
            fail("session context was null after connection");
        }

        /* default should be default of 86400 */
        if (sesCtx.getSessionTimeout() != 86400) {
            error("\t... failed");
            fail("failed to get session timeout");
        }

        try {
            tf.CloseConnection(server, client, false);
        } catch (SSLException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
            error("\t\t... failed");
            fail("session close failed");
        }

        pass("\t... passed");
    }


    @Test
    public void testSetSessionTimeout()
        throws NoSuchProviderException, NoSuchAlgorithmException {
        SSLEngine server;
        SSLEngine client;
        int ret;
        SSLSessionContext sesCtx;
        SSLSession ses;

        /* create new SSLEngine */
        System.out.print("\tTesting setSessionTimeout");

        this.ctx = tf.createSSLContext("TLS", engineProvider);
        server = this.ctx.createSSLEngine();
        client = this.ctx.createSSLEngine("wolfSSL begin handshake test", 11111);

        server.setUseClientMode(false);
        server.setNeedClientAuth(false);
        client.setUseClientMode(true);

        ses = server.getSession(); /* get a copy of session before connection */
        if (ses == null) {
            error("\t... failed");
            fail("failed get session from created engine");
        }

        try {
            server.beginHandshake();
            client.beginHandshake();
        } catch (SSLException e) {
            error("\t... failed");
            fail("failed to begin handshake");
        }

        ret = tf.testConnection(server, client, null, null, "Test in/out bound");
        if (ret != 0) {
            error("\t... failed");
            fail("failed to create engine");
        }

        /* check old session copy is not valid */
        if (ses.isValid() != false) {
            error("\t... failed");
            fail("old session not valid");
        }

        ses = server.getSession(); /* get a new copy of session */
        if (ses.isValid() == false) {
            error("\t... failed");
            fail("session not valid");
        }

        /* sleep for a second to then invalidate with set session */
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        ses = server.getSession();
        sesCtx = ses.getSessionContext();
        sesCtx.setSessionTimeout(1);

        /* client timeout should still be default */
        if (client.getSession().getSessionContext().getSessionTimeout() != 86400) {
            error("\t... failed");
            fail("client session timout should still be default value");
        }

        /* reading the API description I think this should be invalid but it is
         * not with SunJSSE
         * @TODO */
//        if (ses.isValid() != false) {
//            error("\t... failed");
//            fail("session valid when it should not be");
//        }

        try {
            tf.CloseConnection(server, client, false);
        } catch (SSLException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
            error("\t... failed");
            fail("session close failed");
        }

        pass("\t... passed");
    }

    private void testSetCacheSize(SSLSession ses) {
        System.out.print("\tTesting SettingCache");
        /* these are wolfJSSE default values, make sure wolfJSSE is the provider */
        if (ctx.getProvider() == Security.getProvider("wolfJSSE")) {
            SSLSessionContext sesCtx = ses.getSessionContext();

            if (sesCtx.getSessionCacheSize() != 10) {
                error("\t\t... failed");
                fail("session default cache size wrong");
            }

            sesCtx.setSessionCacheSize(1000);
            if (sesCtx.getSessionCacheSize() != 1000) {
                error("\t\t... failed");
                fail("session set cache size failed");
            }
        }
        pass("\t\t... passed");
    }

    @Test
    public void testSessionIDsTLS13()
        throws NoSuchProviderException, NoSuchAlgorithmException {
        SSLEngine server;
        SSLEngine client;
        int ret;
        SSLSession ses;
        String proto[] = {"TLSv1.3"};
        boolean found;
        byte id[];
        Enumeration<byte[]> allIds;

        /* create new SSLEngine */
        System.out.print("\tTesting SessionIDs with TLSv1.3");

        this.ctx = tf.createSSLContext("TLS", engineProvider);
        server = this.ctx.createSSLEngine();
        client = this.ctx.createSSLEngine("wolfSSL begin handshake test", 11111);

        server.setUseClientMode(false);
        server.setNeedClientAuth(false);
        client.setUseClientMode(true);

        try {
            String s[] = server.getEnabledProtocols();
            if (Arrays.asList(s).contains("TLSv1.3") == false) {
                pass("\t... skipped");
                return;
            }

            server.setEnabledProtocols(proto);
            client.setEnabledProtocols(proto);
        } catch (Exception e) {
            e.printStackTrace();
            error("\t... failed");
        }

        try {
            server.beginHandshake();
            client.beginHandshake();
        } catch (SSLException e) {
            error("\t... failed");
            fail("failed to begin handshake");
        }

        ret = tf.testConnection(server, client, null, null, "Test in/out bound");
        if (ret != 0) {
            error("\t... failed");
            fail("failed to create engine");
        }

        ses = server.getSession(); /* get a new copy of session */
        if (ses == null) {
            error("\t... failed");
            fail("unable to get session after handshake");
        }

        id = ses.getId();
        if (id == null) {
            error("\t... failed");
            fail("session had no id....");
        }
        found = false;

        allIds = ctx.getServerSessionContext().getIds();
        while (allIds.hasMoreElements()) {
            byte[] current = allIds.nextElement();
            if (Arrays.equals(current, id) == true) {
                /* found matching session ID */
                found = true;
            }
        }

        if (!found) {
            error("\t... failed");
            fail("did not find session id in global context list");
        }

        if (ses.isValid() == false) {
            error("\t... failed");
            fail("session not valid");
        }

        /* now test finding client session by ID */
        ses = client.getSession(); /* get a new copy of session */
        if (ses == null) {
            error("\t... failed");
            fail("unable to get session after handshake");
        }

        id = ses.getId();
        if (id == null) {
            error("\t... failed");
            fail("client session had no id....");
        }
        found = false;

        allIds = ctx.getClientSessionContext().getIds();
        while (allIds.hasMoreElements()) {
            byte[] current = allIds.nextElement();
            if (Arrays.equals(current, id) == true) {
                /* found matching session ID */
                found = true;
            }
        }

        if (!found) {
            error("\t... failed");
            fail("did not find client session id in global context list");
        }

        try {
            tf.CloseConnection(server, client, false);
        } catch (SSLException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
            error("\t... failed");
            fail("session close failed");
        }
        pass("\t... passed");
    }

    @Test
    public void testSessionIDs()
        throws NoSuchProviderException, NoSuchAlgorithmException {
        SSLEngine server;
        SSLEngine client;
        int ret;
        SSLSession ses;
        String proto[] = {"TLSv1.2"};
        boolean found;
        byte id[];
        Enumeration<byte[]> allIds;

        /* create new SSLEngine */
        System.out.print("\tTesting SessionIDs with TLSv1.2");

        this.ctx = tf.createSSLContext("TLS", engineProvider);
        server = this.ctx.createSSLEngine();
        client = this.ctx.createSSLEngine("wolfSSL begin handshake test", 11111);

        server.setUseClientMode(false);
        server.setNeedClientAuth(false);
        client.setUseClientMode(true);

        try {
            String s[] = server.getEnabledProtocols();
            if (Arrays.asList(s).contains("TLSv1.2") == false) {
                pass("\t... skipped");
                return;
            }

            server.setEnabledProtocols(proto);
            client.setEnabledProtocols(proto);
        } catch (Exception e) {
            e.printStackTrace();
            error("\t... failed");
        }

        try {
            server.beginHandshake();
            client.beginHandshake();
        } catch (SSLException e) {
            error("\t... failed");
            fail("failed to begin handshake");
        }

        ret = tf.testConnection(server, client, null, null, "Test in/out bound");
        if (ret != 0) {
            error("\t... failed");
            fail("failed to create engine");
        }

        ses = server.getSession(); /* get a new copy of session */
        if (ses == null) {
            error("\t... failed");
            fail("unable to get session after handshake");
        }

        id = ses.getId();
        if (id == null) {
            error("\t... failed");
            fail("session had no id....");
        }
        found = false;

        allIds = ctx.getServerSessionContext().getIds();
        while (allIds.hasMoreElements()) {
            byte[] current = allIds.nextElement();
            if (Arrays.equals(current, id) == true) {
                /* found matching session ID */
                found = true;
            }
        }

        if (!found) {
            error("\t... failed");
            fail("did not find session id in global context list");
        }

        if (ses.isValid() == false) {
            error("\t... failed");
            fail("session not valid");
        }

        /* now test finding client session by ID */
        ses = client.getSession(); /* get a new copy of session */
        if (ses == null) {
            error("\t... failed");
            fail("unable to get session after handshake");
        }

        id = ses.getId();
        if (id == null) {
            error("\t... failed");
            fail("client session had no id....");
        }
        found = false;

        allIds = ctx.getClientSessionContext().getIds();
        while (allIds.hasMoreElements()) {
            byte[] current = allIds.nextElement();
            if (Arrays.equals(current, id) == true) {
                /* found matching session ID */
                found = true;
            }
        }

        if (!found) {
            error("\t... failed");
            fail("did not find client session id in global context list");
        }

        pass("\t... passed");

        /* additional tests on the engines and sessions while open */
        testSetCacheSize(ses);


        try {
            tf.CloseConnection(server, client, false);
        } catch (SSLException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
            error("\t\t... failed");
            fail("session close failed");
        }
    }

    private void pass(String msg) {
        WolfSSLTestFactory.pass(msg);
    }

    private void error(String msg) {
        WolfSSLTestFactory.fail(msg);
    }

}
