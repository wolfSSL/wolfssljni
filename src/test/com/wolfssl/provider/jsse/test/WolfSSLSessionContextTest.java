/* WolfSSLServerSocketFactoryTest.java
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

package com.wolfssl.provider.jsse.test;

import org.junit.Test;
import org.junit.BeforeClass;
import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.Enumeration;
import java.io.IOException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import java.security.Security;
import java.security.Provider;
import java.security.KeyStoreException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import com.wolfssl.WolfSSLException;
import com.wolfssl.provider.jsse.WolfSSLProvider;


public class WolfSSLSessionContextTest {
    public final static char[] jksPass = "wolfSSL test".toCharArray();
    public final static String engineProvider = "wolfJSSE";
    private static WolfSSLTestFactory tf;

    private SSLContext ctx = null;

    @BeforeClass
    public static void testProviderInstallationAtRuntime()
        throws NoSuchProviderException, WolfSSLException {

        System.out.println("WolfSSLSessionContext Class");

        /* install wolfJSSE provider at runtime */
        Security.insertProviderAt(new WolfSSLProvider(), 1);

        Provider p = Security.getProvider("wolfJSSE");
        assertNotNull(p);

        tf = new WolfSSLTestFactory();
    }

    @Test
    public void testGetSessionTimeout()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               KeyManagementException, KeyStoreException, CertificateException,
               IOException, UnrecoverableKeyException {

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
            e1.printStackTrace();
            error("\t\t... failed");
            fail("session close failed");
        }

        pass("\t... passed");
    }


    @Test
    public void testSetSessionTimeout()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               KeyManagementException, KeyStoreException, CertificateException,
               IOException, UnrecoverableKeyException {

        SSLEngine server;
        SSLEngine client;
        int ret;
        SSLSessionContext sesCtx;
        SSLSession ses;

        /* create new SSLEngine */
        System.out.print("\tTesting setSessionTimeout");

        this.ctx = tf.createSSLContext("TLS", engineProvider);
        server = this.ctx.createSSLEngine();
        client =
            this.ctx.createSSLEngine("wolfSSL begin handshake test", 11111);

        server.setUseClientMode(false);
        server.setNeedClientAuth(false);
        client.setUseClientMode(true);

        /* get a copy of session before connection */
        ses = server.getSession();
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

        ret = tf.testConnection(server, client, null, null,
            "Test in/out bound");
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
            Thread.currentThread().interrupt();
            fail("interrupted while waiting to test session timeout");
        }
        ses = server.getSession();
        sesCtx = ses.getSessionContext();
        sesCtx.setSessionTimeout(1);

        /* client timeout should still be default */
        if (client.getSession().getSessionContext()
                .getSessionTimeout() != 86400) {
            error("\t... failed");
            fail("client session timout should still be default value");
        }

        try {
            tf.CloseConnection(server, client, false);
        } catch (SSLException e1) {
            e1.printStackTrace();
            error("\t... failed");
            fail("session close failed");
        }

        pass("\t... passed");
    }

    private void testSetCacheSize(SSLSession ses) {
        System.out.print("\tTesting SettingCache");
        /* these are wolfJSSE default values,
         * make sure wolfJSSE is the provider */
        if (ctx.getProvider() == Security.getProvider("wolfJSSE")) {
            SSLSessionContext sesCtx = ses.getSessionContext();

            if (sesCtx.getSessionCacheSize() != 33) {
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

    private void testResizeCache(SSLSession ses) {
        System.out.print("\tTesting ResizeCache");

        if (ctx.getProvider() != Security.getProvider("wolfJSSE")) {
            pass("\t\t... skipped");
            return;
        }

        SSLSessionContext sesCtx = ses.getSessionContext();
        if (sesCtx == null) {
            error("\t\t... failed");
            fail("session context was null");
        }

        int originalSize = sesCtx.getSessionCacheSize();

        /* get session IDs and count before resize */
        Enumeration<byte[]> idsBefore = sesCtx.getIds();
        int countBefore = 0;
        byte[] firstId = null;
        while (idsBefore.hasMoreElements()) {
            byte[] id = idsBefore.nextElement();
            if (firstId == null) {
                firstId = id;
            }
            countBefore++;
        }

        if (countBefore == 0 || firstId == null) {
            error("\t\t... failed");
            fail("no sessions in cache before resize");
        }

        /* resize up, all sessions should survive */
        sesCtx.setSessionCacheSize(countBefore + 10);

        Enumeration<byte[]> idsAfter = sesCtx.getIds();
        int countAfter = 0;
        boolean found = false;
        while (idsAfter.hasMoreElements()) {
            byte[] id = idsAfter.nextElement();
            if (Arrays.equals(id, firstId)) {
                found = true;
            }
            countAfter++;
        }

        if (countAfter != countBefore) {
            error("\t\t... failed");
            fail("resize-up lost sessions: before=" +
                countBefore + " after=" + countAfter);
        }

        if (!found) {
            error("\t\t... failed");
            fail("original session ID not found after resize");
        }

        /* restore original cache size */
        sesCtx.setSessionCacheSize(originalSize);

        pass("\t\t... passed");
    }

    @Test
    public void testSessionIDsTLS13()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               KeyManagementException, KeyStoreException, CertificateException,
               IOException, UnrecoverableKeyException {

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

        /* wolfjsse.clientSessionCache.disabled could be set in users
         * java.security file which would cause this test to not work
         * properly. Save their setting here, and re-enable session
         * cache for this test */
        String originalProp = Security.getProperty(
            "wolfjsse.clientSessionCache.disabled");
        Security.setProperty("wolfjsse.clientSessionCache.disabled", "false");

        try {
            this.ctx = tf.createSSLContext("TLS", engineProvider);
            server = this.ctx.createSSLEngine();
            client = this.ctx.createSSLEngine(
                "wolfSSL begin handshake test", 11111);

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

            ret = tf.testConnection(
                server, client, null, null, "Test in/out bound");
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
                e1.printStackTrace();
                error("\t... failed");
                fail("session close failed");
            }
            pass("\t... passed");

        } finally {
            restoreClientSessionCacheProperty(originalProp);
        }
    }

    @Test
    public void testSessionIDs()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               KeyManagementException, KeyStoreException, CertificateException,
               IOException, UnrecoverableKeyException {

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

        /* wolfjsse.clientSessionCache.disabled could be set in users
         * java.security file which would cause this test to not work
         * properly. Save their setting here, and re-enable session
         * cache for this test */
        String originalProp = Security.getProperty(
            "wolfjsse.clientSessionCache.disabled");
        Security.setProperty("wolfjsse.clientSessionCache.disabled", "false");

        try {
            this.ctx = tf.createSSLContext("TLS", engineProvider);
            server = this.ctx.createSSLEngine();
            client = this.ctx.createSSLEngine(
                "wolfSSL begin handshake test", 11111);

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

            ret = tf.testConnection(
                server, client, null, null, "Test in/out bound");
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
            testResizeCache(ses);


            try {
                tf.CloseConnection(server, client, false);
            } catch (SSLException e1) {
                e1.printStackTrace();
                error("\t\t... failed");
                fail("session close failed");
            }

        } finally {
            restoreClientSessionCacheProperty(originalProp);
        }
    }

    @Test
    public void testSessionTimeoutBoundaryExpiry()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               KeyManagementException, KeyStoreException, CertificateException,
               IOException, UnrecoverableKeyException {

        SSLEngine server;
        SSLEngine client;
        int ret;
        SSLSession ses;
        SSLSessionContext sesCtx;

        /* Regression: session must expire at exactly the
         * timeout boundary (diff >= timeout, not diff > timeout) */
        System.out.print("\tSession timeout boundary");

        String originalProp = Security.getProperty(
            "wolfjsse.clientSessionCache.disabled");
        Security.setProperty("wolfjsse.clientSessionCache.disabled", "false");

        try {
            this.ctx = tf.createSSLContext("TLS", engineProvider);
            server = this.ctx.createSSLEngine();
            client = this.ctx.createSSLEngine("wolfSSL timeout test", 11111);

            server.setUseClientMode(false);
            server.setNeedClientAuth(false);
            client.setUseClientMode(true);

            try {
                server.beginHandshake();
                client.beginHandshake();
            } catch (SSLException e) {
                error("\t... failed");
                fail("failed to begin handshake");
            }

            ret = tf.testConnection(server, client, null, null,
                "timeout boundary test");
            if (ret != 0) {
                error("\t... failed");
                fail("failed to create connection");
            }

            ses = server.getSession();
            if (ses == null || !ses.isValid()) {
                error("\t... failed");
                fail("session should be valid after handshake");
            }

            /* Set timeout to 1 second */
            sesCtx = ses.getSessionContext();
            sesCtx.setSessionTimeout(1);

            /* Sleep just over 1 second to ensure we cross the
             * timeout boundary */
            try {
                Thread.sleep(1200);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                fail("interrupted while waiting for session timeout boundary");
            }

            /* Session should be expired; getIds() triggers
             * updateTimeouts() which invalidates it */
            byte[] sessionId = ses.getId();

            /* getIds() triggers timeout evaluation and filters
             * expired sessions */
            boolean found = false;
            Enumeration<byte[]> ids = sesCtx.getIds();
            while (ids.hasMoreElements()) {
                byte[] id = ids.nextElement();
                if (Arrays.equals(id, sessionId)) {
                    found = true;
                    break;
                }
            }
            if (found) {
                error("\t... failed");
                fail("expired session should not appear in getIds()");
            }

            /* After updateTimeouts ran via getIds(), session should
             * also report as invalid */
            if (ses.isValid()) {
                error("\t... failed");
                fail("session should be invalid after timeout");
            }

            try {
                tf.CloseConnection(server, client, false);
            } catch (SSLException e1) {
                e1.printStackTrace();
                error("\t... failed");
                fail("session close failed");
            }

            pass("\t... passed");

        } finally {
            restoreClientSessionCacheProperty(originalProp);
        }
    }

    @Test
    public void testSessionInvalidationFilteredFromGetIds()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               KeyManagementException, KeyStoreException, CertificateException,
               IOException, UnrecoverableKeyException {

        SSLEngine server;
        SSLEngine client;
        int ret;
        SSLSession ses;
        SSLSessionContext sesCtx;

        /* Regression: invalidated sessions must be filtered
         * from getIds() and getSession(). */
        System.out.print("\tInvalidation filtered getIds");

        String originalProp = Security.getProperty(
            "wolfjsse.clientSessionCache.disabled");
        Security.setProperty("wolfjsse.clientSessionCache.disabled", "false");

        try {
            this.ctx = tf.createSSLContext("TLS", engineProvider);
            server = this.ctx.createSSLEngine();
            client = this.ctx.createSSLEngine(
                "wolfSSL invalidation test", 11111);

            server.setUseClientMode(false);
            server.setNeedClientAuth(false);
            client.setUseClientMode(true);

            try {
                server.beginHandshake();
                client.beginHandshake();
            } catch (SSLException e) {
                error("\t... failed");
                fail("failed to begin handshake");
            }

            ret = tf.testConnection(server, client, null, null,
                "invalidation test");
            if (ret != 0) {
                error("\t... failed");
                fail("failed to create connection");
            }

            ses = server.getSession();
            if (ses == null || !ses.isValid()) {
                error("\t... failed");
                fail("session should be valid after handshake");
            }

            byte[] sessionId = ses.getId();
            sesCtx = ses.getSessionContext();

            /* Verify session is in getIds() before invalidation */
            boolean foundBefore = false;
            Enumeration<byte[]> ids = sesCtx.getIds();
            while (ids.hasMoreElements()) {
                byte[] id = ids.nextElement();
                if (Arrays.equals(id, sessionId)) {
                    foundBefore = true;
                    break;
                }
            }
            if (!foundBefore) {
                error("\t... failed");
                fail("session should be in getIds() before invalidation");
            }

            /* Invalidate the session */
            ses.invalidate();

            if (ses.isValid()) {
                error("\t... failed");
                fail("session should not be valid after invalidation");
            }

            /* Verify invalidated session is NOT in getIds() */
            boolean foundAfter = false;
            ids = sesCtx.getIds();
            while (ids.hasMoreElements()) {
                byte[] id = ids.nextElement();
                if (Arrays.equals(id, sessionId)) {
                    foundAfter = true;
                    break;
                }
            }
            if (foundAfter) {
                error("\t... failed");
                fail("invalidated session should not appear in getIds()");
            }

            /* Verify getSession() does not return the
             * invalidated session */
            SSLSession retrieved = sesCtx.getSession(sessionId);
            if (retrieved != null && retrieved.isValid()) {
                error("\t... failed");
                fail("getSession() should not return valid " +
                     "invalidated session");
            }

            try {
                tf.CloseConnection(server, client, false);
            } catch (SSLException e1) {
                e1.printStackTrace();
                error("\t... failed");
                fail("session close failed");
            }

            pass("\t... passed");

        } finally {
            restoreClientSessionCacheProperty(originalProp);
        }
    }

    private void restoreClientSessionCacheProperty(String originalProp) {
        if (originalProp != null && !originalProp.isEmpty()) {
            Security.setProperty("wolfjsse.clientSessionCache.disabled",
                originalProp);
        } else {
            /* Security does not expose a clear API.
             * Empty restores the same runtime behavior as unset for
             * WolfSSLUtil.sessionCacheDisabled(). */
            Security.setProperty("wolfjsse.clientSessionCache.disabled", "");
        }
    }

    private void pass(String msg) {
        WolfSSLTestFactory.pass(msg);
    }

    private void error(String msg) {
        WolfSSLTestFactory.fail(msg);
    }

}
