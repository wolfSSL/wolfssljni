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

package com.wolfssl.provider.jsse.test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.security.cert.Certificate;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionBindingEvent;
import javax.net.ssl.SSLSessionBindingListener;
import javax.net.ssl.SSLSessionContext;

import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import com.wolfssl.WolfSSLContext;
import com.wolfssl.WolfSSLException;
import com.wolfssl.provider.jsse.WolfSSLProvider;

public class WolfSSLSessionTest {
    public final static char[] jksPass = "wolfSSL test".toCharArray();
    public final static String engineProvider = "wolfJSSE";
    private static WolfSSLTestFactory tf;

    @BeforeClass
    public static void testProviderInstallationAtRuntime()
        throws NoSuchProviderException {

        System.out.println("WolfSSLImplementSSLSession Class");

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
    public void testSessionTimeAndCerts() {
        int ret;
        SSLSession session;

        /* create new SSLEngine */
        System.out.print("\tTesting session time");

        SSLContext ctx = tf.createSSLContext("TLS", engineProvider);
        SSLEngine client = ctx.createSSLEngine("server", 12345);
        SSLEngine server = ctx.createSSLEngine();
        if (client == null || server == null) {
            error("\t\t... failed");
            fail("failed to create engine");
            return;
        }

        server.setUseClientMode(false);
        server.setNeedClientAuth(false);
        client.setUseClientMode(true);
        ret = tf.testConnection(server, client, null, null, "Test reuse");
        if (ret != 0) {
            error("\t... failed");
            fail("failed to connect");
        }

        session = client.getSession();
        if (session.getCreationTime() <= 0) {
            error("\t... failed");
            fail("failed to get creation time");
        }

        if (session.getCreationTime() > session.getLastAccessedTime() ||
                session.getLastAccessedTime() <= 0) {
            error("\t... failed");
            fail("failed creation time does not equal accessed time");
        }

        pass("\t\t... passed");


        /* test certificates */
        System.out.print("\tTesting session cert");
        session = client.getSession();
        if (session.getLocalPrincipal() != null) {
            error("\t... failed");
            fail("found unexpected principal");
        }

        try {
            /* @TODO make match SunJSSE better */
            session.getPeerPrincipal().getName();
        } catch (SSLPeerUnverifiedException e) {
            error("\t... failed");
            fail("failed to find peer principal");
        }

        try {
            session.getPeerCertificateChain();
        } catch (SSLPeerUnverifiedException e) {
            error("\t... failed");
            fail("failed to get peer certificate chain");
        }

        pass("\t\t... passed");
    }

    @Test
    public void testNullSession() {
        int ret;
        SSLSession session;

        /* create new SSLEngine */
        System.out.print("\tTesting null session");

        SSLContext ctx = tf.createSSLContext("TLS", engineProvider);
        SSLEngine client = ctx.createSSLEngine("server", 12345);
        SSLEngine server = ctx.createSSLEngine();
        if (client == null || server == null) {
            error("\t\t... failed");
            fail("failed to create engine");
            return;
        }
        session = client.getSession(); /* get null session since handshake not done */

        server.setUseClientMode(false);
        server.setNeedClientAuth(false);
        client.setUseClientMode(true);
        ret = tf.testConnection(server, client, null, null, "Test reuse");
        if (ret != 0) {
            error("\t... failed");
            fail("failed to create engine");
        }

        /* session stored before handshake should still be null */
        if (session.getId() == null) {
            error("\t... failed");
            fail("failed to get ID");
        }

        if (session.getId().length != 0) {
            error("\t... failed");
            fail("ID longer than expected");
        }

        try {
            session.getPeerCertificates();
            error("\t... failed");
            fail("Unexpected peer certificates found");
        } catch (SSLPeerUnverifiedException e) {
            /* expected to fail with unverified exception */
        }

        if (!session.getCipherSuite().equals("SSL_NULL_WITH_NULL_NULL")) {
            error("\t... failed");
            fail("Unexpected cipher suite found");
        }

        if (!session.getProtocol().equals("NONE")) {
            error("\t... failed");
            fail("Unexpected protocol found");
        }

        try {
            session.getPeerPrincipal();
            error("\t... failed");
            fail("Unexpected peer principal found");
        } catch (SSLPeerUnverifiedException e) {
            /* expected to fail here */
        }

        try {
            session.getPeerCertificateChain();
            error("\t... failed");
            fail("Unexpected peer certificate chain found");
        } catch (SSLPeerUnverifiedException e) {
            /* expected to fail here */
        }

        pass("\t\t... passed");
    }


    @Test
    public void testBinding() {
        int ret;
        String[] values;
        listner bound  = new listner();
        listner bound2 = new listner();

        /* create new SSLEngine */
        System.out.print("\tTesting binding session");

        SSLContext ctx = tf.createSSLContext("TLS", engineProvider);
        SSLEngine client = ctx.createSSLEngine("server", 12345);
        SSLEngine server = ctx.createSSLEngine();
        if (client == null || server == null) {
            error("\t\t... failed");
            fail("failed to create engine");
            return;
        }
        SSLSession session = client.getSession();
        session.putValue("testing", bound);
        bound.setInvalid();

        server.setUseClientMode(false);
        server.setNeedClientAuth(false);
        client.setUseClientMode(true);
        ret = tf.testConnection(server, client, null, null, "Test reuse");
        if (ret != 0) {
            error("\t\t... failed");
            fail("failed to create engine");
        }

        /* override null session set before handshake */
        session = client.getSession();
        session.putValue("testing", bound);
        if (!bound.checkID(session.getId())) {
            error("\t\t... failed");
            fail("test of ID failed");
        }

        if (!bound.checkPeer("server", 12345)) {
            error("\t\t... failed");
            fail("test of port and host fail");

        }

        try {
            if (session.getPeerCertificates() != null) {
                Certificate[] certs = session.getPeerCertificates();

                if (certs.length != 1) {
                    error("\t\t... failed");
                    fail("unexpected number of peer certs found");
                }

                if (!certs[0].getType().equals("X.509")) {
                    error("\t\t... failed");
                    fail("unexpected cert type found");
                }
            }
        } catch (SSLPeerUnverifiedException e) {
            error("\t\t... failed");
            fail("failed to get peer certificate");
        }

        if (!bound.checkCipher(server.getSession().getCipherSuite())) {
            error("\t\t... failed");
            fail("unexpected cipher suite");
        }

        session.removeValue("testing");
        if (bound.isBound) {
            error("\t\t... failed");
            fail("bound when should not be");
        }
        session.putValue("testing", bound);
        if (!bound.isBound) {
            error("\t\t... failed");
            fail("not bound when should be");
        }
        session.putValue("testing", bound2);
        if (!bound2.isBound || bound.isBound) {
            error("\t\t... failed");
            fail("override failed");
        }

        if (!bound2.checkPeer("server", 12345)) {
            error("\t\t... failed");
            fail("test of port and host fail");
        }

        if (!session.getValue("testing").equals(bound2)) {
            error("\t\t... failed");
            fail("failed to get value");
        }

        if (session.getValue("bad") != null) {
            error("\t\t... failed");
            fail("able to get bogus value");
        }

        session.putValue("testing 2", bound);
        values = session.getValueNames();
        if (values.length != 2) {
            error("\t\t... failed");
            fail("unexpected number of values");
        }

        if (!values[0].equals("testing 2") || !values[1].equals("testing")) {
            error("\t\t... failed");
            fail("unexpected value names");
        }

        try {
            session.removeValue("bad");
        } catch (IllegalArgumentException ex) {
            error("\t\t... failed");
            fail("could not remove a bogus value");
        }

        try {
            session.removeValue(null);
            error("\t\t... failed");
            fail("null sanity check failed");
        } catch (IllegalArgumentException ex) {
            /* expected to throw exception */
        }

        if (!server.getSession().getProtocol().equals(
                client.getSession().getProtocol())) {
            error("\t... failed");
            fail("protocols do not match");
        }
        pass("\t\t... passed");
    }

    @Test
    public void testSessionContext() {
        int ret;
        SSLSession session;
        SSLSessionContext context;

        /* create new SSLEngine */
        System.out.print("\tTesting session context");

        SSLContext ctx = tf.createSSLContext("TLS", engineProvider);
        SSLEngine client = ctx.createSSLEngine("server", 12345);
        SSLEngine server = ctx.createSSLEngine();
        if (client == null || server == null) {
            error("\t\t... failed");
            fail("failed to create engine");
            return;
        }

        server.setUseClientMode(false);
        server.setNeedClientAuth(false);
        client.setUseClientMode(true);
        ret = tf.testConnection(server, client, null, null, "Test reuse");
        if (ret != 0) {
            error("\t\t... failed");
            fail("failed to create engine");
        }
        session = client.getSession();
        context = session.getSessionContext();

        context.setSessionTimeout(100);
        if (context.getSessionTimeout() != 100) {
            error("\t\t... failed");
            fail("failed to set session timeout");
        }

        /* @TODO difference in cache size for SunJSSE vs wolfJSSE  0 vs 33 */
        context.getSessionCacheSize();
        try {
            context.setSessionCacheSize(2);
            error("\t\t... failed");
            fail("unexpected set cache size passed, create test case");
        } catch (Exception e) {
            /* currently not available for wolfSSL, is set at build time */
        }
        pass("\t\t... passed");
    }


    private void pass(String msg) {
        WolfSSLTestFactory.pass(msg);
    }

    private void error(String msg) {
        WolfSSLTestFactory.fail(msg);
    }

    private class listner implements SSLSessionBindingListener {
        private SSLSession ses;
        private boolean isBound = false;

        /**
         * Used to test if the right session was passed in
         * @param in ID to compare to local ID
         * @return true on success
         */
        protected boolean checkID(byte[] in) {
            int i;
            byte id[] = ses.getId();

            if (id.length != in.length) {
                return false;
            }

            for (i = 0; i < id.length; i++) {
                if (id[i] != in[i])
                    return false;
            }
            return true;
        }

        /**
         * Used to test host and port
         * @param host host to compare
         * @param port port to compare
         * @return true on success
         */
        protected boolean checkPeer(String host, int port) {
            if (!ses.getPeerHost().equals(host) || ses.getPeerPort() != port)
                return false;
            return true;
        }

        protected void setInvalid() {
            ses.invalidate();
        }

        protected boolean checkCipher(String in) {
            return in.equals(ses.getCipherSuite());
        }

        @Override
        public void valueBound(SSLSessionBindingEvent event) {
            ses = event.getSession();
            isBound = true;
       }

        @Override
        public void valueUnbound(SSLSessionBindingEvent event) {
            isBound = false;
        }

    }
}
