/* WolfSSLImplementSession.java
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
package com.wolfssl.provider.jsse;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLJNIException;
import com.wolfssl.WolfSSLSession;
import java.security.Principal;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionBindingEvent;
import javax.net.ssl.SSLSessionBindingListener;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.X509KeyManager;
import javax.security.cert.*;

/**
 * wolfSSL Session
 * Note: suppress depreciation warning for javax.security.cert.X509Certificate
 * @author wolfSSL
 */
@SuppressWarnings("deprecation")
public class WolfSSLImplementSSLSession implements SSLSession {
    private WolfSSLSession ssl;
    private final WolfSSLAuthStore authStore;
    private boolean valid;
    private final HashMap<String, Object> binding;
    private final int port;
    private final String host;
    Date creation;
    Date accessed; /* when new connection was made using session */

    /**
     * has this session been registered
     */
    protected boolean fromTable = false;
    private long sesPtr = 0;
    private String nullCipher = "SSL_NULL_WITH_NULL_NULL";
    private String nullProtocol = "NONE";


    public WolfSSLImplementSSLSession (WolfSSLSession in, int port, String host,
            WolfSSLAuthStore params) {
        this.ssl = in;
        this.port = port;
        this.host = host;
        this.authStore = params;
        this.valid = true; /* flag if joining or resuming session is allowed */
        binding = new HashMap<String, Object>();

        creation = new Date();
        accessed = new Date();
    }

    public WolfSSLImplementSSLSession (WolfSSLSession in,
                                       WolfSSLAuthStore params) {
        this.ssl = in;
        this.port = -1;
        this.host = null;
        this.authStore = params;
        this.valid = true; /* flag if joining or resuming session is allowed */
        binding = new HashMap<String, Object>();

        creation = new Date();
        accessed = new Date();
    }

    public WolfSSLImplementSSLSession (WolfSSLAuthStore params) {
        this.port = -1;
        this.host = null;
        this.authStore = params;
        this.valid = true; /* flag if joining or resuming session is allowed */
        binding = new HashMap<String, Object>();

        creation = new Date();
        accessed = new Date();
    }

    public byte[] getId() {
        if (ssl == null) {
            return new byte[0];
        }
        return this.ssl.getSessionID();
    }

    public SSLSessionContext getSessionContext() {
        return new WolfSSLSessionContext(this, this.ssl);
    }

    public long getCreationTime() {
        return creation.getTime();
    }

    public long getLastAccessedTime() {
        return accessed.getTime();
    }

    public void invalidate() {
        this.valid = false;
    }

    public boolean isValid() {
        return this.valid;
    }

    public void putValue(String name, Object obj) {
        Object old;

        if (name == null) {
            throw new IllegalArgumentException();
        }

        /* check if Object should be notified */
        if (obj instanceof SSLSessionBindingListener) {
            ((SSLSessionBindingListener) obj).valueBound(
                    new SSLSessionBindingEvent(this, name));
        }

        old = binding.put(name, obj);
        if (old != null) {
            if (old instanceof SSLSessionBindingListener) {
                ((SSLSessionBindingListener) old).valueUnbound(
                        new SSLSessionBindingEvent(this, name));
            }
        }
    }

    public Object getValue(String name) {
        return binding.get(name);
    }

    public void removeValue(String name) {
        Object obj;

        if (name == null) {
            throw new IllegalArgumentException();
        }

        obj = binding.get(name);
        if (obj != null) {
            /* check if Object should be notified */
            if (obj instanceof SSLSessionBindingListener) {
                ((SSLSessionBindingListener) obj).valueUnbound(
                        new SSLSessionBindingEvent(this, name));
            }
            binding.remove(name);
        }
    }

    public String[] getValueNames() {
         return binding.keySet().toArray(new String[binding.keySet().size()]);
    }

    public Certificate[] getPeerCertificates()
            throws SSLPeerUnverifiedException {
        long x509;
        WolfSSLX509 cert;

        if (ssl == null) {
            throw new SSLPeerUnverifiedException("handshake not complete");
        }

        try {
            x509 = this.ssl.getPeerCertificate();
        } catch (IllegalStateException | WolfSSLJNIException ex) {
            Logger.getLogger(
                    WolfSSLImplementSSLSession.class.getName()).log(
                        Level.SEVERE, null, ex);
            return null;
        }

        /* if no peer cert, throw SSLPeerUnverifiedException */
        if (x509 == 0) {
            throw new SSLPeerUnverifiedException("No peer certificate");
        }

        try {
            cert = new WolfSSLX509(x509);
        } catch (WolfSSLException ex) {
            throw new SSLPeerUnverifiedException("Error creating certificate");
        }

        return new Certificate[] { cert };
    }

    @Override
    public Certificate[] getLocalCertificates() {
        X509KeyManager km = authStore.getX509KeyManager();
        return km.getCertificateChain(authStore.getCertAlias());
    }

    @Override
    public X509Certificate[] getPeerCertificateChain()
        throws SSLPeerUnverifiedException {
        WolfSSLX509X x509;

        if (ssl == null) {
            throw new SSLPeerUnverifiedException("handshake not done");
        }

        try {
            x509 = new WolfSSLX509X(this.ssl.getPeerCertificate());
            return new X509Certificate[]{ (X509Certificate)x509 };
        } catch (IllegalStateException | WolfSSLJNIException |
                WolfSSLException ex) {
            Logger.getLogger(
                    WolfSSLImplementSSLSession.class.getName()).log(
                        Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        if (ssl == null) {
            throw new SSLPeerUnverifiedException("handshake not done");
        }

        try {
            WolfSSLX509 x509 = new WolfSSLX509(this.ssl.getPeerCertificate());
            return x509.getSubjectDN();
        } catch (IllegalStateException | WolfSSLJNIException |
                WolfSSLException ex) {
            Logger.getLogger(
                    WolfSSLImplementSSLSession.class.getName()).log(
                        Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    public Principal getLocalPrincipal() {
        int i;

        X509KeyManager km = authStore.getX509KeyManager();
        java.security.cert.X509Certificate[] certs =
                km.getCertificateChain(authStore.getCertAlias());

        if (certs == null) {
            return null;
        }

        for (i = 0; i < certs.length; i++) {
            if (certs[i].getBasicConstraints() < 0) {
                /* is not a CA treat as end of chain */
                return certs[i].getSubjectDN();
            }
        }
        return null;
    }

    @Override
    public String getCipherSuite() {
        if (ssl == null) {
            return this.nullCipher;
        }

        try {
            return this.ssl.cipherGetName();
        } catch (IllegalStateException | WolfSSLJNIException ex) {
            Logger.getLogger(
                    WolfSSLImplementSSLSession.class.getName()).log(
                        Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    public String getProtocol() {
        if (ssl == null) {
            return this.nullProtocol;
        }

        try {
            return this.ssl.getVersion();
        } catch (IllegalStateException | WolfSSLJNIException ex) {
            Logger.getLogger(
                    WolfSSLImplementSSLSession.class.getName()).log(
                        Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    public String getPeerHost() {
        return this.host;
    }

    @Override
    public int getPeerPort() {
        return this.port;
    }

    @Override
    public int getPacketBufferSize() {
        return 16394; /* 2^14, max size by standard, enum MAX_RECORD_SIZE */
    }

    @Override
    public int getApplicationBufferSize() {
        /* 16394 - (38 + 64)
         * max added to msg, mac + pad  from RECORD_HEADER_SZ + BLOCK_SZ (pad) +
         * Max digest sz + BLOC_SZ (iv) + pad byte (1)
         */
        return 16292;
    }


    /**
     * Takes in a new WOLFSSL object and sets the stored session
     * @param in WOLFSSL session to set resume in
     */
    protected void resume(WolfSSLSession in) {
        ssl = in;
        ssl.setSession(this.sesPtr);
    }


    /**
     * Should be called on shutdown to save the session pointer
     */
    protected void setResume() {
        if (ssl != null) {
            this.sesPtr = ssl.getSession();
        }
    }


    private class WolfSSLSessionContext implements SSLSessionContext {
        private WolfSSLImplementSSLSession session;
        private WolfSSLSession sslCtx;

        public WolfSSLSessionContext(WolfSSLImplementSSLSession in,
                WolfSSLSession ssl) {
            this.session = in;
            this.sslCtx = ssl;
        }

        /* rework as session cache */
        @Override
        public SSLSession getSession(byte[] arg0) {
            return session;
        }

        @Override
        public Enumeration<byte[]> getIds() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public void setSessionTimeout(int in) throws IllegalArgumentException {
            if (this.sslCtx.setSessTimeout(in) != WolfSSL.SSL_SUCCESS) {
                throw new IllegalArgumentException();
            }
        }

        @Override
        public int getSessionTimeout() {
            return (int)this.sslCtx.getSessTimeout();
        }

        /* set during compile time with wolfSSL */
        @Override
        public void setSessionCacheSize(int in)
            throws IllegalArgumentException {
            throw new UnsupportedOperationException("Not supported. Cache size "
                    + "is set at compile time with wolfSSL");
        }

        @Override
        public int getSessionCacheSize() {
            return (int)this.sslCtx.getCacheSize();
        }

    }
}
