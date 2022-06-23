/* WolfSSLImplementSession.java
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
package com.wolfssl.provider.jsse;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLJNIException;
import com.wolfssl.WolfSSLSession;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateEncodingException;
import java.util.Date;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionBindingEvent;
import javax.net.ssl.SSLSessionBindingListener;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.X509KeyManager;

/**
 * wolfSSL Session
 * Note: suppress depreciation warning for javax.security.cert.X509Certificate
 * @author wolfSSL
 */
@SuppressWarnings("deprecation")
public class WolfSSLImplementSSLSession implements SSLSession {
    private WolfSSLSession ssl;
    private final WolfSSLAuthStore authStore;
    private WolfSSLSessionContext ctx = null;
    private boolean valid;
    private final HashMap<String, Object> binding;
    private final int port;
    private final String host;
    Date creation;
    Date accessed; /* when new connection was made using session */
    byte pseudoSessionID[] = null; /* used with TLS 1.3*/
    private int side = 0;

    /** Has this session been registered */
    protected boolean fromTable = false;

    private long sesPtr = 0;
    private String nullCipher = "SSL_NULL_WITH_NULL_NULL";
    private String nullProtocol = "NONE";

    /**
     * Create new WolfSSLImplementSSLSession
     *
     * @param in WolfSSLSession to be used with this object
     * @param port peer port for this session
     * @param host peer hostname String for this session
     * @param params WolfSSLAuthStore for this session
     */
    public WolfSSLImplementSSLSession (WolfSSLSession in, int port, String host,
            WolfSSLAuthStore params) {
        this.ssl = in;
        this.port = port;
        this.host = host;
        this.authStore = params;
        this.valid = false; /* flag if joining or resuming session is allowed */
        binding = new HashMap<String, Object>();

        creation = new Date();
        accessed = new Date();
    }

    /**
     * Create new WolfSSLImplementSSLSession
     *
     * @param in WolfSSLSession to be used with this object
     * @param params WolfSSLAuthStore for this session
     */
    public WolfSSLImplementSSLSession (WolfSSLSession in,
                                       WolfSSLAuthStore params) {
        this.ssl = in;
        this.port = -1;
        this.host = null;
        this.authStore = params;
        this.valid = false; /* flag if joining or resuming session is allowed */
        binding = new HashMap<String, Object>();

        creation = new Date();
        accessed = new Date();
    }

    /**
     * Create new WolfSSLImplementSSLSession
     *
     * @param params WolfSSLAuthStore for this session
     */
    public WolfSSLImplementSSLSession (WolfSSLAuthStore params) {
        this.port = -1;
        this.host = null;
        this.authStore = params;
        this.valid = false; /* flag if joining or resuming session is allowed */
        binding = new HashMap<String, Object>();

        creation = new Date();
        accessed = new Date();
    }

    /**
     * Get session ID for this session
     *
     * @return session ID as byte array, empty byte array if wrapped
     *         com.wolfssl.WolfSSLSession is null, or null if inner
     *         IllegalStateException or WolfSSLJNIException are thrown
     */
    public synchronized byte[] getId() {
        if (ssl == null) {
            return new byte[0];
        }
        try {
            /* use pseudo session ID if session tickets are being used */
            if (this.ssl.getVersion().equals("TLSv1.3") ||
                this.ssl.sessionTicketsEnabled()) {
                 return this.pseudoSessionID;
            }
            else {
                return this.ssl.getSessionID();
            }
        } catch (IllegalStateException | WolfSSLJNIException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Get SSLSessionContext for this session
     *
     * @return SSLSessionContext
     */
    public synchronized SSLSessionContext getSessionContext() {
        return ctx;
    }

    /**
     * Setter function for the SSLSessionContext used with session creation
     *
     * @param ctx value to set the session context as
     */
    protected void setSessionContext(WolfSSLSessionContext ctx) {
        this.ctx = ctx;
    }

    /**
     * Get session creation time
     *
     * @return session creation time
     */
    public long getCreationTime() {
        return creation.getTime();
    }

    /**
     * Get session last accessed time
     *
     * @return session last accessed time
     */
    public long getLastAccessedTime() {
        return accessed.getTime();
    }

    /**
     * Invalidate this session
     */
    public void invalidate() {
        this.valid = false;
    }

    /**
     * Check if this session is valid
     *
     * @return boolean if this session is valid
     */
    public boolean isValid() {
        return this.valid;
    }

    /**
     * After a connection has been established or on restoring connection the
     * session is then valid and can be joined or resumed
     * @param in true/false valid boolean
     */
    protected void setValid(boolean in) {
        this.valid = in;
    }

    /**
     * Put value into this session
     *
     * @param name String name of value
     * @param obj Object to store associated with name
     *
     * @throws IllegalArgumentException if input name is null
     */
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

    /**
     * Get stored value associated with name
     *
     * @param name String name to retrieve associated Object value
     *
     * @return Object value associated with name
     */
    public Object getValue(String name) {
        return binding.get(name);
    }

    /**
     * Remove stored String:Object from session
     *
     * @param name String name to remove from session
     *
     * @throws IllegalArgumentException if input name is null
     */
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

    /**
     * Get stored value names in this session
     *
     * @return String array of value names stored in session
     */
    public String[] getValueNames() {
        return binding.keySet().toArray(new String[binding.keySet().size()]);
    }

    /**
     * Get peer certificates for this session
     *
     * @return Certificate array of peer certs for session
     *
     * @throws SSLPeerUnverifiedException if handshake is not complete,
     *         or error getting certificates
     */
    public synchronized Certificate[] getPeerCertificates()
            throws SSLPeerUnverifiedException {
        long x509;
        WolfSSLX509 cert;
        CertificateFactory cf;
        ByteArrayInputStream der;
        X509Certificate exportCert;

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

        /* convert WolfSSLX509 into X509Certificate so we can release
         * our native memory */
        try {
            cf = CertificateFactory.getInstance("X.509");
        } catch (CertificateException ex) {
            cert.free();
            throw new SSLPeerUnverifiedException(
                    "Error getting CertificateFactory instance");
        }

        try {
            der = new ByteArrayInputStream(cert.getEncoded());
        } catch (CertificateEncodingException ex) {
            cert.free();
            throw new SSLPeerUnverifiedException(
                    "Error getting encoded DER from WolfSSLX509 object");
        }

        try {
            exportCert = (X509Certificate)cf.generateCertificate(der);
        } catch (CertificateException ex) {
            cert.free();
            throw new SSLPeerUnverifiedException(
                    "Error generating X509Certificdate from DER encoding");
        }

        /* release native memory */
        cert.free();

        return new Certificate[] { exportCert };
    }

    @Override
    public Certificate[] getLocalCertificates() {
        X509KeyManager km = authStore.getX509KeyManager();
        return km.getCertificateChain(authStore.getCertAlias());
    }

    @Override
    public synchronized javax.security.cert.X509Certificate[] getPeerCertificateChain()
        throws SSLPeerUnverifiedException {
        WolfSSLX509X x509;

        if (ssl == null) {
            throw new SSLPeerUnverifiedException("handshake not done");
        }

        try {
            x509 = new WolfSSLX509X(this.ssl.getPeerCertificate());
            return new javax.security.cert.X509Certificate[] {
                (javax.security.cert.X509Certificate)x509 };

        } catch (IllegalStateException | WolfSSLJNIException |
                WolfSSLException ex) {
            Logger.getLogger(
                    WolfSSLImplementSSLSession.class.getName()).log(
                        Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    public synchronized Principal getPeerPrincipal()
        throws SSLPeerUnverifiedException {
        if (ssl == null) {
            throw new SSLPeerUnverifiedException("handshake not done");
        }

        try {
            Principal peerPrincipal = null;
            WolfSSLX509 x509 = new WolfSSLX509(this.ssl.getPeerCertificate());
            peerPrincipal = x509.getSubjectDN();
            x509.free();

            return peerPrincipal;

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

        X509KeyManager km = authStore.getX509KeyManager();
        java.security.cert.X509Certificate[] certs =
                km.getCertificateChain(authStore.getCertAlias());
        Principal localPrincipal = null;

        if (certs == null) {
            return null;
        }

        for (int i = 0; i < certs.length; i++) {
            if (certs[i].getBasicConstraints() < 0) {
                /* is not a CA treat as end of chain */
                localPrincipal = certs[i].getSubjectDN();
                break;
            }
        }

        /* free native resources earlier than garbage collection if
         * X509Certificate is WolfSSLX509 */
        for (int i = 0; i < certs.length; i++) {
            if (certs[i] instanceof WolfSSLX509) {
                ((WolfSSLX509)certs[i]).free();
            }
        }

        /* return principal, or null if not set */
        return localPrincipal;
    }

    @Override
    public synchronized String getCipherSuite() {
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
    public synchronized String getProtocol() {
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
        /* Match conscrypt's calculations here for maximum potential
         * SSL/TLS record length. Used by SSLEngine consumers to allocate
         * output buffer size.
         *
         * type(1) + version(2) + length(2) + 2^14 plaintext +
         * max compression overhead (1024) + max AEAD overhead (1024) */
        return 18437;
    }

    @Override
    public int getApplicationBufferSize() {
        /* max plaintext bytes allowed by spec, MAX_RECORD_SIZE enum (2^14) */
        return 16384;
    }

    /**
     * Takes in a new WOLFSSL object and sets the stored session
     * @param in WOLFSSL session to set resume in
     */
    protected synchronized void resume(WolfSSLSession in) {
        ssl = in;
        ssl.setSession(this.sesPtr);
    }


    /**
     * Should be called on shutdown to save the session pointer
     */
    protected synchronized void setResume() {
        if (ssl != null) {
            this.sesPtr = ssl.getSession();
        }
    }

    /**
     * Sets the native WOLFSSL_SESSION timeout
     * @param in timeout in seconds
     */
    protected void setNativeTimeout(long in) {
        ssl.setSessTimeout(in);
    }


    /**
     * TLS 1.3 removed session ID's, this can be used instead to
     * search for sessions.
     * @param id pseudo session ID at the java wrapper level
     */
    protected synchronized void setPseudoSessionId(byte id[]) {
        this.pseudoSessionID = id.clone();
    }


    /**
     * Sets (server/client) side of the connection for session
     * @param in the side to be set, server or client
     */
    protected void setSide(int in) {
        this.side = in;
    }


    /**
     * Returns the side session is on (server/client)
     * @return WolfSSL.* integer value of side on
     */
    protected int getSide() {
        return this.side;
    }
}
