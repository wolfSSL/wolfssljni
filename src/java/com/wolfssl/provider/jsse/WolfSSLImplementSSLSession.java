/* WolfSSLImplementSession.java
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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
package com.wolfssl.provider.jsse;

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
    private WolfSSLSession ssl = null;
    private final WolfSSLAuthStore authStore;
    private WolfSSLSessionContext ctx = null;
    private boolean valid = false;
    private final HashMap<String, Object> binding;
    private final int port;
    private final String host;
    Date creation = null;
    Date accessed = null; /* when new connection was made using session */
    byte[] pseudoSessionID = null; /* used with TLS 1.3*/
    private int side = 0;

    /* Cache peer certificates after received. Applications assume that
     * SSLSocket.getSession().getPeerCertificates() will return the peer
     * certificate even on a resumed connection where the cert has not been
     * sent during the handshake. */
    private Certificate[] peerCerts = null;

    /**
     * Is this object currently inside the WolfSSLAuthStore session cache table?
     *
     * Used to mark when and where native WOLFSSL_SESSION pointers are freed.
     * Sessions inside the table always have their sesPtr freed by the finalizer
     * upon garbage collection. Otherwise, if sessions are taken out of the
     * table and sesPtr is updated afterwards sesPtrUpdateAfterTable is set to
     * true and the sesPtr is then freed by that object either during
     * setResume() or finalization.
     */
    protected boolean isInTable = false;
    protected boolean sesPtrUpdatedAfterTable = false;

    /**
     * Indicates if this session was retrieved out of the WolfSSLAuthStore
     * session table/store. This is used by WolfSSLEngineHelper to help
     * determine if session creation is allowed. See Javadocs for
     * SSLEngine/SSLSocket setEnableSessionCreation() */
    protected boolean isFromTable = false;

    /** Native pointer to WOLFSSL_SESSION structure. Obtained via
     * wolfSSL_get1_session(), so needs to be freed */
    private long sesPtr = 0;
    private String nullCipher = "SSL_NULL_WITH_NULL_NULL";
    private String nullProtocol = "NONE";

    /* Lock around access to WOLFSSL_SESSION pointer. Static since there could
     * be multiple WolfSSLSocket refering to the same WOLFSSL_SESSION pointer
     * in resumption cases. */
    private static final Object sesPtrLock = new Object();

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
        this.peerCerts = null;
        this.sesPtr = 0;
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
        this.peerCerts = null;
        this.sesPtr = 0;
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
        this.peerCerts = null;
        this.sesPtr = 0;
        binding = new HashMap<String, Object>();

        creation = new Date();
        accessed = new Date();
    }

    /**
     * Create new WolfSSLImplementSSLSession based on an exisitng one.
     *
     * This constructor is a Copy Constructor and is useful when we want to
     * use a "clone"-like functionality for the original object.
     *
     * WolfSSLImplementSSLSession objects are stored in the WolfSSLAuthStore
     * Java session cache. When we get an object out of that store, we need
     * to make a copy/clone of it instead of using the original object.
     * Otherwise, mutliple threads can be using the same
     * WolfSSLImplementSSLSession object, which does not work well since we
     * wrap a WolfSSLSession inside each of these objects.
     *
     * @param orig Existing WolfSSLImplementSSLSession object to copy/clone
     *             into newly returned object.
     */
    public WolfSSLImplementSSLSession (WolfSSLImplementSSLSession orig) {
        /* Shallow copy WolfSSLSession, caller should reset when needed */
        this.ssl = orig.ssl;

        /* Shallow copy WolfSSLAuthStore, same as primary constructors */
        this.authStore = orig.authStore;

        this.ctx = orig.ctx;
        this.valid = orig.valid;
        this.port = orig.port;
        this.host = orig.host;
        if (orig.creation != null) {
            this.creation = new Date(orig.creation.getTime());
        }
        if (orig.accessed != null) {
            this.accessed = new Date(orig.accessed.getTime());
        }
        if (orig.pseudoSessionID != null) {
            this.pseudoSessionID = orig.pseudoSessionID.clone();
        }
        this.side = orig.side;
        if (orig.peerCerts != null) {
            this.peerCerts = orig.peerCerts.clone();
        }
        /* This session has been copied and is therefore not inside the
         * WolfSSLAuthStore session cache table currently */
        this.isInTable = false;

        /* WOLFSSL_SESSION pointer is copied over into this new object,
         * but mark that it has not been updated post-table so we know not to
         * free sesPtr in this new object unless we overwrite it later on.
         * Original sesPtr will be freed by object in the cache table upon
         * garbage collection or manual purge */
        this.sesPtr = orig.sesPtr;
        this.sesPtrUpdatedAfterTable = false;

        /* Not copying binding, not needed */
        this.binding = null;
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

        } catch (IllegalStateException e) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "In getId(), WolfSSLSession has been freed, returning null");
            return null;

        } catch (WolfSSLJNIException e) {
            /* print stack trace of native JNI error for debugging */
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
    protected synchronized void setSessionContext(WolfSSLSessionContext ctx) {
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

        /* If peer cert is already cached, just return that */
        if (this.peerCerts != null) {
            return this.peerCerts.clone();
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

        /* cache peer cert for use by app in resumed session */
        this.peerCerts = new Certificate[] { exportCert };

        return this.peerCerts.clone();
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
        /* Set session (WOLFSSL_SESSION) into native WOLFSSL, makes
         * a copy of the session so this object can free sesPtr when ready */
        synchronized (sesPtrLock) {
            in.setSession(this.sesPtr);
            ssl = in;
        }
    }


    /**
     * Should be called on shutdown to save the session pointer
     */
    protected synchronized void setResume() {

        if (ssl != null) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "entered setResume(), trying to get sesPtrLock");

            synchronized (sesPtrLock) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "got sesPtrLock: this.sesPtr = " + this.sesPtr);

                /* Only free existing WOLFSSL_SESSION pointer if this
                 * object is in the WolfSSLAuthStore cache table (store),
                 * or it is NOT in the store but has been updated after it
                 * was pulled out of the store. The original WOLFSSL_SESSION
                 * pointer is freed when that original object is garbage
                 * collected during finalization or manually freed */
                if (this.sesPtr != 0) {
                    if (this.isInTable ||
                        (!this.isInTable && this.sesPtrUpdatedAfterTable)) {

                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                           "calling WolfSSLSession.freeSession(this.sesPtr)");

                        WolfSSLSession.freeSession(this.sesPtr);
                        /* reset this.sesPtr to 0 in case ssl.getSession() below
                         * blocks on WOLFSSL lock */
                        this.sesPtr = 0;
                    }
                }

                /* Get new WOLFSSL_SESSION pointer for updated WOLFSSL */
                this.sesPtr = ssl.getSession();
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "called ssl.getSession(), new this.sesPtr = " +
                    this.sesPtr);

                /* If this object is not in the WolfSSLAuthStore store,
                 * mark that we have updated the sesPtr in order to
                 * correctly free later on */
                if (!this.isInTable) {
                    this.sesPtrUpdatedAfterTable = true;
                }
            }
        }
    }

    /**
     * Sets the native WOLFSSL_SESSION timeout
     * @param in timeout in seconds
     */
    protected synchronized void setNativeTimeout(long in) {
        ssl.setSessTimeout(in);
    }


    /**
     * TLS 1.3 removed session ID's, this can be used instead to
     * search for sessions.
     * @param id pseudo session ID at the java wrapper level
     */
    protected synchronized void setPseudoSessionId(byte[] id) {
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

    /**
     * Returns the hostname String associated with this session object.
     *
     * @return Hostname String associated with this session
     */
    protected String getHost() {
        return this.host;
    }

    /**
     * Returns the port associated with this session object.
     *
     * @return Port associated with this session
     */
    protected int getPort() {
        return this.port;
    }

    @SuppressWarnings("deprecation")
    @Override
    protected void finalize() throws Throwable
    {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered finalize(): this.sesPtr = " + this.sesPtr);

        synchronized (sesPtrLock) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "got sesPtrLock: " + this.sesPtr);

            /* Our internal WOLFSSL_SESSION pointer should be freed in
             * the following scenarios:
             *
             * 1. This object is currently in the WolfSSLAuthStore session
             *    cache table (store), OR
             * 2. This object is NOT in the WolfSSLAuthStore session cache
             *    table AND the sesPtr has been updated after we copied
             *    the object out of the cache table.
             */
            if (this.sesPtr != 0) {
                if (this.isInTable ||
                    (!this.isInTable && this.sesPtrUpdatedAfterTable)) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                       "calling WolfSSLSession.freeSession(this.sesPtr)");
                    WolfSSLSession.freeSession(this.sesPtr);
                    this.sesPtr = 0;
                }
            }
        }

        super.finalize();
    }
}
