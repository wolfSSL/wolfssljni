/* WolfSSLImplementSession.java
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
package com.wolfssl.provider.jsse;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLDebug;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLJNIException;
import com.wolfssl.WolfSSLSession;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateEncodingException;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.Collections;
import java.io.ByteArrayInputStream;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
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
public class WolfSSLImplementSSLSession extends ExtendedSSLSession {

    private WolfSSLSession ssl = null;
    private final WolfSSLAuthStore authStore;
    private WolfSSLSessionContext ctx = null;
    private boolean valid = false;
    private final HashMap<String, Object> binding;
    private final int port;
    private final String host;
    String protocol = null;
    int packetBufSz = -1; /* max packet size for TLS record */
    String cipherSuite = null; /* cipher suite used for this session */
    Date creation = null;
    Date accessed = null; /* when new connection was made using session */
    byte[] pseudoSessionID = null; /* used with TLS 1.3*/
    private int side = 0;

    /* Track if client auth was requested, for getPeerCertificates() behavior */
    private volatile boolean clientAuthRequested = false;

    /* Cache peer certificates after received. Applications assume that
     * SSLSocket.getSession().getPeerCertificates() will return the peer
     * certificate even on a resumed connection where the cert has not been
     * sent during the handshake. */
    private X509Certificate[] peerCerts = null;

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

    /**
     * Tracks if WOLFSSL_SESSION pointer has been updated after retreived from
     * cache table.
     */
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
     * Stored SNI server names from original session, used during resumption
     */
    private List<SNIServerName> sniServerNames = null;

    /**
     * Store SNI server names for this session for later resumption
     * @param serverNames list of SNI server names to store
     */
    public synchronized void setSNIServerNames(List<SNIServerName> serverNames) {
        if (serverNames != null && !serverNames.isEmpty()) {
            this.sniServerNames = new ArrayList<>(serverNames);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "Stored SNI server names for session resumption");
        }
    }

    /**
     * Get stored SNI server names for this session
     * @return list of stored SNI server names, may be null
     */
    public synchronized List<SNIServerName> getSNIServerNames() {
        return this.sniServerNames;
    }

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
        this.protocol = this.nullProtocol;
        binding = new HashMap<String, Object>();

        creation = new Date();
        accessed = new Date();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "created new session (port: " + port + ", host: " +
            host + ")");
    }

    /**
     * Create new WolfSSLImplementSSLSession
     *
     * @param in WolfSSLSession to be used with this object
     * @param params WolfSSLAuthStore for this session
     * @param host hostname of peer, or null if not available
     * @param port port of peer
     */
    public WolfSSLImplementSSLSession (WolfSSLSession in,
                                       WolfSSLAuthStore params,
                                       String host, int port) {
        this.ssl = in;
        this.host = host;
        this.authStore = params;
        this.valid = false; /* flag if joining or resuming session is allowed */
        this.peerCerts = null;
        this.sesPtr = 0;
        this.protocol = this.nullProtocol;
        binding = new HashMap<String, Object>();

        creation = new Date();
        accessed = new Date();

        if (port > 0) {
            this.port = port;
        } else {
            this.port = -1;
        }

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "created new session (no host/port yet)");
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
        this.protocol = this.nullProtocol;
        binding = new HashMap<String, Object>();

        creation = new Date();
        accessed = new Date();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "created new session (WolfSSLAuthStore)");
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
        this.clientAuthRequested = orig.clientAuthRequested;
        if (orig.peerCerts != null) {
            this.peerCerts = orig.peerCerts.clone();
        }
        this.protocol = orig.protocol;

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

        /* Copy binding HashMap so session values are preserved */
        if (orig.binding != null) {
            this.binding = new HashMap<String, Object>(orig.binding);
        } else {
            this.binding = new HashMap<String, Object>();
        }

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "created new session (WolfSSLImplementSSLSession)");
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
                 return this.pseudoSessionID.clone();
            }
            else {
                return this.ssl.getSessionID();
            }

        } catch (IllegalStateException e) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "In getId(), WolfSSLSession has been freed, " +
                "returning null");
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
    public synchronized void invalidate() {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "SSLSession.invalidate() called, invalidating session");

        this.valid = false;
    }

    /**
     * Check if this session is valid
     *
     * @return boolean if this session is valid
     */
    public synchronized boolean isValid() {
        return this.valid;
    }

    /**
     * After a connection has been established or on restoring connection the
     * session is then valid and can be joined or resumed
     * @param in true/false valid boolean
     */
    protected synchronized void setValid(boolean in) {
        this.valid = in;
    }

    /**
     * Check if this session is resumable.
     *
     * Calls down to native wolfSSL_SESSION_is_resumable() with
     * WOLFSSL_SESSION pointer.
     *
     * @return true if resumable, otherwise false
     */
    protected synchronized boolean isResumable() {
        synchronized (sesPtrLock) {
            if (WolfSSLSession.sessionIsResumable(this.sesPtr) == 1) {
                return true;
            } else {
                return false;
            }
        }
    }

    /**
     * Return status of internal session pointer (WOLFSSL_SESSION).
     * @return true if this.sesPtr is set, otherwise false if 0 */
    protected boolean sessionPointerSet() {
        synchronized (sesPtrLock) {
            if (this.sesPtr == 0) {
                return false;
            }
            return true;
        }
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
     * This method first tries to call down to native wolfSSL with
     * ssl.getPeerCertificate(). If that succeeds, it caches the peer
     * certificate inside this object (this.peerCerts) so that in a resumed
     * session when this method is called, the caller will still have access
     * to the original certificate (matches SunJSSE behavior). If calling
     * ssl.getPeerCertificate() fails, then we return the cached cert if
     * we have it.
     *
     * @return Certificate array of peer certs for session. Actual subclass
     *         type returned is X509Certificate[] to match SunJSSE behavior
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
            throw new SSLPeerUnverifiedException(
                "internal WolfSSLSession null, handshake not complete or " +
                "SSLSocket/Engine closed");
        }

        /* Throw if server side with no client auth requested */
        if (this.side == WolfSSL.WOLFSSL_SERVER_END &&
            !this.clientAuthRequested) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "Server side, no client auth, throwing exception");
            throw new SSLPeerUnverifiedException(
                "peer not authenticated (no client auth requested)");
        }

        try {
            x509 = this.ssl.getPeerCertificate();
        } catch (IllegalStateException | WolfSSLJNIException ex) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "Error getting peer certificate: "
                    + ex.getMessage());
            x509 = 0;
        }

        /* if no peer cert, throw SSLPeerUnverifiedException */
        if (x509 == 0) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "ssl.getPeerCertificates() returned null, trying " +
                "cached cert");

            if (this.peerCerts != null) {
                /* If peer cert is already cached, just return that */
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "peer cert already cached, returning it");
                return this.peerCerts.clone();
            }
            else {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "No peer cert sent and none cached");
                throw new SSLPeerUnverifiedException("No peer certificate");
            }
        }

        try {
            /* wolfSSL starting with 5.3.0 returns a new WOLFSSL_X509
             * structure from wolfSSL_get_peer_certificate(). In that case,
             * we need to free the pointer when finished. Prior to 5.3.0,
             * this memory was freed internally by wolfSSL since the API
             * only returned a pointer to internal memory */
            if (WolfSSL.getLibVersionHex() >= 0x05003000) {
                cert = new WolfSSLX509(x509, true);
            }
            else {
                cert = new WolfSSLX509(x509, false);
            }
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
        this.peerCerts = new X509Certificate[] { exportCert };

        return this.peerCerts.clone();
    }

    @Override
    public Certificate[] getLocalCertificates() {
        X509KeyManager km = authStore.getX509KeyManager();
        return km.getCertificateChain(authStore.getCertAlias());
    }

    @Override
    public synchronized javax.security.cert.X509Certificate[]
        getPeerCertificateChain() throws SSLPeerUnverifiedException {

        long peerX509 = 0;
        WolfSSLX509X x509;

        if (ssl == null) {
            throw new SSLPeerUnverifiedException("handshake not done");
        }

        /* Throw if server side with no client auth requested */
        if (this.side == WolfSSL.WOLFSSL_SERVER_END &&
            !this.clientAuthRequested) {
            throw new SSLPeerUnverifiedException(
                "peer not authenticated (no client auth requested)");
        }

        try {
            peerX509 = this.ssl.getPeerCertificate();
            if (peerX509 == 0) {
                throw new SSLPeerUnverifiedException("No peer certificate");
            }

            /* wolfSSL starting with 5.3.0 returns a new WOLFSSL_X509
             * structure from wolfSSL_get_peer_certificate(). In that case,
             * we need to free the pointer when finished. Prior to 5.3.0,
             * this memory was freed internally by wolfSSL since the API
             * only returned a pointer to internal memory */
            if (WolfSSL.getLibVersionHex() >= 0x05003000) {
                x509 = new WolfSSLX509X(peerX509, true);
            }
            else {
                x509 = new WolfSSLX509X(peerX509, false);
            }

            return new javax.security.cert.X509Certificate[] {
                (javax.security.cert.X509Certificate)x509 };

        } catch (IllegalStateException | WolfSSLJNIException |
                WolfSSLException ex) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "Error getting peer certificate chain: "
                + ex.getMessage());
        }
        return null;
    }

    @Override
    public synchronized Principal getPeerPrincipal()
        throws SSLPeerUnverifiedException {

        /* Use standard Java X509Certificate.getSubjectDN()
         * for X500Name equals() compatibility */
        Certificate[] certs = getPeerCertificates();
        if (certs != null && certs.length > 0 &&
            certs[0] instanceof X509Certificate) {
            return ((X509Certificate) certs[0]).getSubjectDN();
        }
        throw new SSLPeerUnverifiedException("No peer certificate");
    }

    @Override
    public Principal getLocalPrincipal() {
        /* Logic needs to be added to check for client auth
         * when wrapper is made TODO */
        X509KeyManager km = authStore.getX509KeyManager();
        java.security.cert.X509Certificate[] certs =
                km.getCertificateChain(authStore.getCertAlias());
        Principal localPrincipal = null;

        if (certs == null) {
            return null;
        }

        if (certs.length > 0){
            /* When chain of certificates exceeds one,
             * the user certifcate is the first */
            localPrincipal = certs[0].getSubjectDN();
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
            String currentCipher = this.ssl.cipherGetName();
            if (currentCipher != null) {
                if (!currentCipher.equals(this.cipherSuite)){
                    this.cipherSuite = currentCipher;
                }
                return currentCipher;
            }
        } catch (IllegalStateException | WolfSSLJNIException ex) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "Error getting cipher suite: " + ex.getMessage());
        }

        return this.cipherSuite;
    }

    /**
     * Return the cipher suite from the native WOLFSSL_SESSION structure.
     *
     * @return String representation of the cipher suite from the native
     *         WOLFSSL_SESSION structure, or NULL if not able to be
     *         retrieved.
     */
    public synchronized String getSessionCipherSuite() {
        synchronized (sesPtrLock) {
            return WolfSSLSession.sessionGetCipherName(this.sesPtr);
        }
    }

    @Override
    public synchronized String getProtocol() {
        return this.protocol;
    }

    @Override
    public String getPeerHost() {
        return this.host;
    }

    @Override
    public int getPeerPort() {
        return this.port;
    }

    /**
     * Can be called by SSLEngine consumers to determine maximum
     * output buffer size, to be used for buffer allocations.
     *
     * @return maximum output buffer size
     */
    @Override
    public synchronized int getPacketBufferSize() {

        /* JSSE implementations seem to set the SSL/TLS maximum packet size
         * (record size) differently.
         *
         * Conscrypt calculates this as 18437 bytes:
         *
         * type(1) + version(2) + length(2) + 2^14 plaintext +
         * max compression overhead (1024) + max AEAD overhead (1024)
         *
         * wolfJSSE originally matched the Conscrypt value, but it conflicts
         * with the maximum allowed/used by the tls-channel project, which
         * we have a few customers using. tls-channel uses a maximum size of
         * 17k.
         *
         * Native wolfSSL has the wolfSSL_GetMaxOutputSize() function, but
         * it only works post-handshake. getPacketBufferSize() can be called
         * pre-handshake, so we set a default value here that matches
         * the upper limit for tls-channel, which is 17k, then if
         * wolfSSL_GetMaxOutputSize() is larger, we increase to that value.
         */
        int nativeMax;
        int ret = 17 * 1024;

        /* Try to get maximum TLS record size from native wolfSSL */
        if (ssl != null) {
            try {
                nativeMax = ssl.getMaxOutputSize();
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "ssl.getMaxOutputSize() returned: " + nativeMax);
                if ((nativeMax > 0) && (nativeMax > ret)) {
                    ret = nativeMax;
                }
                if (ret > this.packetBufSz) {
                    this.packetBufSz = ret;
                }
            } catch (IllegalStateException ex) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "Error getting packet buffer size: "
                    + ex.getMessage());
                /* If ssl.getMaxOutputSize failed, check for cached value */
                if (this.packetBufSz > ret) {
                    ret = this.packetBufSz;
                } else { 
                    /* Cache ret if greater than or equal to packetBufSz */
                    this.packetBufSz = ret;
                }
            }

        } else if (this.packetBufSz >= 0) {
            ret = this.packetBufSz;
        }

        final int tmpRet = ret;
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "getPacketBufferSize() returning: " + tmpRet);

        return ret;
    }

    @Override
    public int getApplicationBufferSize() {
        /* max plaintext bytes allowed by spec, MAX_RECORD_SIZE enum (2^14) */
        return WolfSSL.MAX_RECORD_SIZE;
    }

    /**
     * Takes in a new WOLFSSL object and sets the stored session
     * @param in WOLFSSL session to set resume in
     * @return WolfSSL.SSL_SUCCESS if wolfSSL_set_session() was successful,
     *         otherwise WolfSSL.SSL_FAILURE.
     */
    protected synchronized int resume(WolfSSLSession in) {

        int ret = WolfSSL.SSL_FAILURE;

        /* Set session (WOLFSSL_SESSION) into native WOLFSSL, makes
         * a copy of the session so this object can free sesPtr when ready */
        synchronized (sesPtrLock) {
            if (this.sesPtr != 0) {
                ret = in.setSession(this.sesPtr);
            }
            ssl = in;
        }

        return ret;
    }


    /**
     * Should be called on shutdown or after handshake has completed to save
     * the session pointer.
     */
    protected synchronized void setResume() {

        final long tmpSesPtr;

        if (ssl != null) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "entered setResume(), trying to get sesPtrLock");

            synchronized (sesPtrLock) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "got sesPtrLock: this.sesPtr = " + this.sesPtr);

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
                           () -> "calling WolfSSLSession.freeSession(" +
                           "this.sesPtr)");

                        WolfSSLSession.freeSession(this.sesPtr);
                        /* reset this.sesPtr to 0 in case ssl.getSession() below
                         * blocks on WOLFSSL lock */
                        this.sesPtr = 0;
                    }
                }
            }

            /* Get new WOLFSSL_SESSION pointer for updated WOLFSSL locally
             * instead inside of sesPtrLock to minimize blocking time inside
             * that lock, then set class variable next inside lock once
             * value has been retrieved. */
            tmpSesPtr = ssl.getSession();
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "called ssl.getSession(), new this.sesPtr = " +
                tmpSesPtr);

            synchronized (sesPtrLock) {
                this.sesPtr = tmpSesPtr;

                if (this.sesPtr != 0) {
                    this.valid = true;
                }

                /* If this object is not in the WolfSSLAuthStore store,
                 * mark that we have updated the sesPtr in order to
                 * correctly free later on */
                if (!this.isInTable) {
                    this.sesPtrUpdatedAfterTable = true;
                }
            }

            /* Update cached values in this SSLSession from WolfSSLSession,
             * in case that goes out of scope and is garbage collected. */
            updateStoredSessionValues();
        }
    }

    /**
     * Update internally-stored session values.
     */
    protected synchronized void updateStoredSessionValues() {
        try {
            this.protocol = this.ssl.getVersion();
        } catch (IllegalStateException | WolfSSLJNIException ex) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "Not able to update stored WOLFSSL protocol");
        }

        /* Also store SNI server names if not already set */
        if (this.sniServerNames == null || this.sniServerNames.isEmpty()) {
            try {
                List<SNIServerName> names = this.getRequestedServerNames();
                if (names != null && !names.isEmpty()) {
                    this.sniServerNames = new ArrayList<>(names);
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            () -> "Extracted SNI server names from session");
                }
            } catch (UnsupportedOperationException ex) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "Error extracting SNI server names: " +
                    ex.getMessage());
            }
        }

        /* Update packet buffer size */
        try {
            int maxOutputSize = this.ssl.getMaxOutputSize();
            if (this.packetBufSz < 0 || this.packetBufSz < maxOutputSize)
                this.packetBufSz = maxOutputSize;
        } catch (IllegalStateException ex) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "Not able to update packet buffer size: " +
                ex.getMessage());
        }

        /* Update cipher suite */
        try {
            if (this.ssl != null && this.cipherSuite == null) {
                this.cipherSuite = this.ssl.cipherGetName();
                if (this.cipherSuite != null && !this.cipherSuite.isEmpty()) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "Updated cipher suite: " + this.cipherSuite);
                }
            }
        } catch (WolfSSLJNIException ex) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "Not able to update cipher suite: " +
                ex.getMessage());
        }

        /* Update peer certificates */
        try {
            if (this.peerCerts == null) {
                this.getPeerCertificates();
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "Updated peer certificates for session" +
                    "getPeerCertificates() caches peer certs");
            }
        } catch (SSLPeerUnverifiedException ex) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO, () ->
                "Not able to update peer certificates: " + ex.getMessage());
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
     * Set whether client auth was requested.
     * Used for getPeerCertificates() behavior.
     *
     * @param requested true if client auth was requested, false otherwise
     */
    protected void setClientAuthRequested(boolean requested) {
        this.clientAuthRequested = requested;
    }

    /**
     * Return the side session is on (server/client) as a String
     * @return "client" or "server" representing the side of this session
     */
    protected String getSideString() {
        if (this.side == WolfSSL.WOLFSSL_CLIENT_END) {
            return "client";
        } else {
            return "server";
        }
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

    @Override
    public String[] getLocalSupportedSignatureAlgorithms() {
        ArrayList<String> algs = new ArrayList<String>(2);

        if (WolfSSL.RsaEnabled()) {
            algs.add("SHA256withRSA");
        }
        if (WolfSSL.EccEnabled()) {
            algs.add("SHA256withECDSA");
        }

        return algs.toArray(new String[algs.size()]);
    }

    @Override
    public String[] getPeerSupportedSignatureAlgorithms() {
        return new String[0];
    }

    /**
     * Return a list of all SNI server names of the requested Server Name
     * Indication (SNI) extension.
     *
     * @return non-null immutable List of SNIServerNames. List may be empty
     *         if no SNI names were requested.
     */
    @Override
    public synchronized List<SNIServerName> getRequestedServerNames()
        throws UnsupportedOperationException {

        byte[] sniRequestArr = null;

        if (this.ssl == null) {
            if (this.sniServerNames != null &&
                !this.sniServerNames.isEmpty()) {
                return Collections.unmodifiableList(
                    new ArrayList<SNIServerName>(this.sniServerNames));
            }
            return Collections.emptyList();
        }

        try {
            /* Return SNI name saved by Client
             * or return cached request name from Server
             * Currently WolfSSL.WOLFSSL_SNI_HOST_NAME is the only
             * supported type */
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "calling getRequestedServerNames (" +
                this.getSideString() + ")");
            if (this.ssl.getSide() == WolfSSL.WOLFSSL_CLIENT_END){
                sniRequestArr = this.ssl.getClientSNIRequest();
            } else {
                sniRequestArr = this.ssl.getSNIRequestBytes((byte)WolfSSL.
                                            WOLFSSL_SNI_HOST_NAME);
            }

            if (sniRequestArr != null) {
                List<SNIServerName> sniNames = new ArrayList<>(1);
                SNIHostName sniName = new SNIHostName(sniRequestArr);
                sniNames.add(sniName);
                this.sniServerNames = new ArrayList<SNIServerName>(sniNames);

                return sniNames;
            }
        } catch (IllegalArgumentException e) {
            throw new UnsupportedOperationException(e);
        }

        if (this.sniServerNames != null && !this.sniServerNames.isEmpty()) {
            return Collections.unmodifiableList(
                new ArrayList<SNIServerName>(this.sniServerNames));
        }

        return Collections.emptyList();
    }

    @SuppressWarnings("deprecation")
    @Override
    protected synchronized void finalize() throws Throwable
    {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered finalize(): this.sesPtr = " + this.sesPtr);

        /* Only grab lock and free session if sesPtr not 0/null to prevent
         * garbage collector from backing up unnecessarily waiting on lock */
        if (this.sesPtr != 0) {
            synchronized (sesPtrLock) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "got sesPtrLock: " + this.sesPtr);

                /* Our internal WOLFSSL_SESSION pointer should be freed in
                 * the following scenarios:
                 *
                 * 1. This object is currently in the WolfSSLAuthStore session
                 *    cache table (store), OR
                 * 2. This object is NOT in the WolfSSLAuthStore session cache
                 *    table AND the sesPtr has been updated after we copied
                 *    the object out of the cache table.
                 */
                if (this.isInTable ||
                    (!this.isInTable && this.sesPtrUpdatedAfterTable)) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                       () -> "calling WolfSSLSession.freeSession(this.sesPtr)");
                    WolfSSLSession.freeSession(this.sesPtr);
                    this.sesPtr = 0;
                }
            }
        } /* synchronized sesPtr */

        super.finalize();
    }

    /**
     * Return hash code for this SSLSession.
     *
     * Hash code is computed from session ID, host, port, and creation time
     * to handle cases where session ID may be null or empty (such as with
     * TLS 1.3 session tickets before resumption, or error conditions).
     *
     * @return hash code for this SSLSession
     */
    @Override
    public int hashCode() {

        byte[] id = getId();

        return Objects.hash(
            id == null ? 0 : Arrays.hashCode(id), host, port, creation);
    }

    /**
     * Compares this SSLSession with another object for equality.
     *
     * Two WolfSSLImplementSSLSession objects are considered equal if they
     * have the same session ID, host, port, and creation time. This method
     * maintains the general contract with hashCode() as required by
     * Object.equals().
     *
     * @param obj the object to compare with
     * @return true if the objects are equal, false otherwise
     */
    @Override
    public boolean equals(Object obj) {

        WolfSSLImplementSSLSession other;

        if (this == obj) {
            return true;
        }

        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }

        other = (WolfSSLImplementSSLSession) obj;

        return Objects.deepEquals(this.getId(), other.getId())
            && Objects.equals(this.host, other.host)
            && this.port == other.port
            && Objects.equals(this.creation, other.creation);
    }
}
