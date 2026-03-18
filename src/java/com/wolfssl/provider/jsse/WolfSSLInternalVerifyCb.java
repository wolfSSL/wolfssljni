/* WolfSSLInternalVerifyCb.java
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
import com.wolfssl.WolfSSLVerifyCallback;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLJNIException;
import com.wolfssl.WolfSSLCertificate;
import com.wolfssl.WolfSSLX509StoreCtx;
import com.wolfssl.provider.jsse.WolfSSLInternalVerifyCb;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.lang.ref.WeakReference;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Internal verify callback.
 * This is used when a user registers a TrustManager which is NOT
 * com.wolfssl.provider.jsse.WolfSSLTrustManager. It is used to call
 * TrustManager checkClientTrusted() or checkServerTrusted().
 * If wolfJSSE TrustManager is used, native wolfSSL does certificate
 * verification internally. Used by WolfSSLEngineHelper.
 */
public class WolfSSLInternalVerifyCb implements WolfSSLVerifyCallback {

    private X509TrustManager tm = null;
    private boolean clientMode;
    private WolfSSLParameters params = null;

    /* Use WeakReference for SSLSocket and SSLEngine to avoid
     * holding back garbage collection of WolfSSLSocket/WolfSSLEngine
     * objects */
    private WeakReference<SSLSocket> callingSocket = null;
    private WeakReference<SSLEngine> callingEngine = null;

    /* TrustManager exception for SSLHandshakeException cause chain */
    private Exception verifyException = null;

    /**
     * Create new WolfSSLInternalVerifyCb
     *
     * @param xtm X509TrustManager to use with this object
     * @param client boolean representing if this is client side
     * @param socket SSLSocket associated with this callback, or null
     * @param engine SSLEngine associated with this callback, or null
     * @param params WolfSSLParameters associated with this callback
     */
    public WolfSSLInternalVerifyCb(X509TrustManager xtm, boolean client,
        SSLSocket socket, SSLEngine engine, WolfSSLParameters params) {
        this.tm = xtm;
        this.clientMode = client;
        this.params = params;

        if (socket != null) {
            this.callingSocket = new WeakReference<>(socket);
        } else {
            this.callingSocket = null;
        }

        if (engine != null) {
            this.callingEngine = new WeakReference<>(engine);
        } else {
            this.callingEngine = null;
        }
    }

    /**
     * Reset internal variables back to null/default.
     */
    protected void clearInternalVars() {
        this.callingSocket = null;
        this.callingEngine = null;
        this.params = null;
        this.tm = null;
        this.verifyException = null;
    }

    /**
     * Get the last exception thrown by the TrustManager during
     * certificate verification. Returns null if verification succeeded
     * or no verification has occurred.
     *
     * @return Exception from last failed verification, or null
     */
    public Exception getVerifyException() {
        return this.verifyException;
    }

    /**
     * Verify hostname of provided peer certificate using
     * Endpoint Identification Algorithm if set in SSLParameters.
     *
     * Used by verifyCallback() only for case where internal native wolfSSL
     * peer verification is done. Otherwise, hostname is verified as part
     * of full cert validation later in verifyCallback().
     *
     * @param peer peer certificate to use for hostname verification
     *
     * @return 1 if hostname verification was successful (allows verify
     *         callback to proceed, otherwise 0 if verification was not
     *         successful (or not able to do it since Endpoitn Identification
     *         Algorithm has not been set).
     */
    private int verifyHostnameOnly(X509Certificate peer) {

        WolfSSLTrustX509 wolfTM = (WolfSSLTrustX509)tm;

        try {
            SSLSocket sock = (this.callingSocket != null) ?
                this.callingSocket.get() : null;
            SSLEngine eng = (this.callingEngine != null) ?
                this.callingEngine.get() : null;

            if (sock != null) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "checking hostname verification using SSLSocket");

                /* Throws CertificateException when verify fails */
                wolfTM.verifyHostname(peer, sock, null, clientMode);
            }
            else if (eng != null) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "checking hostname verification using SSLEngine");

                /* Throws CertificateException when verify fails */
                wolfTM.verifyHostname(peer, null, eng, clientMode);
            }
            else {
                /* SSLSocket/SSLEngine null. Fail if endpoint ID
                 * is set, otherwise skip hostname verification. */
                String eia = null;
                if (this.params != null) {
                    eia = this.params.getEndpointIdentificationAlgorithm();
                }
                if (eia != null && !eia.isEmpty()) {
                    throw new CertificateException(
                        "Both SSLSocket and SSLEngine null, cannot " +
                        "perform hostname verification for " +
                        "endpoint identification algorithm: " + eia);
                }
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "Both SSLSocket and SSLEngine null, skipping " +
                    "hostname verification (native verify already " +
                    "passed, no endpoint identification configured)");
            }
        } catch (CertificateException e) {
            this.verifyException = e;
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "X509ExtendedTrustManager hostname verification " +
                "failed: " + e.getMessage());
            return 0;
        }

        /* Hostname verification successful */
        return 1;
    }

    /**
     * Verify hostname for basic X509TrustManager when Endpoint
     * Identification Algorithm is set. Matches SunJSSE behavior.
     *
     * @param peer peer certificate to verify hostname against
     *
     * @return 1 if passed or not needed, 0 if failed
     */
    private int verifyHostnameForExternalTM(X509Certificate peer) {

        String endpointIdAlgo = null;
        String peerHost = null;
        SSLSession session = null;

        /* Get endpoint identification algorithm from params */
        if (this.params != null) {
            endpointIdAlgo = this.params.getEndpointIdentificationAlgorithm();
        }

        /* If no endpoint identification algorithm set, skip hostname
         * verification - it has not been requested */
        if (endpointIdAlgo == null || endpointIdAlgo.isEmpty()) {
            return 1;
        }

        /* Only HTTPS and LDAPS are supported. Fail if endpoint ID was
         * explicitly set to something else (typo or unsupported algo). */
        if (!endpointIdAlgo.equals("HTTPS") &&
            !endpointIdAlgo.equals("LDAPS")) {
            final String tmpAlgoUnsup = endpointIdAlgo;
            this.verifyException = new CertificateException(
                "Unsupported endpoint identification algorithm: " +
                endpointIdAlgo);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "Unsupported endpoint identification algorithm: "
                    + tmpAlgoUnsup);
            return 0;
        }

        final String tmpAlgo = endpointIdAlgo;
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "Provider-level hostname verification, algorithm: " +
            tmpAlgo);

        /* Get peer host from SSLEngine or SSLSocket handshake session */
        try {
            SSLEngine eng = (this.callingEngine != null) ?
                this.callingEngine.get() : null;
            SSLSocket sock = (this.callingSocket != null) ?
                this.callingSocket.get() : null;

            if (eng != null) {
                session = eng.getHandshakeSession();
            }
            else if (sock != null) {
                session = sock.getHandshakeSession();
            }
        } catch (UnsupportedOperationException e) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "getHandshakeSession() not supported: " + e.getMessage());
            CertificateException ce = new CertificateException(
                "getHandshakeSession() not supported: " + e.getMessage());
            ce.initCause(e);
            this.verifyException = ce;
            return 0;
        }

        /* Prefer SNI hostname from SSLParameters over session peer host.
         * session.getPeerHost() returns the IP address (e.g. 127.0.0.1),
         * but for SNI verification we need the logical hostname the client
         * requested (e.g. "something.netty.io"). */
        if (this.params != null) {
            List<WolfSSLSNIServerName> sniNames =
                this.params.getWolfSSLServerNames();
            if (sniNames != null && !sniNames.isEmpty()) {
                for (WolfSSLSNIServerName sni : sniNames) {
                    /* Type 0 = host_name (RFC 6066) */
                    if (sni.getType() == 0) {
                        byte[] encoded = sni.getEncoded();
                        if (encoded != null && encoded.length > 0) {
                            peerHost = new String(encoded,
                                StandardCharsets.US_ASCII);
                        }
                        break;
                    }
                }
            }
        }

        /* Fall back to session peer host if no SNI hostname */
        if (peerHost == null || peerHost.isEmpty()) {
            if (session != null) {
                peerHost = session.getPeerHost();
            }
        }

        if (peerHost == null || peerHost.isEmpty()) {
            this.verifyException = new CertificateException(
                "No peer host available for hostname verification");
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "No peer host available for hostname verification");
            /* No peer host to verify against, fail verification since
             * endpoint identification was explicitly requested */
            return 0;
        }

        /* Verify hostname against certificate SAN/CN using native
         * wolfSSL X509_check_host() */
        final String tmpHost = peerHost;
        WolfSSLCertificate wCert = null;
        try {
            wCert = new WolfSSLCertificate(peer.getEncoded());
            int ret = wCert.checkHost(peerHost);
            if (ret == WolfSSL.SSL_SUCCESS) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "Provider-level hostname verification " +
                        "passed for: " + tmpHost);
                return 1;
            } else {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "Provider-level hostname verification " +
                        "FAILED for: " + tmpHost);
                this.verifyException = new CertificateException(
                    "Hostname verification failed for: " + tmpHost);
                return 0;
            }
        } catch (Exception e) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "Hostname verification error: " + e.getMessage());
            this.verifyException = e;
            return 0;
        } finally {
            if (wCert != null) {
                wCert.free();
            }
        }
    }

    /**
     * Calls registered X509TrustManager / X509ExtendedTrustManager to
     * verify certificate chain.
     *
     * @param certs Peer certificate chain to validate
     * @param authType Authentication type
     *
     * @return true on successful validation, otherwise false on failure
     */
    private boolean VerifyCertChainWithTrustManager(X509Certificate[] certs,
        String authType) {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "Verifying peer with X509TrustManager: " + this.tm);
        if (this.tm instanceof X509ExtendedTrustManager) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "X509TrustManager of type X509ExtendedTrustManager");
        }
        else {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "X509TrustManager of type X509TrustManager");
        }

        try {
            /* Call TrustManager to do cert verification, should throw
             * CertificateException if verification fails */
            SSLSocket sock = (this.callingSocket != null) ?
                this.callingSocket.get() : null;
            SSLEngine eng = (this.callingEngine != null) ?
                this.callingEngine.get() : null;

            if (this.clientMode) {
                if (this.tm instanceof X509ExtendedTrustManager) {
                    X509ExtendedTrustManager xtm =
                        (X509ExtendedTrustManager)this.tm;

                    if (sock != null) {
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                          () -> "Calling TrustManager.checkServerTrusted(" +
                          "SSLSocket)");

                        xtm.checkServerTrusted(certs, authType, sock);
                    }
                    else if (eng != null) {
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                          () -> "Calling TrustManager.checkServerTrusted(" +
                          "SSLEngine)");

                        xtm.checkServerTrusted(certs, authType, eng);
                    }
                    else {
                        /* If we do have access to X509ExtendedTrustManager,
                         * but don't have SSLSocket/Engine, error out instead
                         * of falling back to verify without hostname. */
                        throw new Exception(
                            "SSLSocket/SSLEngine null during server peer " +
                            "verification, failed to verify");
                    }
                }
                else {
                    /* Basic X509TrustManager does not support HTTPS
                     * hostname verification, no SSLSocket/Engine needed */
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "Calling TrustManager.checkServerTrusted()");
                    this.tm.checkServerTrusted(certs, authType);
                }

            } else {
                if (this.tm instanceof X509ExtendedTrustManager) {
                    X509ExtendedTrustManager xtm =
                        (X509ExtendedTrustManager)this.tm;

                    if (sock != null) {
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                          () -> "Calling TrustManager.checkClientTrusted(" +
                          "SSLSocket)");

                        xtm.checkClientTrusted(certs, authType, sock);
                    }
                    else if (eng != null) {
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                          () -> "Calling TrustManager.checkClientTrusted(" +
                          "SSLEngine)");

                        xtm.checkClientTrusted(certs, authType, eng);
                    }
                    else {
                        /* If we do have access to X509ExtendedTrustManager,
                         * but don't have SSLSocket/Engine, error out instead
                         * of falling back to verify without hostname. */
                        throw new Exception(
                            "SSLSocket/SSLEngine null during client peer " +
                            "verification, failed to verify");
                    }
                }
                else {
                    /* Basic X509TrustManager does not support HTTPS
                     * hostname verification, no SSLSocket/Engine needed */
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "Calling TrustManager.checkClientTrusted()");
                    this.tm.checkClientTrusted(certs, authType);
                }
            }
        } catch (Exception e) {
            /* Store for SSLHandshakeException cause chain */
            this.verifyException = e;
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "TrustManager rejected certificates, " +
                "verification failed: " + e.getMessage());
            return false;
        }

        return true;
    }

    /**
     * Native wolfSSL verify callback.
     *
     * @param preverify_ok Will be 1 if native wolfSSL verification
     *        procedured have passed, otherwise 0.
     * @param x509StorePtr Native pointer to WOLFSSL_X509_STORE structure
     *
     * @return 1 if verification should be considered successful and
     *         SSL/TLS handshake should continue. Otherwise return 0
     *         to mark verification failure and stop/abort handshake.
     */
    public int verifyCallback(int preverify_ok, long x509StorePtr) {

        WolfSSLCertificate[] certs = null;
        String authType = null;
        X509Certificate[] x509certs = new X509Certificate[0];

        /* Clear any prior callback failure so callers don't see stale causes
         * if this callback instance is reused across handshakes. */
        this.verifyException = null;

        if (preverify_ok == 1) {
            /* When using WolfSSLTrustX509 implementation of
             * X509TrustManager, we use internal wolfSSL verification logic
             * but register this verify callback (always called) so that
             * we can do additional hostname verification if user has set
             * the Endpoint Identification Algorithm in SSLParameters.
             * Note that certificate verification has already been done and
             * passed if preverify_ok == 1, so we skip doing it again here
             * later on for this case */
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "Native wolfSSL peer verification passed (clientMode: " +
                this.clientMode + ")");
        } else {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "NOTE: Native wolfSSL peer verification failed " +
                "(clientMode: " + this.clientMode + ")");
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "      Continuing with X509TrustManager verification");
        }

        try {
            /* Get WolfSSLCertificate[] from x509StorePtr, certs from
             * store.getCerts() should be listed in order of peer to root */
            WolfSSLX509StoreCtx store =
                new WolfSSLX509StoreCtx(x509StorePtr);
            certs = store.getCerts();

        } catch (WolfSSLException e) {
            /* failed to get certs from native, give app null array */
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "Failed to get certs from x509StorePtr, certs = null: " +
                e.getMessage());
            certs = null;
        }

        if (certs != null && certs.length > 0) {
            try {
                /* Convert WolfSSLCertificate[] to X509Certificate[] */
                x509certs = new X509Certificate[certs.length];
                for (int i = 0; i < certs.length; i++) {
                    x509certs[i] = certs[i].getX509Certificate();
                    final String tmpName =
                        x509certs[i].getSubjectDN().getName();
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "Peer cert: " + tmpName);
                }
            } catch (CertificateException | IOException |
                     WolfSSLJNIException ce) {
                /* failed to get cert array, give app empty array */
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "Failed to get X509Certificate[] array, set to " +
                    "empty array: " + ce.getMessage());
                x509certs = new X509Certificate[0];
            }

            /* get authType, use first cert */
            String sigType = certs[0].getSignatureType();
            if (sigType.contains("RSA")) {
                authType = "RSA";
            } else if (sigType.contains("ECDSA")) {
                authType = "ECDSA";
            } else if (sigType.contains("DSA")) {
                authType = "DSA";
            } else if (sigType.contains("ED25519")) {
                authType = "ED25519";
            }
            final String tmpAuthType = authType;
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "Auth type: " + tmpAuthType);

            /* Free native WolfSSLCertificate memory. At this
             * point x509certs[] is all Java managed memory now. */
            for (int i = 0; i < certs.length; i++) {
                certs[i].free();
            }
        }

        /* Case where native wolfSSL verification was already done and passed
         * and we only want to do hostname verification if needed additionally.
         * We do that here and return before going on to additional
         * checkServerTrusted/checkClientTrusted() so that we do not
         * duplicate verification. */
        if ((preverify_ok == 1) && (x509certs.length > 0) &&
            (tm instanceof WolfSSLTrustX509)) {
            return verifyHostnameOnly(x509certs[0]);
        }

        /* If server-side application has explicitly disabled client
         * authentication (neither needClientAuth nor wantClientAuth set),
         * return as success and skip X509TrustManager verification. */
        if ((!this.clientMode) && (this.params != null) &&
            (!this.params.getNeedClientAuth()) &&
            (!this.params.getWantClientAuth())) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "Application has disabled client verification " +
                "(needClientAuth=false, wantClientAuth=false), " +
                "skipping verification");
            return 1;
        }
        else if ((x509certs.length == 0) &&
            (!this.clientMode) && (this.params != null) &&
            this.params.getWantClientAuth() &&
            (!this.params.getNeedClientAuth())) {
            /* No peer certificates sent and client authentication is
             * optional (wantClientAuth == true, needClientAuth == false).
             * Don't call TrustManager with empty certificate chain,
             * just consider verification successful. Don't require
             * preverify_ok == 1 here since native wolfSSL may report
             * failure when no CAs are loaded (foreign TrustManager). */
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "No client cert sent and client auth marked optional, " +
                "not calling TrustManager for hostname verification");
        }
        else if ((!this.clientMode) && (this.params != null) &&
            this.params.getWantClientAuth() &&
            (!this.params.getNeedClientAuth())) {
            /* wantClientAuth is set and client sent a certificate.
             * Try to verify via TrustManager, but don't fail the
             * handshake if verification fails — matches SunJSSE
             * behavior where wantClientAuth is non-fatal. */
            if (VerifyCertChainWithTrustManager(x509certs, authType)) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "wantClientAuth: client cert verified successfully");
            } else {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "wantClientAuth: client cert verification failed, " +
                    "continuing handshake (non-fatal)");
            }
        }
        else {
            /* Poll X509TrustManager / X509ExtendedTrustManager for certificate
             * verification status. Returns 0 if certificates are rejected,
             * otherwise 1 on successful verification */
            if (VerifyCertChainWithTrustManager(x509certs, authType) == false) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "TrustManager verification failed");
                /* Abort handshake, verification failed */
                return 0;
            }
        }

        /* Provider-level hostname verify for basic X509TrustManager
         * (X509ExtendedTrustManager handles it internally) */
        if (!(tm instanceof WolfSSLTrustX509) &&
            !(tm instanceof X509ExtendedTrustManager) &&
            this.clientMode && x509certs.length > 0) {
            if (verifyHostnameForExternalTM(x509certs[0]) == 0) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "Provider-level hostname verification failed");
                return 0;
            }
        }

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "TrustManager verification successful");

        /* Continue handshake, verification succeeded */
        return 1;
    }
}
