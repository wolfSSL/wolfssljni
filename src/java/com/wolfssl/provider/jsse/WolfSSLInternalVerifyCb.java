/* WolfSSLInternalVerifyCb.java
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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
import com.wolfssl.WolfSSLVerifyCallback;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLSession;
import com.wolfssl.WolfSSLCertificate;
import com.wolfssl.WolfSSLX509StoreCtx;
import com.wolfssl.provider.jsse.WolfSSLInternalVerifyCb;
import java.util.Arrays;
import java.util.List;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.SSLHandshakeException;
import java.io.IOException;

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

    /**
     * Create new WolfSSLInternalVerifyCb
     *
     * @param xtm X509TrustManager to use with this object
     * @param client boolean representing if this is client side
     */
    public WolfSSLInternalVerifyCb(X509TrustManager xtm, boolean client) {
        this.tm = xtm;
        this.clientMode = client;
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
        X509Certificate[] x509certs = null;
        String authType = null;

        if (preverify_ok == 1) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "Native wolfSSL peer verification passed");
        } else {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "NOTE: Native wolfSSL peer verification failed");
        }

        try {
            /* get WolfSSLCertificate[] from x509StorePtr */
            WolfSSLX509StoreCtx store =
                new WolfSSLX509StoreCtx(x509StorePtr);
            certs = store.getCerts();

        } catch (WolfSSLException e) {
            /* failed to get certs from native, give app null array */
            certs = null;
        }

        if (certs != null && certs.length > 0) {
            try {
                /* Convert WolfSSLCertificate[] to X509Certificate[] */
                x509certs = new X509Certificate[certs.length];
                for (int i = 0; i < certs.length; i++) {
                    x509certs[i] = certs[i].getX509Certificate();
                }
            } catch (CertificateException | IOException ce) {
                /* failed to get cert array, give app null array */
                x509certs = null;
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

            /* Free native WolfSSLCertificate memory. At this
             * point x509certs[] is all Java managed memory now. */
            for (int i = 0; i < certs.length; i++) {
                certs[i].free();
            }
        }

        try {
            /* poll TrustManager for cert verification, should throw
             * CertificateException if verification fails */
            if (clientMode) {
                tm.checkServerTrusted(x509certs, authType);
            } else {
                tm.checkClientTrusted(x509certs, authType);
            }
        } catch (Exception e) {
            /* TrustManager rejected certificate, not valid */
            return 0;
        }

        /* continue handshake, verification succeeded */
        return 1;
    }
}

