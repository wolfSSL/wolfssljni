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

/* Internal verify callback. This is used when a user registers a
 * TrustManager which is NOT com.wolfssl.provider.jsse.WolfSSLTrustManager
 * and is used to call TrustManager checkClientTrusted() or
 * checkServerTrusted(). If wolfJSSE TrustManager is used, native wolfSSL
 * does certificate verification internally. Used by WolfSSLEngineHelper. */
public class WolfSSLInternalVerifyCb implements WolfSSLVerifyCallback {

    private X509TrustManager tm = null;
    private boolean clientMode;

    public WolfSSLInternalVerifyCb(X509TrustManager xtm, boolean client) {
        this.tm = xtm;
        this.clientMode = client;
    }

    public int verifyCallback(int preverify_ok, long x509StorePtr) {

        WolfSSLCertificate[] certs = null;
        X509Certificate[] x509certs = null;
        String authType = null;

        if (preverify_ok == 1) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "Native wolfSSL peer verification passed");
        } else {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "WARNING: Native wolfSSL peer verification failed!");
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

