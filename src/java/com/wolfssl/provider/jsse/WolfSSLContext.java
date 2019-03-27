/* WolfSSLContext.java
 *
 * Copyright (C) 2006-2018 wolfSSL Inc.
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
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.security.SecureRandom;

import com.wolfssl.provider.jsse.WolfSSLAuthStore.TLS_VERSION;

import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLJNIException;
import java.io.ByteArrayOutputStream;

import java.lang.IllegalArgumentException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLParameters;

public class WolfSSLContext extends SSLContextSpi {

    private TLS_VERSION currentVersion = TLS_VERSION.SSLv23;
    private WolfSSLAuthStore authStore = null;
    private com.wolfssl.WolfSSLContext ctx = null;
    private SSLParameters params = null;
    private WolfSSLDebug debug;
    
    private WolfSSLContext(TLS_VERSION version) {
        this.currentVersion = version;
    }

    private void createCtx() throws WolfSSLException {
        long method = 0;

        switch (this.currentVersion) {
            case TLSv1:
                method = WolfSSL.TLSv1_Method();
                break;
            case TLSv1_1:
                method = WolfSSL.TLSv1_1_Method();
                break;
            case TLSv1_2:
                method = WolfSSL.TLSv1_2_Method();
                break;
            case SSLv23:
                method = WolfSSL.SSLv23_Method();
                break;
            default:
                throw new IllegalArgumentException(
                    "Invalid SSL/TLS protocol version");
        }

        if (method == WolfSSL.NOT_COMPILED_IN) {
            throw new IllegalArgumentException("Protocol version not " +
                "compiled into native wolfSSL library");
        }
        ctx = new com.wolfssl.WolfSSLContext(method);

        if (debug.DEBUG) {
            log("created new native WOLFSSL_CTX");
        }

        try {
            LoadTrustedRootCerts();
            LoadClientKeyAndCertChain();

        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }

        /* auto-populate enabled ciphersuites with supported ones */
        params.setCipherSuites(WolfSSL.getCiphersIana());
    }
    
    private void LoadTrustedRootCerts() {

        int loadedCACount = 0;

        /* extract root certs from X509TrustManager */
        X509TrustManager tm = authStore.getX509TrustManager();
        X509Certificate[] caList =  tm.getAcceptedIssuers();

        for (int i = 0; i < caList.length; i++) {

            try {
                byte[] derCert = caList[i].getEncoded();

                ctx.loadVerifyBuffer(derCert, derCert.length,
                    WolfSSL.SSL_FILETYPE_ASN1);

                loadedCACount++;

            } catch (CertificateEncodingException ce) {
                /* skip loading if encoding error is encountered */
            } catch (WolfSSLJNIException we) {
                /* skip loading if wolfSSL fails to load der encoding */
            }

            if (loadedCACount == 0) {
                throw new IllegalArgumentException("wolfSSL failed to load " +
                    "any trusted CA certificates from TrustManager");
            }

            if (debug.DEBUG) {
                log("loaded trusted root certs from TrustManager");
            }
        }
    }

    private void LoadClientKeyAndCertChain() throws Exception {

        int ret, offset;
        X509KeyManager km = authStore.getX509KeyManager();

        /* We only load keys from algorithms enabled in native wolfSSL,
         * and in the priority order of ECC first, then RSA */
        ArrayList<String> keyAlgos = new ArrayList<String>();
        if (WolfSSL.EccEnabled()) {
            keyAlgos.add("EC");
        }
        if (WolfSSL.RsaEnabled()) {
            keyAlgos.add("RSA");
        }

        String[] keyStrings = new String[keyAlgos.size()];
        keyStrings = keyAlgos.toArray(keyStrings);

        String alias = km.chooseClientAlias(keyStrings, null, null);
        authStore.setCertAlias(alias);

        /* client private key */
        PrivateKey privKey = km.getPrivateKey(alias);
        byte[] privKeyEncoded = privKey.getEncoded();
        if (!privKey.getFormat().equals("PKCS#8")) {
            throw new Exception("Private key is not in PKCS#8 format");
        }

        /* skip past PKCS#8 offset */
        offset = WolfSSL.getPkcs8TraditionalOffset(privKeyEncoded, 0,
            privKeyEncoded.length);

        byte[] privKeyTraditional = Arrays.copyOfRange(privKeyEncoded,
            offset, privKeyEncoded.length);

        ret = ctx.usePrivateKeyBuffer(privKeyTraditional,
            privKeyTraditional.length, WolfSSL.SSL_FILETYPE_ASN1);

        if (ret != WolfSSL.SSL_SUCCESS) {
            throw new WolfSSLJNIException("Failed to load private key " +
                "buffer, err = " + ret);
        }

        if (debug.DEBUG) {
            log("loaded private key from KeyManager (alias: " + alias + ")");
        }

        /* client certificate chain */
        X509Certificate[] cert = km.getCertificateChain(alias);
        ByteArrayOutputStream certStream = new ByteArrayOutputStream();
        int chainLength = 0;
        for (int i = 0; i < cert.length; i++) {
            /* concatenate certs into single byte array */
            certStream.write(cert[i].getEncoded());
            chainLength++;
        }
        byte certChain[] = certStream.toByteArray();

        ret = ctx.useCertificateChainBufferFormat(certChain,
            certChain.length, WolfSSL.SSL_FILETYPE_ASN1);

        if (ret != WolfSSL.SSL_SUCCESS) {
            throw new WolfSSLJNIException("Failed to load certificate " +
                "chain buffer, err = " + ret);
        }

        if (debug.DEBUG) {
            log("loaded certificate chain from KeyManager (length: " +
                chainLength + ")");
        }
    }

    @Override
    protected void engineInit(KeyManager[] km, TrustManager[] tm,
        SecureRandom sr) throws KeyManagementException {

        try {
            authStore = new WolfSSLAuthStore(km, tm, sr, currentVersion);
            params = new SSLParameters();
            createCtx();
        } catch (IllegalArgumentException iae) {
            throw new KeyManagementException(iae);
        }
        catch (WolfSSLException we) {
            throw new KeyManagementException(we);
        }
    }

    @Override
    protected SSLSocketFactory engineGetSocketFactory()
        throws IllegalStateException {

        if (authStore == null) {
            throw new IllegalStateException("SSLContext must be initialized " +
                "before use, please call init()");
        }

        return new WolfSSLSocketFactory(this.ctx, authStore, params);
    }

    @Override
    protected SSLServerSocketFactory engineGetServerSocketFactory() {

        if (authStore == null) {
            throw new IllegalStateException("SSLContext must be initialized " +
                "before use, please call init()");
        }

        return new WolfSSLServerSocketFactory(this.ctx, this.authStore,
            this.params);
    }

    @Override
    protected SSLEngine engineCreateSSLEngine() {

        if (authStore == null) {
            throw new IllegalStateException("SSLContext must be initialized " +
                "before use, please call init()");
        }

        try {
            return new WolfSSLEngine(this.ctx, this.authStore, this.params);
        } catch (WolfSSLException ex) {
            Logger.getLogger(WolfSSLContext.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    protected SSLEngine engineCreateSSLEngine(String host, int port) {

        if (authStore == null) {
            throw new IllegalStateException("SSLContext must be initialized " +
                "before use, please call init()");
        }

        try {
            return new WolfSSLEngine(this.ctx, this.authStore, this.params, host, port);
        } catch (WolfSSLException ex) {
            Logger.getLogger(WolfSSLContext.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    protected SSLSessionContext engineGetServerSessionContext() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    protected SSLSessionContext engineGetClientSessionContext() {
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    public static final class TLSV1_Context extends WolfSSLContext {
        public TLSV1_Context() {
            super(TLS_VERSION.TLSv1);
        }
    }
    
    public static final class TLSV11_Context extends WolfSSLContext {
        public TLSV11_Context() {
            super(TLS_VERSION.TLSv1_1);
        }
    }
    
    public static final class TLSV12_Context extends WolfSSLContext {
        public TLSV12_Context() {
            super(TLS_VERSION.TLSv1_2);
        }
    }
    
    public static final class TLSV23_Context extends WolfSSLContext {
        public TLSV23_Context() {
            super(TLS_VERSION.SSLv23);
        }
    }

    private void log(String msg) {
        debug.print("[WolfSSLContext] " + msg);
    }
}
