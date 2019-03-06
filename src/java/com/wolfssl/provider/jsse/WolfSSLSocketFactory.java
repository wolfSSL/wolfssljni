/* WolfSSLSocketFactory.java
 *
 * Copyright (C) 2006-2019 wolfSSL Inc.
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

import java.util.ArrayList;
import java.io.InputStream;
import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.net.Socket;
import java.net.InetAddress;
import java.net.UnknownHostException;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.SecureRandom;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateEncodingException;

import com.wolfssl.provider.jsse.WolfSSLParameters.TLS_VERSION;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLContext;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLJNIException;


public class WolfSSLSocketFactory extends SSLSocketFactory {

    private WolfSSLParameters params = null;
    private WolfSSLContext ctx = null;

    public WolfSSLSocketFactory(WolfSSLParameters parameters)
        throws WolfSSLException {
        super();

        long method = 0;
        this.params = parameters;

        switch (params.getProtocolVersion()) {
            case TLSv1:
                method = WolfSSL.TLSv1_ClientMethod();
                break;
            case TLSv1_1:
                method = WolfSSL.TLSv1_1_ClientMethod();
                break;
            case TLSv1_2:
                method = WolfSSL.TLSv1_2_ClientMethod();
                break;
            case SSLv23:
                method = WolfSSL.SSLv23_ClientMethod();
                break;
            default:
                throw new IllegalArgumentException(
                    "Invalid SSL/TLS protocol version");
        }

        if (method == WolfSSL.NOT_COMPILED_IN) {
            throw new IllegalArgumentException("Protocol version not " +
                "compiled into native wolfSSL library");
        }
        ctx = new WolfSSLContext(method);

        try {
            LoadTrustedRootCerts();
            LoadClientKeyAndCertChain();

        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    private void LoadTrustedRootCerts() {

        int loadedCACount = 0;

        /* extract root certs from X509TrustManager */
        X509TrustManager tm = params.getX509TrustManager();
        X509Certificate[] caList =  tm.getAcceptedIssuers();

        for (int i = 0; i < caList.length; i++) {

            try {
                byte[] derCert = caList[i].getTBSCertificate();

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
        }
    }

    private void LoadClientKeyAndCertChain() throws Exception {

        X509KeyManager km = params.getX509KeyManager();

        /* We only load keys from algorithms enabled in native wolfSSL,
         * and in the priority order of ECC first, then RSA */
        ArrayList<String> keyAlgos = new ArrayList<String>();
        if (WolfSSL.EccEnabled()) {
            keyAlgos.add("ECC");
        }
        if (WolfSSL.RsaEnabled()) {
            keyAlgos.add("RSA");
        }

        String[] keyStrings = new String[keyAlgos.size()];
        keyStrings = keyAlgos.toArray(keyStrings);

        String alias = km.chooseClientAlias(keyStrings, null, null);
        params.setCertAlias(alias);

        /* client private key */
        PrivateKey privKey = km.getPrivateKey(alias);
        byte[] privKeyEncoded = privKey.getEncoded();
        if (!privKey.getFormat().equals("PKCS#8")) {
            throw new Exception("Private key is not in PKCS#8 format");
        }

        try {
            ctx.usePrivateKeyBuffer(privKeyEncoded, privKeyEncoded.length,
                WolfSSL.SSL_FILETYPE_ASN1);
        } catch (WolfSSLJNIException e) {
            throw new Exception("Error loading client private key");
        }

        /* client certificate chain */
        X509Certificate[] cert = km.getCertificateChain(alias);
        ByteArrayOutputStream certStream = new ByteArrayOutputStream();
        for (int i = 0; i < cert.length; i++) {
            /* concatenate certs into single byte array */
            certStream.write(cert[i].getTBSCertificate());
        }
        byte certChain[] = certStream.toByteArray();

        try {
            ctx.useCertificateChainBuffer(certChain, certChain.length);
        } catch (WolfSSLJNIException e) {
            throw new Exception("Error loading client certificate chain");
        }
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return WolfSSL.getCiphers();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return getDefaultCipherSuites();
    }

    @Override
    public Socket createSocket() throws IOException {
        return new WolfSSLSocket(ctx, params);
    }

    @Override
    public Socket createSocket(InetAddress host, int port)
        throws IOException {
        return new WolfSSLSocket(ctx, params, host, port);
    }

    @Override
    public Socket createSocket(InetAddress address, int port,
        InetAddress localAddress, int localPort) throws IOException {
        return new WolfSSLSocket(ctx, params, address, port,
            localAddress, localPort);
    }

    @Override
    public Socket createSocket(String host, int port)
        throws IOException, UnknownHostException {
        return new WolfSSLSocket(ctx, params, host, port);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost,
        int localPort) throws IOException, UnknownHostException {
        return new WolfSSLSocket(ctx, params, host, port, localHost, localPort);
    }

    @Override
    public Socket createSocket(Socket s, String host, int port,
        boolean autoClose) throws IOException {
        /* TODO */
        return null;
    }

    @Override
    public Socket createSocket(Socket s, InputStream consumed,
        boolean autoClose) throws IOException {
        /* TODO */
        return null;
    }
}

