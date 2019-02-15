/* WolfSSLContextTest.java
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

package com.wolfssl.provider.jsse.test;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

import java.security.Provider;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

public class server {
    public server(){}
    
    public void test_server() throws NoSuchAlgorithmException, KeyManagementException,
            IOException, KeyStoreException, CertificateException,
            UnrecoverableKeyException {
        SSLContext ctx = SSLContext.getInstance("TLSV1.2");
        KeyStore pKey, cert;
        TrustManagerFactory tm;
        KeyManagerFactory km;
        int port = 11111;
        Provider  p;
        SSLEngine e; 
        String ciphers[];
        char[] psw = "wolfSSL test".toCharArray();
        
        byte msg[] = "This is the JSSE".getBytes();
        ServerSocketFactory srv;
        ServerSocket tls;
        Socket sock;
        InputStream in;
        OutputStream out;
        
        pKey = KeyStore.getInstance("JKS");
        pKey.load(new FileInputStream("server.jks"), psw);
        cert = KeyStore.getInstance("JKS");
        cert.load(new FileInputStream("server.jks"), psw);
        
        /* trust manager (certificates) */
        tm = TrustManagerFactory.getInstance("SunX509");
        tm.init(cert);
        
        /* load private key */
        km = KeyManagerFactory.getInstance("SunX509");
        km.init(pKey, psw);
        
        /* setup context with certificate and private key */
        ctx.init(km.getKeyManagers(), tm.getTrustManagers(), null);
        
        /* print out information */
        System.out.printf("Found protocol %s\n", ctx.getProtocol());
        p = ctx.getProvider();
        System.out.printf("Provider name = %s\n", p.getName());
        e = ctx.createSSLEngine();
        ciphers = e.getSupportedCipherSuites();
        System.out.printf("Available cipher suites = %d\n", ciphers.length);
     
        /* listing and setting specific cipher suites */
//        int z = 0;
//        String ecdhe_rsa_ciphers[] = new String[3];
//        for (int i = 0; i < ciphers.length; i++) {
//            System.out.printf("\t%s\n", ciphers[i]);
//            if (ciphers[i].contains("ECDHE_RSA") && z < ecdhe_rsa_ciphers.length) {
//                ecdhe_rsa_ciphers[z++] =ciphers[i];
//            }
//        }
//        System.out.printf("Adding %d ciphers\n", ecdhe_rsa_ciphers.length);
//        e.setEnabledCipherSuites(ecdhe_rsa_ciphers);
        
        
        System.out.printf("Waiting for Client connection on port %d\n", port);
        srv = ctx.getServerSocketFactory();
        tls = srv.createServerSocket(port);
        sock = tls.accept();
        in = sock.getInputStream();
        in.read(); /* drop input */
        out = sock.getOutputStream();
        out.write(msg);
 

    }
    
    public static void main(String[] args) {
        server t = new server();
        try {
            t.test_server();
        } catch (Exception ex) {
            Logger.getLogger(server.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}