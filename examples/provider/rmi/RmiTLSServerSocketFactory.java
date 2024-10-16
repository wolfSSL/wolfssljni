/* RmiTLSServerSocketFactory.java
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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

import java.rmi.server.RMIServerSocketFactory;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.net.ServerSocket;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

public class RmiTLSServerSocketFactory implements RMIServerSocketFactory
{
    /* Create one SSLServerSocketFactory */
    private SSLServerSocketFactory sf = null;

    public RmiTLSServerSocketFactory() {

        /* Keystore holding server key and cert */
        String serverJKS = "../provider/server.jks";
        String serverPass = "wolfSSL test";
        /* Keystore holding CA certs to verify client */
        String caJKS = "../provider/ca-client.jks";
        String caPass = "wolfSSL test";
        String keystoreFormat = "JKS";

        /* TLS protocol version - "TLS" uses highest compiled in */
        String tlsVersion = "TLS";

        SSLContext ctx;
        TrustManagerFactory tm;
        KeyManagerFactory km;
        KeyStore cert, pKey;

        try {
            /* Create TrustManagerFactory with certs to verify peer */
            tm = TrustManagerFactory.getInstance("SunX509");
            cert = KeyStore.getInstance(keystoreFormat);
            cert.load(new FileInputStream(caJKS), caPass.toCharArray());
            tm.init(cert);
            System.out.println("Created server TrustManagerFactory");

            /* Create KeyManagerFactory with server cert/key */
            pKey = KeyStore.getInstance(keystoreFormat);
            pKey.load(new FileInputStream(serverJKS), serverPass.toCharArray());
            km = KeyManagerFactory.getInstance("SunX509");
            km.init(pKey, serverPass.toCharArray());
            System.out.println("Created server KeyManagerFactory");

            /* Create SSLContext, doing peer auth */
            ctx = SSLContext.getInstance(tlsVersion);
            ctx.init(km.getKeyManagers(), tm.getTrustManagers(), null);
            System.out.println("Created server SSLContext");

            /* Create SocketFactory */
            sf = (SSLServerSocketFactory)ctx.getServerSocketFactory();
            System.out.println("Created server SSLServerSocketFactory");

        } catch (Exception e) {
            System.out.println("Exception when creating server SocketFactory");
            e.printStackTrace();
        }
    }

    public ServerSocket createServerSocket(int port) throws IOException {

        if (sf == null) {
            return null;
        }

        System.out.println("Creating server Socket");
        return (ServerSocket)sf.createServerSocket(port);

    }

    public int hashCode() {
        return getClass().hashCode();
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        else if (obj == null || (obj.getClass() != getClass())) {
            return false;
        }
        return true;
    }
}


