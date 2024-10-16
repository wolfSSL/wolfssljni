/* RmiTLSClientSocketFactory.java
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

import java.rmi.server.RMIClientSocketFactory;
import java.io.Serializable;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.net.Socket;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLContext;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

public class RmiTLSClientSocketFactory
    implements RMIClientSocketFactory, Serializable
{

    public RmiTLSClientSocketFactory() {
    }

    public Socket createSocket(String host, int port) throws IOException {

        /* Keystore holding client key and cert */
        String clientJKS = "../provider/client.jks";
        String clientPass = "wolfSSL test";
        /* Keystore holding CA certs to verify server */
        String caJKS = "../provider/ca-server.jks";
        String caPass = "wolfSSL test";
        String keystoreFormat = "JKS";

        /* TLS protocol version - "TLS" uses highest compiled in */
        String tlsVersion = "TLS";

        SSLContext ctx;
        TrustManagerFactory tm;
        KeyManagerFactory km;
        KeyStore cert, pKey;
        SocketFactory sf = null;

        try {
            /* Create TrustManagerFactory with certs to verify peer */
            tm = TrustManagerFactory.getInstance("SunX509");
            cert = KeyStore.getInstance(keystoreFormat);
            cert.load(new FileInputStream(caJKS), caPass.toCharArray());
            tm.init(cert);
            System.out.println("Created client TrustManagerFactory");

            /* Create KeyManagerFactory with client cert/key */
            pKey = KeyStore.getInstance(keystoreFormat);
            pKey.load(new FileInputStream(clientJKS), clientPass.toCharArray());
            km = KeyManagerFactory.getInstance("SunX509");
            km.init(pKey, clientPass.toCharArray());
            System.out.println("Created client KeyManagerFactory");

            /* Create SSLContext, doing peer auth */
            ctx = SSLContext.getInstance(tlsVersion);
            ctx.init(km.getKeyManagers(), tm.getTrustManagers(), null);
            System.out.println("Created client SSLContext");

            /* Create SocketFactory */
            sf = ctx.getSocketFactory();
            System.out.println("Created client SocketFactory");

        } catch (Exception e) {
            System.out.println("Exception when creating client SocketFactory");
            e.printStackTrace();
        }

        System.out.println("Creating client Socket");
        return (SSLSocket)sf.createSocket(host, port);
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

