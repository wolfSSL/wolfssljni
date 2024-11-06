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
    SocketFactory sf = null;

    public RmiTLSClientSocketFactory(SocketFactory sf) {
        this.sf = sf;
    }

    public Socket createSocket(String host, int port) throws IOException {

        if (this.sf == null) {
            return null;
        }

        System.out.println("Creating client Socket");
        return sf.createSocket(host, port);
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

