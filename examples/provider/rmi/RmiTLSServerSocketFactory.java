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

    public RmiTLSServerSocketFactory(SSLServerSocketFactory sf) {
        this.sf = sf;
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


