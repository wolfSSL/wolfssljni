/* MyRecvCallback.java
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
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

import java.io.*;
import java.net.*;
import java.nio.*;
import com.wolfssl.*;

class MyRecvCallback implements WolfSSLIORecvCallback
{
    public int receiveCallback(WolfSSLSession ssl, byte[] buf, int sz,
            Object ctx) {

        MyIOCtx ioctx = (MyIOCtx) ctx;
        int doDTLS = ioctx.isDTLS();

        if (doDTLS == 1) {

            int dtlsTimeout;
            DatagramSocket dsock;
            DatagramPacket recvPacket;

            try {
                dtlsTimeout = ssl.dtlsGetCurrentTimeout() * 1000;
                dsock = ioctx.getDatagramSocket();
                dsock.setSoTimeout(dtlsTimeout);
                recvPacket = new DatagramPacket(buf, sz);

                dsock.receive(recvPacket);

                ioctx.setAddress(recvPacket.getAddress());
                ioctx.setPort(recvPacket.getPort());

            } catch (SocketTimeoutException ste) {
                return WolfSSL.WOLFSSL_CBIO_ERR_TIMEOUT;
            } catch (SocketException se) {
                se.printStackTrace();
                return WolfSSL.WOLFSSL_CBIO_ERR_GENERAL;
            } catch (IOException ioe) {
                ioe.printStackTrace();
                return WolfSSL.WOLFSSL_CBIO_ERR_GENERAL;
            } catch (Exception e) {
                e.printStackTrace();
                return WolfSSL.WOLFSSL_CBIO_ERR_GENERAL;
            }

            return recvPacket.getLength();

        } else {
            DataInputStream is = ioctx.getInputStream();
            if (is == null) {
                System.out.println("DataInputStream is null in recvCallback!");
                System.exit(1);
            }

            try {
                is.read(buf, 0, sz);
            } catch (IOException e) {
                e.printStackTrace();
                return WolfSSL.WOLFSSL_CBIO_ERR_GENERAL;
            }
        }

        return sz;
    }
}

