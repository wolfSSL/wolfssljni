/* WolfSSLOutputStream.java
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

package com.wolfssl.provider.jsse;

import java.io.OutputStream;
import java.io.IOException;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLSession;

public class WolfSSLOutputStream extends OutputStream {

    private WolfSSLSession ssl;
    private WolfSSLSocket  socket;
    final private Object writeLock = new Object();

    public WolfSSLOutputStream(WolfSSLSession ssl, WolfSSLSocket socket) {
        this.ssl = ssl;
        this.socket = socket; /* parent socket */
    }

    public void write(int b) throws IOException {
        byte[] data = new byte[1];
        data[0] = (byte)(b & 0xFF);

        this.write(data, 0, 1);
    }

    public void write(byte[] b) throws IOException {
        this.write(b, 0, b.length);
    }

    public void write(byte[] b, int off, int len) throws IOException {

        int ret;
        byte[] data = null;

        if (b == null) {
            throw new NullPointerException("Input array is null");
        }

        if (off < 0 || len < 0 || (off + len) > b.length) {
            throw new IndexOutOfBoundsException("Array index out of bounds");
        }

        if (off != 0) {
            data = new byte[len];
            System.arraycopy(b, off, data, 0, len);
        } else {
            data = b;
        }

        synchronized (writeLock) {
            try {
                if (socket.handshakeInitCalled == false) {
                    socket.handshakeInitCalled = true;
                    socket.startHandshake();
                }

                ret = ssl.write(data, len);

                if (ret <= 0) {
                    int err = ssl.getError(ret);
                    String errStr = WolfSSL.getErrorString(err);

                    throw new IOException("Native wolfSSL write() failed: " +
                        errStr + " (error code: " + err + ")");
                }

            } catch (IllegalStateException e) {
                throw new IOException(e);
            }
        }
    }
}

