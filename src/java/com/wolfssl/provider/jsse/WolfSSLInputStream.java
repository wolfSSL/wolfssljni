/* WolfSSLInputStream.java
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

import java.io.InputStream;
import java.io.IOException;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLSession;

public class WolfSSLInputStream extends InputStream {

    private WolfSSLSession ssl;
    private WolfSSLSocket  socket;
    final private Object readLock = new Object();

    public WolfSSLInputStream(WolfSSLSession ssl, WolfSSLSocket socket) {
        this.ssl = ssl;
        this.socket = socket; /* parent socket */
    }

    @Override
    public int read() throws IOException {

        int ret = 0;
        byte[] data = new byte[1];

        try {
            ret = this.read(data, 0, 1);

        } catch (NullPointerException ne) {
            throw new IOException(ne);

        } catch (IndexOutOfBoundsException ioe) {
            throw new IndexOutOfBoundsException(ioe.toString());
        }

        return (data[0] & 0xFF);
    }

    public int read(byte[] b) throws NullPointerException, IOException {

        return this.read(b, 0, b.length);
    }

    public int read(byte[] b, int off, int len)
        throws NullPointerException, IndexOutOfBoundsException, IOException {

        int ret = 0;
        byte[] data = null;

        if (b == null) {
            throw new NullPointerException("Input array is null");
        }

        if (b.length == 0 || len == 0) {
            return 0;
        }

        if (off < 0 || len < 0 || len > (b.length - off)) {
            throw new IndexOutOfBoundsException("Array index out of bounds");
        }

        if (off != 0) {
            /* create new tmp buffer to read data into */
            data = new byte[len];
        } else {
            data = b;
        }

        synchronized (readLock) {
            try {
                if (socket.handshakeInitCalled == false) {
                    socket.handshakeInitCalled = true;
                    socket.startHandshake();
                }

                ret = ssl.read(data, len);
                if (ret <= 0) {
                    int err = ssl.getError(ret);
                    String errStr = WolfSSL.getErrorString(err);

                    /* received CloseNotify, InputStream should return "-1"
                       when there is no more data */
                    if (err == WolfSSL.SSL_ERROR_ZERO_RETURN) {
                        return -1;
                    }

                    throw new IOException("Native wolfSSL read() failed: " +
                        errStr + " (error code: " + err + ")");
                }

            } catch (IllegalStateException e) {
                throw new IOException(e);
            }

            if (off != 0) {
                /* copy data into original array at offset */
                System.arraycopy(data, 0, b, off, ret);
            }

            /* return number of bytes read */
            return ret;
        }
    }
}

