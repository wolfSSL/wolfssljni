/* WolfSSLByteBufferIORecvCallback.java
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
package com.wolfssl;

import java.nio.ByteBuffer;

/**
 * wolfSSL ByteBuffer I/O Receive Callback Interface.
 *
 * This interface specifies how applicaitons should implement the I/O receive
 * callback class to be used by wolfSSL, using a ByteBuffer as the buffer.
 * <p>
 * After implementing this interface, it should be passed as a parameter
 * to the {@link WolfSSLContext#setIORecv(WolfSSLIORecvCallback)
 * WolfSSLContext.setIORecv()} or
 * {@link WolfSSLSession#setIORecv(WolfSSLIORecvCallback)
 * WolfSSLSession.setIORecv()} methods to be registered with the native wolfSSL
 * library.
 */
public interface WolfSSLByteBufferIORecvCallback {

    /**
     * I/O receive callback method, using ByteBuffer.
     *
     * This method acts as the I/O receive callback to be used with wolfSSL.
     * This can be registered with an SSL session at the WolfSSLContext level
     * using WolfSSLContext#setIORecv(WolfSSLIORecvCallback), or at the
     * WolfSSLSession level using
     * WolfSSLSession#setIORecv(WolfSSLIORecvCallback).
     *
     * This method will be called by native wolfSSL when it needs data to
     * be read from the transport layer. The callback should read data and
     * place the data into the buffer provided. The number of bytes read should
     * be returned. The callback should return an error code on error.
     *
     * @param ssl   the current SSL session object from which the callback was
     *              initiated.
     * @param buf   buffer in which the application should place data which
     *              has been received from the peer.
     * @param sz    size of buffer, <b>buf</b>
     * @param ctx   I/O context to be used.
     * @return      the number of bytes read, or an error. For possible error
     *              codes, see the default EmbedRecv() function in
     *              wolfssl_package/src/io.c
     */
    public int receiveCallback(WolfSSLSession ssl, ByteBuffer buf, int sz,
            Object ctx);
}

