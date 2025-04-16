/* WolfSSLByteBufferIOSendCallback.java
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
 * wolfSSL I/O Send Callback Interface.
 *
 * This interface specifies how applicaitons should implement the I/O send
 * callback class to be used by wolfSSL.
 * <p>
 * After implementing this interface, it should be passed as a parameter
 * to the {@link WolfSSLContext#setIOSend(WolfSSLIOSendCallback)
 * WolfSSLContext.setIOSend()} or
 * {@link WolfSSLSession#setIOSend(WolfSSLIOSendCallback) 
 * WolfSSLSession.setIOSend()} methods to be registered with the native wolfSSL
 * library.
 */
public interface WolfSSLByteBufferIOSendCallback {

    /**
     * I/O send callback method, using ByteBuffer.
     *
     * This method acts as the I/O send callback to be used with wolfSSL.
     * This can be registered with an SSL session at the WolfSSLContext level
     * using WolfSSLContext#setIOSend(WolfSSLIOSendCallback), or at the
     * WolfSSLSession level using
     * WolfSSLSession#setIOSend(WolfSSLIOSendCallback).
     *
     * This method will be called by native wolfSSL when it needs to send data.
     * The callback should send data from the provided ByteBuffer (buf) across
     * the transport layer. The number of bytes sent should be returned, or
     * a negative error code on error.
     *
     * @param ssl   the current SSL session object from which the callback was
     *              initiated.
     * @param buf   buffer containing data to be sent to the peer.
     * @param sz    size of data in buffer "<b>buf</b>"
     * @param ctx   I/O context to be used.
     * @return      the number of bytes sent, or an error. For possible error
     *              codes, see the default EmbedSend() function in
     *              wolfssl_package/src/io.c
     */
    public int sendCallback(WolfSSLSession ssl, ByteBuffer buf, int sz,
           Object ctx);
}

