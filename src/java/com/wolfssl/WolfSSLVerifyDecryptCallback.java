/* WolfSSLVerifyDecryptCallback.java
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
 * wolfSSL Verify/Decrypt callback interface.
 * This interface specifies how applicaitons should implement the verify/decrypt
 * callback class to be used by wolfSSL when using atomic record layer callbacks.
 * Note that this is different than the decrypt/verify callback. For that, see
 * WolfSSLDecryptVerifyCallback.
 * <p>
 * After implementing this interface, it should be passed as a parameter
 * to the {@link WolfSSLContext#setVerifyDecryptCb(WolfSSLVerifyDecryptCallback)
 * WolfSSLContext.setVerifyDecryptCb()} method to be registered with the
 * native wolfSSL library.
 *
 * @author  wolfSSL
 */
public interface WolfSSLVerifyDecryptCallback {

    /**
     * Atomic record layer verify/decrypt callback method.
     * This method acts as the verify/decrypt callback to be used with
     * the wolfSSL atomic record layer processing.
     *
     * @param ssl       the current SSL session object from which the
     *                  callback was initiated.
     * @param decOut    output buffer where the result of the decryption
     *                  should be stored.
     * @param decIn     the encrypted input buffer
     * @param decSz     the size of the input buffer, <b>decIn</b>
     * @param content   used with setTlsHmacInner(), the type of message
     * @param macVerify used with setTlsHmacInner(), specifies whether this
     *                  is a verification of a peer message.
     * @param padSz     output variable that should be set with the total
     *                  value of the padding. When setting this, the first
     *                  element of the the array should be used.
     * @param ctx       user-registered decrypt/verify context
     * @return          <b><code>0</code></b> upon success,
     *                  otherwise a negative value on failure.
     */
    public int verifyDecryptCallback(WolfSSLSession ssl, ByteBuffer decOut,
            byte[] decIn, long decSz, int content, int macVerify, long[] padSz,
            Object ctx);
}

