/* WolfSSLMacEncryptCallback.java
 *
 * Copyright (C) 2006-2013 wolfSSL Inc.
 *
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

package com.wolfssl;

import java.nio.ByteBuffer;

/**
 * wolfSSL MAC Encrypt Callback Interface.
 * This interface specifies how applicaitons should implement the MAC Encrypt
 * callback class to be used by wolfSSL when using atomic record layer
 * callbacks.
 * <p>
 * After implementing this interface, it should be passed as a parameter
 * to the {@link WolfSSLContext#setMacEncryptCb(WolfSSLMacEncryptCallback) 
 * WolfSSLContext.setMacEncryptCb()} method to be registered with the native
 * wolfSSL library.
 *
 * @author  wolfSSL
 * @version 1.0, August 2013
 */
public interface WolfSSLMacEncryptCallback {

    /**
     * Atomic record layer MAC Encrypt callback method.
     * This method acts as the Atomic User Record Processing Mac/Encrypt
     * callback to be used with the wolfSSL atomic record layer processing.
     *
     * @param ssl           the current SSL session object from which the
     *                      callback was initiated.
     * @param macOut        output buffer where the result of the mac should
     *                      be stored.
     * @param macIn         the mac input buffer
     * @param macInSz       the size of the mac input buffer, <b>macIn</b>
     * @param macContent    used for setTlsHmacInner(), the type of message
     * @param macVerify     used for setTlsHmacInner(), specifies whether this
     *                      is a verification of a peer message.
     * @param encOut        the output buffer where the result on the
     *                      encryption should be stored.
     * @param encIn         the input buffer to encrypt
     * @param encSz         the size of the input buffer, <b>encIn</b>
     * @param ctx           custom user context to be used
     * @return              <b><code>0</code></b> upon success,
     *                      otherwise a negative value on error.
     */
    public int macEncryptCallback(WolfSSLSession ssl, ByteBuffer macOut,
            byte[] macIn, long macInSz, int macContent, int macVerify,
            ByteBuffer encOut, ByteBuffer encIn, long encSz, Object ctx);
}
