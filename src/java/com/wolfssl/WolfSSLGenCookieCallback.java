/* WolfSSLGenCookieCallback.java
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

/**
 * wolfSSL I/O Receive Callback Interface.
 * This interface specifies how applicaitons should implement the DTLS cookie
 * generation callback class to be used by wolfSSL.
 * <p>
 * After implementing this interface, it should be passed as a parameter
 * to the {@link WolfSSLContext#setGenCookie(WolfSSLGenCookieCallback) 
 * WolfSSLContext.setGenCookie()} method to be registered with the native
 * wolfSSL library.
 *
 * @author  wolfSSL
 * @version 1.0, August 2013
 */
public interface WolfSSLGenCookieCallback {

    /**
     * DTLS cookie generation callback method.
     * This method acts as the cookie generation callback to be used with
     * wolfSSL's DTLS implementation.
     * This can be registered with an SSL context using the
     * WolfSSLContext#setGenCookie(WolfSSLGenCookieCallback) method.
     *
     * @param ssl   the current SSL session object from which the callback was
     *              initiated.
     * @param buf   buffer in which the application should place generated
     *              cookie.
     * @param sz    size of buffer, <b>buf</b>
     * @param ctx   cookie context to be used
     * @return      the size of the cookie generated, or WolfSSL.GEN_COOKIE_E
     *              upon error.
     */
    public int genCookieCallback(WolfSSLSession ssl, byte[] buf, int sz,
            Object ctx);
}

