/* WolfSSLSessionTicketCallback.java
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

/**
 * wolfSSL session ticket callback interface.
 * This interface specifies how applications should implement the session
 * ticket callback class, to be used by wolfSSL when receiving a session
 * ticket message.
 * <p>
 * To use this interface, native wolfSSL must be compiled with
 * HAVE_SESSION_TICKET defined.
 * </p>
 * After implementing this interface, it should be passed as a parameter
 * to the
 * {@link WolfSSLSession#setSessionTicketCb(WolfSSLSessionTicketCallback, Object)
 * WolfSSLSession.setSessionTicketCb()} method to be registered with the native
 * wolfSSL library.
 */
public interface WolfSSLSessionTicketCallback {

    /**
     * Callback method which is called when native wolfSSL receives a
     * session ticket message.
     *
     * @param ssl     the current SSL session object from which the
     *                callback was initiated
     * @param ticket  Session ticket received as a byte array
     * @param ctx     Optional user context if set when callback was
     *                registered
     *
     * @return 0 on success. wolfSSL does not currently do anything with
     *         the return value of this method, but is in place for
     *         future expansion if needed.
     */
    public int sessionTicketCallback(WolfSSLSession ssl, byte[] ticket,
        Object ctx);
}


