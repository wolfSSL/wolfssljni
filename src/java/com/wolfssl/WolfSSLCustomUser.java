
/* WolfSSLCustomUser.java
 *
 * Copyright (C) 2006-2019 wolfSSL Inc.
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

package com.wolfssl;
/**
 * User custom callback from Context.Create.
 *
 * @author  wolfSSL
 * @version 1.0, August 2013
 */
public class WolfSSLCustomUser {
    public long method = 0;
    public String[] list;

    /**
     * Set callback for Context attributes, TLS protocol and Cipher lsit
     *
     * @param method       default version of TLS method
     * @return             method: Lowest TLS protocol version allowed to the context
     *                     list:   Cipher list allwed to the context
     */

    public static WolfSSLCustomUser GetCtxAttributes(long method) {

        WolfSSLCustomUser ctxAttr = new WolfSSLCustomUser();

        /*** 
            custom code 
        ***/

        ctxAttr.method = method;
        ctxAttr.list   = null;
        return ctxAttr;
    }

} /* end WolfSSL */