
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

package com.wolfssl.provider.jsse;
import  com.wolfssl.provider.jsse.WolfSSLAuthStore.TLS_VERSION;

/**
 * Base class is intended to give some customizing points. Currently it is limited
 * to be invoked from WolfSSLContext.Create
 *
 * @author  wolfSSL
 * @version 1.0, August 2013
 */
public class WolfSSLCustomUser {
    public TLS_VERSION version;
    public String[] list;

    /**
     * Set callback for Context attributes, TLS protocol and Cipher list
     *
     *      WARNING: inappropriate code or use of this callback may cause serious security issue.
     *
     * @param version      default version of TLS for refernce.
     * @param list         default cipher list for refernce.
     * @return             version: TLS protocol version to the context. The value has
     *                             to be one compiled in.
     *                     list:   Cipher list allowed to the context. list has to contain subset of 
     *                             default cipher list. If it is null, default list is applied.
     * 
     */

    public static WolfSSLCustomUser GetCtxAttributes(TLS_VERSION version, String[] list) {

        WolfSSLCustomUser ctxAttr = new WolfSSLCustomUser();

        /*** 
            custom code 
        ***/

        ctxAttr.version = version;
        ctxAttr.list   = list;
        return ctxAttr;
    }

} /* end WolfSSL */