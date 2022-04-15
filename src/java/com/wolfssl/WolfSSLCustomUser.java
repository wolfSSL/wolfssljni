/* WolfSSLCustomUser.java
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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
import  com.wolfssl.WolfSSL;
import  com.wolfssl.WolfSSL.TLS_VERSION;

/**
 * Base class is intended to give some customizing points.
 * Currently it is limited to be invoked from WolfSSLContext.Create
 *
 * @author  wolfSSL
 */
public class WolfSSLCustomUser {
    /** SSL/TLS version */
    public TLS_VERSION version;
    /** String array of allowed cipher suites */
    public String[] list;
    /** Mask of options to set for the associated WOLFSSL_CTX */
    public long noOptions;

    /** Default WolfSSLCustomUser constructor */
    public WolfSSLCustomUser() { }

    /**
     * callback for getting Context attributes before creating context,
     *                                     TLS protocol and Cipher list
     *
     *      WARNING: inappropriate code or use of this callback may cause
     *               serious security issue.
     *
     * @param version default version of TLS for refernce.
     * @param list    default cipher list for refernce.
     * @return        version: TLS protocol version to the context. The value
     *                         has to be one compiled in.
     *                list: Cipher list allowed to the context. list has to
     *                      contain subset of default cipher list. If it is
     *                      null, default list is applied.
     */
    public static WolfSSLCustomUser GetCtxAttributes(TLS_VERSION version,
                                                     String[] list) {

        WolfSSLCustomUser ctxAttr = new WolfSSLCustomUser();

        /***
         custom code

         Example:
            ctxAttr.NoOptions = WolfSSL.SSL_OP_NO_TLSv1 | WolfSSL.SSL_OP_NO_TLSv1_3;

        ***/

        ctxAttr.version = version;
        ctxAttr.list   = list;
        ctxAttr.noOptions = 0;
        return ctxAttr;
    }
} /* end WolfSSL */
