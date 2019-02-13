/* WolfSSLProvider.java 
 *
 * Copyright (C) 2006-2017 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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

import java.security.Provider;

/**
 * wolfSSL JSSE Provider implementation
 *
 * @author wolfSSL
 * @version 1.0
 */
public final class WolfSSLProvider extends Provider {

    public WolfSSLProvider() {
        super("wolfJSSE", 1.0, "wolfSSL JSSE Provider");

        // 3 listed adds for JSSE in Provider.java
        //addEngine("KeyManagerFactory",                  false, null);
        put("SSLContext", WolfSSLContext.class.getName());
        //addEngine("TrustManagerFactory",                false, null);
    }
}

