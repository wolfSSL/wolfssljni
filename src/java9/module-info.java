/* module-info.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

/**
 * wolfSSL JNI/JSSE Module
 *
 * This module provides:
 * - JNI bindings to the native wolfSSL SSL/TLS library (com.wolfssl)
 * - A JSSE provider implementation (com.wolfssl.provider.jsse)
 *
 * Note: This module-info.java is only compiled when building with Java 9+.
 * When building with Java 8, this file is excluded and the resulting JAR
 * will be a standard (non-modular) JAR that works on the classpath.
 */
module com.wolfssl {
    /* Required modules */
    requires java.logging;

    /* Export public API packages */
    exports com.wolfssl;
    exports com.wolfssl.provider.jsse;

    /* Declare service usage for ServiceLoader.load(Provider.class) */
    uses java.security.Provider;

    /* Register wolfJSSE as a security provider */
    provides java.security.Provider
        with com.wolfssl.provider.jsse.WolfSSLProvider;
}
