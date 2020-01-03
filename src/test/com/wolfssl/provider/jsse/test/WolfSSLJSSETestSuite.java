/* WolfSSLJSSETestSuite.java
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
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

package com.wolfssl.provider.jsse.test;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({
    WolfSSLTrustX509Test.class,
    WolfSSLContextTest.class,
    WolfSSLEngineTest.class,
    WolfSSLSocketFactoryTest.class,
    WolfSSLSocketTest.class,
    WolfSSLServerSocketFactoryTest.class,
    WolfSSLServerSocketTest.class,
    WolfSSLSessionTest.class,
    WolfSSLX509Test.class,
    WolfSSLKeyX509Test.class,
})


public class WolfSSLJSSETestSuite {
    /* this class remains empty,
     * only used as a holder for the above
     * annotations */
}

