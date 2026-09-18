/* WolfSSLParametersTest.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

package com.wolfssl.provider.jsse.test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.security.Provider;
import java.security.Security;

import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;

import com.wolfssl.WolfSSLException;
import com.wolfssl.provider.jsse.WolfSSLParameters;
import com.wolfssl.provider.jsse.WolfSSLProvider;
import com.wolfssl.test.TimedTestWatcher;

public class WolfSSLParametersTest {

    @Rule
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void testProviderInstallationAtRuntime()
        throws WolfSSLException {

        System.out.println("WolfSSLParameters Class");

        Security.insertProviderAt(new WolfSSLProvider(), 1);
        Provider p = Security.getProvider("wolfJSSE");
        assertNotNull(p);
    }

    @Test
    public void testSetApplicationProtocolsRejectsInvalid() {

        WolfSSLParameters params = new WolfSSLParameters();

        try {
            params.setApplicationProtocols(null);
            fail("null protocols array should throw IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            /* expected */
        }

        try {
            params.setApplicationProtocols(new String[] { "h2", null });
            fail("null protocol element should throw IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            /* expected */
        }

        try {
            params.setApplicationProtocols(new String[] { "h2", "" });
            fail("empty protocol element should throw " +
                "IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            /* expected */
        }

        params.setApplicationProtocols(new String[] { "h2", "http/1.1" });
        assertArrayEquals(new String[] { "h2", "http/1.1" },
            params.getApplicationProtocols());

        /* an empty array is valid, it has no elements to reject */
        params.setApplicationProtocols(new String[0]);
        assertArrayEquals(new String[0], params.getApplicationProtocols());
    }
}
