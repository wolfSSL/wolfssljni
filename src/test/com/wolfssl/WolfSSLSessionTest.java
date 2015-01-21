/* WolfSSLSessionTest.java
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import static org.junit.Assert.*;

import com.wolfssl.WolfSSL;

public class WolfSSLSessionTest {

    WolfSSLContext ctx;
    WolfSSLSession ssl;

    @Test
    public void testWolfSSLSession() throws WolfSSLException {

        ctx = new WolfSSLContext(WolfSSL.SSLv23_ClientMethod());

        System.out.println("WolfSSLSession Class");

        test_WolfSSLSession_new();
        test_WolfSSLSession_freeSSL();

    }

    public void test_WolfSSLSession_new() {

        try {
            System.out.print("\tWolfSSLSession()");
            ssl = new WolfSSLSession(ctx);
        } catch (WolfSSLException we) {
            System.out.println("\t... failed");
            fail("failed to create WolfSSLSession object");
        }

        System.out.println("\t... passed");
    }

    public void test_WolfSSLSession_freeSSL() {

        System.out.print("\tfreeSSL()");
        ssl.freeSSL();
        System.out.println("\t\t... passed");
    }
}

