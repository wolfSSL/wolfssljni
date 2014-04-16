/* WolfSSLTest.java
 *
 * Copyright (C) 2006-2014 wolfSSL Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

package com.wolfssl;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import static org.junit.Assert.*;

import com.wolfssl.WolfSSL;

public class WolfSSLContextTest {

    @Test
    public void testWolfSSLContext() throws WolfSSLException {

        WolfSSL lib = null;

        try {
            lib = new WolfSSL();
        } catch (WolfSSLException e) {
            fail("failed to create WolfSSL object");
        }

        System.out.println("WolfSSLContext Class");

        test_WolfSSLContext_new(lib.SSLv23_ServerMethod());

    }

    public void test_WolfSSLContext_new(long method) {

        if (method != 0)
        {
            System.out.print("\tWolfSSLContext()");
            WolfSSLContext wc = null;

            /* test failure case */
            try {

                wc = new WolfSSLContext(0);

            } catch (WolfSSLException e) {

                /* now test success case */
                try {
                    wc = new WolfSSLContext(method);
                } catch (WolfSSLException we) {
                    System.out.println("\t... failed");
                    fail("failed to create WolfSSLContext object");
                }

                System.out.println("\t... passed");
                return;
            }

            System.out.println("\t... failed");
            fail("failure case improperly succeeded, WolfSSLContext()");
        }
    }
}

