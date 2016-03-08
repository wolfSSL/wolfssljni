/* WolfSSLTest.java
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
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
import org.junit.BeforeClass;
import static org.junit.Assert.*;


/* suppress SSLv3 deprecation warnings, meant for end user not tests */
@SuppressWarnings("deprecation")
public class WolfSSLTest {

    @BeforeClass
    public static void loadLibrary() {
        try {
            WolfSSL.loadLibrary();
        } catch (UnsatisfiedLinkError ule) {
            fail("failed to load native JNI library");
        }
    }

    @Test
    public void testWolfSSL() throws WolfSSLException {

        WolfSSL lib = null;
        System.out.println("WolfSSL Class");

        test_WolfSSL_new(lib);
        test_WolfSSL_Method_Allocators(lib);

    }

    public void test_WolfSSL_new(WolfSSL lib) {

        try {
            System.out.print("\tWolfSSL()");
            lib = new WolfSSL();
        } catch (UnsatisfiedLinkError ule) {
            System.out.println("\t\t\t... failed");
            fail("failed to load native JNI library");
        } catch (WolfSSLException we) {
            System.out.println("\t\t\t... failed");
            fail("failed to create WolfSSL object");
        }

        System.out.println("\t\t\t... passed");
    }

    public void test_WolfSSL_Method_Allocators(WolfSSL lib) {
        tstMethod(WolfSSL.SSLv3_ServerMethod(), "SSLv3_ServerMethod()");
        tstMethod(WolfSSL.SSLv3_ClientMethod(), "SSLv3_ClientMethod()");
        tstMethod(WolfSSL.TLSv1_ServerMethod(), "TLSv1_ServerMethod()");
        tstMethod(WolfSSL.TLSv1_ClientMethod(), "TLSv1_ClientMethod()");
        tstMethod(WolfSSL.TLSv1_1_ServerMethod(), "TLSv1_1_ServerMethod()");
        tstMethod(WolfSSL.TLSv1_1_ClientMethod(), "TLSv1_1_ClientMethod()");
        tstMethod(WolfSSL.TLSv1_2_ServerMethod(), "TLSv1_2_ServerMethod()");
        tstMethod(WolfSSL.TLSv1_2_ClientMethod(), "TLSv1_2_ClientMethod()");
        tstMethod(WolfSSL.DTLSv1_ServerMethod(), "DTLSv1_ServerMethod()");
        tstMethod(WolfSSL.DTLSv1_ClientMethod(), "DTLSv1_ClientMethod()");
        tstMethod(WolfSSL.DTLSv1_2_ServerMethod(), "DTLSv1_2_ServerMethod()");
        tstMethod(WolfSSL.DTLSv1_2_ClientMethod(), "DTLSv1_2_ClientMethod()");
        tstMethod(WolfSSL.SSLv23_ServerMethod(), "SSLv23_ServerMethod()");
        tstMethod(WolfSSL.SSLv23_ClientMethod(), "SSLv23_ClientMethod()");
    }

    public void tstMethod(long method, String name) {

        System.out.print("\t" + name);

        if (method == 0) {
            System.out.println("\t\t... failed");
            fail("method test failed, method was null");
        } else if (method != WolfSSL.NOT_COMPILED_IN) {
            WolfSSL.nativeFree(method);
        }
        System.out.println("\t\t... passed");
    }
}

