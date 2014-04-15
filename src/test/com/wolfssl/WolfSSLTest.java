/* WolfSSLTest.java
 *
 * Copyright (C) 2006-2013 wolfSSL Inc.
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

package com.wolfssl;

import org.junit.Test;
import junit.framework.TestCase;

import com.wolfssl.WolfSSL;

public class WolfSSLTest extends TestCase {

    public void testWolfSSL() throws WolfSSLException {

        WolfSSL lib = null;

        try {
            WolfSSL.loadLibrary();
            lib = new WolfSSL();
        } catch (UnsatisfiedLinkError ule) {
            fail("failed to load native JNI library");
        } catch (WolfSSLException e) {
            fail("failed to create WolfSSL object");
        }

        tstMethod(lib.SSLv3_ServerMethod(), "SSLv3_ServerMethod()");
        tstMethod(lib.SSLv3_ClientMethod(), "SSLv3_ClientMethod()");
        tstMethod(lib.TLSv1_ServerMethod(), "TLSv1_ServerMethod()");
        tstMethod(lib.TLSv1_ClientMethod(), "TLSv1_ClientMethod()");
        tstMethod(lib.TLSv1_1_ServerMethod(), "TLSv1_1_ServerMethod()");
        tstMethod(lib.TLSv1_1_ClientMethod(), "TLSv1_1_ClientMethod()");
        tstMethod(lib.TLSv1_2_ServerMethod(), "TLSv1_2_ServerMethod()");
        tstMethod(lib.TLSv1_2_ClientMethod(), "TLSv1_2_ClientMethod()");
        tstMethod(lib.DTLSv1_ServerMethod(), "DTLSv1_ServerMethod()");
        tstMethod(lib.DTLSv1_ClientMethod(), "DTLSv1_ClientMethod()");
        tstMethod(lib.DTLSv1_2_ServerMethod(), "DTLSv1_2_ServerMethod()");
        tstMethod(lib.DTLSv1_2_ClientMethod(), "DTLSv1_2_ClientMethod()");
        tstMethod(lib.SSLv23_ServerMethod(), "SSLv23_ServerMethod()");
        tstMethod(lib.SSLv23_ClientMethod(), "SSLv23_ClientMethod()");
    }

    public void tstMethod(long method, String name) {
       
        System.out.print("\t" + name);

        if (method == 0) {
            System.out.println("\t... failed");
            fail("method test failed, method was null");
        }

        WolfSSL.nativeFree(method);
        System.out.println("\t... passed");
    }
}
