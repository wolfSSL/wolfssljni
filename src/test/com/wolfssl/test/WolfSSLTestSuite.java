/* WolfSSLTestSuite.java
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

package com.wolfssl.test;

import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLException;

@RunWith(Suite.class)
@Suite.SuiteClasses({
    WolfSSLTest.class,
    WolfSSLContextTest.class,
    WolfSSLSessionTest.class,
    WolfCryptRSATest.class,
    WolfCryptECCTest.class,
    WolfSSLCertificateTest.class,
    WolfSSLCertRequestTest.class,
    WolfSSLCertManagerTest.class,
    WolfSSLNameConstraintsTest.class,
    WolfSSLCRLTest.class
})


public class WolfSSLTestSuite {

    /* Static WolfSSL reference to keep library initialized for the duration
     * of the entire test suite. Without this, a WolfSSL object created by
     * an individual test class could be garbage collected after that test
     * class finishes, triggering wolfSSL_Cleanup() in the finalizer and
     * freeing session cache locks (and other items) while subsequent test
     * classes are still running. This caused crashes on Windows when the
     * garbage collector ran between test classes.
     *
     * We intentionally do not call cleanup() in @AfterClass because on
     * Android all tests run in a single process and multiple test suites
     * may be active. Cleanup will happen via the finalizer when the
     * process exits. */
    private static WolfSSL sslLib = null;

    @BeforeClass
    public static void initializeLibrary() throws WolfSSLException {
        WolfSSL.loadLibrary();
        sslLib = new WolfSSL();
    }
}

