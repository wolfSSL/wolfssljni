/* WolfSSLTest.java
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

import org.junit.Test;
import org.junit.BeforeClass;
import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.List;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLException;

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
        test_WolfSSL_protocol();
        test_WolfSSL_getProtocolsMask();
        test_WolfSSL_Method_Allocators(lib);
        test_WolfSSL_getLibVersionHex();
        test_WolfSSL_getErrno();
        testGetCiphersAvailableIana();
        test_isLibraryLoadSkippedReturnsFalseByDefault();
        test_SystemPropertyNotSetByDefault();
        test_SettingPropertyAfterLoadHasNoEffect();
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

    public void test_WolfSSL_protocol() {
        String[] p = WolfSSL.getProtocols();

        System.out.print("\tWolfSSL_protocol()");
        if (p == null) {
            System.out.println("\t\t... failed");
            fail("failed to get protocols");
        }
        System.out.println("\t\t... passed");
    }

    public void test_WolfSSL_getProtocolsMask() {
        System.out.print("\tgetProtocolsMask()");

        /* Get all protocols (no mask) */
        String[] allProtocols = WolfSSL.getProtocolsMask(0);
        if (allProtocols == null) {
            System.out.println("\t\t... failed");
            fail("getProtocolsMask(0) returned null");
        }
        List<String> allProtoList = Arrays.asList(allProtocols);

        /* Test with TLSv1.3 masked off, verify TLSv1.3 not in result */
        String[] noTls13 = WolfSSL.getProtocolsMask(WolfSSL.SSL_OP_NO_TLSv1_3);
        if (noTls13 == null) {
            System.out.println("\t\t... failed");
            fail("getProtocolsMask(SSL_OP_NO_TLSv1_3) returned null");
        }
        List<String> noTls13List = Arrays.asList(noTls13);
        if (noTls13List.contains("TLSv1.3")) {
            System.out.println("\t\t... failed");
            fail("TLSv1.3 should not be in result when masked");
        }

        /* Test with TLSv1.2 masked off, verify TLSv1.2 not in result */
        String[] noTls12 = WolfSSL.getProtocolsMask(WolfSSL.SSL_OP_NO_TLSv1_2);
        if (noTls12 == null) {
            System.out.println("\t\t... failed");
            fail("getProtocolsMask(SSL_OP_NO_TLSv1_2) returned null");
        }
        List<String> noTls12List = Arrays.asList(noTls12);
        if (noTls12List.contains("TLSv1.2")) {
            System.out.println("\t\t... failed");
            fail("TLSv1.2 should not be in result when masked");
        }

        /* Test with multiple versions masked off */
        long multiMask = WolfSSL.SSL_OP_NO_TLSv1_2 | WolfSSL.SSL_OP_NO_TLSv1_3;
        String[] noTls12And13 = WolfSSL.getProtocolsMask(multiMask);
        if (noTls12And13 == null) {
            System.out.println("\t\t... failed");
            fail("getProtocolsMask with multiple masks returned null");
        }
        List<String> noTls12And13List = Arrays.asList(noTls12And13);
        if (noTls12And13List.contains("TLSv1.2") ||
            noTls12And13List.contains("TLSv1.3")) {
            System.out.println("\t\t... failed");
            fail("TLSv1.2 and TLSv1.3 should not be in result when masked");
        }

        System.out.println("\t\t... passed");
    }

    public void test_WolfSSL_Method_Allocators(WolfSSL lib) {
        /* Get protocols compiled into native wolfSSL */
        List<String> enabledProtocols = Arrays.asList(WolfSSL.getProtocols());

        if (enabledProtocols.contains("SSLv3")) {
            tstMethod(WolfSSL.SSLv3_ServerMethod(), "SSLv3_ServerMethod()");
            tstMethod(WolfSSL.SSLv3_ClientMethod(), "SSLv3_ClientMethod()");
        }
        if (enabledProtocols.contains("TLSv1")) {
            tstMethod(WolfSSL.TLSv1_ServerMethod(), "TLSv1_ServerMethod()");
            tstMethod(WolfSSL.TLSv1_ClientMethod(), "TLSv1_ClientMethod()");
        }
        if (enabledProtocols.contains("TLSv1.1")) {
            tstMethod(WolfSSL.TLSv1_1_ServerMethod(), "TLSv1_1_ServerMethod()");
            tstMethod(WolfSSL.TLSv1_1_ClientMethod(), "TLSv1_1_ClientMethod()");
        }
        if (enabledProtocols.contains("TLSv1.2")) {
            tstMethod(WolfSSL.TLSv1_2_ServerMethod(), "TLSv1_2_ServerMethod()");
            tstMethod(WolfSSL.TLSv1_2_ClientMethod(), "TLSv1_2_ClientMethod()");
        }
        if (enabledProtocols.contains("TLSv1.3")) {
            tstMethod(WolfSSL.TLSv1_3_ServerMethod(), "TLSv1_3_ServerMethod()");
            tstMethod(WolfSSL.TLSv1_3_ClientMethod(), "TLSv1_3_ClientMethod()");
        }
        if (enabledProtocols.contains("DTLSv1")) {
            tstMethod(WolfSSL.DTLSv1_ServerMethod(), "DTLSv1_ServerMethod()");
            tstMethod(WolfSSL.DTLSv1_ClientMethod(), "DTLSv1_ClientMethod()");
        }
        if (enabledProtocols.contains("DTLSv1.2")) {
            tstMethod(WolfSSL.DTLSv1_2_ServerMethod(),
                "DTLSv1_2_ServerMethod()");
            tstMethod(WolfSSL.DTLSv1_2_ClientMethod(),
                "DTLSv1_2_ClientMethod()");
        }
        if (enabledProtocols.contains("DTLSv1.3")) {
            tstMethod(WolfSSL.DTLSv1_3_ServerMethod(),
                "DTLSv1_3_ServerMethod()");
            tstMethod(WolfSSL.DTLSv1_3_ClientMethod(),
                "DTLSv1_3_ClientMethod()");
        }
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

    public void testGetCiphersAvailableIana() {
        System.out.print("\tgetCiphersAvailableIana()");

        String[] ciphers = WolfSSL.getCiphersAvailableIana(
                WolfSSL.TLS_VERSION.SSLv23);
        if (ciphers == null) {
            System.out.println("\t... failed");
            fail("available ciphers array was null");
        }
        if (ciphers.length == 0) {
            System.out.println("\t... failed");
            fail("available ciphers array length was zero");
        }

        System.out.println("\t... passed");
    }

    public void test_WolfSSL_getLibVersionHex() {
        System.out.print("\tgetLibVersionHex()");

        long verHex = WolfSSL.getLibVersionHex();
        if (verHex == 0 || verHex < 0) {
            System.out.println("\t\t... failed");
            fail("getting library version hex failed");
        }

        System.out.println("\t\t... passed");
    }

    public void test_WolfSSL_getErrno() {
        System.out.print("\tgetErrno()");

        /* Just make sure we don't seg fault or crash here */
        int errno = WolfSSL.getErrno();

        System.out.println("\t\t\t... passed");
    }

    public void test_isLibraryLoadSkippedReturnsFalseByDefault() {

        System.out.print(
            "\tisLibraryLoadSkipped() default");

        /* Library was loaded normally in @BeforeClass, so
         * isLibraryLoadSkipped() should return false */
        assertFalse(
            "isLibraryLoadSkipped() should be false when " +
            "library was loaded normally",
            WolfSSL.isLibraryLoadSkipped());

        System.out.println("\t... passed");
    }

    public void test_SystemPropertyNotSetByDefault() {

        System.out.print(
            "\twolfssl.skipLibraryLoad not set");

        /* Verify property is not set by default in test env */
        String val =
            System.getProperty("wolfssl.skipLibraryLoad");
        assertNull(
            "wolfssl.skipLibraryLoad should not be set " +
            "by default", val);

        System.out.println("\t... passed");
    }

    public void test_SettingPropertyAfterLoadHasNoEffect() {

        System.out.print(
            "\tskipLibraryLoad after load");

        /* Setting the property after library has already been
         * loaded should not change isLibraryLoadSkipped() */
        try {
            System.setProperty(
                "wolfssl.skipLibraryLoad", "true");

            assertFalse(
                "isLibraryLoadSkipped() should still be " +
                "false after setting property post-load",
                WolfSSL.isLibraryLoadSkipped());

        } finally {
            System.clearProperty("wolfssl.skipLibraryLoad");
        }

        System.out.println("\t... passed");
    }
}

