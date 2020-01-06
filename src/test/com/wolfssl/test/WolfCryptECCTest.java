/* WolfCryptECCTest.java
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

package com.wolfssl.test;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import static org.junit.Assert.*;

import com.wolfssl.WolfSSLException;
import com.wolfssl.wolfcrypt.ECC;

public class WolfCryptECCTest {

    ECC ecc;

    @Test
    public void testECC() throws WolfSSLException {

        System.out.println("ECC Class");

        test_ECC_new();
    }

    public void test_ECC_new() {

        System.out.print("\tECC()");
        ecc = new ECC();
        System.out.println("\t\t\t\t... passed");
    }
}

