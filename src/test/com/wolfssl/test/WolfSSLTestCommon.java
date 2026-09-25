 /* WolfSSLTestCommon.java
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

package com.wolfssl.test;

import java.io.File;

import com.wolfssl.WolfSSLException;

public class WolfSSLTestCommon {

    /* RFC 7919 ffdhe2048 prime, generator is 2 */
    private static final String FFDHE2048_P =
        "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695" +
        "A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617A" +
        "D3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935" +
        "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797A" +
        "BC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4" +
        "AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61" +
        "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005" +
        "C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF";

	/**
	 * Returns a string with the right path to use
	 * @param in relative path from root wolfSSL JNI directory
	 * @return Adjusted path
	 * @throws WolfSSLException
	 */
	public static String getPath(String in) throws WolfSSLException {
		String esc = "../../../"; /* if running from IDE directory */
		String scd = "/data/local/tmp/"; /* if running on Android */

	    /* test if running from IDE directory */
        File f = new File(in);
        if (!f.exists()) {
            f = new File(esc.concat(in));
            if (!f.exists()) {
                f = new File(scd.concat(in));
                if (!f.exists()) {
                    System.out.println("could not find files " +
                        f.getAbsolutePath());
                    throw new WolfSSLException("Unable to find test files");
                }
                return scd.concat(in);
            }
            return esc.concat(in);
        }
        else {
            return in;
        }
	}

	/**
	 * Check if running on Windows platform.
	 * @return true if os.name contains "Windows"
	 */
	public static boolean isWindows() {
		String os = System.getProperty("os.name");
		return (os != null && os.contains("Windows"));
	}

    /**
     * Get RFC 7919 ffdhe2048 DH group parameters.
     * @return two element array, prime p then generator g
     */
    public static byte[][] getFfdhe2048Params() {
        byte[] p = new byte[FFDHE2048_P.length() / 2];
        for (int i = 0; i < p.length; i++) {
            p[i] = (byte)Integer.parseInt(
                FFDHE2048_P.substring(i * 2, i * 2 + 2), 16);
        }
        return new byte[][] { p, new byte[] { 2 } };
    }
}
