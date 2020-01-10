 /* WolfSSLTestCommon.java
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

import java.io.File;

import com.wolfssl.WolfSSLException;

public class WolfSSLTestCommon {
	
	/**
	 * Returns a string with the right path to use
	 * @param in relative path from root wolfSSL JNI directory
	 * @return Adjusted path
	 * @throws WolfSSLException 
	 */
	public static String getPath(String in) throws WolfSSLException {
		String esc = "../../../"; /* if running from IDE directory */
		String scd = "/sdcard/"; /* if running on Android */
		
	    /* test if running from IDE directory */
        File f = new File(in);
        if (!f.exists()) {
            f = new File(esc.concat(in));
            if (!f.exists()) {
                f = new File(scd.concat(in));
                if (!f.exists()) {
                    System.out.println("could not find files " + f.getAbsolutePath());
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
}
