/* WolfSSLDebug.java
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

package com.wolfssl.provider.jsse;

/**
 * Central location for all debugging messages
 *
 * This class is used internally for displaying debug message.
 *
 * @author wolfSSL
 */
public class WolfSSLDebug {

    /**
     * boolean to check if debug mode is on
     */
    public static boolean DEBUG = checkProperty();


    /**
     * Error level debug message
     */
    public static String ERROR = "ERROR";


    /**
     * Info level debug message
     */
    public static String INFO = "INFO";

    private static boolean checkProperty() {

        String enabled = System.getProperty("wolfjsse.debug");

        if ((enabled != null) && (enabled.equalsIgnoreCase("true"))) {
            return true;
        }

        return false;
    }

    /**
     * Prints out a message to the console
     * @param string message to be printed
     */
    public static void print(String string) {
        System.out.println("wolfJSSE: " + string);
    }

    /**
     * Checks if debugging is turned on and prints out the message.
     *
     * @param cl class being called from to get debug info
     * @param tag level of debug message i.e. WolfSSLDebug.INFO
     * @param string message to be printed out
     */
    public static void log(Class cl, String tag, String string) {
        if (DEBUG) {
            System.out.println("[wolfJSSE " + tag + " : " +
                               cl.getSimpleName() + "] " + string);
        }
    }
}

