/* WolfSSLDebug.java
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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

package com.wolfssl;

import java.util.Date;
import java.sql.Timestamp;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLLoggingCallback;

/**
 * Central location for all debugging messages
 *
 * This class is used internally for displaying debug message.
 *
 * @author wolfSSL
 */
public class WolfSSLDebug {

    /**
     * Check if JSSE level debug logging has been enabled.
     * This could have been named "DEBUG_JSSE", but was originally called
     * "DEBUG" prior to JNI debug being enabled. Thus for backwards
     * compatibility it has been left as "DEBUG".
     *
     * Is true if "wolfjsse.debug" is set to "true", otherwise false.
     */
    public static volatile boolean DEBUG = checkJSSEDebugProperty();

    /**
     * Check if JNI level debug logging has been enabled.
     *
     * Is true if "wolfssljni.debug" is set to "true", otherwise false.
     */
    public static volatile boolean DEBUG_JNI = checkJNIDebugProperty();

    /**
     * Check if JSON debug logging format has been enabled.
     *
     * Is true if "wolfjsse.debugFormat" is set to "JSON", otherwise false.
     */
    public static volatile boolean DEBUG_JSON = jsonOutEnabled();

    /**
     * wolfSSL JNI/JSSE component level being logged.
     * Will be used to determine what string gets put into log messages.
     */
    public enum Component {
        /** wolfSSL JNI component */
        JNI("wolfJNI"),
        /** wolfSSL JSSE component */
        JSSE("wolfJSSE");

        private final String componentString;

        Component(String compString) {
            this.componentString = compString;
        }

        public String toString() {
            return this.componentString;
        }
    }

    /**
     * Error level debug message
     */
    public static final String ERROR = "ERROR";

    /**
     * Info level debug message
     */
    public static final String INFO = "INFO";

    /**
     * Native wolfSSL logging callback.
     * Used to print native wolfSSL debug logs when 'wolfssl.debug' System
     * property is set to "true".
     */
    private static WolfSSLNativeLoggingCallback nativeLogCb = null;

    /**
     * Default constructor for wolfJSSE debug class.
     */
    public WolfSSLDebug() {
    }

    /**
     * Check if "wolfssljni.debug" System property is set to "true".
     *
     * @return true if set to "true", otherwise return false
     */
    private static boolean checkJNIDebugProperty() {

        String enabled = System.getProperty("wolfssljni.debug");

        if ((enabled != null) && (enabled.equalsIgnoreCase("true"))) {
            return true;
        }

        return false;
    }

    /**
     * Check if "wolfjsse.debug" System property is set to "true".
     *
     * @return true if set to "true", otherwise return false
     */
    private static boolean checkJSSEDebugProperty() {

        String enabled = System.getProperty("wolfjsse.debug");

        if ((enabled != null) && (enabled.equalsIgnoreCase("true"))) {
            return true;
        }

        return false;
    }

    /**
     * Check if "wolfjsse.debugFormat" is set to "JSON".
     *
     * @return true if set to "JSON", otherwise false.
     */
    private static boolean jsonOutEnabled() {

        String enabled = System.getProperty("wolfjsse.debugFormat");

        if ((enabled != null) && (enabled.equalsIgnoreCase("JSON"))) {
            return true;
        }

        return false;
    }

    /**
     * Check if debug logging is enabled for the specified component, based
     * on the System properties that are set.
     *
     * @param Component to check if debug is enabled for
     *
     * @return true if debug is enabled for this Component, otherwise false
     */
    private static boolean isDebugEnabled(Component component) {

        /* JSSE debug enabled and component is JSSE */
        if (DEBUG && (component == Component.JSSE)) {
            return true;
        }

        /* JSSE debug enabled and component null (backwards compat) */
        if (DEBUG && (component == null)) {
            return true;
        }

        /* JNI debug enabled and component is JNI */
        if (DEBUG_JNI && (component == Component.JNI)) {
            return true;
        }

        return false;
    }

    /**
     * Refresh debug enabled/disabled flags based on current
     * System properties.
     *
     * Applications may need to call this if they adjust debug
     * System properties after the WolfSSLDebug class has been called
     * and initialized the first time. Debug flags (DEBUG, DEBUG_JNI, and
     * DEBUG_JSON are static class variables.
     */
    public static void refreshDebugFlags() {
        DEBUG = checkJSSEDebugProperty();
        DEBUG_JNI = checkJNIDebugProperty();
        DEBUG_JSON = jsonOutEnabled();
    }

    /**
     * Prints out a message to the console
     * @param string message to be printed
     */
    public static void print(String string) {
        print(string, null);
    }

    /**
     * Prints out a message to the console
     * @param string message to be printed
     * @param component JNI/JSSE component being logged, from Component enum
     */
    public static void print(String string, Component component) {
        /* Default to wolfJSSE for backwards compatibility log() method */
        String componentName = "wolfJSSE";

        if (!isDebugEnabled(component)) {
            /* Debug logs not enabled for this component */
            return;
        }

        if (component != null) {
            componentName = component.toString();
        }

        System.out.println(componentName + ": " + string);
    }

    /**
     * Internal method to print debug message as JSON for consumption by
     * tools such as DataDog.
     */
    private static synchronized void logJSON(String tag, String msg,
        long threadID, String threadName, String className) {

        System.out.printf(
            "{\n" +
            "    \"@timestamp\": \"%s\",\n" +
            "    \"level\": \"%s\",\n" +
            "    \"logger_name\": \"wolfJSSE\",\n" +
            "    \"message\": \"%s\",\n" +
            "    \"thread_name\": \"%s\",:\n" +
            "    \"thread_id\": \"%s\"\n" +
            "}\n",
            new Timestamp(new java.util.Date().getTime()),
            tag, "[" + className + "] " + msg,
            threadID, threadName
        );
    }

    /**
     * Internal method to print debug message with byte array hex as JSON,
     * for consumption by tools such as DataDog.
     */
    private static synchronized void logJSONHex(String tag, String label,
        long threadID, String threadName, String className, byte[] in, int sz) {

        /* Convert byte[] to hex string */
        StringBuilder builder = new StringBuilder();
        for (byte b: in) {
            builder.append(String.format("%02X", b));
        }

        logJSON(tag, label + " [" + sz + "]: " + builder.toString(), threadID,
                threadName, className);
    }

    /**
     * Checks if debugging is turned on and prints out the message.
     *
     * Output format can be controlled with the "wolfjsse.debugFormat"
     * System property. If not set, default debug output format will be used.
     * If set to "JSON", all debug logs will be output in the following JSON
     * format, which can be read by DataDog:
     *
     *     {
     *         "@timestamp": "2024-04-05 11:13:07.193",
     *         "level": "INFO",
     *         "logger_name": "wolfJSSE",
     *         "message": "debug message",
     *         "thread_name": "thread_name",:
     *         "thread_id": "thread_ID"
     *     }
     *
     * @param <T> class type of cl
     * @param cl class being called from to get debug info
     * @param tag level of debug message i.e. WolfSSLDebug.INFO
     * @param string message to be printed out
     */
    public static synchronized <T> void log(Class<T> cl, String tag,
        String string) {

        log(cl, null, tag, 0, string);
    }

    /**
     * Checks if debugging is turned on and prints out the message,
     * includes component that is passed in.
     *
     * Output format can be controlled with the "wolfjsse.debugFormat"
     * System property. If not set, default debug output format will be used.
     * If set to "JSON", all debug logs will be output in the following JSON
     * format, which can be read by DataDog:
     *
     *     {
     *         "@timestamp": "2024-04-05 11:13:07.193",
     *         "level": "INFO",
     *         "logger_name": "wolfJSSE",
     *         "message": "debug message",
     *         "thread_name": "thread_name",:
     *         "thread_id": "thread_ID"
     *     }
     *
     * @param <T> class type of cl
     * @param component JNI/JSSE component being logged, from Component enum
     * @param cl class being called from to get debug info
     * @param tag level of debug message i.e. WolfSSLDebug.INFO
     * @param string message to be printed out
     */
    public static synchronized <T> void log(Class<T> cl, Component component,
        String tag, String string) {

        log(cl, component, tag, 0, string);
    }

    /**
     * Checks if debugging is turned on and prints out the message, including
     * native pointer that is passed in.
     *
     * Output format can be controlled with the "wolfjsse.debugFormat"
     * System property. If not set, default debug output format will be used.
     * If set to "JSON", all debug logs will be output in the following JSON
     * format, which can be read by DataDog:
     *
     *     {
     *         "@timestamp": "2024-04-05 11:13:07.193",
     *         "level": "INFO",
     *         "logger_name": "wolfJSSE",
     *         "message": "debug message",
     *         "thread_name": "thread_name",:
     *         "thread_id": "thread_ID"
     *     }
     *
     * @param <T> class type of cl
     * @param component JNI/JSSE component being logged, from Component enum
     * @param cl class being called from to get debug info
     * @param tag level of debug message i.e. WolfSSLDebug.INFO
     * @param nativePtr native pointer of class object, if available
     * @param string message to be printed out
     */
    public static synchronized <T> void log(Class<T> cl, Component component,
        String tag, long nativePtr, String string) {

        long threadID;
        String threadName;
        String className;
        String componentName;

        if (!isDebugEnabled(component)) {
            /* Debug logs not enabled for this component */
            return;
        }

        threadID = Thread.currentThread().getId();
        threadName = Thread.currentThread().getName();

        className = cl.getSimpleName();
        if (nativePtr != 0) {
            className = className + ": " + nativePtr;
        }

        /* Default to wolfJSSE for backwards compatibility log() method */
        componentName = "wolfJSSE";
        if (component != null) {
            componentName = component.toString();
        }

        if (DEBUG_JSON) {
            logJSON(tag, string, threadID, threadName, className);
        }
        else {
            System.out.println(
                new Timestamp(new java.util.Date().getTime()) +
                " [" + componentName + " " + tag + ": TID " + threadID +
                ": " + className + "] " + string);
        }
    }

    /**
     * Print out a byte array in hex if debugging is enabled.
     *
     * Output format can be controlled with the "wolfjsse.debugFormat"
     * System property. If not set, default debug output format will be used.
     * If set to "JSON", all debug logs will be output in the following JSON
     * format, which can be read by DataDog:
     *
     *     {
     *         "@timestamp": "2024-04-05 11:13:07.193",
     *         "level": "INFO",
     *         "logger_name": "wolfJSSE",
     *         "message": "label [sz]: array hex string",
     *         "thread_name": "thread_name",:
     *         "thread_id": "thread_ID"
     *     }
     *
     * @param <T> class type for cl
     * @param cl class this method is being called from
     * @param tag level of debug message i.e. WolfSSLDebug.INFO
     * @param label label string to print with hex
     * @param in byte array to be printed as hex
     * @param sz number of bytes from in array to be printed
     */
    public static synchronized <T> void logHex(Class<T> cl, String tag,
        String label, byte[] in, int sz) {

        logHex(cl, null, tag, 0, label, in, sz);
    }

    /**
     * Print out a byte array in hex if debugging is enabled, including
     * component name passed in.
     *
     * Output format can be controlled with the "wolfjsse.debugFormat"
     * System property. If not set, default debug output format will be used.
     * If set to "JSON", all debug logs will be output in the following JSON
     * format, which can be read by DataDog:
     *
     *     {
     *         "@timestamp": "2024-04-05 11:13:07.193",
     *         "level": "INFO",
     *         "logger_name": "wolfJSSE",
     *         "message": "label [sz]: array hex string",
     *         "thread_name": "thread_name",:
     *         "thread_id": "thread_ID"
     *     }
     *
     * @param <T> class type for cl
     * @param cl class this method is being called from
     * @param component JNI/JSSE component being logged, from Component enum
     * @param tag level of debug message i.e. WolfSSLDebug.INFO
     * @param label label string to print with hex
     * @param in byte array to be printed as hex
     * @param sz number of bytes from in array to be printed
     */
    public static synchronized <T> void logHex(Class<T> cl, Component component,
        String tag, String label, byte[] in, int sz) {

        logHex(cl, component, tag, 0, label, in, sz);
    }

    /**
     * Print out a byte array in hex if debugging is enabled, including
     * component name and native pointer.
     *
     * Output format can be controlled with the "wolfjsse.debugFormat"
     * System property. If not set, default debug output format will be used.
     * If set to "JSON", all debug logs will be output in the following JSON
     * format, which can be read by DataDog:
     *
     *     {
     *         "@timestamp": "2024-04-05 11:13:07.193",
     *         "level": "INFO",
     *         "logger_name": "wolfJSSE",
     *         "message": "label [sz]: array hex string",
     *         "thread_name": "thread_name",:
     *         "thread_id": "thread_ID"
     *     }
     *
     * @param <T> class type for cl
     * @param cl class this method is being called from
     * @param component JNI/JSSE component being logged, from Component enum
     * @param tag level of debug message i.e. WolfSSLDebug.INFO
     * @param nativePtr native pointer of class object, if available
     * @param label label string to print with hex
     * @param in byte array to be printed as hex
     * @param sz number of bytes from in array to be printed
     */
    public static synchronized <T> void logHex(Class<T> cl, Component component,
        String tag, long nativePtr, String label, byte[] in, int sz) {

        int i = 0, j = 0;
        int printSz = 0;
        long threadID;
        String threadName;
        String className;
        String componentName;

        if (cl == null || in == null || sz == 0) {
            return;
        }

        if (!isDebugEnabled(component)) {
            /* Debug logs not enabled for this component */
            return;
        }

        threadID = Thread.currentThread().getId();
        threadName = Thread.currentThread().getName();
        printSz = Math.min(in.length, sz);

        className = cl.getSimpleName();
        if (nativePtr != 0) {
            className = className + ": " + nativePtr;
        }

        /* Default to wolfJSSE for backwards compatibility log() method */
        componentName = "wolfJSSE";
        if (component != null) {
            componentName = component.toString();
        }

        if (DEBUG_JSON) {
            logJSONHex(tag, label, threadID, threadName, className, in, sz);
        }
        else {
            System.out.print("[" + componentName + " " + tag + ": TID " +
                threadID + ": " + className + "] " + label + " [" + sz + "]: ");
            for (i = 0; i < printSz; i++) {
                if ((i % 16) == 0) {
                    System.out.printf("\n[" + componentName + " " + tag +
                        ": TID " + threadID + ": " + className + "] %06X",
                        j * 16);
                    j++;
                }
                System.out.printf(" %02X ", in[i]);
            }
            System.out.println("");
        }
    }

    /**
     * Enable native wolfSSL debug logging based on value of the
     * 'wolfssl.debug' System property.
     *
     * Native wolfSSL must ben compiled with "--enable-debug" or
     * DEBUG_WOLFSSL defined in order for debug logs to print.
     */
    public static synchronized void setNativeWolfSSLDebugging() {

        String wolfsslDebug = System.getProperty("wolfssl.debug");

        if ((wolfsslDebug != null) && (wolfsslDebug.equalsIgnoreCase("true"))) {

            WolfSSL.debuggingON();
        }

        /* Register our default logging callback for native wolfSSL logs */
        setDefaultNativeLoggingCallback();
    }

    /**
     * Register default native wolfSSL logging callback.
     * Default callback class is WolfSSLNativeLoggingCallback. This could be
     * modified in the future to allow a custom user-registerable callback.
     */
    private static synchronized void setDefaultNativeLoggingCallback() {

        /* Only create one logging callback object */
        if (nativeLogCb == null) {
            nativeLogCb = new WolfSSLNativeLoggingCallback();
        }

        WolfSSL.setLoggingCb(nativeLogCb);
    }
}

