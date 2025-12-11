/* WolfSSLDebug.java
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.logging.*;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.function.Supplier;

/**
 * Central location for all debugging messages
 *
 * This class is used internally for displaying debug message.
 *
 * @author wolfSSL
 */
public class WolfSSLDebug {

    /**
     * Shared time formatter for all debug log messages.
     */
    public static final DateTimeFormatter TIME_FORMATTER =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS")
            .withZone(ZoneId.systemDefault());

    /**
     * Create one Logger per logging layer:
     *     com.wolfssl.jni - JNI layer logging
     *     com.wolfssl.jsse - JSSE layer logging
     */
    private static final Logger jniLogger =
        Logger.getLogger("com.wolfssl.jni");
    private static final Logger jsseLogger =
        Logger.getLogger("com.wolfssl.jsse");

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

    /** Error level debug message */
    public static final String ERROR = "ERROR";

    /** Info level debug message */
    public static final String INFO = "INFO";

    /**
     * Native wolfSSL logging callback.
     * Used to print native wolfSSL debug logs when 'wolfssl.debug' System
     * property is set to "true".
     */
    private static WolfSSLNativeLoggingCallback nativeLogCb = null;

    static {
        configureLoggers();
    }

    /**
     * Custom handler that flushes after each log record
     */
    private static class FlushingStreamHandler extends StreamHandler {
        public FlushingStreamHandler() {
            super(System.err, new WolfSSLFormatter());
        }

        @Override
        public synchronized void publish(LogRecord record) {
            super.publish(record);
            flush();
        }
    }

    /**
     * Configure loggers based on system properties
     */
    private static void configureLoggers() {
        /* Remove any existing handlers */
        for (Handler handler : jniLogger.getHandlers()) {
            jniLogger.removeHandler(handler);
        }
        for (Handler handler : jsseLogger.getHandlers()) {
            jsseLogger.removeHandler(handler);
        }

        /* Only configure handlers if debug is enabled for either component */
        if (DEBUG || DEBUG_JNI) {
            /* Create custom handler that flushes after each record */
            FlushingStreamHandler handler = new FlushingStreamHandler();

            if (DEBUG_JSON) {
                handler.setFormatter(new JSONFormatter());
            } else {
                handler.setFormatter(new WolfSSLFormatter());
            }

            /* Add handlers */
            if (DEBUG_JNI) {
                jniLogger.addHandler(handler);
            }
            if (DEBUG) {
                jsseLogger.addHandler(handler);
            }
        }

        /* Set log levels based on debug properties */
        jniLogger.setLevel(DEBUG_JNI ? Level.ALL : Level.OFF);
        jsseLogger.setLevel(DEBUG ? Level.ALL : Level.OFF);

        /* Disable parent handlers to prevent double logging */
        jniLogger.setUseParentHandlers(false);
        jsseLogger.setUseParentHandlers(false);
    }

    /**
     * Custom formatter for wolfSSL logs
     */
    private static class WolfSSLFormatter extends Formatter {
        @Override
        public String format(LogRecord record) {

            if (record == null) {
                return "null record\n";
            }

            String sourceClass = record.getSourceClassName();
            if (sourceClass == null) {
                sourceClass = "unknown";
            } else {
                /* Extract simple class name (after last dot) */
                int lastDot = sourceClass.lastIndexOf('.');
                if (lastDot >= 0) {
                    sourceClass = sourceClass.substring(lastDot + 1);
                }
            }

            String component;
            String loggerName = record.getLoggerName();
            if (loggerName != null && loggerName.contains("jni")) {
                component = "wolfJNI";
            }
            else {
                component = "wolfJSSE";
            }

            Level level = record.getLevel();
            String levelStr = (level != null) ? level.toString() : "UNKNOWN";

            long threadId = record.getThreadID();
            String message = record.getMessage();
            if (message == null) {
                message = "";
            }

            return String.format("%s [%s %s: TID %d: %s] %s%n",
                TIME_FORMATTER.format(Instant.ofEpochMilli(record.getMillis())),
                component,
                levelStr,
                threadId,
                sourceClass,
                message);
        }
    }

    /**
     * JSON formatter for wolfSSL logs
     */
    private static class JSONFormatter extends Formatter {
        @Override
        public String format(LogRecord record) {
            if (record == null) {
                return "{\"error\": \"null record\"}\n";
            }

            String sourceClass = record.getSourceClassName();
            if (sourceClass == null) {
                sourceClass = "unknown";
            } else {
                /* Extract simple class name (after last dot) */
                int lastDot = sourceClass.lastIndexOf('.');
                if (lastDot >= 0) {
                    sourceClass = sourceClass.substring(lastDot + 1);
                }
            }

            String component;
            String loggerName = record.getLoggerName();
            if (loggerName != null && loggerName.contains("jni")) {
                component = "wolfJNI";
            }
            else {
                component = "wolfJSSE";
            }

            Level level = record.getLevel();
            String levelStr = (level != null) ? level.toString() : "UNKNOWN";

            String threadName = Thread.currentThread().getName();
            if (threadName == null) {
                threadName = "unknown";
            }

            String message = record.getMessage();
            if (message == null) {
                message = "";
            }

            return String.format(
                "{\n" +
                "    \"@timestamp\": \"%s\",\n" +
                "    \"level\": \"%s\",\n" +
                "    \"logger_name\": \"%s\",\n" +
                "    \"message\": \"%s\",\n" +
                "    \"thread_name\": \"%s\",\n" +
                "    \"thread_id\": \"%d\"\n" +
                "}\n",
                TIME_FORMATTER.format(Instant.ofEpochMilli(record.getMillis())),
                levelStr,
                component,
                message,
                threadName,
                record.getThreadID());
        }
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
     * Refresh debug enabled/disabled flags based on current
     * System properties.
     */
    public static synchronized void refreshDebugFlags() {
        boolean oldDebug = DEBUG;
        boolean oldDebugJNI = DEBUG_JNI;

        DEBUG = checkJSSEDebugProperty();
        DEBUG_JNI = checkJNIDebugProperty();
        DEBUG_JSON = jsonOutEnabled();

        /* Only reconfigure if debug state has changed */
        if (oldDebug != DEBUG || oldDebugJNI != DEBUG_JNI) {
            configureLoggers();
        }
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
     *         "thread_name": "thread_name",
     *         "thread_id": "thread_ID"
     *     }
     *
     * @param <T> class type of cl
     * @param cl class being called from to get debug info
     * @param tag level of debug message i.e. WolfSSLDebug.INFO
     * @param messageSupplier supplier of message to be printed out
     */
    public static synchronized <T> void log(Class<T> cl, String tag,
        Supplier<String> messageSupplier) {

        log(cl, Component.JSSE, tag, 0, messageSupplier);
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
     *         "thread_name": "thread_name",
     *         "thread_id": "thread_ID"
     *     }
     *
     * @param <T> class type of cl
     * @param component JNI/JSSE component being logged, from Component enum
     * @param cl class being called from to get debug info
     * @param tag level of debug message i.e. WolfSSLDebug.INFO
     * @param messageSupplier supplier of message to be printed out
     */
    public static synchronized <T> void log(Class<T> cl, Component component,
        String tag, Supplier<String> messageSupplier) {

        log(cl, component, tag, 0, messageSupplier);
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
     *         "thread_name": "thread_name",
     *         "thread_id": "thread_ID"
     *     }
     *
     * @param <T> class type of cl
     * @param component JNI/JSSE component being logged, from Component enum
     * @param cl class being called from to get debug info
     * @param tag level of debug message i.e. WolfSSLDebug.INFO
     * @param nativePtr native pointer of class object, if available
     * @param messageSupplier supplier of message to be printed out
     */
    public static synchronized <T> void log(Class<T> cl, Component component,
        String tag, long nativePtr, Supplier<String> messageSupplier) {

        if (!isDebugEnabled(component)) {
            return;
        }

        Logger targetLogger;
        if (component == Component.JNI) {
            targetLogger = jniLogger;
        }
        else {
            targetLogger = jsseLogger;
        }

        Level level = tag.equals(ERROR) ? Level.SEVERE : Level.INFO;

        String className = cl.getSimpleName();
        if (nativePtr != 0) {
            className = className + ": " + nativePtr;
        }

        LogRecord record = new LogRecord(level, messageSupplier.get());
        record.setSourceClassName(cl.getName());
        record.setLoggerName(targetLogger.getName());
        targetLogger.log(record);
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
     *         "thread_name": "thread_name",
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
        Supplier<String> label, byte[] in, int sz) {

        logHex(cl, Component.JSSE, tag, 0, label, in, sz);
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
     *         "thread_name": "thread_name",
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
        String tag, long nativePtr, Supplier<String> label, byte[] in, int sz) {

        if (!isDebugEnabled(component) || cl == null || in == null || sz == 0) {
            return;
        }

        Logger targetLogger;
        if (component == Component.JNI) {
            targetLogger = jniLogger;
        }
        else {
            targetLogger = jsseLogger;
        }

        Level level = tag.equals(ERROR) ? Level.SEVERE : Level.INFO;

        StringBuilder hexString = new StringBuilder();
        int printSz = Math.min(in.length, sz);

        for (int i = 0; i < printSz; i++) {
            if ((i % 16) == 0) {
                hexString.append(String.format("\n%06X", (i / 16) * 16));
            }
            hexString.append(String.format(" %02X", in[i]));
        }

        String className = cl.getSimpleName();
        if (nativePtr != 0) {
            className = className + ": " + nativePtr;
        }

        LogRecord record = new LogRecord(level, label.get() +
            " [" + sz + "]: " + hexString.toString());
        record.setSourceClassName(cl.getName());
        record.setLoggerName(targetLogger.getName());
        targetLogger.log(record) ;
    }

    /**
     * Check if debug logging is enabled for the specified component.
     *
     * @param component the component to check (JNI or JSSE)
     *
     * @return true if debug logging is enabled for the component,
     */
    public static boolean isDebugEnabled(Component component) {
        if (component == Component.JSSE && DEBUG) {
            return true;
        }
        if (component == Component.JNI && DEBUG_JNI) {
            return true;
        }
        return false;
    }

    /**
     * Enable native wolfSSL debug logging based on value of the
     * 'wolfssl.debug' System property.
     */
    public static synchronized void setNativeWolfSSLDebugging() {
        String wolfsslDebug = System.getProperty("wolfssl.debug");
        if ((wolfsslDebug != null) && (wolfsslDebug.equalsIgnoreCase("true"))) {
            WolfSSL.debuggingON();
        }
        setDefaultNativeLoggingCallback();
    }

    /**
     * Register default native wolfSSL logging callback
     */
    private static synchronized void setDefaultNativeLoggingCallback() {
        if (nativeLogCb == null) {
            nativeLogCb = new WolfSSLNativeLoggingCallback();
        }
        WolfSSL.setLoggingCb(nativeLogCb);
    }
}

