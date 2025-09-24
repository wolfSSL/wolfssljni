/* WolfSSLEngineHelper.java
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
package com.wolfssl.provider.jsse;

import java.lang.reflect.Method;
import java.lang.reflect.InvocationTargetException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import javax.net.ssl.SSLParameters;
import com.wolfssl.provider.jsse.WolfSSLJDK8Helper;

/**
 * WolfSSLParametersHelper class
 * @author wolfSSL Inc.
 */
public class WolfSSLParametersHelper
{
    private static Method getServerNames = null;
    private static Method setServerNames = null;
    private static Method getApplicationProtocols = null;
    private static Method setApplicationProtocols = null;
    private static Method getEndpointIdentificationAlgorithm = null;
    private static Method setEndpointIdentificationAlgorithm = null;
    private static Method getSNIMatchers = null;
    private static Method setSNIMatchers = null;
    private static Method getMaximumPacketSize = null;
    private static Method setMaximumPacketSize = null;
    private static Method setUseCipherSuitesOrder = null;
    private static Method getUseCipherSuitesOrder = null;

    /** Default WolfSSLParametersHelper constructor */
    public WolfSSLParametersHelper() { }

    /* Runs upon class initialization to detect if this version of Java
     * has SSLParameters methods that older versions may not have */
    static
    {
        AccessController.doPrivileged(new PrivilegedAction<Object>() {
            public Object run() {
                Class<?> c = SSLParameters.class;
                Method[] methods = c.getDeclaredMethods();

                if (methods != null) {
                    /* check for availability of methods */
                    try {
                        for (Method m : methods) {
                            switch (m.getName()) {
                                case "getServerNames":
                                    getServerNames = m;
                                    continue;
                                case "setServerNames":
                                    setServerNames = m;
                                    continue;
                                case "getApplicationProtocols":
                                    getApplicationProtocols = m;
                                    continue;
                                case "setApplicationProtocols":
                                    setApplicationProtocols = m;
                                    continue;
                                case "getEndpointIdentificationAlgorithm":
                                    getEndpointIdentificationAlgorithm = m;
                                    continue;
                                case "setEndpointIdentificationAlgorithm":
                                    setEndpointIdentificationAlgorithm = m;
                                    continue;
                                case "getSNIMatchers":
                                    getSNIMatchers = m;
                                    continue;
                                case "setSNIMatchers":
                                    setSNIMatchers = m;
                                    continue;
                                case "getMaximumPacketSize":
                                    getMaximumPacketSize = m;
                                    continue;
                                case "setMaximumPacketSize":
                                    setMaximumPacketSize = m;
                                    continue;
                                case "setUseCipherSuitesOrder":
                                    setUseCipherSuitesOrder = m;
                                    continue;
                                case "getUseCipherSuitesOrder":
                                    getUseCipherSuitesOrder = m;
                                    continue;
                                default:
                                    continue;
                            }
                        }
                    } catch (Exception e) {
                    }
                }

                return null;
            }
        });
    }

    /**
     * Creates a new SSLParameters class with the same settings as the
     * WolfSSLParameters passed in.
     *
     * @param in WolfSSLParameters to convert to SSLParameters
     * @return new SSLParameters object representing same settings as "in"
     */
    protected static SSLParameters decoupleParams(WolfSSLParameters in) {

        /* Note: Android API 23 only supports the following SSLParameters
         * methods. All newer methods we will need to conditionally
         * support:
         *     get/setCipherSuites()
         *     get/setCipherSuites()
         *     get/setNeedClientAuth()
         *     get/setWantClientAuth()
         */

        SSLParameters ret = new SSLParameters(in.getCipherSuites(),
                                              in.getProtocols());

        ret.setNeedClientAuth(in.getNeedClientAuth());
        if (!ret.getNeedClientAuth()) {
            ret.setWantClientAuth(in.getWantClientAuth());
        }

        /* Methods added as of JDK 1.8 that rely on specific classes that
         * do not existing in older JDKs. Since older JDKs will not have them,
         * use Java reflection to detect availability in helper class. */
        if (setServerNames != null || setApplicationProtocols != null ||
            setEndpointIdentificationAlgorithm != null ||
            setSNIMatchers != null || setUseCipherSuitesOrder != null) {

            try {
                /* load WolfSSLJDK8Helper at runtime, not compiled
                 * on older JDKs */
                Class<?> cls = Class.forName(
                    "com.wolfssl.provider.jsse.WolfSSLJDK8Helper");
                Object obj = cls.getConstructor().newInstance();
                Class<?>[] paramList = new Class<?>[3];
                paramList[0] = javax.net.ssl.SSLParameters.class;
                paramList[1] = java.lang.reflect.Method.class;
                paramList[2] = com.wolfssl.provider.jsse.WolfSSLParameters.class;
                Method mth = null;

                if (setServerNames != null) {
                    mth = cls.getDeclaredMethod("setServerNames", paramList);
                    mth.invoke(obj, ret, setServerNames, in);
                }
                if (setApplicationProtocols != null) {
                    mth = cls.getDeclaredMethod(
                        "setApplicationProtocols", paramList);
                    mth.invoke(obj, ret, setApplicationProtocols, in);
                }
                if (setEndpointIdentificationAlgorithm != null) {
                    mth = cls.getDeclaredMethod(
                        "setEndpointIdentificationAlgorithm", paramList);
                    mth.invoke(obj, ret,
                        setEndpointIdentificationAlgorithm, in);
                }
                if (setSNIMatchers != null) {
                    mth = cls.getDeclaredMethod("setSNIMatchers", paramList);
                    mth.invoke(obj, ret, setSNIMatchers, in);
                }
                if (setUseCipherSuitesOrder != null) {
                    mth = cls.getDeclaredMethod("setUseCipherSuitesOrder",
                                                 paramList);
                    mth.invoke(obj, ret, setUseCipherSuitesOrder, in);
                }

            } catch (Exception e) {
                /* ignore, class not found */
            }
        }

        /* Methods added in later versions of SSLParameters which do not
         * use any additional classes. Since no unique class names, these
         * are called here directly instead of placed into a separate helper
         * class. */
        try {
            if (setMaximumPacketSize != null) {
                setMaximumPacketSize.invoke(ret, in.getMaximumPacketSize());
            }
        } catch (IllegalAccessException | InvocationTargetException e) {
            /* Not available, just ignore and continue */
        }

        try {
            if (setSNIMatchers != null) {
                ret.setSNIMatchers(in.getSNIMatchers());
            }
        } catch (Exception e) {
            /* Not available, just ignore and continue */
        }

        try {
            if (setUseCipherSuitesOrder != null) {
                ret.setUseCipherSuitesOrder(in.getUseCipherSuitesOrder());
            }
        } catch (Exception e) {
            /* Not available, just ignore and continue */
        }

        /* The following SSLParameters features are not yet supported
         * by wolfJSSE (see Android API 23 note above). They are supported
         * with newer versions of SSLParameters, but will need to be added
         * conditionally to wolfJSSE when supported. */
        /*ret.setAlgorithmConstraints(in.getAlgorithmConstraints());
        ret.setEnableRetransmissions(in.getEnableRetransmissions());
        */

        return ret;
    }

    /**
     * Import SSLParameters into an existing WolfSSLParameters object. Used
     * internally by SSLSocket.setSSLParameters().
     *
     * @param in SSLParameters to import settings from
     * @param out WolfSSLParameters to copy settings into
     */
    protected static void importParams(SSLParameters in,
                                       WolfSSLParameters out) {

        if (in == null || out == null) {
            throw new NullPointerException("input parameters cannot be " +
                    "null to WolfSSLParametersHelper.importParams()");
        }

        /* Note: Android API 23 only supports the following SSLParameters
         * methods. All newer methods we will need to conditionally
         * support:
         *     get/setCipherSuites()
         *     get/setCipherSuites()
         *     get/setNeedClientAuth()
         *     get/setWantClientAuth()
         */

        out.setCipherSuites(in.getCipherSuites());
        out.setProtocols(in.getProtocols());
        out.setNeedClientAuth(in.getNeedClientAuth());
        if (!out.getNeedClientAuth()) {
            out.setWantClientAuth(in.getWantClientAuth());
        }

        /* Methods added as of JDK 1.8 that rely on specific classes that
         * do not existing in older JDKs. Since older JDKs will not have them,
         * use Java reflection to detect availability in helper class. */
        if (getServerNames != null || getApplicationProtocols != null ||
            getEndpointIdentificationAlgorithm != null ||
            getSNIMatchers != null || getUseCipherSuitesOrder != null) {
            try {
                /* load WolfSSLJDK8Helper at runtime, not compiled on older JDKs */
                Class<?> cls = Class.forName(
                    "com.wolfssl.provider.jsse.WolfSSLJDK8Helper");
                Object obj = cls.getConstructor().newInstance();
                Class<?>[] paramList = new Class<?>[2];
                paramList[0] = javax.net.ssl.SSLParameters.class;
                paramList[1] = com.wolfssl.provider.jsse.WolfSSLParameters.class;
                Method mth = null;

                if (getServerNames != null) {
                    mth = cls.getDeclaredMethod("getServerNames", paramList);
                    mth.invoke(obj, in, out);
                }
                if (getApplicationProtocols != null) {
                    mth = cls.getDeclaredMethod(
                        "getApplicationProtocols", paramList);
                    mth.invoke(obj, in, out);
                }
                if (getEndpointIdentificationAlgorithm != null) {
                    mth = cls.getDeclaredMethod(
                        "getEndpointIdentificationAlgorithm", paramList);
                    mth.invoke(obj, in, out);
                }
                if (getSNIMatchers != null) {
                    mth = cls.getDeclaredMethod("getSNIMatchers", paramList);
                    mth.invoke(obj, in, out);
                }
                if (getUseCipherSuitesOrder != null) {
                    mth = cls.getDeclaredMethod("getUseCipherSuitesOrder",
                                                 paramList);
                    mth.invoke(obj, in, out);
                }

            } catch (Exception e) {
                /* ignore, class not found */
            }
        }

        /* Methods added in later versions of SSLParameters which do not
         * use any additional classes. Since no unique class names, these
         * are called here directly instead of placed into a separate helper
         * class. */
        try {
            if (getMaximumPacketSize != null) {
                int maxPacketSz = (int)getMaximumPacketSize.invoke(in);
                out.setMaximumPacketSize(maxPacketSz);
            }
        } catch (IllegalAccessException | InvocationTargetException e) {
            /* Not available, just ignore and continue */
        }

        /* The following SSLParameters features are not yet supported
         * by wolfJSSE (see Android API 23 note above). They are supported
         * with newer versions of SSLParameters, but will need to be added
         * conditionally to wolfJSSE when supported. */
        /*out.setAlgorithmConstraints(in.getAlgorithmConstraints());
        out.setEnableRetransmissions(in.getEnableRetransmissions());
        */

        try {
            out.setSNIMatchers(in.getSNIMatchers());
        } catch (Exception e) {
            /* Not available, just ignore and continue */
        }

        try {
            if (getUseCipherSuitesOrder != null) {
                out.setUseCipherSuitesOrder(in.getUseCipherSuitesOrder());
            }
        } catch (Exception e) {
            /* Not available, just ignore and continue */
        }

    }
}

