/* WolfSSLUtil.java
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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

import java.util.List;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.security.Security;

import com.wolfssl.WolfSSLException;

/**
 * Utility class to help with JSSE-level functionality.
 *
 * @author wolfSSL
 */
public class WolfSSLUtil {

    /**
     * Sanitize or filter protocol list based on system property limitations.
     *
     * Supported system properties which limit protocol list are:
     *    - java.security.Security:
     *        jdk.tls.disabledAlgorithms
     *
     * These system properties should contain a comma-separated list of
     * values, for example:
     *
     *    jdk.tls.disabledAlgorithms="TLSv1, TLSv1.1"
     *
     * @param protocols Full list of protocols to sanitize/filter, should be
     *                  in a format similar to: "TLSv1", "TLSv1.1", etc.
     *
     * @return New filtered String array of protocol strings
     */
    protected static String[] sanitizeProtocols(String[] protocols) {
        ArrayList<String> filtered = new ArrayList<String>();

        String disabledAlgos =
            Security.getProperty("jdk.tls.disabledAlgorithms");
        List disabledList = null;

        /* If system property not set, no filtering needed */
        if (disabledAlgos == null || disabledAlgos.isEmpty()) {
            return protocols;
        }

        WolfSSLDebug.log(WolfSSLUtil.class, WolfSSLDebug.INFO,
            "sanitizing enabled protocols");
        WolfSSLDebug.log(WolfSSLUtil.class, WolfSSLDebug.INFO,
            "jdk.tls.disabledAlgorithms: " + disabledAlgos);

        /* Remove spaces after commas, split into List */
        disabledAlgos = disabledAlgos.replaceAll(", ",",");
        disabledList = Arrays.asList(disabledAlgos.split(","));

        for (int i = 0; i < protocols.length; i++) {
            if (!disabledList.contains(protocols[i])) {
                filtered.add(protocols[i]);
            }
        }

        return filtered.toArray(new String[filtered.size()]);
    }

    /**
     * Sanitize or filter SSL/TLS cipher suite list based on custom wolfJSSE
     * system property limitations.
     *
     * Supported system Security properties which limit cipher suite list are:
     *    - wolfjsse.enabledCipherSuites
     *
     * This security property should contain a comma-separated list of
     * values, for example:
     *
     *    wolfjsse.enabledCipherSuites=
     *        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, \
     *         TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
     *
     * Only the cipher suites included in this list will be allowed to be used
     * in JSSE TLS connections. Applications can still set cipher suites,
     * using for example SSLParameters, but the set cipher suite list will be
     * filtered by this function to remove any suites not included in the
     * system property mentioned here if it has been set.
     *
     * @param suites Full list of TLS cipher suites to sanitize/filter,
     *               should be in format similar to: "SUITE1", "SUITE2", etc.
     *
     * @return New filtered String array of cipher suites.
     */
    protected static String[] sanitizeSuites(String[] suites) {
        ArrayList<String> filtered = new ArrayList<String>();

        String enabledSuites =
            Security.getProperty("wolfjsse.enabledCipherSuites");
        List enabledList = null;

        /* If system property not set, no filtering needed */
        if (enabledSuites == null || enabledSuites.isEmpty()) {
            return suites;
        }

        WolfSSLDebug.log(WolfSSLUtil.class, WolfSSLDebug.INFO,
            "sanitizing enabled cipher suites");
        WolfSSLDebug.log(WolfSSLUtil.class, WolfSSLDebug.INFO,
            "wolfjsse.enabledCipherSuites: " + enabledSuites);

        /* Remove spaces after commas, split into List */
        enabledSuites = enabledSuites.replaceAll(", ",",");
        enabledList = Arrays.asList(enabledSuites.split(","));

        for (int i = 0; i < suites.length; i++) {
            if (enabledList.contains(suites[i])) {
                filtered.add(suites[i]);
            }
        }

        return filtered.toArray(new String[filtered.size()]);
    }

    /**
     * Check if a given String-based Security property is set.
     *
     * @param property security property to check
     * @return true if security property is set (meaning not null or
     *         empty string), otherwise false.
     */
    protected static boolean isSecurityPropertyStringSet(String property) {

        if (property == null || property.isEmpty()) {
            return false;
        }

        String sysProp = Security.getProperty(property);
        if (sysProp == null || sysProp.isEmpty()) {
            return false;
        }

        return true;
    }

    /**
     * Return TLS signature algorithms allowed if set in
     * wolfjsse.enabledSignatureAlgorithms system Security property.
     *
     * @return Colon delimited list of signature algorithms to be set
     *         in the ClientHello.
     */
    protected static String getSignatureAlgorithms() {

        String sigAlgos =
            Security.getProperty("wolfjsse.enabledSignatureAlgorithms");

        if (sigAlgos == null || sigAlgos.isEmpty()) {
            return null;
        }

        WolfSSLDebug.log(WolfSSLUtil.class, WolfSSLDebug.INFO,
            "restricting enabled ClientHello signature algorithms");
        WolfSSLDebug.log(WolfSSLUtil.class, WolfSSLDebug.INFO,
            "wolfjsse.enabledSigAlgos: " + sigAlgos);

        /* Remove spaces between colons if present */
        sigAlgos = sigAlgos.replaceAll(" : ", ":");

        return sigAlgos;
    }

    /**
     * Return maximum key size allowed if minimum is set in
     * jdk.tls.disabledAlgorithms security property for specified algorithm.
     *
     * @param algo Algorithm to search for key size limitation for, options
     *             are "RSA", "DH", and "EC".
     *
     * @return maximum RSA key size allowed, or 0 if not set in property
     *
     * @throws WolfSSLException if algorithm string does not match
     *         a supported string.
     */
    protected static int getDisabledAlgorithmsKeySizeLimit(String algo)
        throws WolfSSLException {

        int ret = 0;
        List<String> disabledList = null;
        Pattern p = Pattern.compile("\\d+");
        Matcher match = null;
        String needle = null;

        String disabledAlgos =
            Security.getProperty("jdk.tls.disabledAlgorithms");

        if (disabledAlgos == null) {
            return ret;
        }

        switch (algo) {
            case "RSA":
                needle = "RSA keySize <";
                break;
            case "DH":
                needle = "DH keySize <";
                break;
            case "EC":
                needle = "EC keySize <";
                break;
            default:
                throw new WolfSSLException(
                    "Invalid algorithm string for key size limitation");
        }

        /* Remove spaces after commas, split into List */
        disabledAlgos = disabledAlgos.replaceAll(", ",",");
        disabledList = Arrays.asList(disabledAlgos.split(","));

        for (String s: disabledList) {
            if (s.contains(needle)) {
                match = p.matcher(s);
                if (match.find()) {
                    ret = Integer.parseInt(match.group());
                    WolfSSLDebug.log(WolfSSLUtil.class, WolfSSLDebug.INFO,
                        algo + " key size limitation found " +
                        "[jdk.tls.disabledAlgorithms]: " + ret);
                }
            }
        } 

        return ret;
    }
}

