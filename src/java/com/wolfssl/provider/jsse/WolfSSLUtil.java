/* WolfSSLUtil.java
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

import java.util.List;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.Security;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLDebug;
import com.wolfssl.WolfSSLException;

/**
 * Utility class to help with JSSE-level functionality.
 *
 * @author wolfSSL
 */
public class WolfSSLUtil {

    /**
     * Default constructor for WolfSSLUtil class.
     */
    public WolfSSLUtil() {
    }

    /**
     * Sanitize or filter protocol list based on system property limitations
     * and current TLS/DTLS protocol being established.
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
     * @param currentVersion current protocol being used by the object
     *                       that is calling this method. If WolfSSL.INVALID
     *                       is passed in, no filtering is done on protocol
     *                       list based on currentVersion.
     *
     * @return New filtered String array of protocol strings
     */
    protected static String[] sanitizeProtocols(String[] protocols,
        WolfSSL.TLS_VERSION currentVersion) {

        /* Return null if protocols is null, let caller handle */
        if (protocols == null) {
            return null;
        }

        ArrayList<String> filtered = new ArrayList<String>();

        String disabledAlgos =
            Security.getProperty("jdk.tls.disabledAlgorithms");
        List<?> disabledList = null;

        final String tmpDisabledAlgos = disabledAlgos;
        WolfSSLDebug.log(WolfSSLUtil.class, WolfSSLDebug.INFO,
            () -> "sanitizing enabled protocols");
        WolfSSLDebug.log(WolfSSLUtil.class, WolfSSLDebug.INFO,
            () -> "jdk.tls.disabledAlgorithms: " + tmpDisabledAlgos);

        /*
         * WolfJSSE only supports DTLSv1.3, automatically add DTLSv1,
         * and DTLSv1.2 to disabled algorithms for now */

        disabledAlgos += ",DTLSv1,DTLSv1.2";

        /* If WolfSSL.INVALID is passed in as currentVersion, no filtering
         * is done based on current protocol */
        if (currentVersion != WolfSSL.TLS_VERSION.INVALID) {
            /* Remove DTLS protocols if using TLS explicitly. Needed
             * since native wolfSSL doesn't have protocol masks for DTLS. */
            if (currentVersion != WolfSSL.TLS_VERSION.DTLSv1_3) {
                disabledAlgos += ",DTLSv1.3";
            }
        }

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
        List<?> enabledList = null;

        /* If system property not set, no filtering needed */
        if (enabledSuites == null || enabledSuites.isEmpty()) {
            return suites;
        }

        final String tmpSuites = enabledSuites;
        WolfSSLDebug.log(WolfSSLUtil.class, WolfSSLDebug.INFO,
            () -> "sanitizing enabled cipher suites");
        WolfSSLDebug.log(WolfSSLUtil.class, WolfSSLDebug.INFO,
            () -> "wolfjsse.enabledCipherSuites: " + tmpSuites);

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
     * Translate SignatureSchemes property string to wolfJSSE
     * Signature Algorithm format.
     *
     * Signature Algorithms produced from the signature schemes property
     * will not appear in the returned string if they already appear in the
     * given signature algorithms list.
     *
     * @param sigAlgs Full list of TLS signature algorithms to format, provided
     *        by "wolfjsse.enabledSignatureAlgorithms". Should be in format
     *        similar to: "SCHEME1:SCHEME2". See {@link
     *        #getSignatureAlgorithms()}.
     *
     * @param sigSchemes String list of TLS signature schemes to format,
     *        provided by Signature Schemes property. Should be in format
     *        similar to: "SCHEME1,SCHEME2", etc. See {@link
     *        #getSignatureSchemes(boolean)}.
     *
     * @return New colon separated String of filtered signature algorithms.
     *         Returns null if both signature algorithms and signature schemes
     *         lists are null.
     */
    protected static String formatSigSchemes(String sigAlgs,
                                             String sigSchemes) {
        ArrayList<String> sigAlgList = null;
        if (sigAlgs == null && sigSchemes == null) {
            return null;
        }
        else if (sigAlgs != null && sigSchemes == null) {
            return sigAlgs;
        }

        if (sigAlgs != null) {
            sigAlgList = new ArrayList<>(Arrays.asList(sigAlgs.split(":")));
        }
        else {
            sigAlgList = new ArrayList<String>();
        }

        /* Separate schemes */
        sigSchemes = sigSchemes.trim();
        String[] schemes = sigSchemes.split(",");

        /* Tokenize scheme components and convert to signature
           algorithm format */
        for (String scheme : schemes) {
            scheme = scheme.toUpperCase();
            if (scheme.isEmpty()) {
                continue;
            }

            String[] schemeComp = scheme.split("_");
            String algorithm = schemeComp[0];
            String hash = null;

            /* Handle standalone algorithms with no hash component */
            if (schemeComp.length == 1) {
                if (algorithm.equals("ED25519") || algorithm.equals("ED448")) {
                    if (!sigAlgList.contains(algorithm)) {
                        sigAlgList.add(algorithm);
                    }
                    continue;
                } else {
                    /* Invalid format, skip */
                    continue;
                }
            }

            if (schemeComp.length < 2) {
                /* Invalid format, skip */
                continue;
            }

            if (schemeComp.length >= 3 &&
                schemeComp[0].equals("RSA") &&
                schemeComp[1].equals("PSS")) {
                algorithm = "RSA-PSS";
                hash = schemeComp[schemeComp.length - 1];
            } else {
                /* Standard case: algorithm_curvePadding_hash */
                hash = schemeComp[schemeComp.length - 1];
            }

            /* Validate algorithm is supported */
            if (!algorithm.equals("ECDSA") && !algorithm.equals("RSA") &&
                !algorithm.equals("RSA-PSS") && !algorithm.equals("ED25519") &&
                !algorithm.equals("ED448") && !algorithm.equals("DSA")) {
                /* Unknown algorithm, skip */
                WolfSSLDebug.log(WolfSSLUtil.class, WolfSSLDebug.INFO,
                    () -> "Unknown algorithm, skip");
                continue;
            }

            if (!hash.startsWith("SHA") &&
                !hash.equals("MD5")) {
                /* Invalid hash format, skip */
                continue;
            }

            String sigAlg = algorithm + "+" + hash;

            if (!sigAlgList.contains(sigAlg)) {
                sigAlgList.add(sigAlg);
            }
        }

        return String.join(":", sigAlgList);
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

        final String tmpSigAlgos = sigAlgos;
        WolfSSLDebug.log(WolfSSLUtil.class, WolfSSLDebug.INFO,
            () -> "restricting enabled ClientHello signature algorithms");
        WolfSSLDebug.log(WolfSSLUtil.class, WolfSSLDebug.INFO,
            () -> "wolfjsse.enabledSigAlgos: " + tmpSigAlgos);

        /* Remove spaces between colons if present */
        sigAlgos = sigAlgos.replaceAll(" : ", ":");

        return sigAlgos;
    }

    /**
     * Return TLS signature algorithms allowed if set in
     * jdk.tls.client.SignatureSchemes or jdk.tls.server.SignatureSchemes
     * System property.
     *
     * This security property should contain a comma-separated list of
     * values, for example:
     *      jdk.tls.server.SignatureSchemes=
     *          "ecdsa_secp384r1_sha384"
     *      jdk.tls.client.SignatureSchemes=
     *          "ecdsa_secp256r1_sha256,ecdsa_secp384r1_sha384"
     *
     * @param clientMode Get Client or Server SignatureSchemes
     * @return comma delimited list of signature schemes.
     *         Returns null if property has not been set or is empty.
     */
    protected static String getSignatureSchemes(boolean clientMode) {
        String sigSchemes;
        if (clientMode) {
            sigSchemes = System.getProperty("jdk.tls.client.SignatureSchemes");
        }
        else {
            sigSchemes = System.getProperty("jdk.tls.server.SignatureSchemes");
        }

        if (sigSchemes == null || sigSchemes.isEmpty()) {
            return null;
        }

        final String tmpSigSchemes = sigSchemes;
        WolfSSLDebug.log(WolfSSLUtil.class, WolfSSLDebug.INFO,
            () -> "jdk.tls." + (clientMode ? "client" : "server")
                + ".SignatureSchemes: " + tmpSigSchemes);

        /* Remove spaces between colons if present */
        sigSchemes = sigSchemes.replaceAll(" , ", ",");

        return sigSchemes;
    }

    /**
     * Return TLS Supported Curves allowed if set in
     * wolfjsse.enabledSupportedCurves system Security property.
     *
     * @return String array of Supported Curves to be set into the
     *         TLS ClientHello.
     */
    protected static String[] getSupportedCurves() {

        String curves =
            Security.getProperty("wolfjsse.enabledSupportedCurves");

        if (curves == null || curves.isEmpty()) {
            return null;
        }

        final String tmpCurves = curves;
        WolfSSLDebug.log(WolfSSLUtil.class, WolfSSLDebug.INFO,
            () -> "restricting enabled ClientHello supported curves");
        WolfSSLDebug.log(WolfSSLUtil.class, WolfSSLDebug.INFO,
            () -> "wolfjsse.enabledSupportedCurves: " + tmpCurves);

        /* Remove spaces between commas if present */
        curves = curves.replaceAll(", ", ",");

        return curves.split(",");
    }

    /**
     * Return KeyStore type restriction if set in java.security
     * with 'wolfjsse.keystore.type.required' Security property.
     *
     * @return String with required KeyStore type, or null if no
     *         requirement set
     */
    protected static String getRequiredKeyStoreType() {

        String requiredType =
            Security.getProperty("wolfjsse.keystore.type.required");

        if (requiredType == null || requiredType.isEmpty()) {
            return null;
        }
        else {
            requiredType = requiredType.toUpperCase();
        }

        return requiredType;
    }

    /**
     * Return if session cache has been disabled in java.security
     * with 'wolfjsse.clientSessionCache.disabled' Security property.
     *
     * @return true if disabled, otherwise false
     */
    protected static boolean sessionCacheDisabled() {

        String disabled =
            Security.getProperty("wolfjsse.clientSessionCache.disabled");

        if (disabled == null || disabled.isEmpty()) {
            return false;
        }

        if (disabled.equalsIgnoreCase("true")) {
            return true;
        }

        return false;
    }

    /**
     * Return if TLS Extended Master Secret support has been enabled or
     * disabled via the following System property:
     *
     * jdk.tls.useExtendedMasterSecret
     *
     * If property is not set (null) or an empty string, we default to
     * leaving TLS Extended Master Secret enabled.
     *
     * @return true if enabled, otherwise false
     */
    protected static boolean useExtendedMasterSecret() {

        String useEMS =
            System.getProperty("jdk.tls.useExtendedMasterSecret");

        /* Native wolfSSL defaults to having extended master secret support
         * enabled. Do the same here if property not set or empty. */
        if (useEMS == null || useEMS.isEmpty()) {
            return true;
        }

        if (useEMS.equalsIgnoreCase("false")) {
            return false;
        }

        return true;
    }

    /**
     * Check given KeyStore against any pre-defind requirements for
     * KeyStore use, including the following.
     *
     * Restricted KeyStore type: wolfjsse.keystore.type.required
     *
     * @param store Input KeyStore to check against requirements
     *
     * @throws KeyStoreException if KeyStore given does not meet wolfJSSE
     *         requirements
     */
    protected static void checkKeyStoreRequirements(
        KeyStore store) throws KeyStoreException {

        String requiredType = null;

        if (store == null) {
            return;
        }

        requiredType = getRequiredKeyStoreType();
        if ((requiredType != null) &&
            (!store.getType().equals(requiredType))) {
            throw new KeyStoreException(
                "KeyStore does not match required type, got " +
                store.getType() + ", required " + requiredType);
        }
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
                    final int tmpRet = ret;
                    WolfSSLDebug.log(WolfSSLUtil.class, WolfSSLDebug.INFO,
                        () -> algo + " key size limitation found " +
                        "[jdk.tls.disabledAlgorithms]: " + tmpRet);
                }
            }
        }

        return ret;
    }

    /**
     * Get Java home directory path, append trailing slash if needed.
     *
     * First checks JAVA_HOME environment variable. If not set, falls back
     * to java.home system property which should be set by the JVM.
     *
     * @return String path to Java home directory, otherwise null if not set
     */
    protected static String GetJavaHome() {

        String javaHome = System.getenv("JAVA_HOME");

        if (javaHome == null) {
            javaHome = System.getProperty("java.home");
        }

        if (javaHome != null) {
            if (!javaHome.endsWith("/") &&
                !javaHome.endsWith("\\")) {
                /* add trailing slash if not there already */
                javaHome = javaHome.concat("/");
            }
        }

        return javaHome;
    }

    /**
     * Detect if we are running on Android or not.
     *
     * @return true if we are running on an Android VM, otherwise false
     */
    protected static boolean isAndroid() {

        String vmVendor = System.getProperty("java.vm.vendor");

        if ((vmVendor != null) &&
            vmVendor.equals("The Android Project")) {
            return true;
        }

        return false;
    }

    /**
     * Check if wolfJCE WKS KeyStore is available for use.
     *
     * @return true if WKS KeyStore type available, otherwise false
     */
    protected static boolean WKSAvailable() {

        boolean wksAvailable = false;

        try {
            KeyStore.getInstance("WKS");
            wksAvailable = true;
        } catch (KeyStoreException e) {
            /* wolfJCE WKS not available, may be that wolfJCE is not being
             * used or hasn't bee installed in system */
        }

        return wksAvailable;
    }

    /**
     * Try to get KeyStore instance of type specified and load from
     * given file using provided password.
     *
     * @param file KeyStore file to load into new KeyStore object
     * @param pass KeyStore password used to verify KeyStore integrity
     * @param type KeyStore type of file to load
     *
     * @return new KeyStore object loaded with KeyStore file, or null
     *         if unable to load KeyStore
     */
    protected static KeyStore LoadKeyStoreFileByType(String file, char[] pass,
        String type) {

        KeyStore ks = null;
        FileInputStream stream = null;

        try {
            ks = KeyStore.getInstance(type);

            try {
                /* Initialize KeyStore, loading certs below will overwrite if
                 * needed, but Android needs this to be initialized here */
                ks.load(null, null);

            } catch (Exception e) {
                WolfSSLDebug.log(WolfSSLUtil.class, WolfSSLDebug.ERROR,
                    () -> "Error initializing KeyStore with load(null, null)");
                return null;
            }

            stream = new FileInputStream(file);
            ks.load(stream, pass);
            stream.close();

        } catch (KeyStoreException | IOException | NoSuchAlgorithmException |
                 CertificateException e) {
            return null;
        }

        return ks;
    }

}

