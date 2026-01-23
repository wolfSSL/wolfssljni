/* WolfSSLTrustManager.java
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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.security.Security;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CertificateException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;
import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLDebug;
import com.wolfssl.WolfSSLCertificate;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLJNIException;

/**
 * wolfSSL implemenation of TrustManagerFactorySpi
 *
 * @author wolfSSL
 */
public class WolfSSLTrustManager extends TrustManagerFactorySpi {
    private KeyStore store;
    private boolean initialized = false;

    /** Default WolfSSLTrustManager constructor */
    public WolfSSLTrustManager() { }

    /**
     * Try to load KeyStore from System properties if set.
     *
     * If a KeyStore file has been specified in the javax.net.ssl.keyStore
     * System property, then we try to load it in the following ways:
     *
     *   1. Using type specified in javax.net.ssl.keyStoreType. If not given:
     *   2. Using wolfJCE WKS type, if available
     *   3. Using BKS type if on Android
     *   4. Using JKS type if above all fail
     *
     * @param wksAvailable Boolean indicating if wolfJCE WKS KeyStore type
     *        is available, true if so, false if not
     * @param tsPass javax.net.ssl.trustStorePassword system property
     *        value, or null
     * @param tsFile javax.net.ssl.trustStore system property value, or null
     * @param tsType javax.net.ssl.trustStoreType system property value,
     *        or null
     * @param requiredType KeyStore type required by user through
     *        java.security if wolfjsse.keystore.type.required property
     *        has been set.
     *
     * @return new KeyStore object that has been created and loaded using
     *         details specified in System properties.
     *
     * @throws KeyStoreException if javax.net.ssl.keyStore property is
     *         set but KeyStore fails to load
     */
    private KeyStore LoadKeyStoreFromSystemProperties(boolean wksAvailable,
        String tsPass, String tsFile, String tsType, String requiredType)
        throws KeyStoreException {

        char[] passArr = null;
        KeyStore sysStore = null;

        if (tsFile != null) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "Loading certs from: " + tsFile);

            /* Set KeyStore password if javax.net.ssl.keyStorePassword set */
            if (tsPass != null) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "javax.net.ssl.trustStorePassword system property " +
                    "set, using password");
                passArr = tsPass.toCharArray();
            } else {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "javax.net.ssl.trustStorePassword system property " +
                    "not set");
            }

            /* System keystore type set, try loading using it first */
            if (tsType != null && !tsType.trim().isEmpty()) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "javax.net.ssl.trustStoreType set: " + tsType);

                if (requiredType != null && !requiredType.equals(tsType)) {
                    throw new KeyStoreException(
                        "javax.net.ssl.trustStoreType conflicts with " +
                        "required KeyStore type from " +
                        "wolfjsse.keystore.type.required");
                }

                sysStore = WolfSSLUtil.LoadKeyStoreFileByType(
                    tsFile, passArr, tsType);
            }
            else {
                /* Try with wolfJCE WKS type first, in case wolfCrypt
                 * FIPS is being used */
                if (wksAvailable &&
                    (requiredType == null || requiredType.equals("WKS"))) {
                    sysStore = WolfSSLUtil.LoadKeyStoreFileByType(
                        tsFile, passArr, "WKS");
                }

                /* Try with BKS, if we're running on Android */
                if (sysStore == null && WolfSSLUtil.isAndroid() &&
                    (requiredType == null || requiredType.equals("BKS"))) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "Detected Android VM, trying BKS KeyStore type");
                    sysStore = WolfSSLUtil.LoadKeyStoreFileByType(
                        tsFile, passArr, "BKS");
                }

                /* Try falling back to JKS */
                if (sysStore == null &&
                    (requiredType == null || requiredType.equals("JKS"))) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "javax.net.ssl.trustStoreType system property " +
                        "not set, trying type: JKS");
                    sysStore = WolfSSLUtil.LoadKeyStoreFileByType(
                        tsFile, passArr, "JKS");
                }
            }

            if (sysStore == null) {
                throw new KeyStoreException(
                    "Failed to load KeyStore from System properties, " +
                    "please double check settings");
            }
            else {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "Loaded certs from KeyStore via System properties");
            }
        }

        return sysStore;
    }

    /**
     * Try to load system CA certs from jssecacerts or cacerts KeyStore.
     *
     * Java 9+ has cacerts and/or jssecacerts under:
     *     $JAVA_HOME/lib/security/[jssecacerts | cacerts]
     * Java 8 and earlier use:
     *     $JAVA_HOME/jre/lib/security/[jssecacerts | cacerts ]
     *
     * If wolfJCE WKS KeyStore type is available (ie: wolfJCE has been
     * registered on this system), we first try to load jssecacerts.wks
     * or cacerts.wks as WKS type KeyStore before falling back to trying to
     * load KeyStore type specified in java.security by 'keystore.type'
     * Security property. This is "JKS" type by default on my platforms.
     *
     * @param jh String value of $JAVA_HOME with trailing slash
     * @param wksAvailable Boolean if wolfJCE WKS KeyStore typs is available
     * @param tsPass javax.net.ssl.trustStorePassword, or null if not set
     * @param certBundleName Name of system certificate bundle, either
     *        "jssecacerts" or "cacerts"
     * @param requiredType KeyStore type required by user through
     *        java.security if wolfjsse.keystore.type.required property
     *        has been set.
     *
     * @return KeyStore object loaded with CA certs from jssecacerts, or
     *         null if not able to find KeyStore or load certs
     */
    private KeyStore LoadJavaSystemCerts(String jh, boolean wksAvailable,
        String tsPass, String certBundleName, String requiredType) {

        char[] passArr = null;
        KeyStore sysStore = null;
        File f = null;
        FileInputStream stream = null;

        /* Get default KeyStore type, set in java.security and normally JKS */
        String storeType = Security.getProperty("keystore.type");
        if (storeType != null) {
            storeType = storeType.toUpperCase();
            final String tmpStoreType = storeType;
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "keystore.type Security property set: " + tmpStoreType);
        }

        if (wksAvailable) {
            /* First try wolfJCE WKS converted version for Java 9+ */
            f = new File(jh.concat("lib/security/")
                .concat(certBundleName).concat(".wks"));

            /* Second try wolfJCE WKS converted version for Java <= 8 */
            if (!f.exists()) {
                f = new File(jh.concat("jre/lib/security/")
                    .concat(certBundleName).concat(".wks"));
            }

            if (f.exists()) {
                storeType = "WKS";
            }
        }

        /* Third try normal Java 9+ location */
        if ((f == null) || !f.exists()) {
            f = new File(jh.concat("lib/security/").concat(certBundleName));
        }

        /* Fourth try normal Java <= 8 location */
        if (!f.exists()) {
            f = new File(jh.concat("jre/lib/security/").concat(certBundleName));
        }

        if (f.exists()) {
            final String absPath = f.getAbsolutePath();

            if (requiredType != null && !requiredType.equals(storeType)) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "Skipping loading of system KeyStore, required " +
                    "type does not match wolfjsse.keystore.type.required");
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "Skipped loading: " + absPath);
                return null;
            }

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
               () -> "Loading certs from " + absPath);

            try {
                sysStore = KeyStore.getInstance(storeType);
            } catch (KeyStoreException e) {
                final String tmpStoreType = storeType;
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "Not able to get KeyStore of type: " + tmpStoreType);
                return null;
            }
            try {
                sysStore.load(null, null);
            } catch (IOException | NoSuchAlgorithmException |
                     CertificateException e) {
                final String tmpStoreType = storeType;
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "Not able to load empty KeyStore(" +
                    tmpStoreType + ")");
                return null;
            }

            if (tsPass != null) {
                passArr = tsPass.toCharArray();
            }

            try {
                stream = new FileInputStream(f);
            } catch (FileNotFoundException e) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "Not able to open KeyStore file for reading: " +
                    absPath);
            }

            try {
                sysStore.load(stream, passArr);

            } catch (IOException | NoSuchAlgorithmException |
                     CertificateException e) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "Not able to load KeyStore with file stream: " +
                    absPath);

            } finally {
                try {
                    if (stream != null) {
                        stream.close();
                    }
                } catch (IOException e) {
                }
            }

        } else {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "$JAVA_HOME/(jre/)lib/security/" +
                certBundleName + ": not found");
        }

        return sysStore;
    }

    private KeyStore LoadSystemJsseCaCerts(String jh, boolean wksAvailable,
        String tsPass, String requiredType) {

        return LoadJavaSystemCerts(jh, wksAvailable, tsPass, "jssecacerts",
            requiredType);
    }

    private KeyStore LoadSystemCaCerts(String jh, boolean wksAvailable,
        String tsPass, String requiredType) {

        return LoadJavaSystemCerts(jh, wksAvailable, tsPass, "cacerts",
            requiredType);
    }

    /**
     * Try to load system CA certs from common KeyStore locations.
     *
     * Currently includes:
     *     1. /etc/ssl/certs/java/cacerts
     *
     * @param wksAvailable Boolean if wolfJCE WKS KeyStore typs is available
     * @param tsPass javax.net.ssl.trustStorePassword, or null if not set
     * @param requiredType KeyStore type required by user through
     *        java.security if wolfjsse.keystore.type.required property
     *        has been set.
     *
     */
    private KeyStore LoadCommonSystemCerts(boolean wksAvailable,
        String tsPass, String requiredType) {

        char[] passArr = null;
        final File f;
        FileInputStream stream = null;
        KeyStore sysStore = null;

        /* Get default KeyStore type, set in java.security and normally JKS */
        String storeType = Security.getProperty("keystore.type");
        if (storeType != null) {
            storeType = storeType.toUpperCase();
            final String tmpStoreType = storeType;
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "keystore.type Security property set: " + tmpStoreType);
        }

        f = new File("/etc/ssl/certs/java/cacerts");

        if (f.exists()) {

            if (requiredType != null && !requiredType.equals(storeType)) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "Skipping loading of system KeyStore, required " +
                    "type does not match wolfjsse.keystore.type.required");
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "Skipped loading: " + f.getAbsolutePath());
                return null;
            }

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                   () -> "Loading certs from " + f.getAbsolutePath());

            if (tsPass != null) {
                passArr = tsPass.toCharArray();
            }

            try {
                stream = new FileInputStream(f);
            } catch (FileNotFoundException e) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "Not able to open KeyStore file for reading: " +
                    f.getAbsolutePath());
            }

            try {
                sysStore = KeyStore.getInstance(storeType);
                sysStore.load(stream, passArr);

            } catch (IOException | NoSuchAlgorithmException |
                     CertificateException | KeyStoreException e) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "Not able to get or load KeyStore with file " +
                    "stream: " + f.getAbsolutePath());
                sysStore = null;

            } finally {
                try {
                    if (stream != null) {
                        stream.close();
                    }
                } catch (IOException e) {
                }
            }

        } else {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "/etc/ssl/certs/java/cacerts: not found");
        }

        return sysStore;
    }

    /**
     * Try to load Android system CA certs from AndroidCAStore KeyStore.
     *
     * The AndroidCAStore KeyStore is pre-loaded with Android system CA
     * certs. We try to load this first before going on to load root certs
     * manually, since it's already pre-imported and set up.
     *
     * @param requiredType KeyStore type required by user through
     *        java.security if wolfjsse.keystore.type.required property
     *        has been set.
     *
     * @return KeyStore object referencing AndroidCAStore, or null if not
     *         found or not able to be loaded
     */
    private KeyStore LoadAndroidCAStore(String requiredType) {

        KeyStore sysStore = null;

        if (requiredType != null && !requiredType.equals("AndroidCAStore")) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "Skipping loading of AndroidCAStore, required type " +
                "does not match wolfjsse.keystore.type.required");
            return null;
        }

        try {
            sysStore = KeyStore.getInstance("AndroidCAStore");

        } catch (KeyStoreException e) {
            /* Error finding AndroidCAStore */
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "AndroidCAStore KeyStore not found, not loading");
            return null;
        }

        try {
            sysStore.load(null, null);

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "Using AndroidCAStore KeyStore for default system certs");

        } catch (IOException | NoSuchAlgorithmException |
                 CertificateException e) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "Not able to load AndroidCAStore with null args");
            return null;
        }

        return sysStore;
    }

    /**
     * Try to load Android system root certificates manually by reading
     * all PEM certificates in [android_root]/etc/security/cacerts directory.
     *
     * @param requiredType KeyStore type required by user through
     *        java.security if wolfjsse.keystore.type.required property
     *        has been set.
     *
     * @return KeyStore object containing Android system CA certificates, or
     *         null if none found or error loading any certs
     */
    private KeyStore LoadAndroidSystemCertsManually(String requiredType) {

        int aliasCnt = 0;
        byte[] derArray = null;
        KeyStore sysStore = null;
        CertificateFactory cfactory = null;
        ByteArrayInputStream bis = null;
        Certificate tmpCert = null;
        final String storeType;
        String androidRoot = System.getenv("ANDROID_ROOT");

        if (androidRoot != null) {

            /* Android default KeyStore type is BKS */
            if (requiredType != null) {
                storeType = requiredType;
            } else {
                storeType = "BKS";
            }

            try {
                sysStore = KeyStore.getInstance(storeType);
            } catch (KeyStoreException e) {
                /* Unable to get or load empty KeyStore type */
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "Unable to get or load KeyStore instance, type: " +
                    storeType);
                return null;
            }

            try {
                sysStore.load(null, null);

            } catch (IOException | NoSuchAlgorithmException |
                     CertificateException e) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "Not able to load BKS KeyStore with null args");
                return null;
            }

            /* Add trailing slash if not there already */
            if (!androidRoot.endsWith("/") &&
                !androidRoot.endsWith("\\")) {
                androidRoot = androidRoot.concat("/");
            }

            String caStoreDir = androidRoot.concat("etc/security/cacerts");
            File cadir = new File(caStoreDir);
            final String[] cafiles;

            if (cadir == null) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "Unable to open etc/security/cacerts, none loaded");
                return null;
            }

            try {
                cafiles = cadir.list();
                if (cafiles != null) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "Found " + cafiles.length +
                        " CA files to load into KeyStore");
                }
            } catch (Exception e) {
                /* Denied access reading cacerts directory */
                WolfSSLDebug.log(getClass(), WolfSSLDebug.ERROR,
                    () -> "Permission error when trying to read system " +
                    "CA certificates");
                return null;
            }

            /* Get factory for cert creation */
            try {
                cfactory = CertificateFactory.getInstance("X.509");
            } catch (CertificateException e) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "Not able to get X.509 CertificateFactory instance");
                return null;
            }

            /* Loop over all PEM certs */
            for (String cafile : cafiles) {

                WolfSSLCertificate certPem = null;
                String fullCertPath = caStoreDir.concat("/");
                fullCertPath = fullCertPath.concat(cafile);

                try {
                    certPem = new WolfSSLCertificate(
                        fullCertPath, WolfSSL.SSL_FILETYPE_PEM);
                } catch (WolfSSLException we) {
                    final String tmpPath = fullCertPath;
                    /* skip, error parsing PEM */
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "Skipped loading cert: " + tmpPath);
                    if (certPem != null) {
                        certPem.free();
                    }
                    continue;
                }

                try {
                    derArray = certPem.getDer();
                } catch (WolfSSLJNIException e) {
                    final String tmpPath = fullCertPath;
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "Error getting DER from PEM cert, skipping: " +
                        tmpPath);
                } finally {
                    certPem.free();
                }

                bis = new ByteArrayInputStream(derArray);

                try {
                    tmpCert = cfactory.generateCertificate(bis);

                } catch (CertificateException ce) {
                    final String tmpPath = fullCertPath;
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.ERROR,
                        () -> "Error generating certificate from " +
                        "ByteArrayInputStream, skipped loading cert: " +
                        tmpPath);
                    continue;

                } finally {
                    try {
                        if (bis != null) {
                            bis.close();
                        }
                    } catch (IOException e) {
                    }
                }

                String aliasString = "alias" + aliasCnt;
                try {
                    sysStore.setCertificateEntry(aliasString, tmpCert);
                } catch (KeyStoreException kse) {
                    final String tmpPath = fullCertPath;
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.ERROR,
                        () -> "Error setting certificate entry in " +
                        "KeyStore, skipping loading cert: " +
                        tmpPath);
                    continue;
                }

                /* increment alias counter for unique aliases */
                aliasCnt++;
            }

            if (aliasCnt == 0) {
                /* No certs loaded, don't return empty KeyStore */
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "No root certificates loaded from etc/security/cacerts");
                return null;
            }
        }

        return sysStore;
    }

    /**
     * Initialize TrustManager, loading root/CA certs.
     *
     * Attempts to load CA certifciates as trusted roots into wolfSSL from
     * user-provided KeyStore. If KeyStore is null, we attempt to load default
     * system CA certificates. Certs are loaded in the following priority order:
     *
     *   1. User-provided KeyStore passed in
     *   2. javax.net.ssl.trustStore location, if set. Using password
     *      in javax.net.ssl.trustStorePassword.
     *   3. Java installation 'jssecacerts' bundle:
     *        a. $JAVA_HOME/lib/security/jssecacerts     (JDK 9+)
     *        b. $JAVA_HOME/jre/lib/security/jssecacerts (JDK less than 9)
     *   4. Java installation 'cacerts' bundle:
     *        a. $JAVA_HOME/lib/security/cacerts         (JDK 9+)
     *        b. $JAVA_HOME/jre/lib/security/cacerts     (JDK less than 9)
     *   5. Common system CA certs locations:
     *        a. /etc/ssl/certs/java/cacerts
     *   6. Android: AndroidCAStore system KeyStore
     *   7. Android: $ANDROID_ROOT/etc/security/cacerts
     *
     * If none of the locations above work for finding/loading CA certs,
     * none are loaded into this TrustManager.
     *
     * @param in KeyStore from which to load trusted root/CA certificates, may
     *        be null
     */
    @Override
    protected void engineInit(KeyStore in) throws KeyStoreException {

        KeyStore certs = in;
        final String javaHome;
        final boolean wksAvailable;
        String pass = System.getProperty("javax.net.ssl.trustStorePassword");
        String file = System.getProperty("javax.net.ssl.trustStore");
        String type = System.getProperty("javax.net.ssl.trustStoreType");
        final String requiredType;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered engineInit(KeyStore in)");

        requiredType = WolfSSLUtil.getRequiredKeyStoreType();
        if (requiredType != null) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "java.security has restricted KeyStore type");
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "wolfjsse.keystore.type.required = " + requiredType);
        }

        /* [1] Just use KeyStore passed in by user if available */
        if (in == null) {

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "input KeyStore null, trying to load system CA certs");

            /* Check if wolfJCE WKS KeyStore is registered and available */
            wksAvailable = WolfSSLUtil.WKSAvailable();

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "wolfJCE WKS KeyStore type available: " + wksAvailable);

            /* [2] Try to load from system property details */
            certs = LoadKeyStoreFromSystemProperties(
                wksAvailable, pass, file, type, requiredType);

            /* Get JAVA_HOME for trying to load system certs next */
            if (certs == null) {
                javaHome = WolfSSLUtil.GetJavaHome();
                if (javaHome == null) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "$JAVA_HOME not set, unable to load system " +
                        "CA certs");
                }
                else {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "$JAVA_HOME = " + javaHome);
                }
            } else {
                javaHome = null;
            }

            /* [3] Try to load system jssecacerts */
            if ((certs == null) && (javaHome != null)) {
                certs = LoadSystemJsseCaCerts(javaHome, wksAvailable, pass,
                    requiredType);
            }

            /* [4] Try to load system cacerts */
            if ((certs == null) && (javaHome != null)) {
                certs = LoadSystemCaCerts(javaHome, wksAvailable, pass,
                    requiredType);
            }

            /* [5] Try to load common CA cert locations */
            if (certs == null) {
                certs = LoadCommonSystemCerts(wksAvailable, pass,
                    requiredType);
            }

            /* [6] Try to load system certs if on Android */
            if ((certs == null) && WolfSSLUtil.isAndroid()) {
                certs = LoadAndroidCAStore(requiredType);
            }

            /* [7] Try to load Android system root certs manually */
            if ((certs == null) && WolfSSLUtil.isAndroid()) {
                certs = LoadAndroidSystemCertsManually(requiredType);
            }
        }
        else {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "input KeyStore provided, using for trusted certs");
        }

        /* Verify KeyStore we got matches our requirements, for example
         * type may be restricted by users trying to conform to FIPS
         * requirements */
        if (certs != null) {
            WolfSSLUtil.checkKeyStoreRequirements(certs);
        }

        this.store = certs;
        this.initialized = true;
    }

    @Override
    protected void engineInit(ManagerFactoryParameters arg0)
        throws InvalidAlgorithmParameterException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered engineInit(ManagerFactoryParameters arg0)");

        /* Handle CertPathTrustManagerParameters (used by Tomcat, etc) */
        if (arg0 instanceof javax.net.ssl.CertPathTrustManagerParameters) {
            javax.net.ssl.CertPathTrustManagerParameters certPathParams =
                (javax.net.ssl.CertPathTrustManagerParameters) arg0;
            java.security.cert.CertPathParameters certPathParameters =
                certPathParams.getParameters();

            if (certPathParameters instanceof
                    java.security.cert.PKIXParameters) {
                java.security.cert.PKIXParameters pkixParams =
                    (java.security.cert.PKIXParameters) certPathParameters;
                java.util.Set<java.security.cert.TrustAnchor> anchors =
                    pkixParams.getTrustAnchors();

                try {
                    java.security.KeyStore ks =
                        java.security.KeyStore.getInstance(
                            java.security.KeyStore.getDefaultType());
                    ks.load(null, null);
                    int count = 0;
                    for (java.security.cert.TrustAnchor anchor : anchors) {
                        java.security.cert.X509Certificate cert =
                            anchor.getTrustedCert();
                        if (cert != null) {
                            ks.setCertificateEntry(
                                "trustanchor-" + count, cert);
                            count++;
                        }
                    }
                    final int finalCount = count;
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "Initialized TrustManager from " +
                            "CertPathTrustManagerParameters with " +
                            finalCount + " anchors");
                    engineInit(ks);
                    return;
                } catch (Exception e) {
                    throw new InvalidAlgorithmParameterException(
                        "Failed to create KeyStore from TrustAnchors: " +
                        e.getMessage(), e);
                }
            }
        }

        /* Handle KeyStoreBuilderParameters */
        if (arg0 instanceof javax.net.ssl.KeyStoreBuilderParameters) {
            javax.net.ssl.KeyStoreBuilderParameters ksParams =
                (javax.net.ssl.KeyStoreBuilderParameters) arg0;
            java.util.List<java.security.KeyStore.Builder> builders =
                ksParams.getParameters();

            if (builders != null && !builders.isEmpty()) {
                try {
                    /* Use the first KeyStore builder */
                    java.security.KeyStore ks =
                        builders.get(0).getKeyStore();
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "Initialized TrustManager from " +
                            "KeyStoreBuilderParameters");
                    engineInit(ks);
                    return;
                } catch (Exception e) {
                    throw new InvalidAlgorithmParameterException(
                        "Failed to get KeyStore from Builder: " +
                        e.getMessage(), e);
                }
            }
        }

        throw new InvalidAlgorithmParameterException(
            "Unsupported ManagerFactoryParameters type: " +
            (arg0 != null ? arg0.getClass().getName() : "null"));
    }

    @Override
    protected TrustManager[] engineGetTrustManagers()
        throws IllegalStateException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered engineGetTrustManagers()");

        if (!this.initialized) {
            throw new IllegalStateException("TrustManagerFactory must be " +
                "initialized before use, please call init()");
        }


        /* array of WolfSSLX509Trust objects to use */
        TrustManager[] tm = {new WolfSSLTrustX509(this.store)};
        return tm;
    }
}

