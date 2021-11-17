/* WolfSSLTrustManager.java
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;
import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLCertificate;
import com.wolfssl.WolfSSLException;

/**
 * wolfSSL implemenation of TrustManagerFactorySpi
 *
 * @author wolfSSL
 */
public class WolfSSLTrustManager extends TrustManagerFactorySpi {
    private KeyStore store;

    /** Default WolfSSLTrustManager constructor */
    public WolfSSLTrustManager() { }

    /* Initialize TrustManager. Attempts to load CA certifciates as trusted
     * roots into wolfSSL from user-provided KeyStore. If KeyStore is null,
     * we attempt to load default system CA certificates in the following
     * priority order:
     *   1. javax.net.ssl.trustStore location, if set. Using password
     *      in javax.net.ssl.trustStorePassword.
     *   2. $JAVA_HOME/lib/security/jssecacerts     (JDK 9+)
     *   3. $JAVA_HOME/jre/lib/security/jssecacerts (JDK <= 8)
     *   4. $JAVA_HOME/lib/security/cacerts         (JDK 9+)
     *   5. $JAVA_HOME/jre/lib/security/cacerts     (JDK <= 8)
     *   6. /etc/ssl/certs/java/cacerts
     *   7. Android: AndroidCAStore system KeyStore
     *   8. Android: $ANDROID_ROOT/etc/security/cacerts
     */
    @Override
    protected void engineInit(KeyStore in) throws KeyStoreException {
        KeyStore certs = in;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered engineInit()");

        if (in == null) {
            String pass = System.getProperty("javax.net.ssl.trustStorePassword");
            String file = System.getProperty("javax.net.ssl.trustStore");
            String type = System.getProperty("javax.net.ssl.trustStoreType");
            String vmVendor = System.getProperty("java.vm.vendor");
            String javaHome = System.getenv("JAVA_HOME");
            String androidRoot = System.getenv("ANDROID_ROOT");
            char passAr[] = null;
            InputStream stream = null;
            boolean systemCertsFound = false;
            int aliasCnt = 0;

            try {
                if (pass != null) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "javax.net.ssl.trustStorePassword system property " +
                        "set, using password");
                    passAr = pass.toCharArray();
                } else {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "javax.net.ssl.trustStorePassword system property " +
                        "not set");
                }

                /* default to JKS KeyStore type if not set at system level */
                /* We default to use a JKS KeyStore type if not set at the
                 * system level, except on Android we use BKS */
                try {
                    if (type != null && type != "") {
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            "javax.net.ssl.trustStoreType system property " +
                            "set: " + type);
                        certs = KeyStore.getInstance(type);
                    } else {
                        if (vmVendor != null &&
                                vmVendor.equals("The Android Project")) {
                            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                "Detected Android VM, using BKS KeyStore type");
                            certs = KeyStore.getInstance("BKS");
                        } else {
                            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            "javax.net.ssl.trustStoreType system property " +
                            "not set, using type: JKS");
                            certs = KeyStore.getInstance("JKS");
                        }
                    }
                } catch (KeyStoreException kse) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.ERROR,
                        "Unsupported KeyStore type: " + type);
                    throw kse;
                }

                try {
                    /* initialize KeyStore, loading certs below will
                     * overwrite if needed, otherwise Android needs
                     * this to be initialized here */
                    certs.load(null, null);

                } catch (Exception e) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.ERROR,
                        "Error initializing KeyStore with load(null, null)");
                    throw new KeyStoreException(e);
                }

                if (file == null) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "javax.net.ssl.trustStore system property not set, " +
                        "trying to load system certs");

                    /* try to load trusted system certs if possible */
                    if (javaHome != null) {
                        if (!javaHome.endsWith("/") &&
                            !javaHome.endsWith("\\")) {
                            /* add trailing slash if not there already */
                            javaHome = javaHome.concat("/");
                        }

                        /* Java 9+ have cacerts under:
                         *     $JAVA_HOME/lib/security/cacerts
                         * Java 8 and earlier use:
                         *     $JAVA_HOME/jre/lib/security/cacerts
                         */
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                "$JAVA_HOME = " + javaHome);

                        /* trying: "lib/security/jssecacerts" */
                        File f = new File(javaHome.concat(
                                          "lib/security/jssecacerts"));
                        if (!f.exists()) {
                            f = new File(javaHome.concat(
                                         "jre/lib/security/jssecacerts"));
                        }
                        if (f.exists()) {
                            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                   "Loading certs from " + f.getAbsolutePath());
                            stream = new FileInputStream(f);
                            certs.load(stream, passAr);
                            stream.close();
                            systemCertsFound = true;
                        } else {
                            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                "$JAVA_HOME/(jre/)lib/security/jssecacerts: " +
                                "not found");
                        }

                        /* trying: "lib/security/cacerts" */
                        f = new File(javaHome.concat("lib/security/cacerts"));
                        if (!f.exists()) {
                            f = new File(javaHome.concat(
                                         "jre/lib/security/cacerts"));
                        }
                        if (f.exists()) {
                            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                    "Loading certs from " + f.getAbsolutePath());
                            stream = new FileInputStream(f);
                            certs.load(stream, passAr);
                            stream.close();
                            systemCertsFound = true;
                        } else {
                            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                "$JAVA_HOME/(jre/)lib/security/cacerts: " +
                                "not found");
                        }
                    } else {
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            "$JAVA_HOME not set, unable to load system certs");
                    }

                    if (systemCertsFound == false) {
                        /* try loading from common system paths */
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            "Trying to load system certs from common " +
                            "system paths");

                        /* trying: "/etc/ssl/certs/java/cacerts" */
                        File f = new File("/etc/ssl/certs/java/cacerts");
                        if (f.exists()) {
                            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                   "Loading certs from " + f.getAbsolutePath());
                            stream = new FileInputStream(f);
                            certs.load(stream, passAr);
                            stream.close();
                            systemCertsFound = true;
                        } else {
                            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                "/etc/ssl/certs/java/cacerts: not found");
                        }
                    }

                    if (androidRoot != null) {

                        /* first try to use AndroidCAStore KeyStore, this is
                         * pre-loaded with Android system CA certs */
                        try {
                            certs = KeyStore.getInstance("AndroidCAStore");
                            certs.load(null, null);
                            systemCertsFound = true;
                            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                "Using AndroidCAStore KeyStore for default " +
                                "system certs");
                        } catch (KeyStoreException e) {
                            /* error finding AndroidCAStore */
                            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                "AndroidCAStore KeyStore not found, trying " +
                                "to manually load system certs");
                            systemCertsFound = false;
                        }

                        /* Otherwise, try to manually load system certs */
                        if (systemCertsFound == false) {
                            if (!androidRoot.endsWith("/") &&
                                !androidRoot.endsWith("\\")) {
                                /* add trailing slash if not there already */
                                androidRoot = androidRoot.concat("/");
                            }

                            String caStoreDir = androidRoot.concat(
                                                    "etc/security/cacerts");
                            File cadir = new File(caStoreDir);
                            String[] cafiles = null;
                            try {
                                cafiles = cadir.list();
                            } catch (Exception e) {
                                /* denied access reading cacerts directory */
                                WolfSSLDebug.log(getClass(), WolfSSLDebug.ERROR,
                                    "Permission error when trying to read " +
                                    "system CA certificates");
                                throw new KeyStoreException(e);
                            }
                            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                "Found " + cafiles.length + " CA files to load " +
                                "into KeyStore");

                            /* get factory for cert creation */
                            CertificateFactory cfactory =
                                CertificateFactory.getInstance("X.509");

                            /* loop over all PEM certs */
                            for (String cafile : cafiles) {

                                WolfSSLCertificate certPem = null;
                                String fullCertPath = caStoreDir.concat("/");
                                fullCertPath = fullCertPath.concat(cafile);

                                try {
                                    certPem = new WolfSSLCertificate(
                                        fullCertPath, WolfSSL.SSL_FILETYPE_PEM);
                                } catch (WolfSSLException we) {
                                    /* skip, error parsing PEM */
                                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                        "Skipped loading cert: " + fullCertPath);
                                    if (certPem != null) {
                                        certPem.free();
                                    }
                                    continue;
                                }

                                byte[] derArray = certPem.getDer();
                                certPem.free();
                                ByteArrayInputStream bis =
                                    new ByteArrayInputStream(derArray);
                                Certificate tmpCert = null;

                                try {
                                    tmpCert = cfactory.generateCertificate(bis);
                                    bis.close();
                                } catch (CertificateException ce) {
                                    WolfSSLDebug.log(getClass(), WolfSSLDebug.ERROR,
                                        "Error generating certificate from " +
                                        "ByteArrayInputStream");
                                    bis.close();
                                    throw new KeyStoreException(ce);
                                }

                                String aliasString = "alias" + aliasCnt;
                                try {
                                    certs.setCertificateEntry(aliasString, tmpCert);
                                } catch (KeyStoreException kse) {
                                    WolfSSLDebug.log(getClass(), WolfSSLDebug.ERROR,
                                        "Error setting certificate entry in " +
                                        "KeyStore, skipping loading cert");
                                    continue;
                                }

                                /* increment alias counter for unique aliases */
                                aliasCnt++;
                            }
                            systemCertsFound = true;

                        } /* end Android manual load */
                    }

                    if (systemCertsFound == false) {
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                "No trusted system certs found, none " +
                                "loaded by default");
                    }
                }
                else {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            "Loading certs from " + file);
                    stream = new FileInputStream(file);
                    certs.load(stream, passAr);
                    stream.close();
                }
            } catch (FileNotFoundException ex) {
                throw new KeyStoreException(ex);
            } catch (IOException ex) {
                throw new KeyStoreException(ex);
            } catch (NoSuchAlgorithmException ex) {
                throw new KeyStoreException(ex);
            } catch (CertificateException ex) {
                throw new KeyStoreException(ex);
            }
        }
        this.store = certs;
    }

    @Override
    protected void engineInit(ManagerFactoryParameters arg0)
        throws InvalidAlgorithmParameterException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered engineInit(ManagerFactoryParameters arg0)");

        throw new UnsupportedOperationException(
            "TrustManagerFactory.init(ManagerFactoryParameters) " +
            "not supported yet");
    }

    @Override
    protected TrustManager[] engineGetTrustManagers() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered engineGetTrustManagers()");

        /* array of WolfSSLX509Trust objects to use */
        TrustManager[] tm = {new WolfSSLTrustX509(this.store)};
        return tm;
    }
}

