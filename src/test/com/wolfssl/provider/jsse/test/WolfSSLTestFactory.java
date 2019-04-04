/* WolfSSLTestFactory.java
 *
 * Copyright (C) 2006-2018 wolfSSL Inc.
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
package com.wolfssl.provider.jsse.test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import com.wolfssl.WolfSSLException;

/**
 * Used to create common classes among test cases
 *
 * @author wolfSSL
 */
class WolfSSLTestFactory {

    protected String clientJKS;
    protected String serverJKS;
    protected String allJKS;
    protected String mixedJKS;
    protected String caJKS;
    protected final static char[] jksPass = "wolfSSL test".toCharArray();

    protected WolfSSLTestFactory() throws WolfSSLException {
        String esc = "../../../";
        serverJKS = "examples/provider/server.jks";
        clientJKS = "examples/provider/client.jks";
        allJKS = "examples/provider/all.jks";
        mixedJKS = "examples/provider/all_mixed.jks";
        caJKS = "examples/provider/cacerts.jks";
        
        /* test if running from IDE directory */
        File f = new File(serverJKS);
        if (!f.exists()) {
            f = new File(esc.concat(serverJKS));
            if (!f.exists()) {
                System.out.println("could not find files " + f.toPath());
                throw new WolfSSLException("Unable to find test files");
            }
            serverJKS = esc.concat(serverJKS);
            clientJKS = esc.concat(clientJKS);
            allJKS = esc.concat(allJKS);
            mixedJKS = esc.concat(mixedJKS);
            caJKS = esc.concat(caJKS);
        }
    }
    
    private TrustManager[] internalCreateTrustManager(String type, String file,
            String provider) {
        TrustManagerFactory tm;
        KeyStore cert = null;
        
        try {
            if (file != null) {
                InputStream stream = new FileInputStream(file);
                cert = KeyStore.getInstance("JKS");
                cert.load(stream, jksPass);
                stream.close();
            }
            if (provider == null) {
                tm = TrustManagerFactory.getInstance(type);
            }
            else {
                tm = TrustManagerFactory.getInstance(type, provider);
            }
            tm.init(cert);
            return tm.getTrustManagers();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyStoreException ex) {
            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(WolfSSLTestFactory.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    /**
     * Using default password "wolfSSL test"
     *
     * @param type of key manager i.e. "SunX509"
     * @param file file name to read from
     * @return new trustmanager [] on success and null on failure
     */
    protected TrustManager[] createTrustManager(String type, String file) {
        return internalCreateTrustManager(type, file, null);
    }
    
    /**
     * Using default password "wolfSSL test"
     *
     * @param type of key manager i.e. "SunX509"
     * @param file file name to read from
     * @return new trustmanager [] on success and null on failure
     */
    protected TrustManager[] createTrustManager(String type, String file,
            String provider) {
        return internalCreateTrustManager(type, file, provider);
    }

    private KeyManager[] internalCreateKeyManager(String type, String file,
            String provider) {
        KeyManagerFactory km;
        KeyStore pKey;

        try {
            /* set up KeyStore */
            InputStream stream = new FileInputStream(file);
            pKey = KeyStore.getInstance("JKS");
            pKey.load(stream, jksPass);
            stream.close();
            
            /* load private key */
            if (provider == null) {
                km = KeyManagerFactory.getInstance(type);
            }
            else {
                km = KeyManagerFactory.getInstance(type, provider);
            }
            km.init(pKey, jksPass);
            return km.getKeyManagers();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyStoreException ex) {
            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnrecoverableKeyException ex) {
            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(WolfSSLTestFactory.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    /**
     * Using default password "wolfSSL test"
     *
     * @param type of key manager i.e. "SunX509"
     * @param file file name to read from
     * @return new keymanager [] on success and null on failure
     */
    protected KeyManager[] createKeyManager(String type, String file) {
        return internalCreateKeyManager(type, file, null);
    }
    
    /**
     * Using default password "wolfSSL test"
     *
     * @param type of key manager i.e. "SunX509"
     * @param file file name to read from
     * @return new keymanager [] on success and null on failure
     */
    protected KeyManager[] createKeyManager(String type, String file,
            String provider) {
        return internalCreateKeyManager(type, file, provider);
    }

    private SSLContext internalCreateSSLContext(String protocol, String provider,
            TrustManager[] tm, KeyManager[] km) {
        SSLContext ctx = null;
        TrustManager[] localTm = tm;
        KeyManager[] localKm = km;

        try {
            if (provider != null) {
                ctx = SSLContext.getInstance(protocol, provider);
                if (tm == null) {
                    localTm = createTrustManager("SunX509", clientJKS);
                }
                if (km == null) {
                    localKm = createKeyManager("SunX509", clientJKS);
                }
            } else {
                ctx = SSLContext.getInstance(protocol);
                if (tm == null) {
                    localTm = createTrustManager("SunX509", clientJKS, provider);
                }
                if (km == null) {
                    localKm = createKeyManager("SunX509", clientJKS, provider);
                }
            }

            if (km == null) {
                localKm = createKeyManager("SunX509", clientJKS);
            }
            ctx.init(localKm, localTm, null);
            return ctx;
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyManagementException ex) {
            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            System.out.println("Could not find the provider : " + provider);
            Logger.getLogger(WolfSSLEngineTest.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * Creates a new context using default provider of system (usually Oracle)
     *
     * @param protocol to be used when creating context
     * @return new SSLContext on success and null on failure
     */
    protected SSLContext createSSLContext(String protocol) {
        return internalCreateSSLContext(protocol, null, null, null);
    }

    /**
     * Creates a new context using provider passed in
     *
     * @param protocol to be used when creating context
     * @param provider to be used when creating context
     * @return new SSLContext on success and null on failure
     */
    protected SSLContext createSSLContext(String protocol, String provider) {
        return internalCreateSSLContext(protocol, provider, null, null);
    }

    /**
     * Creates a new context using provider passed in and km/tm
     *
     * @param protocol to be used when creating context
     * @param provider to be used when creating context (can be null)
     * @param tm trust manager to use (can be null)
     * @param km key manager to use (can be null)
     * @return new SSLContext on success and null on failure
     */
    protected SSLContext createSSLContext(String protocol, String provider,
            TrustManager[] tm, KeyManager[] km) {
        return internalCreateSSLContext(protocol, provider, tm, km);
    }
    
    /**
     * Red coloring to fail message
     * @param msg 
     */
    static void fail(String msg) {
        System.out.println(msg);
        /* commented out because of portability concerns
        if (System.getProperty("os.name").contains("Windows")) {
            System.out.println(msg);
        }
        else {
            String red = "\u001B[31m";
            String reset = "\u001B[0m";
            System.out.println(red + msg + reset);
        }
        */
    }
    
    /**
     * Green coloring to pass message
     * @param msg 
     */
    static void pass(String msg) {
        System.out.println(msg);
        /* commented out because of portability concerns
        if (System.getProperty("os.name").contains("Windows")) {
            System.out.println(msg);
        }
        else {
            String green = "\u001B[32m";
            String reset = "\u001B[0m";
            System.out.println(green + msg + reset);
        }
        */
    }
}
