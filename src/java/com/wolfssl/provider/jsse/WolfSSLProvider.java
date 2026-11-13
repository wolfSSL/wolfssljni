/* WolfSSLProvider.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.Reader;
import java.security.Provider;
import java.security.Security;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Function;
import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLDebug;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLFIPSErrorCallback;

/**
 * wolfSSL JSSE Provider implementation
 *
 * Services are registered by the constructor and are read-only afterwards.
 * Provider and Properties methods that would add, change or remove a service
 * throw SecurityException.
 *
 * @author wolfSSL
 */
public final class WolfSSLProvider extends Provider {

    private static final long serialVersionUID = 1L;

    /* Keep one static reference to native wolfSSL library across
     * all WolfSSLProvider objects. */
    private static WolfSSL sslLib = null;

    /* Set at end of the constructor, after services are registered */
    private transient volatile boolean servicesLocked = false;

    /* False for deserialized objects, which can never be changed */
    private final transient boolean constructed;

    /**
     * Inner callback class for wolfCrypt FIPS 140-2/3 errors
     */
    public static class JSSEFIPSErrorCallback implements WolfSSLFIPSErrorCallback {

        /** Default JSSEFIPSErrorCallback constructor */
        public JSSEFIPSErrorCallback() { }

        /**
         * wolfCrypt FIPS 140-2/3 error callback.
         * Called when FIPS integrity test fails
         *
         * @param ok 0 if FIPS error not OK, otherwise 1
         * @param err wolfCrypt FIPS error code
         * @param hash expected wolfCrypt FIPS verifyCore hash value
         */
        public void errorCallback(int ok, int err, String hash) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "In FIPS error callback, ok = " + ok + " err = " + err);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "hash = " + hash);

            if (err == -203) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "In core integrity hash check failure, copy " +
                    "above hash");
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "into verifyCore[] in fips_test.c and rebuild " +
                    "native wolfSSL");
            }
        }
    }

    /**
     * wolfSSL JSSE Provider class
     */
    @SuppressWarnings("deprecation")
    public WolfSSLProvider() {
        super("wolfJSSE", 1.19, "wolfSSL JSSE Provider");
        /* super("wolfJSSE", "1.19", "wolfSSL JSSE Provider"); */
        constructed = true;

        /* load native wolfSSLJNI library */
        WolfSSL.loadLibrary();

        /* Register wolfCrypt FIPS error callback. Used for FIPS builds to
         * output correct verifyCore hash to logging mechanism. */
        int rc = WolfSSL.setFIPSCb(new JSSEFIPSErrorCallback());
        if (rc != WolfSSL.SSL_SUCCESS) {
            if (rc == WolfSSL.NOT_COMPILED_IN) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "FIPS callback not set, not using wolfCrypt FIPS");
            } else {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "Error setting wolfCrypt FIPS Callback, ret = " + rc);
            }
        } else {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "Registered wolfCrypt FIPS error callback");
        }

        try {
            /* initialize native wolfSSL */
            sslLib = new WolfSSL();
        } catch (WolfSSLException e) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "Failed to initialize native wolfSSL library");
        }

        /* Enable native wolfSSL debug logging if 'wolfssl.debug' System
         * property has been set to "true" and native wolfSSL compiled with
         * '--enable-debug' */
        WolfSSLDebug.setNativeWolfSSLDebugging();

        /* Key Factory */
        put("KeyManagerFactory.PKIX",
                "com.wolfssl.provider.jsse.WolfSSLKeyManager");
        put("KeyManagerFactory.X509",
                "com.wolfssl.provider.jsse.WolfSSLKeyManager");
        put("KeyManagerFactory.SunX509",
                "com.wolfssl.provider.jsse.WolfSSLKeyManager");

        /* TLS connection Contexts */
        if (WolfSSL.TLSv1Enabled()) {
            put("SSLContext.TLSv1",
                    "com.wolfssl.provider.jsse.WolfSSLContext$TLSV1_Context");
        }
        if (WolfSSL.TLSv11Enabled()) {
            put("SSLContext.TLSv1.1",
                    "com.wolfssl.provider.jsse.WolfSSLContext$TLSV11_Context");
        }
        if (WolfSSL.TLSv12Enabled()) {
            put("SSLContext.TLSv1.2",
                    "com.wolfssl.provider.jsse.WolfSSLContext$TLSV12_Context");
        }
        if (WolfSSL.TLSv13Enabled()) {
            put("SSLContext.TLSv1.3",
                    "com.wolfssl.provider.jsse.WolfSSLContext$TLSV13_Context");
        }
        if (WolfSSL.DTLSv13Enabled()) {
            put("SSLContext.DTLSv1.3",
                    "com.wolfssl.provider.jsse.WolfSSLContext$DTLSV13_Context");
        }
        put("SSLContext.SSL",
                "com.wolfssl.provider.jsse.WolfSSLContext$TLSV23_Context");
        put("SSLContext.TLS",
                "com.wolfssl.provider.jsse.WolfSSLContext$TLSV23_Context");
        put("SSLContext.DEFAULT",
                "com.wolfssl.provider.jsse.WolfSSLContext$DEFAULT_Context");

        /* Trust Factory */
        put("TrustManagerFactory.PKIX",
                "com.wolfssl.provider.jsse.WolfSSLTrustManager");
        put("TrustManagerFactory.X509",
                "com.wolfssl.provider.jsse.WolfSSLTrustManager");
        put("TrustManagerFactory.SunX509",
                "com.wolfssl.provider.jsse.WolfSSLTrustManager");

        /* No services can be added or removed after this point */
        servicesLocked = true;
    }

    /**
     * Lock the deserialized object. It is then replaced by readResolve().
     *
     * @param in stream to read the object from
     * @throws IOException if reading the stream fails
     * @throws ClassNotFoundException if a serialized class is not found
     */
    private void readObject(ObjectInputStream in)
        throws IOException, ClassNotFoundException {

        servicesLocked = true;
        in.defaultReadObject();
    }

    /**
     * Replace a deserialized provider with the registered wolfJSSE provider,
     * or a new one, so services always come from the constructor and never
     * from serialized data.
     *
     * @return the registered wolfJSSE provider, or a new WolfSSLProvider
     */
    private Object readResolve() {

        Provider p = Security.getProvider("wolfJSSE");
        if (p instanceof WolfSSLProvider) {
            return p;
        }
        return new WolfSSLProvider();
    }

    /**
     * Reject service changes once services are registered. Prevents code from
     * adding a non-wolfSSL implementation under the wolfJSSE name.
     *
     * @throws SecurityException if services are locked or this object was
     *         deserialized
     */
    private void checkServicesUnlocked() {

        if (servicesLocked || !constructed) {
            throw new SecurityException(
                "wolfJSSE provider services cannot be modified");
        }
    }

    @Override
    public synchronized Object put(Object key, Object value) {
        checkServicesUnlocked();
        return super.put(key, value);
    }

    @Override
    public synchronized void putAll(Map<?, ?> t) {
        /* Drop entries restored by Provider.readObject() */
        if (!constructed && !servicesLocked) {
            return;
        }
        checkServicesUnlocked();
        super.putAll(t);
    }

    @Override
    public synchronized Object putIfAbsent(Object key, Object value) {
        checkServicesUnlocked();
        return super.putIfAbsent(key, value);
    }

    @Override
    public synchronized Object remove(Object key) {
        checkServicesUnlocked();
        return super.remove(key);
    }

    @Override
    public synchronized boolean remove(Object key, Object value) {
        checkServicesUnlocked();
        return super.remove(key, value);
    }

    @Override
    public synchronized boolean replace(Object key, Object oldValue,
        Object newValue) {
        checkServicesUnlocked();
        return super.replace(key, oldValue, newValue);
    }

    @Override
    public synchronized Object replace(Object key, Object value) {
        checkServicesUnlocked();
        return super.replace(key, value);
    }

    @Override
    public synchronized void replaceAll(BiFunction<? super Object,
        ? super Object, ? extends Object> function) {
        checkServicesUnlocked();
        super.replaceAll(function);
    }

    @Override
    public synchronized Object compute(Object key, BiFunction<? super Object,
        ? super Object, ? extends Object> remappingFunction) {
        checkServicesUnlocked();
        return super.compute(key, remappingFunction);
    }

    @Override
    public synchronized Object computeIfAbsent(Object key, Function<? super
        Object, ? extends Object> mappingFunction) {
        checkServicesUnlocked();
        return super.computeIfAbsent(key, mappingFunction);
    }

    @Override
    public synchronized Object computeIfPresent(Object key, BiFunction<?
        super Object, ? super Object, ? extends Object> remappingFunction) {
        checkServicesUnlocked();
        return super.computeIfPresent(key, remappingFunction);
    }

    @Override
    public synchronized Object merge(Object key, Object value,
        BiFunction<? super Object, ? super Object, ? extends Object>
        remappingFunction) {
        checkServicesUnlocked();
        return super.merge(key, value, remappingFunction);
    }

    @Override
    public synchronized void clear() {
        checkServicesUnlocked();
        super.clear();
    }

    @Override
    public synchronized Object setProperty(String key, String value) {
        checkServicesUnlocked();
        return super.setProperty(key, value);
    }

    @Override
    public synchronized void load(InputStream inStream) throws IOException {
        checkServicesUnlocked();
        super.load(inStream);
    }

    @Override
    public synchronized void load(Reader reader) throws IOException {
        checkServicesUnlocked();
        super.load(reader);
    }

    @Override
    public synchronized void loadFromXML(InputStream in) throws IOException {
        checkServicesUnlocked();
        super.loadFromXML(in);
    }

    @Override
    protected synchronized void putService(Provider.Service s) {
        checkServicesUnlocked();
        super.putService(s);
    }

    @Override
    protected synchronized void removeService(Provider.Service s) {
        checkServicesUnlocked();
        super.removeService(s);
    }

    /**
     * Set the native wolfSSL crypto callback devId for SSLContext
     * objects.
     *
     * This only stores the device ID. Use registerDevId() to register the
     * native crypto callback for the device.
     *
     * @param devId crypto callback device ID. Default is
     *        WolfSSL.INVALID_DEVID which will cause software crypto
     *        to be used. To reset global device ID, pass in
     *        WolfSSL.INVALID_DEVID.
     *
     * @throws WolfSSLException never thrown, declared for API compatibility
     */
    public static void setDevId(int devId) throws WolfSSLException {

        /* Store devId into static WolfSSL variable, used by
         * WolfSSLContext (SSLContext) */
        WolfSSL.devId = devId;

    }

    /**
     * Registers native crypto callback device ID for given devID.
     *
     * This currently requires custom modifications to native JNI code.
     * Please contact support@wolfssl.com to discuss your use case and
     * get help modifying native code if needed.
     *
     * Once this API has been called to register the crypto callback device,
     * WolfSSLProvider.setDevId() or WolfSSLContext.setDevId() should be
     * called to set the device ID to be used for new SSLContext objects.
     *
     * @param devId crypto callback device ID.
     *
     * @throws WolfSSLException if error registering native crypto callback
     *         function
     */
    public void registerDevId(int devId) throws WolfSSLException {
        int ret = 0;

        /* Call native JNI entry point to register native wolfSSL
         * CryptoDevice callback function. See native JNI function in
         * native/com_wolfssl_WolfSSL.c */
        ret = WolfSSL.cryptoCbRegisterDevice(devId);
        if (ret != 0) {
            throw new WolfSSLException(
                "Error registering native wolfSSL crypto callback, " +
                "ret = " + ret);
        }
    }

    /**
     * Un-registers native crypto callback device ID for given devID.
     *
     * This API can be called after WolfSSLProvider.registerDevId(int devId)
     * to unregister the native crypto callback device ID for the given devId.
     *
     * @param devId crypto callback device ID to unregister device for
     *
     * @throws WolfSSLException if error registering native crypto callback
     *         function
     */
    public void unRegisterDevId(int devId) throws WolfSSLException {
        int ret = 0;

        /* Call native JNI entry point to unregister native wolfSSL
         * CryptoDevice callback function. See native JNI function in
         * native/com_wolfssl_WolfSSL.c */
        ret = WolfSSL.cryptoCbUnRegisterDevice(devId);
        if (ret != 0) {
            throw new WolfSSLException(
                "Error unregistering native wolfSSL crypto callback, " +
                "ret = " + ret);
        }
    }
}

