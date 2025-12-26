/* WolfSSLServiceLoaderTest.java
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

package com.wolfssl.provider.jsse.test;

import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.BeforeClass;

import java.security.Provider;
import java.security.Security;
import java.util.Iterator;
import java.util.ServiceLoader;
import javax.net.ssl.SSLContext;

import com.wolfssl.provider.jsse.WolfSSLProvider;
import org.junit.Assume;

/**
 * Test suite for ServiceLoader functionality.
 *
 * Tests that WolfSSLProvider can be discovered via Java ServiceLoader
 * mechanism, which is required for Java Module System compatibility and
 * some security frameworks.
 *
 * Note: These tests are skipped on Android since ServiceLoader-based
 * provider discovery relies on META-INF/services which is a JAR mechanism.
 * Android apps register providers directly.
 */
public class WolfSSLServiceLoaderTest {

    @BeforeClass
    public static void setUpClass() {
        System.out.println("JSSE WolfSSLProvider ServiceLoader Test");
    }

    /**
     * Test that WolfSSLProvider can be discovered via ServiceLoader.
     * This verifies that the META-INF/services/java.security.Provider
     * file exists in the JAR and contains the correct provider class name.
     */
    @Test
    public void testProviderDiscoverableViaServiceLoader() {

        /* Skip on Android - ServiceLoader relies on META-INF/services
         * which is a JAR/module system mechanism not available on Android */
        Assume.assumeFalse("Skipping on Android",
            WolfSSLTestFactory.isAndroid());
        ServiceLoader<Provider> serviceLoader =
            ServiceLoader.load(Provider.class);

        boolean foundWolfSSL = false;
        Iterator<Provider> iterator = serviceLoader.iterator();

        while (iterator.hasNext()) {
            Provider provider = iterator.next();
            String className = provider.getClass().getName();

            /* Check if we found WolfSSLProvider */
            if (className.equals(
                "com.wolfssl.provider.jsse.WolfSSLProvider")) {
                foundWolfSSL = true;

                /* Verify provider name is correct */
                assertEquals("Provider name should be wolfJSSE",
                    "wolfJSSE", provider.getName());

                /* Verify it's the right class */
                assertTrue("Provider should be instance of " +
                    "WolfSSLProvider",
                    provider instanceof WolfSSLProvider);

                break;
            }
        }

        assertTrue("WolfSSLProvider should be discoverable via " +
            "ServiceLoader", foundWolfSSL);
    }

    /**
     * Test that ServiceLoader-discovered provider is functional.
     * This verifies that providers loaded via ServiceLoader can actually
     * be used for SSL/TLS operations.
     */
    @Test
    public void testServiceLoaderProviderIsFunctional() throws Exception {

        /* Skip on Android - ServiceLoader relies on META-INF/services
         * which is a JAR/module system mechanism not available on Android */
        Assume.assumeFalse("Skipping on Android",
            WolfSSLTestFactory.isAndroid());

        ServiceLoader<Provider> serviceLoader =
            ServiceLoader.load(Provider.class);

        Provider wolfSSLProvider = null;
        Iterator<Provider> iterator = serviceLoader.iterator();

        while (iterator.hasNext()) {
            Provider provider = iterator.next();
            if (provider instanceof WolfSSLProvider) {
                wolfSSLProvider = provider;
                break;
            }
        }

        assertNotNull("Should find WolfSSLProvider via ServiceLoader",
            wolfSSLProvider);

        /* Add provider temporarily for testing */
        int position = Security.addProvider(wolfSSLProvider);

        try {
            /* Test that we can get an SSLContext from this provider */
            assertNotNull("Should be able to get SSLContext.TLS",
                SSLContext.getInstance("TLS", wolfSSLProvider));

            /* Test that we can get TLSv1.2 from this provider */
            assertNotNull("Should be able to get SSLContext.TLSv1.2",
                SSLContext.getInstance("TLSv1.2", wolfSSLProvider));

        } finally {
            /* Remove provider after test */
            if (position != -1) {
                Security.removeProvider(wolfSSLProvider.getName());
            }
        }
    }

    /**
     * Test that WolfSSLProvider loaded via ServiceLoader matches
     * directly instantiated provider.
     */
    @Test
    public void testServiceLoaderProviderMatchesDirectInstance() {

        /* Skip on Android - ServiceLoader relies on META-INF/services
         * which is a JAR/module system mechanism not available on Android */
        Assume.assumeFalse("Skipping on Android",
            WolfSSLTestFactory.isAndroid());

        ServiceLoader<Provider> serviceLoader =
            ServiceLoader.load(Provider.class);

        Provider serviceLoaderProvider = null;
        Iterator<Provider> iterator = serviceLoader.iterator();

        while (iterator.hasNext()) {
            Provider provider = iterator.next();
            if (provider instanceof WolfSSLProvider) {
                serviceLoaderProvider = provider;
                break;
            }
        }

        assertNotNull("Should find provider via ServiceLoader",
            serviceLoaderProvider);

        /* Create direct instance */
        Provider directProvider = new WolfSSLProvider();

        /* Verify they have same name */
        assertEquals("Provider names should match",
            directProvider.getName(), serviceLoaderProvider.getName());

        /* Verify they have same version */
        assertEquals("Provider versions should match",
            directProvider.getVersion(),
            serviceLoaderProvider.getVersion(), 0.0);

        /* Verify they are same class */
        assertEquals("Provider classes should match",
            directProvider.getClass(), serviceLoaderProvider.getClass());
    }
}

