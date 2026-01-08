/* WolfSSLEngineMemoryLeakTest.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.rules.Timeout;
import static org.junit.Assert.*;

import java.util.concurrent.TimeUnit;
import java.nio.ByteBuffer;
import java.security.Security;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;

import com.wolfssl.provider.jsse.WolfSSLProvider;

/**
 * Memory leak regression test for WolfSSLEngine.
 *
 * Tests that JNI global references are properly cleaned up when SSLEngine
 * instances are abandoned (e.g., due to exceptions during handshake).
 *
 * This test verifies fixes for memory leak caused by:
 * - I/O callback references (setIOWriteCtx, setIOReadCtx)
 * - Session ticket callback references (setSessionTicketCb)
 * - Verify callback references (WolfSSLInternalVerifyCb.callingEngine)
 */
public class WolfSSLEngineMemoryLeakTest {

    /**
     * Global timeout for all tests in this class.
     */
    @Rule
    public Timeout globalTimeout = new Timeout(60, TimeUnit.SECONDS);

    @BeforeClass
    public static void setupProvider() {

        System.out.println("WolfSSLEngineMemoryLeakTest");

        Security.addProvider(new WolfSSLProvider());
    }

    private void pass(String msg) {
        WolfSSLTestFactory.pass(msg);
    }

    private void error(String msg) {
        WolfSSLTestFactory.fail(msg);
    }

    /**
     * Test that abandoned SSLEngine instances can be garbage collected.
     *
     * This test creates many SSLEngine instances that fail during handshake
     * (simulating real-world scenarios where connections are dropped), then
     * verifies that memory is properly released after garbage collection.
     *
     * The test will fail if JNI global references prevent garbage collection.
     */
    @Test
    public void testEngineMemoryLeakWithAbandonedEngines() throws Exception {

        /* Skip on Android due to performance and timeout issues */
        if (WolfSSLTestFactory.isAndroid()) {
            System.out.println("\tmem leak test\t\t\t... skipped (Android)");
            return;
        }

        /* Number of engines to create. Use a smaller number for unit tests
         * to keep test time reasonable (few seconds). */
        final int numEngines = 500;

        /* Threshold for acceptable memory growth (in MB).
         * I/O and session ticket callbacks are immediately released. Verify
         * callbacks may be retained until finalization.
         * JDK 21+ has larger object overhead than earlier JDKs.
         * Acceptable: ~20-65 MB for 500 engines depending on JDK version.
         * Before fixes, growth would be ~230+ MB for 500 engines.
         * We use a conservative threshold that detects major leaks while
         * accounting for JVM differences. */
        final double maxAcceptableGrowthMB = 80.0;

        String javaVersion = System.getProperty("java.version");
        System.out.print("\tmem leak test with " + numEngines +
                         " engines (JDK " + javaVersion + ")");

        /* Measure baseline memory - use aggressive GC */
        for (int i = 0; i < 3; i++) {
            System.gc();
            System.runFinalization();
        }
        Thread.sleep(200);
        long baselineMemory = getUsedMemoryBytes();

        /* Create and abandon many SSLEngine instances */
        for (int i = 0; i < numEngines; i++) {
            createAndAbandonSSLEngine();
        }

        /* Force aggressive garbage collection and finalization.
         * Multiple rounds help ensure finalizers run for abandoned engines.
         * This may be important for JDK 21+ which seems to have different
         * GC timing characteristics. */
        for (int i = 0; i < 5; i++) {
            System.gc();
            System.runFinalization();
        }
        Thread.sleep(300);

        /* Measure final memory */
        long finalMemory = getUsedMemoryBytes();
        long memoryGrowthBytes = finalMemory - baselineMemory;
        double memoryGrowthMB = memoryGrowthBytes / (1024.0 * 1024.0);

        /* Verify memory growth is within acceptable limits */
        String message = String.format(
            "Memory leak detected: created %d engines, " +
            "memory grew by %.2f MB (max acceptable: %.2f MB). " +
            "JNI global references may not be properly cleaned up.",
            numEngines, memoryGrowthMB, maxAcceptableGrowthMB);

        if (memoryGrowthMB > maxAcceptableGrowthMB) {
            error("\t... failed");
            fail(message);
        }

        pass("\t... passed");
    }

    /**
     * Test that SSLEngine instances that complete handshake successfully
     * and are properly closed do not leak memory.
     */
    @Test
    public void testEngineMemoryLeakWithProperClose() throws Exception {

        final int numEngines = 100;
        final double maxAcceptableGrowthMB = 10.0;

        System.gc();
        System.gc();
        Thread.sleep(100);
        long baselineMemory = getUsedMemoryBytes();

        System.out.print("\tmem leak test closed engines");

        /* Create engines and explicitly close them */
        for (int i = 0; i < numEngines; i++) {
            SSLContext sslContext =
                SSLContext.getInstance("TLS", "wolfJSSE");
            sslContext.init(null, null, null);

            SSLEngine engine =
                sslContext.createSSLEngine("example.com", 443);
            engine.setUseClientMode(true);

            /* Explicitly close the engine */
            engine.closeOutbound();

            /* For inbound, we need to handle the exception if not connected */
            try {
                engine.closeInbound();
            } catch (SSLException e) {
                /* Expected - not a real connection */
            }
        }

        System.gc();
        System.gc();
        Thread.sleep(100);

        long finalMemory = getUsedMemoryBytes();
        long memoryGrowthBytes = finalMemory - baselineMemory;
        double memoryGrowthMB = memoryGrowthBytes / (1024.0 * 1024.0);

        String message = String.format(
            "Memory leak detected with proper close: created %d engines, " +
            "memory grew by %.2f MB (max acceptable: %.2f MB).",
            numEngines, memoryGrowthMB, maxAcceptableGrowthMB);

        if (memoryGrowthMB > maxAcceptableGrowthMB) {
            error("\t... failed");
            fail(message);
        }

        pass("\t... passed");
    }

    /**
     * Creates an SSLEngine, initializes it (which creates JNI global
     * references), attempts a wrap operation that will fail, then abandons
     * the engine without proper cleanup.
     *
     * This simulates real-world scenarios where:
     * - Connections are dropped mid-handshake
     * - Exceptions occur during handshake
     * - Applications don't properly close engines
     */
    private void createAndAbandonSSLEngine() throws Exception {

        /* Create SSLContext using WolfSSL provider */
        SSLContext sslContext = SSLContext.getInstance("TLS", "wolfJSSE");

        /* Initialize with null (will use default trust/key managers) */
        sslContext.init(null, null, null);

        /* Create SSLEngine in client mode */
        SSLEngine engine = sslContext.createSSLEngine("wolfssl.com", 443);
        engine.setUseClientMode(true);

        /* Begin handshake - this triggers initialization of callbacks
         * and creates JNI global references */
        engine.beginHandshake();

        /* Allocate buffers for handshake */
        ByteBuffer netBuffer = ByteBuffer.allocate(
            engine.getSession().getPacketBufferSize());
        ByteBuffer appBuffer = ByteBuffer.allocate(
            engine.getSession().getApplicationBufferSize());

        try {
            /* Attempt a wrap operation - this will create initial ClientHello
             * and set up all the JNI global references. The operation will
             * fail because there's no peer to connect to. */
            engine.wrap(appBuffer, netBuffer);

        } catch (SSLException e) {
            /* Expected - we don't have a real peer to connect to */
        }

        /* IMPORTANT: We intentionally do NOT call:
         *   - engine.closeOutbound()
         *   - engine.closeInbound()
         *   - Any final wrap()/unwrap() operations
         *
         * This simulates scenarios where connections are abruptly dropped
         * or applications don't properly close engines. Without the fix,
         * JNI global references will keep the engine in memory forever. */
    }

    /**
     * Gets the current used memory in bytes.
     */
    private long getUsedMemoryBytes() {
        Runtime runtime = Runtime.getRuntime();
        return runtime.totalMemory() - runtime.freeMemory();
    }
}
