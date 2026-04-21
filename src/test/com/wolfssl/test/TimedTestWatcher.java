/* TimedTestWatcher.java
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

package com.wolfssl.test;

import org.junit.AssumptionViolatedException;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

/**
 * Reusable JUnit TestWatcher that prints timing information for each test
 * method. Displays elapsed time in milliseconds aligned in a column format.
 * Tests skipped via Assume.assume*() are labeled "SKIP" instead of timed.
 *
 * Usage in test classes:
 * <pre>
 * {@literal @}Rule
 * public TestRule testWatcher = TimedTestWatcher.create();
 * </pre>
 */
public class TimedTestWatcher extends TestWatcher {
    private volatile long startTime;
    private volatile boolean skipped;

    /**
     * Factory method to create a new TimedTestWatcher instance.
     * Recommended usage pattern for consistency across test classes.
     *
     * @return new TimedTestWatcher instance
     */
    public static TimedTestWatcher create() {
        return new TimedTestWatcher();
    }

    @Override
    protected void starting(Description description) {
        startTime = System.nanoTime();
        skipped = false;
    }

    @Override
    protected void skipped(AssumptionViolatedException e,
        Description description) {
        skipped = true;
        System.out.printf("\t       SKIP  %s%n", description.getMethodName());
    }

    @Override
    protected void finished(Description description) {
        if (skipped) {
            return;
        }
        long elapsed = System.nanoTime() - startTime;
        double elapsedMs = elapsed / 1_000_000.0;
        System.out.printf("\t%8.2f ms  %s%n",
            elapsedMs, description.getMethodName());
    }
}
