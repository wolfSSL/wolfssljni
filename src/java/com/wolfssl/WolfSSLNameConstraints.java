/* WolfSSLNameConstraints.java
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
package com.wolfssl;

import java.util.List;
import java.util.ArrayList;
import java.util.Collections;

/**
 * Represents X.509 Name Constraints extension (OID 2.5.29.30), wraps
 * native wolfSSL WOLFSSL_NAME_CONSTRAINTS structure.
 *
 * The name constraints extension indicates a name space within which all
 * subject names in subsequent certificates in a certification path must
 * be located. See RFC 5280 Section 4.2.1.10.
 *
 * Use {@link WolfSSLCertificate#getNameConstraints()} to obtain an instance.
 * Caller must call {@link #free()} when done to release native resources,
 * or let the garbage collector handle it via finalize().
 *
 * @author wolfSSL
 */
public class WolfSSLNameConstraints {

    /* Lock for synchronizing access to ncPtr and active state */
    private final Object ncLock = new Object();
    private long ncPtr = 0;
    private boolean active = false;

    /* Cached Java lists, loaded once from native on construction */
    private List<WolfSSLGeneralName> permittedSubtrees;
    private List<WolfSSLGeneralName> excludedSubtrees;

    private static native void wolfSSL_NAME_CONSTRAINTS_free(long ncPtr);
    private static native int wolfSSL_NAME_CONSTRAINTS_permittedNum(long ncPtr);
    private static native int wolfSSL_NAME_CONSTRAINTS_excludedNum(long ncPtr);
    private static native int wolfSSL_GENERAL_SUBTREE_getBaseType(long ncPtr,
        boolean permitted, int idx);
    private static native String wolfSSL_GENERAL_SUBTREE_getBaseValue(
        long ncPtr, boolean permitted, int idx);
    private static native int wolfSSL_NAME_CONSTRAINTS_check_name(long ncPtr,
        int type, String name);

    /**
     * Internal constructor, called from WolfSSLCertificate.
     *
     * @param ncPtr Native pointer to WOLFSSL_NAME_CONSTRAINTS
     *
     * @throws IllegalArgumentException if ncPtr is 0
     */
    WolfSSLNameConstraints(long ncPtr) {
        if (ncPtr == 0) {
            throw new IllegalArgumentException(
                "Invalid native NAME_CONSTRAINTS pointer");
        }
        this.ncPtr = ncPtr;
        this.active = true;
        loadSubtrees();
    }

    /**
     * Load subtrees from native struct into Java lists.
     * Called once during construction to cache data.
     */
    private void loadSubtrees() {
        int i, type, permCount, exclCount;
        String value;

        /* Load permitted subtrees */
        permCount = wolfSSL_NAME_CONSTRAINTS_permittedNum(ncPtr);
        permittedSubtrees = new ArrayList<>(permCount);
        for (i = 0; i < permCount; i++) {
            type = wolfSSL_GENERAL_SUBTREE_getBaseType(ncPtr, true, i);
            value = wolfSSL_GENERAL_SUBTREE_getBaseValue(ncPtr, true, i);
            if (type >= 0 && value != null) {
                permittedSubtrees.add(new WolfSSLGeneralName(type, value));
            }
        }

        /* Load excluded subtrees */
        exclCount = wolfSSL_NAME_CONSTRAINTS_excludedNum(ncPtr);
        excludedSubtrees = new ArrayList<>(exclCount);
        for (i = 0; i < exclCount; i++) {
            type = wolfSSL_GENERAL_SUBTREE_getBaseType(ncPtr, false, i);
            value = wolfSSL_GENERAL_SUBTREE_getBaseValue(ncPtr, false, i);
            if (type >= 0 && value != null) {
                excludedSubtrees.add(new WolfSSLGeneralName(type, value));
            }
        }
    }

    /**
     * Get permitted subtrees.
     *
     * @return Unmodifiable list of permitted GeneralName entries
     *
     * @throws IllegalStateException if object has been freed
     */
    public List<WolfSSLGeneralName> getPermittedSubtrees() {

        synchronized (ncLock) {
            checkActive();
            return Collections.unmodifiableList(permittedSubtrees);
        }
    }

    /**
     * Get excluded subtrees.
     *
     * @return Unmodifiable list of excluded GeneralName entries
     *
     * @throws IllegalStateException if object has been freed
     */
    public List<WolfSSLGeneralName> getExcludedSubtrees() {

        synchronized (ncLock) {
            checkActive();
            return Collections.unmodifiableList(excludedSubtrees);
        }
    }

    /**
     * Check if a name satisfies these constraints.
     *
     * A name is valid if it matches at least one permitted subtree (if any
     * exist for that type) and it does not match any excluded subtree.
     *
     * @param type GeneralName type (GEN_DNS, GEN_EMAIL, GEN_IPADD, GEN_URI)
     * @param name The name to validate
     *
     * @return true if name satisfies constraints, false otherwise
     *
     * @throws IllegalStateException if object has been freed
     * @throws IllegalArgumentException if name is null
     */
    public boolean checkName(int type, String name) {

        if (name == null) {
            throw new IllegalArgumentException("name cannot be null");
        }

        synchronized (ncLock) {
            checkActive();
            return wolfSSL_NAME_CONSTRAINTS_check_name(ncPtr, type, name) == 1;
        }
    }

    /**
     * Check if a DNS name satisfies these constraints.
     *
     * @param dnsName The DNS name to validate
     *
     * @return true if permitted, false if excluded or not permitted
     */
    public boolean checkDnsName(String dnsName) {

        return checkName(WolfSSLGeneralName.GEN_DNS, dnsName);
    }

    /**
     * Check if an email address satisfies these constraints.
     *
     * @param email The email address to validate
     *
     * @return true if permitted, false if excluded or not permitted
     */
    public boolean checkEmail(String email) {

        return checkName(WolfSSLGeneralName.GEN_EMAIL, email);
    }

    /**
     * Check if an IP address satisfies these constraints.
     *
     * @param ipAddress The IP address to validate (e.g., "192.168.1.50")
     *
     * @return true if permitted, false if excluded or not permitted
     */
    public boolean checkIpAddress(String ipAddress) {

        return checkName(WolfSSLGeneralName.GEN_IPADD, ipAddress);
    }

    /**
     * Check if a URI satisfies these constraints.
     *
     * @param uri The URI to validate
     *
     * @return true if permitted, false if excluded or not permitted
     */
    public boolean checkUri(String uri) {

        return checkName(WolfSSLGeneralName.GEN_URI, uri);
    }

    /**
     * Check if object is active (not freed).
     *
     * @throws IllegalStateException if object has been freed
     */
    private void checkActive() {
        if (!active) {
            throw new IllegalStateException(
                "WolfSSLNameConstraints has been freed");
        }
    }

    /**
     * Free native resources. Must be called when done with this object,
     * although garbage collector will also call it via finalize().
     */
    public void free() {

        synchronized (ncLock) {
            if (active && ncPtr != 0) {
                wolfSSL_NAME_CONSTRAINTS_free(ncPtr);
                ncPtr = 0;
                active = false;
            }
        }
    }

    @Override
    @SuppressWarnings("deprecation")
    protected void finalize() throws Throwable {
        try {
            free();
        } finally {
            super.finalize();
        }
    }
}

