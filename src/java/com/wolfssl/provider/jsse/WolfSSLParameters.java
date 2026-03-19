/* WolfSSLParameters.java
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
package com.wolfssl.provider.jsse;

import java.util.List;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SSLParameters;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

import com.wolfssl.WolfSSLPskClientCallback;
import com.wolfssl.WolfSSLPskServerCallback;

/**
 * wolfJSSE implementation of SSLParameters.
 *
 * Extends {@link javax.net.ssl.SSLParameters} so that instances can be
 * passed directly to {@code SSLEngine.setSSLParameters()} and
 * {@code SSLSocket.setSSLParameters()}.
 *
 * This class includes the functionality of java SSLParameters, but allows
 * wolfJSSE better control over settings, interop with older Java versions,
 * etc. Strings set and returned should be cloned.
 *
 * In addition to the standard SSLParameters settings, this class exposes
 * wolfSSL-specific options such as PSK callbacks, PSK identity hint, and
 * keepArrays. Applications can configure these fields and then call
 * {@code engine.setSSLParameters(wolfParams)} to apply them before the
 * TLS handshake.
 *
 * @author wolfSSL
 */
public class WolfSSLParameters extends SSLParameters {

    private String[] cipherSuites;
    private String[] protocols;
    private boolean wantClientAuth = false;
    private boolean needClientAuth = false;
    private String endpointIdAlgorithm = null;
    private List<WolfSSLSNIServerName> wolfSSLServerNames;
    String[] applicationProtocols = new String[0];
    private boolean useSessionTickets = false;
    private byte[] alpnProtocols = null;
    /* Default to 0, means use implicit implementation size */
    private int maxPacketSize = 0;

    /* PSK callbacks and settings, set via public API */
    private WolfSSLPskClientCallback pskClientCb = null;
    private WolfSSLPskServerCallback pskServerCb = null;
    private String pskIdentityHint = null;
    private boolean keepArrays = false;

    /* Local storage for cipher-suite-order preference, to support
     * runtimes where SSLParameters.get/setUseCipherSuitesOrder() is
     * unavailable. */
    private Boolean useCipherSuitesOrder = null;

    /** Default WolfSSLParameters constructor */
    @SuppressWarnings("this-escape")
    public WolfSSLParameters() {
        super();
        /* wolfJSSE defaults to honoring server cipher order */
        this.useCipherSuitesOrder = Boolean.TRUE;
        try {
            super.setUseCipherSuitesOrder(true);
        } catch (NoSuchMethodError e) {
            /* Older runtimes may not have this method,
             * state kept in local useCipherSuitesOrder field */
        }
    }

    /**
     * Create duplicate copy of these parameters.
     *
     * @return new WolfSSLParameters copy of this object
     */
    protected synchronized WolfSSLParameters copy() {
        WolfSSLParameters cp = new WolfSSLParameters();
        cp.setCipherSuites(this.cipherSuites);
        cp.setProtocols(this.protocols);
        cp.wantClientAuth = this.wantClientAuth;
        cp.needClientAuth = this.needClientAuth;
        cp.setWolfSSLServerNames(this.getWolfSSLServerNames());
        cp.useSessionTickets = this.useSessionTickets;
        cp.endpointIdAlgorithm = this.endpointIdAlgorithm;
        cp.setApplicationProtocols(this.applicationProtocols);
        try {
            cp.setUseCipherSuitesOrder(this.getUseCipherSuitesOrder());
        } catch (NoSuchMethodError e) {
            /* Fall back to local field copy for older runtimes where parent
             * final methods are absent */
            cp.useCipherSuitesOrder = this.useCipherSuitesOrder;
        }
        cp.maxPacketSize = this.maxPacketSize;
        cp.pskClientCb = this.pskClientCb;
        cp.pskServerCb = this.pskServerCb;
        cp.pskIdentityHint = this.pskIdentityHint;
        cp.keepArrays = this.keepArrays;

        if (alpnProtocols != null && alpnProtocols.length != 0) {
            cp.setAlpnProtocols(this.alpnProtocols);
        }

        /* Copy SNI matchers and server names using parent final methods.
         * Server names set via the standard SSLParameters.setServerNames()
         * are stored in the parent and must be copied separately from
         * wolfSSLServerNames. */
        cp.setSNIMatchers(this.getSNIMatchers());
        cp.setServerNames(this.getServerNames());

        return cp;
    }

    @Override
    public synchronized String[] getCipherSuites() {
        if (this.cipherSuites == null) {
            return null;
        }
        return this.cipherSuites.clone();
    }

    @Override
    public synchronized void setCipherSuites(String[] cipherSuites) {
        /* cipherSuites array is sanitized by wolfJSSE caller */
        if (cipherSuites == null) {
            this.cipherSuites = null;
        }
        else {
            this.cipherSuites = cipherSuites.clone();
        }
    }

    @Override
    public synchronized String[] getProtocols() {
        if (this.protocols == null) {
            return null;
        }
        return this.protocols.clone();
    }

    @Override
    public synchronized void setProtocols(String[] protocols) {
        /* protocols array is sanitized by wolfJSSE caller */
        if (protocols == null) {
            this.protocols = null;
        }
        else {
            this.protocols = protocols.clone();
        }
    }

    @Override
    public boolean getWantClientAuth() {
        return this.wantClientAuth;
    }

    @Override
    public void setWantClientAuth(boolean wantClientAuth) {
        /* wantClientAuth OR needClientAuth can be set true, not both */
        this.wantClientAuth = wantClientAuth;
        if (this.wantClientAuth) {
            this.needClientAuth = false;
        }
    }

    @Override
    public boolean getNeedClientAuth() {
        return this.needClientAuth;
    }

    @Override
    public void setNeedClientAuth(boolean needClientAuth) {
        /* wantClientAuth OR needClientAuth can be set true, not both */
        this.needClientAuth = needClientAuth;
        if (this.needClientAuth) {
            this.wantClientAuth = false;
        }
    }

    @Override
    public String getEndpointIdentificationAlgorithm() {
        return this.endpointIdAlgorithm;
    }

    @Override
    public void setEndpointIdentificationAlgorithm(String algorithm) {
        this.endpointIdAlgorithm = algorithm;
    }

    /**
     * Set wolfSSL SNI server names.
     * Uses WolfSSLSNIServerName type to maintain compatibility with older Java
     * versions. This is separate from the parent SSLParameters setServerNames()
     * which uses SNIServerName.
     *
     * @param serverNames list of WolfSSLSNIServerName to set, or null to clear
     */
    public void setWolfSSLServerNames(List<WolfSSLSNIServerName> serverNames) {
        if (serverNames == null) {
            this.wolfSSLServerNames = null;
        } else {
            this.wolfSSLServerNames = Collections.unmodifiableList(
                new ArrayList<WolfSSLSNIServerName>(serverNames));
        }
    }

    /**
     * Get wolfSSL SNI server names.
     * Returns WolfSSLSNIServerName type for internal use.
     *
     * @return list of WolfSSLSNIServerName, or null if not set
     */
    public List<WolfSSLSNIServerName> getWolfSSLServerNames() {
        if (this.wolfSSLServerNames == null) {
            return null;
        } else {
            return Collections.unmodifiableList(
                new ArrayList<WolfSSLSNIServerName>(this.wolfSSLServerNames));
        }
    }

    /* Not part of Java SSLParameters. Needed here for Android compatibility */
    void setUseSessionTickets(boolean useTickets) {
        this.useSessionTickets = useTickets;
    }

    boolean getUseSessionTickets() {
        return this.useSessionTickets;
    }

    void setAlpnProtocols(byte[] alpnProtos) {
        if (alpnProtos == null || alpnProtos.length == 0) {
            throw new IllegalArgumentException(
                "ALPN protocol array null or zero length");
        }

        this.alpnProtocols = alpnProtos;
    }

    byte[] getAlpnProtos() {
        return this.alpnProtocols;
    }

    /*
     * SSLParameters.setSNIMatchers() and getSNIMatchers() are final. This
     * class delegates to the parent for SNI matcher storage and does not
     * maintain its own field.
     *
     * SSLParameters.setServerNames() and getServerNames() are also final,
     * so wolfSSL-specific server names use
     * setWolfSSLServerNames()/getWolfSSLServerNames() instead.
     *
     * SSLParameters.setUseCipherSuitesOrder() and getUseCipherSuitesOrder()
     * are also final. The local useCipherSuitesOrder field provides a backup
     * copy so copy() can transfer the value without calling the parent
     * methods, which may not exist on older runtimes.
     */

    public synchronized String[] getApplicationProtocols() {
        if (this.applicationProtocols == null) {
            return null;
        }
        return this.applicationProtocols.clone();
    }

    public synchronized void setApplicationProtocols(String[] protocols) {
        if (protocols == null) {
            this.applicationProtocols = new String[0];
        }
        else {
            this.applicationProtocols = protocols.clone();
        }
    }

    public int getMaximumPacketSize() {
        return this.maxPacketSize;
    }

    public void setMaximumPacketSize(int maximumPacketSize) {
        this.maxPacketSize = maximumPacketSize;
    }

    /**
     * Set the PSK client callback to be used for this connection.
     *
     * @param callback PSK client callback implementation, or null to clear
     */
    public void setPskClientCb(WolfSSLPskClientCallback callback) {
        this.pskClientCb = callback;
    }

    /**
     * Get the PSK client callback set for this connection.
     *
     * @return PSK client callback, or null if not set
     */
    public WolfSSLPskClientCallback getPskClientCb() {
        return this.pskClientCb;
    }

    /**
     * Set the PSK server callback to be used for this connection.
     *
     * @param callback PSK server callback implementation, or null to clear
     */
    public void setPskServerCb(WolfSSLPskServerCallback callback) {
        this.pskServerCb = callback;
    }

    /**
     * Get the PSK server callback set for this connection.
     *
     * @return PSK server callback, or null if not set
     */
    public WolfSSLPskServerCallback getPskServerCb() {
        return this.pskServerCb;
    }

    /**
     * Set the PSK identity hint for this connection.
     *
     * @param hint PSK identity hint string, or null to clear
     */
    public void setPskIdentityHint(String hint) {
        this.pskIdentityHint = hint;
    }

    /**
     * Get the PSK identity hint set for this connection.
     *
     * @return PSK identity hint string, or null if not set
     */
    public String getPskIdentityHint() {
        return this.pskIdentityHint;
    }

    /**
     * Set whether to keep handshake arrays after handshake completion.
     * <p>
     * When enabled, wolfSSL will retain internal arrays after the handshake,
     * which is needed for some PSK use cases where session data must be
     * accessed after handshake completion.
     *
     * @param keep true to keep arrays, false otherwise
     */
    public void setKeepArrays(boolean keep) {
        this.keepArrays = keep;
    }

    /**
     * Get whether keepArrays is enabled.
     *
     * @return true if keepArrays is enabled, false otherwise
     */
    public boolean getKeepArrays() {
        return this.keepArrays;
    }
}
