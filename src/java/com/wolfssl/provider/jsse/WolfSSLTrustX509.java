/* WolfSSLTrustX509.java
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

import com.wolfssl.WolfSSL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Enumeration;
import java.net.Socket;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.StandardConstants;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.security.auth.x500.X500Principal;

import com.wolfssl.WolfSSLDebug;
import com.wolfssl.WolfSSLCertificate;
import com.wolfssl.WolfSSLCertManager;
import com.wolfssl.WolfSSLException;
import java.security.cert.Certificate;

/**
 * wolfSSL implementation of X509TrustManager, extends
 * X509ExtendedTrustManager for additional hostname verification for
 * HTTPS (RFC 2818) and LDAPS (RFC 2830).
 *
 * @author wolfSSL
 */
public final class WolfSSLTrustX509 extends X509ExtendedTrustManager {

    private KeyStore store = null;

    /** X509ExtendedTrustManager hostname type HTTPS */
    private static int HOSTNAME_TYPE_HTTPS = 1;
    /** X509ExtendedTrustManager hostname type LDAPS */
    private static int HOSTNAME_TYPE_LDAPS = 2;

    /**
     * Create new WolfSSLTrustX509 object
     *
     * @param in KeyStore to use with this X509TrustManager
     */
    public WolfSSLTrustX509(KeyStore in) {
        this.store = in;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "created new WolfSSLTrustX509");
    }

    /**
     * Sort provided certificate chain by subject and issuer.
     *
     * Begin with leaf cert, end with last most intermediate cert. Current
     * routine assumes that peer cert will be first in the provided certs
     * array, and will use that as a base/starting point to sort intermediate
     * certs going up the chain.
     *
     * @param certs Peer certificate chain, assuming leaf/peer is first
     *
     * @return List of X509Certifiates representing peer cert chain, sorted
     *         from leaf to last intermediate. Not including root CA.
     * @throws CertificateException if error occurs while building chain.
     */
    private X509Certificate[] sortCertChainBySubjectIssuer(
            X509Certificate[] certs) throws CertificateException {

        int i, curr, next;
        int leafIdx = -1;
        boolean nextFound = false;
        final X509Certificate[] chain;
        X509Certificate[] retChain = null;

        if (certs == null) {
            throw new CertificateException("Input cert chain null");
        }

        /* If certs array is only one cert (peer), just return copy of it */
        if (certs.length == 1) {
            return certs.clone();
        }

        /* Make copy of peer cert chain, so we don't change original */
        chain = certs.clone();

        /* Print out chain for debugging */
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "sorting peer chain (" + chain.length + " certs):");
        for (i = 0; i < chain.length; i++) {
            final int tmpI = i;
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "\t[" + tmpI + "]: subject: " +
                chain[tmpI].getSubjectX500Principal().getName());
        }

        /* Find the leaf certificate using BasicConstraints extension.
         * Per RFC 5280, leaf/end-entity certs have getBasicConstraints()
         * return -1, while CA certs return >= 0. */
        for (i = 0; i < chain.length; i++) {
            if (chain[i].getBasicConstraints() == -1) {
                leafIdx = i;
                final int tmpLeaf = i;
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "Identified leaf cert at index " + tmpLeaf +
                    " (BasicConstraints CA=false)");
                break;
            }
        }

        /* If we couldn't identify leaf cert by BasicConstraints, default
         * to treat the first cert as peer */
        if (leafIdx == -1) {
            final int tmpLeaf = 0;
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "Could not identify leaf cert by BasicConstraints, " +
                "assuming index " + tmpLeaf);
            leafIdx = 0;
        }

        /* Move leaf cert to position 0 if not already there */
        if (leafIdx != 0) {
            X509Certificate tmp = chain[0];
            chain[0] = chain[leafIdx];
            chain[leafIdx] = tmp;
        }

        /* Now build chain from leaf to root */
        for (curr = 0; curr < chain.length; curr++) {
            nextFound = false;
            for (next = curr + 1; next < chain.length; next++) {
                /* check if next subject matches curr issuer */
                if (chain[curr].getIssuerX500Principal().equals(
                    chain[next].getSubjectX500Principal())) {
                    /* if next not directly after curr, swap */
                    if (next != curr + 1) {
                        X509Certificate tmp = chain[next];
                        chain[next] = chain[curr + 1];
                        chain[curr + 1] = tmp;
                    }
                    nextFound = true;
                    break;
                }
            }

            /* if next not found, stop building chain */
            if (nextFound == false) {
                break;
            }
        }

        /* Print out sorted peer chain for debugging */
        final int tmpCurr = curr;
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "sorted peer chain (" + (tmpCurr + 1) + " certs):");
        for (i = 0; i <= curr; i++) {
            final int tmpI = i;
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "\t[" + tmpI + "]: subject: " +
                chain[tmpI].getSubjectX500Principal().getName());
        }

        /* If chain is now shorter, return adjusted size array */
        if (chain.length > (curr + 1)) {
            retChain = Arrays.copyOf(chain, curr + 1);
        } else {
            retChain = chain;
        }

        return retChain;
    }

    /**
     * Finds and returns X509Certificate matching the root CA that will
     * verify the given leaf/intermediate certificate.
     *
     * This will search through the provided KeyStore for the approproate
     * root CA that correctly verifies the given certificate.
     *
     * @param cert Certificate for which to find verifying root CA
     * @param ks   KeyStore to search in for root CA
     *
     * @return X509Certificate representing root CA which will verify cert
     * @throws CertificateException on error/failure getting root CA.
     */
    private X509Certificate findRootCAFromKeyStoreForCert(X509Certificate cert,
        KeyStore ks) throws CertificateException {

        int i = 0;
        int ret;
        int verifiedRootIdx = -1;
        WolfSSLCertManager cm = null;
        List<X509Certificate> possibleCerts = new ArrayList<X509Certificate>();
        byte[] encodedRoot = null;
        byte[] encodedCert = null;
        boolean rootFound = false;

        if (cert == null || ks == null) {
            throw new CertificateException("Certificate or KeyStore is null");
        }

        /* Issuer name we need to match */
        X500Principal issuer = cert.getIssuerX500Principal();
        if (issuer == null) {
            throw new CertificateException("Unable to get expected issuer");
        }

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "Searching KeyStore for root CA matching: " +
            issuer.getName());

        /* Find all issuers that match needed issuer name */
        try {
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String name = aliases.nextElement();
                X509Certificate root = null;

                if (ks.isKeyEntry(name)) {
                    Certificate[] chain = ks.getCertificateChain(name);
                    if (chain != null) {
                        root = (X509Certificate) chain[0];
                    }
                } else {
                    root = (X509Certificate) ks.getCertificate(name);
                }

                if (root != null && root.getBasicConstraints() >= 0) {
                    if (root.getSubjectX500Principal().equals(issuer)) {
                        /* Found correct CN, add to possible roots list */
                        possibleCerts.add(root);
                    }
                }
            }
        } catch (KeyStoreException ex) {
            throw new CertificateException(ex);
        }

        if (possibleCerts.size() == 0) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "No root CA found in KeyStore to validate certificate");
            return null;
        }

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "Found " + possibleCerts.size() +
            " possible root CAs, testing");

        /* Use wolfSSL Cert Manager to make sure root verifies input cert */
        try {
            cm = new WolfSSLCertManager();
        } catch (WolfSSLException e) {
            throw new CertificateException(
                "Failed to create native WolfSSLCertManager");
        }

        for (i = 0; i < possibleCerts.size(); i++) {
            final int tmpI = i;

            /* load candidate root CA as trusted */
            encodedRoot = possibleCerts.get(tmpI).getEncoded();
            ret = cm.CertManagerLoadCABuffer(encodedRoot, encodedRoot.length,
                WolfSSL.SSL_FILETYPE_ASN1);
            if (ret != WolfSSL.SSL_SUCCESS) {
                cm.free();
                throw new CertificateException(
                    "Failed to load root CA DER into wolfSSL cert manager");
            }

            /* try to verify input cert */
            encodedCert = cert.getEncoded();
            ret = cm.CertManagerVerifyBuffer(encodedCert, encodedCert.length,
                    WolfSSL.SSL_FILETYPE_ASN1);
            if (ret != WolfSSL.SSL_SUCCESS) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "Potential root " + tmpI + " did not verify cert");
            } else {
                rootFound = true;
                verifiedRootIdx = tmpI;
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "Found valid root: " +
                    possibleCerts.get(tmpI).getSubjectX500Principal().getName());
            }

            /* unload CAs from WolfSSLCertManager */
            ret = cm.CertManagerUnloadCAs();
            if (ret != WolfSSL.SSL_SUCCESS) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "Error unloading root CAs from WolfSSLCertManager");
                cm.free();
                throw new CertificateException("Failed to unload root CA " +
                    "from WolfSSLCertManager");
            }

            if (rootFound == true) {
                break;
            }
        }

        /* Free native WolfSSLCertManager resources */
        cm.free();

        if (rootFound == true) {
            return possibleCerts.get(verifiedRootIdx);
        }

        return null;
    }

    /**
     * Verify cert chain using WolfSSLCertManager.
     * Do all loading and verification in one function to avoid holding native
     * resources at the object/class level.
     *
     * @param certs       Certificate chain to validate
     * @param type        Authentication type
     * @param returnChain Boolean (true/false), return validation chain or not
     *
     * @return Complete chain used for validation, including root CA, if
     * returnChain is true. Otherwise, if returnChain is false return NULL
     * @throws CertificateException on verification error/failure
     */
    private List<X509Certificate> certManagerVerify(
        X509Certificate[] certs, String type, boolean returnChain)
        throws CertificateException {

        int ret;
        WolfSSLCertManager cm = null;
        final X509Certificate[] sortedCerts;

        X509Certificate rootCA = null;
        List<X509Certificate> fullChain = null;

        if (certs == null || certs.length == 0 ||
            type == null || type.length() == 0) {
            throw new CertificateException();
        }

        /* create new WolfSSLCertManager */
        try {
            cm = new WolfSSLCertManager();
        } catch (WolfSSLException e) {
            throw new CertificateException(
                "Failed to create native WolfSSLCertManager");
        }

        /* load trusted certs from KeyStore */
        try {
            ret = cm.CertManagerLoadCAKeyStore(this.store);
            if (ret != WolfSSL.SSL_SUCCESS) {
                throw new CertificateException(
                    "Failed to load trusted certs into WolfSSLCertManager");
            }
        } catch (WolfSSLException e) {
            cm.free();
            throw new CertificateException(
                "Failed to load trusted certs into WolfSSLCertManager");
        }

        /* Sort cert chain in order from peer to last intermedate. We
         * assume cert chain starts with peer certificate (certs[0]). */
        sortedCerts = sortCertChainBySubjectIssuer(certs);

        /* If requested to return full chain, initialize new list and add
         * peer cert first. Intermediate and root CAs added as verified. */
        if (returnChain) {
            fullChain = new ArrayList<X509Certificate>();
            fullChain.add(sortedCerts[0]); /* Add peer cert */
        }

        /* Walk backwards down list of intermediate CA certs, verify each one
         * based on trusted certs we already have loaded in the CertManager,
         * then once verified load the intermediate into the CertManager
         * as a root that can be used to verify our peer cert.
         *
         * Similarly to native wolfSSL WOLFSSL_ALT_CERT_CHAINS behavior: if a CA
         * certificate cannot be verified, we skip it and continue building
         * the chain through other certificates. This allows handling of
         * cross-signed certificates and extra certificates in the chain. */

        for (int i = sortedCerts.length-1; i > 0; i--) {
            final int tmpI = i;

            /* Verify chain cert */
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "Verifying intermediate chain cert: " +
                sortedCerts[tmpI].getSubjectX500Principal().getName());

            byte[] encoded = sortedCerts[tmpI].getEncoded();
            ret = cm.CertManagerVerifyBuffer(encoded, encoded.length,
                    WolfSSL.SSL_FILETYPE_ASN1);
            if (ret != WolfSSL.SSL_SUCCESS) {
                /* Failure here is ok if this is a CA cert and we can still
                 * build and verify a complete chain. Some cert chains may
                 * include extra CA certs. Similar to native wolfSSL
                 * WOLFSSL_ALT_CERT_CHAINS. */
                if (sortedCerts[tmpI].getBasicConstraints() != -1) {
                    /* This is a CA certificate, skip it and continue.
                     * Do not add it to the certificate manager. */
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "Using alternate cert chain (skipping CA): " +
                        sortedCerts[tmpI].getSubjectX500Principal().getName());
                    continue;
                }
                /* Non-CA certificates must verify successfully */
                cm.free();
                throw new CertificateException(
                    "Failed to verify intermediate chain cert");
            }

            /* Load chain cert as trusted CA */
            ret = cm.CertManagerLoadCABuffer(encoded, encoded.length,
                    WolfSSL.SSL_FILETYPE_ASN1);
            if (ret != WolfSSL.SSL_SUCCESS) {
                cm.free();
                throw new CertificateException("Failed to load intermediate " +
                    "CA certificate as trusted root");
            }

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "Loaded intermediate CA: " +
                sortedCerts[tmpI].getSubjectX500Principal().getName());

            /* Chain cert verified successfully, add to fullChain if requested.
             * Inserting at position 1 maintains peer to root order and shifts
             * all other certs in the list down a position. */
            if (returnChain) {
                fullChain.add(1, sortedCerts[tmpI]);
            }
        }

        /* Verify peer certificate */
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "Verifying peer certificate: " +
            sortedCerts[0].getSubjectX500Principal().getName());

        byte[] peer = sortedCerts[0].getEncoded();
        if (peer == null) {
            cm.free();
            throw new CertificateException("Failed to get encoded peer cert");
        }

        ret = cm.CertManagerVerifyBuffer(peer, peer.length,
                WolfSSL.SSL_FILETYPE_ASN1);
        if (ret != WolfSSL.SSL_SUCCESS) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "Failed to verify peer certificate");
            cm.free();
            throw new CertificateException("Failed to verify peer certificate");
        }

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "Verified peer certificate: " +
            sortedCerts[0].getSubjectX500Principal().getName());

        cm.free();

        if (returnChain) {
            /* Find root CA from KeyStore to append to chain. Use the last
             * cert in fullChain (last verified intermediate) to find its
             * issuer root CA. */
            rootCA = findRootCAFromKeyStoreForCert(
                        fullChain.get(fullChain.size() - 1), this.store);
            if (rootCA == null) {
                throw new CertificateException("Unable to find root CA " +
                    "in KeyStore to append to chain list");
            }

            /* Append root CA if not already present */
            if (!fullChain.contains(rootCA)) {
                fullChain.add(rootCA);
            }
        }
        else {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "Not returning cert chain from verify, not requested");
        }

        return fullChain;
    }

    /**
     * Verify hostname using HTTPS or LDAPS verification method.
     *
     * For HTTPS hostname verification (RFC 2818):
     *
     *   - If SNI name has been received during TLS handshake, try to
     *      first verify peer certificate against that. Skip this step when
     *      on server side verifying the client, since server does not set
     *      an SNI for the client.
     *   - Otherwise, try to verify certificate against SSLSocket or SSLEngine
     *      hostname (getHandshakeSession().getHostName()).
     *   - If both of the above fail, fail hostname verification.
     *   - Hostname matching rules for HTTPS come from RFC 2818
     *
     * For LDAPS hostname verification (RFC 2830):
     *
     *   - Try to verify certificate against hostname used to create
     *      the SSLSocket or SSLEngine, obtained via
     *      getHandshakeSession().getPeerHost().
     *   - Hostname matching rules for LDAPS come from RFC 2830
     *
     * @param cert peer certificate
     * @param socket SSLSocket associated with connection to peer. Only one
     *               of socket or engine params should be used. The other should
     *               be set to null.
     * @param engine SSLEngine associated with connection to peer. Either/or
     *               between this and socket param. Other should be set to
     *               null.
     * @param isClient true if we are calling this from client side, otherwise
     *               false if calling from server side.
     * @param type type of hostname to verify, options are
     *               HOSTNAME_TYPE_HTTPS or HOSTNAME_TYPE_LDAPS
     * @throws CertificateException if hostname cannot be verified
     */
    private void verifyHostnameByType(X509Certificate cert, SSLSocket socket,
        SSLEngine engine, boolean isClient, int type)
        throws CertificateException {

        final String peerHost;
        List<SNIServerName> sniNames = null;
        String sniHostName = null;
        SSLSession session = null;
        final WolfSSLCertificate peerCert;
        int ret = WolfSSL.SSL_FAILURE;

        if (type == HOSTNAME_TYPE_HTTPS) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "verifying hostname type HTTPS");
        } else if (type == HOSTNAME_TYPE_LDAPS) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "verifying hostname type LDAPS");
        } else {
            throw new CertificateException("Unsupported hostname type, " +
                "HTTPS and LDAPS only supported currently: " + type);
        }

        /* Get session associated with SSLSocket or SSLEngine */
        try {
            if (socket != null) {
                session = socket.getHandshakeSession();
            }
            else if (engine != null) {
                session = engine.getHandshakeSession();
            }
        } catch (UnsupportedOperationException e) {
            e.printStackTrace();
            throw new CertificateException(e);
        }

        /* Get peer host from SSLSocket */
        if (session != null) {
            peerHost = session.getPeerHost();
        } else {
            peerHost = null;
        }

        /* Get SNI name if SSLSocket/SSLEngine has received that from peer.
         * Only check this when on the client side and verifying a server since
         * SNI holding expected server name is available on client-side but not
         * vice-versa. Also only checked for HTTPS type, not LDAPS. As per
         * RFC 2830, the client MUST use the server hostname it used to open
         * the LDAP connection. */
        if ((session != null) && isClient &&
            (session instanceof ExtendedSSLSession) &&
            (type == HOSTNAME_TYPE_HTTPS)) {
            sniNames = ((ExtendedSSLSession)session).getRequestedServerNames();

            for (SNIServerName name : sniNames) {
                if (name.getType() == StandardConstants.SNI_HOST_NAME) {
                    SNIHostName tmpName = new SNIHostName(name.getEncoded());
                    if (tmpName != null) {
                        /* Get SNI name as ASCII string for comparison */
                        sniHostName = tmpName.getAsciiName();
                    }
                }
            }
        }

        /* Create new WolfSSLCertificate (WOLFSSL_X509) from
         * DER encoding of peer certificate */
        try {
            peerCert = new WolfSSLCertificate(cert.getEncoded());
            if (peerCert == null) {
                throw new CertificateException(
                    "Unable to create WolfSSLCertificate from peer cert");
            }

        } catch (WolfSSLException e) {
            throw new CertificateException(e);
        }

        /* Try verifying hostname against SNI name, if HTTPS type */
        if (isClient && (type == HOSTNAME_TYPE_HTTPS)) {
            if (sniHostName != null) {
                final String tmpSniName = sniHostName;
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "trying hostname verification against SNI: " +
                    tmpSniName);

                ret = peerCert.checkHost(sniHostName);
                if (ret == WolfSSL.SSL_SUCCESS) {
                    /* Hostname successfully verified against SNI name */
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "successfully verified X509 hostname using " +
                        "SNI name");
                    return;
                }
                else {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "hostname match with SNI failed");
                }
            }
            else {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "no provided SNI name found");
            }
        }

        /* Try verifying hostname against peerHost from SSLSocket/SSLEngine */
        if (peerHost != null) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "trying hostname verification against peer host: " +
                peerHost);

            if (type == HOSTNAME_TYPE_LDAPS) {
                /* LDAPS requires wildcard left-most matching only */
                ret = peerCert.checkHost(peerHost,
                        WolfSSL.WOLFSSL_LEFT_MOST_WILDCARD_ONLY);
            } else {
                ret = peerCert.checkHost(peerHost);
            }
            if (ret == WolfSSL.SSL_SUCCESS) {
                /* Hostname successfully verified against peer host name */
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "successfully verified X509 hostname using " +
                    "SSLSession getPeerHost()");
                return;
            }
        }

        final String tmpSniName = sniHostName;
        final String tmpPeerHost = peerHost;
        if (isClient) {
            if (type == HOSTNAME_TYPE_HTTPS) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "hostname verification failed for server peer " +
                    "cert, tried SNI (" + tmpSniName + "), peer host (" +
                    tmpPeerHost + ")\n" + peerCert);
            } else {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "hostname verification failed for server peer " +
                    "cert, peer host (" + tmpPeerHost + ")\n" + peerCert);
            }
        } else {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "hostname verification failed for client peer cert, " +
                "tried peer host (" + tmpPeerHost + ")\n" + peerCert);
        }

        throw new CertificateException("Hostname verification failed");
    }

    /**
     * Verify hostname of certificate.
     *
     * @param cert peer certificate
     * @param socket SSLSocket associated with connection to peer. Only one
     *               of socket or engine params should be used. The other should
     *               be set to null.
     * @param engine SSLEngine associated with connection to peer. Either/or
     *               between this and socket param. Other should be set to
     *               null.
     * @param isClient true if we are calling this from client side, otherwise
     *               false if calling from server side.
     * @throws CertificateException if hostname cannot be verified
     */
    protected void verifyHostname(X509Certificate cert,
        Socket socket, SSLEngine engine, boolean isClient)
        throws CertificateException {

        String endpointIdAlgo = null;
        SSLParameters sslParams = null;

        /* Hostname verification on Socket done only if Socket is of SSLSocket,
         * not null, and connected */
        if ((socket != null) && (socket instanceof SSLSocket) &&
            (socket.isConnected())) {

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "entered verifyHostname, using SSLSocket for host info");

            sslParams = ((SSLSocket)socket).getSSLParameters();
            if (sslParams == null) {
                throw new CertificateException(
                    "SSLParameters in SSLSocket is null");
            }
            endpointIdAlgo = sslParams.getEndpointIdentificationAlgorithm();

            /* If endpoint ID algo is null or empty, skips hostname verify */
            if (endpointIdAlgo != null && !endpointIdAlgo.isEmpty()) {
                if (endpointIdAlgo.equals("HTTPS")) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "verifying hostname, endpoint identification " +
                        "algorithm = HTTPS");
                    verifyHostnameByType(cert, (SSLSocket)socket,
                        null, isClient, HOSTNAME_TYPE_HTTPS);
                }
                else if (endpointIdAlgo.equals("LDAPS")) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "verifying hostname, endpoint identification " +
                        "algorithm = LDAPS");
                    verifyHostnameByType(cert, (SSLSocket)socket,
                        null, isClient, HOSTNAME_TYPE_LDAPS);
                }
                else {
                    throw new CertificateException(
                        "Unsupported Endpoint Identification Algorithm: " +
                        endpointIdAlgo);
                }
            }
            else {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "endpoint Identification algo is null or empty, " +
                    "skipping hostname verification");
            }
        }
        else if (engine != null) {

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "entered verifyHostname, using SSLEngine for host info");

            sslParams = engine.getSSLParameters();
            if (sslParams == null) {
                throw new CertificateException(
                    "SSLParameters in SSLEngine is null");
            }
            endpointIdAlgo = sslParams.getEndpointIdentificationAlgorithm();

            /* If endpoint ID algo is null or empty, skips hostname verify */
            if (endpointIdAlgo != null && !endpointIdAlgo.isEmpty()) {
                if (endpointIdAlgo.equals("HTTPS")) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "verifying hostname, endpoint identification " +
                        "algorithm = HTTPS");
                    verifyHostnameByType(cert, null, engine, isClient,
                        HOSTNAME_TYPE_HTTPS);
                }
                else if (endpointIdAlgo.equals("LDAPS")) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "verifying hostname, endpoint identification " +
                        "algorithm = LDAPS");
                    verifyHostnameByType(cert, null, engine, isClient,
                        HOSTNAME_TYPE_LDAPS);
                }
                else {
                    throw new CertificateException(
                        "Unsupported Endpoint Identification Algorithm: " +
                        endpointIdAlgo);
                }
            }
            else {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "endpoint Identification algo is null or empty, " +
                    "skipping hostname verification");
            }
        }
        else {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "Socket is null, not connected, or not SSLSocket. " +
                "SSLEngine is also null. Skipping hostname verification " +
                "in ExtendedX509TrustManager");
        }
    }

    /**
     * Try to build and validate the client certificate chain based on the
     * provided certificates and authentication type.
     *
     * Does not do hostname verification internally. Calling applications are
     * responsible for checking hostname for accuracy if desired. To use
     * internal hostname verification use X509ExtendedTrustManager APIs
     * (for HTTPS verification).
     *
     * @param certs peer certificate chain
     * @param type authentication type based on the client certificate
     * @throws CertificateException if certificate chain is not trusted
     */
    @Override
    public void checkClientTrusted(X509Certificate[] certs, String type)
            throws CertificateException, IllegalArgumentException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered checkClientTrusted()");

        if (certs == null) {
            throw new IllegalArgumentException("Input cert chain null");
        }

        if (type == null || type.length() == 0) {
            throw new IllegalArgumentException("Input auth type null");
        }

        /* Verify cert chain, throw CertificateException if not valid */
        certManagerVerify(certs, type, false);

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "leaving checkClientTrusted(), success");
    }

    /**
     * Try to build and validate the client certificate chain based on the
     * provided certificates and authentication type.
     *
     * Does hostname verification internally if Endpoint Identification
     * Algorithm has been set by application in SSLParameters, and that
     * Algorithm matches "HTTPS" or "LDAPS". If "HTTPS" is set, hostname
     * verification is done using SNI first then peer host value.
     *
     * Other Endpoint Identification Algorithms besides "HTTPS" and "LDAPS"
     * are not currently supported.
     *
     * @param certs peer certificate chain
     * @param type authentication type based on the client certificate
     * @throws CertificateException if certificate chain is not trusted
     */
    @Override
    public void checkClientTrusted(X509Certificate[] certs, String type,
        Socket socket) throws CertificateException, IllegalArgumentException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered checkClientTrusted() with Socket");

        if (certs == null) {
            throw new IllegalArgumentException("Input cert chain null");
        }

        if (type == null || type.length() == 0) {
            throw new IllegalArgumentException("Input auth type null");
        }

        /* Verify cert chain, throw CertificateException if not valid */
        certManagerVerify(certs, type, false);

        /* Verify hostname if right criteria matches */
        verifyHostname(certs[0], socket, null, false);

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "leaving checkClientTrusted(Socket), success");
    }

    @Override
    public void checkClientTrusted(X509Certificate[] certs, String type,
        SSLEngine engine) throws CertificateException, IllegalArgumentException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered checkClientTrusted() with SSLEngine");

        if (certs == null) {
            throw new IllegalArgumentException("Input cert chain null");
        }

        if (type == null || type.length() == 0) {
            throw new IllegalArgumentException("Input auth type null");
        }

        /* Verify cert chain, throw CertificateException if not valid */
        certManagerVerify(certs, type, false);

        /* Verify hostname if right criteria matches */
        verifyHostname(certs[0], null, engine, false);

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "leaving checkClientTrusted(SSLEngine), success");
    }

    /**
     * Try to build and validate the server certificate chain based on the
     * provided certificates and authentication type.
     *
     * Does not do hostname verification internally. Calling applications are
     * responsible for checking hostname for accuracy if desired. To use
     * internal hostname verification use X509ExtendedTrustManager APIs
     * (for HTTPS verification).
     *
     * @param certs peer certificate chain
     * @param type authentication type based on the client certificate
     * @throws CertificateException if certificate chain is not trusted
     */
    @Override
    public void checkServerTrusted(X509Certificate[] certs, String type)
        throws CertificateException, IllegalArgumentException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered checkServerTrusted()");

        if (certs == null) {
            throw new IllegalArgumentException("Input cert chain null");
        }

        if (type == null || type.length() == 0) {
            throw new IllegalArgumentException("Input auth type null");
        }

        /* Verify cert chain, throw CertificateException if not valid */
        certManagerVerify(certs, type, false);

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "leaving checkServerTrusted(certs, type), success");
    }

    @Override
    public void checkServerTrusted(X509Certificate[] certs, String type,
        Socket socket) throws CertificateException, IllegalArgumentException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered checkServerTrusted() with Socket");

        if (certs == null) {
            throw new IllegalArgumentException("Input cert chain null");
        }

        if (type == null || type.length() == 0) {
            throw new IllegalArgumentException("Input auth type null");
        }

        /* Verify cert chain, throw CertificateException if not valid */
        certManagerVerify(certs, type, false);

        /* Verify hostname if right criteria matches */
        verifyHostname(certs[0], socket, null, true);

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "leaving checkServerTrusted(certs, type, Socket), success");
    }

    @Override
    public void checkServerTrusted(X509Certificate[] certs, String type,
        SSLEngine engine) throws CertificateException, IllegalArgumentException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered checkServerTrusted() with SSLEngine");

        if (certs == null) {
            throw new IllegalArgumentException("Input cert chain null");
        }

        if (type == null || type.length() == 0) {
            throw new IllegalArgumentException("Input auth type null");
        }

        /* Verify cert chain, throw CertificateException if not valid */
        certManagerVerify(certs, type, false);

        /* Verify hostname if right criteria matches */
        verifyHostname(certs[0], null, engine, true);

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "leaving checkServerTrusted(certs, type, SSLEngine), " +
            "success");
    }

    /**
     * Verifies a specified certificate chain.
     * Non standard API, this is called/needed on some versions of Android.
     *
     * @param certs Certificate chain to validate
     * @param type  Authentication type
     * @param host  Hostname of the server. Cert pinning at this level not
     *              currently supported by wolfJSSE. If supported, and host was
     *              non-null, would check if chain is pinned correctly for
     *              this host.
     *
     * @throws CertificateException if chain does not verify properly
     * @return Certificate chain used for verification, ordered with leaf/peer
     *         cert first, root CA cert last
     */
    public List<X509Certificate> checkServerTrusted(X509Certificate[] certs,
        String type, String host) throws CertificateException {

        List<X509Certificate> certList = null;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered checkServerTrusted(cert, type, host)");

        certList = certManagerVerify(certs, type, true);

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "leaving checkServerTrusted(certs, type, host), success");

        return certList;
    }

    /**
     * Verifies a specified certificate chain.
     * Non standard API, this is called/needed by Android.
     *
     * Android expects this method signature for OCSP stapling support.
     * Native wolfSSL supports OCSP response processing via
     * wolfSSL_CertManagerCheckOCSPResponse(). The ocspData parameter
     * contains DER-encoded OCSP response data that is processed for
     * certificate revocation checking.
     *
     * @param chain      Certificate chain to validate
     * @param ocspData   OCSP response data (DER-encoded), may be null
     * @param tlsSctData TLS SCT data (unused, wolfSSL does not support SCT)
     * @param authType   Authentication type
     * @param host       Hostname of the server
     *
     * @return Certificate chain used for verification, ordered with leaf/peer
     *         cert first, root CA cert last
     *
     * @throws CertificateException if chain does not verify properly
     */
    public List<X509Certificate> checkServerTrusted(X509Certificate[] chain,
        byte[] ocspData, byte[] tlsSctData, String authType, String host)
        throws CertificateException {

        int ret;
        WolfSSLCertManager cm = null;
        byte[] leafCertDer = null;
        byte[] issuerCertDer = null;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered checkServerTrusted(chain, ocspData, tlsSctData, " +
            "authType, host)");

        /* First verify the cert chain normally, throws if chain invalid
         * including checks that chain != null and chain.length > 0 */
        List<X509Certificate> certList =
            checkServerTrusted(chain, authType, host);

        /* Verify OCSP response data if provided */
        if (ocspData != null && ocspData.length > 0) {

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "Verifying OCSP response data (" +
                    ocspData.length + " bytes)");

            try {
                cm = new WolfSSLCertManager();

                /* Load trusted CAs that were used for cert verification */
                ret = cm.CertManagerLoadCAKeyStore(this.store);
                if (ret != WolfSSL.SSL_SUCCESS) {
                    throw new CertificateException(
                        "Failed to load trusted CAs for OCSP verification, " +
                        "ret = " + ret);
                }

                /* Get DER-encoded leaf certificate from chain */
                leafCertDer = chain[0].getEncoded();

                /* Get issuer certificate if available in chain. Issuer
                 * needed to compute issuer key hash for OCSP matching. */
                if (chain.length > 1) {
                    issuerCertDer = chain[1].getEncoded();
                }

                /* Check OCSP response against the specific certificate */
                ret = cm.CertManagerCheckOCSPResponse(ocspData, leafCertDer,
                    issuerCertDer);
                if (ret != WolfSSL.SSL_SUCCESS) {
                    throw new CertificateException(
                        "OCSP response validation failed: " + ret);
                }

                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    () -> "OCSP response validation successful");

            } catch (WolfSSLException e) {
                String msg = e.getMessage();
                if (msg != null && msg.contains("not compiled")) {
                    /* OCSP not available, log and continue */
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        () -> "OCSP support not available, skipping " +
                        "OCSP validation");
                } else {
                    throw new CertificateException("OCSP validation error", e);
                }

            } catch (CertificateEncodingException e) {
                throw new CertificateException(
                    "Failed to encode certificate for OCSP verification", e);

            } finally {
                if (cm != null) {
                    cm.free();
                }
            }

        } else {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "No OCSP data provided, not doing OCSP validation");
        }

        /* Ignore TLS SCT data as wolfSSL doesn't support it */
        if (tlsSctData != null && tlsSctData.length > 0) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                () -> "TLS SCT data provided (" + tlsSctData.length +
                " bytes), currently not processed");
        }

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "leaving checkServerTrusted(chain, ocspData, tlsSctData, " +
            "authType, host), success");

        return certList;
    }

    /**
     * Returns an array of certificate authorities which are trusted for
     * authenticating peers.
     *
     * @return array of X509Certificate objects representing trusted
     *         CA certificates. May be empty (non-null).
     */
    @Override
    public X509Certificate[] getAcceptedIssuers() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            () -> "entered getAcceptedIssuers()");

        if (store == null) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.ERROR,
                () -> "Trust Manager was not initialized");
            return new X509Certificate[0];
        }

        try {
            List<X509Certificate> CAs = new ArrayList<X509Certificate>();
            /* Store the alias of all CAs */
            Enumeration<String> aliases = store.aliases();
            while (aliases.hasMoreElements()) {
                final String name = aliases.nextElement();
                X509Certificate cert = null;

                if (store.isKeyEntry(name)) {
                    Certificate[] chain = store.getCertificateChain(name);
                    if (chain != null)
                        cert = (X509Certificate) chain[0];
                } else {
                    cert = (X509Certificate) store.getCertificate(name);
                }

                /* Add certificate entry as trusted if either:
                 * 1. X509v3 Basic Constraint CA:TRUE is set, or
                 * 2. Native wolfSSL has been compiled with
                 *    WOLFSSL_TRUST_PEER_CERT defined.
                 * SunJSSE implementation just adds all certificate entries
                 * it finds in the provided KeyStore as trusted, so this
                 * behavior does vary slightly from the default Sun
                 * implementation. */
                if (cert != null &&
                    (cert.getBasicConstraints() >= 0 ||
                     WolfSSL.trustPeerCertEnabled())) {
                    CAs.add(cert);
                }
            }

            return CAs.toArray(new X509Certificate[CAs.size()]);

        } catch (KeyStoreException ex) {
            return new X509Certificate[0];
        }
    }

    @SuppressWarnings("deprecation")
    @Override
    protected void finalize() throws Throwable {
        this.store = null;
        super.finalize();
    }
}

