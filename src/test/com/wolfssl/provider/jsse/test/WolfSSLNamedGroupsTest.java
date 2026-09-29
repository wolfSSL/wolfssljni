/* WolfSSLNamedGroupsTest.java
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

package com.wolfssl.provider.jsse.test;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLContext;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLSession;
import com.wolfssl.provider.jsse.WolfSSLParametersHelper;
import com.wolfssl.provider.jsse.WolfSSLProvider;
import com.wolfssl.test.TimedTestWatcher;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Tests for TLS named-groups (supported_groups) configuration in wolfJSSE.
 *
 * wolfJSSE selects a single named-groups configuration source per session,
 * in strict override precedence order:
 *
 *   1. SSLParameters.setNamedGroups() (JDK 20+, reflective bridge)
 *   2. jdk.tls.namedGroups System property
 *   3. wolfjsse.enabledSupportedCurves Security property
 *
 * Only the highest-precedence source that is set is applied. Sources never
 * union/accumulate. All sources restrict both client and server mode.
 * Unrecognized group tokens and groups rejected by native wolfSSL are ignored
 * (skipped with a log), matching the JDK contract for
 * SSLParameters.setNamedGroups() and SunJSSE handling of jdk.tls.namedGroups.
 * SSLException is thrown during handshake setup only when a configured list
 * yields no usable groups at all (for example all tokens unknown, or the list
 * is left empty after PQC filtering on a non-TLS-1.3 session).
 *
 * Coverage:
 *   - Reflection bridge in WolfSSLParametersHelper returns null cleanly
 *     when the host JDK lacks the methods.
 *   - When present, per-engine/socket setNamedGroups() overrides (not
 *     unions with) the static properties.
 *   - jdk.tls.namedGroups overrides wolfjsse.enabledSupportedCurves.
 *   - Unknown tokens are ignored, all-unknown lists fail.
 *
 * Per-method Assume.assume* skips handle JDKs that don't expose the methods.
 */
public class WolfSSLNamedGroupsTest {

    private static final String PROVIDER = "wolfJSSE";
    private static final String APP_DATA = "named groups test";

    private static WolfSSLTestFactory tf;
    private static boolean jdkHasNamedGroups = false;

    @Rule
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void setUp()
        throws NoSuchProviderException, WolfSSLException {

        System.out.println("WolfSSLNamedGroups Class");

        Security.insertProviderAt(new WolfSSLProvider(), 1);
        tf = new WolfSSLTestFactory();

        try {
            SSLParameters.class.getMethod("setNamedGroups", String[].class);
            SSLParameters.class.getMethod("getNamedGroups");
            jdkHasNamedGroups = true;

        } catch (NoSuchMethodException e) {
            jdkHasNamedGroups = false;
        }
    }

    /**
     * Helper to apply named groups to one SSLEngine through the public
     * WolfSSLParametersHelper bridge.
     */
    private static void setEngineNamedGroups(SSLEngine engine,
        String[] groups) {

        SSLParameters params = engine.getSSLParameters();
        WolfSSLParametersHelper.setNamedGroupsOnParams(params, groups);
        engine.setSSLParameters(params);
    }

    /**
     * Reflection helper must return null cleanly when the host JDK does not
     * expose SSLParameters.set/getNamedGroups, so callers can safely fall back
     * to the static properties without special handling for the JDK version.
     */
    @Test
    public void testHelper_returnsNullWhenApiAbsent() {

        Assume.assumeFalse(
            "Host JDK has SSLParameters.setNamedGroups/getNamedGroups",
            jdkHasNamedGroups);

        SSLParameters p = new SSLParameters();
        assertNull("getNamedGroupsFromParams must return null on a JDK " +
            "without SSLParameters.getNamedGroups",
            WolfSSLParametersHelper.getNamedGroupsFromParams(p));

        /* setNamedGroupsOnParams must be a clean no-op on a JDK without
         * SSLParameters.setNamedGroups. */
        WolfSSLParametersHelper.setNamedGroupsOnParams(p,
            new String[] { "X25519MLKEM768" });
        assertNull(WolfSSLParametersHelper.getNamedGroupsFromParams(p));
    }

    /**
     * When the host JDK exposes SSLParameters.setNamedGroups, the public
     * WolfSSLParametersHelper bridge must round-trip the value.
     */
    @Test
    public void testHelper_roundTripsViaReflection() throws Exception {

        Assume.assumeTrue("Host JDK lacks SSLParameters.setNamedGroups",
            jdkHasNamedGroups);

        SSLParameters p = new SSLParameters();
        String[] groups = new String[] {
            "X25519MLKEM768", "SecP256r1MLKEM768", "x25519"
        };

        WolfSSLParametersHelper.setNamedGroupsOnParams(p, groups);

        String[] back = WolfSSLParametersHelper.getNamedGroupsFromParams(p);
        assertArrayEquals("Round-tripped named groups must match", groups,
            back);

        /* Mutating the returned array must not affect the stored value
         * (helper returns a clone). */
        if (back != null) {
            back[0] = "MUTATED";
            String[] back2 =
                WolfSSLParametersHelper.getNamedGroupsFromParams(p);
            assertEquals("getNamedGroupsFromParams must return a defensive " +
                "copy", "X25519MLKEM768", back2[0]);
        }
    }

    /**
     * Per-engine SSLParameters.setNamedGroups() must override the global
     * wolfjsse.enabledSupportedCurves Security property. Only the
     * setNamedGroups() list is applied, the property is ignored. Sources
     * are never unioned.
     *
     * Negative path: property = X25519MLKEM768, client setNamedGroups()
     * = secp256r1 only, server setNamedGroups() = X25519MLKEM768 only.
     * Under override semantics the client offers ONLY secp256r1 and the
     * server accepts ONLY X25519MLKEM768, so there is no common group and
     * the handshake must fail.
     *
     * Positive path: both engines setNamedGroups() to the same PQC group
     * while the property names a different group. The handshake succeeds
     * using only the per-engine list.
     */
    @Test
    public void testEngineHonorsPerEngineNamedGroups() throws Exception {

        Assume.assumeTrue("Host JDK lacks SSLParameters.setNamedGroups",
            jdkHasNamedGroups);
        Assume.assumeTrue("ML-KEM not enabled in native wolfSSL",
            WolfSSL.MLKEMEnabled() && WolfSSL.TLSv13Enabled());

        synchronized (WolfSSLPQCTestUtil.GROUP_PROP_LOCK) {
            String prev =
                WolfSSLPQCTestUtil.setCurvesProperty("X25519MLKEM768");
            try {
                /* Negative: disjoint per-engine lists, no common group. */
                SSLContext ctx = tf.createSSLContext("TLSv1.3", PROVIDER);
                SSLEngine server = ctx.createSSLEngine();
                server.setUseClientMode(false);
                server.setNeedClientAuth(false);
                SSLEngine client =
                    ctx.createSSLEngine("wolfSSL named groups test", 11111);
                client.setUseClientMode(true);

                setEngineNamedGroups(client,
                    new String[] { "secp256r1" });
                setEngineNamedGroups(server,
                    new String[] { "X25519MLKEM768" });

                int ret = tf.testConnection(server, client, null,
                    new String[] { "TLSv1.3" }, APP_DATA);
                assertFalse("Handshake must fail under override " +
                    "semantics: client offers only secp256r1, server " +
                    "accepts only X25519MLKEM768. Success would indicate " +
                    "the Security property was unioned into the " +
                    "per-engine list", ret == 0);

                /* Positive: same per-engine PQC group on both sides, with
                 * the property still naming a different group. */
                ctx = tf.createSSLContext("TLSv1.3", PROVIDER);
                server = ctx.createSSLEngine();
                server.setUseClientMode(false);
                server.setNeedClientAuth(false);
                client =
                    ctx.createSSLEngine("wolfSSL named groups test", 11111);
                client.setUseClientMode(true);

                String[] perEngine = new String[] { "SECP256R1MLKEM768" };
                setEngineNamedGroups(client, perEngine);
                setEngineNamedGroups(server, perEngine);

                ret = tf.testConnection(server, client, null,
                    new String[] { "TLSv1.3" }, APP_DATA);
                assertEquals("Per-engine setNamedGroups should drive a " +
                    "successful PQC handshake", 0, ret);
            }
            finally {
                WolfSSLPQCTestUtil.restoreCurvesProperty(prev);
            }
        }
    }

    /**
     * Server-side application of SSLEngine setNamedGroups. Named-groups
     * configuration restricts servers as well as clients. When the server
     * restricts itself to a PQC group via setNamedGroups but the client
     * offers only classical groups, the handshake must fail (no common
     * group).
     */
    @Test
    public void testServerNamedGroupsRestriction() throws Exception {

        Assume.assumeTrue("Host JDK lacks SSLParameters.setNamedGroups",
            jdkHasNamedGroups);
        Assume.assumeTrue("ML-KEM not enabled in native wolfSSL",
            WolfSSL.MLKEMEnabled() && WolfSSL.TLSv13Enabled());

        synchronized (WolfSSLPQCTestUtil.GROUP_PROP_LOCK) {
            String prev = WolfSSLPQCTestUtil.setCurvesProperty(null);
            try {
                SSLContext ctx = tf.createSSLContext("TLSv1.3", PROVIDER);

                /* Server restricts to PQC only. */
                SSLEngine server = ctx.createSSLEngine();
                server.setUseClientMode(false);
                server.setNeedClientAuth(false);
                setEngineNamedGroups(server,
                    new String[] { "SECP384R1MLKEM1024" });

                /* Client offers only classical groups. */
                SSLEngine client =
                    ctx.createSSLEngine("wolfSSL named groups test", 11111);
                client.setUseClientMode(true);
                setEngineNamedGroups(client,
                    new String[] { "secp256r1" });

                int ret = tf.testConnection(server, client, null,
                    new String[] { "TLSv1.3" }, APP_DATA);
                assertFalse("Handshake must fail: server restricts to PQC, " +
                    "client offers classical only", ret == 0);
            }
            finally {
                WolfSSLPQCTestUtil.restoreCurvesProperty(prev);
            }
        }
    }

    /**
     * With no SSLEngine override and no Security property set, the helper
     * must report null.
     */
    @Test
    public void testHelper_unsetReturnsNull() {

        SSLParameters p = new SSLParameters();
        String[] result = WolfSSLParametersHelper.getNamedGroupsFromParams(p);
        assertNull("Unset SSLParameters.namedGroups must surface as null",
            result);
    }

    /**
     * getNamedGroupsFromParams must tolerate a null input without throwing.
     */
    @Test
    public void testHelper_nullInputReturnsNull() {

        assertNull(WolfSSLParametersHelper.getNamedGroupsFromParams(null));
    }

    /**
     * jdk.tls.namedGroups System property alone (no wolfJSSE Security prop or
     * SSLEngine override) must do a successful PQC handshake. The property
     * restricts both client and server mode, so a successful handshake with
     * a single PQC group in the list proves both sides applied it.
     */
    @Test
    public void testJdkTlsNamedGroupsAloneDrivesHandshake() throws Exception {

        Assume.assumeTrue("ML-KEM not enabled in native wolfSSL",
            WolfSSL.MLKEMEnabled() && WolfSSL.TLSv13Enabled());

        synchronized (WolfSSLPQCTestUtil.GROUP_PROP_LOCK) {
            String prevWolf = WolfSSLPQCTestUtil.setCurvesProperty(null);
            String prevJdk = WolfSSLPQCTestUtil.setJdkNamedGroupsProperty(
                "SECP256R1MLKEM768");
            try {
                SSLContext ctx = tf.createSSLContext("TLSv1.3", PROVIDER);
                SSLEngine server = ctx.createSSLEngine();
                server.setUseClientMode(false);
                server.setNeedClientAuth(false);
                SSLEngine client =
                    ctx.createSSLEngine("wolfSSL named groups test", 11111);
                client.setUseClientMode(true);

                int ret = tf.testConnection(server, client, null,
                    new String[] { "TLSv1.3" }, APP_DATA);
                assertEquals("jdk.tls.namedGroups alone should drive a " +
                    "successful PQC handshake", 0, ret);
            }
            finally {
                WolfSSLPQCTestUtil.restoreCurvesProperty(prevWolf);
                WolfSSLPQCTestUtil.restoreJdkNamedGroupsProperty(prevJdk);
            }
        }
    }

    /**
     * A server whose KeyStore holds both RSA and ECC private keys must
     * complete a TLS 1.2 handshake when jdk.tls.namedGroups is restricted
     * to FFDHE groups only.
     *
     * Server certificate selection prefers an ECC alias over RSA when the
     * KeyStore holds both. With no ECC curves in supported_groups, ECDHE
     * suites cannot be negotiated on TLS 1.2, so an ECDSA certificate
     * cannot complete any key exchange and the handshake previously failed
     * with no shared cipher suite. The RSA alias must be preferred instead
     * so a DHE_RSA suite can complete over the RFC 7919 group.
     */
    @Test
    public void testJdkTlsNamedGroupsFfdheOnlyTls12PrefersRsaCert()
        throws Exception {

        Assume.assumeTrue("TLS 1.2, RSA and ECC required in native wolfSSL",
            WolfSSL.TLSv12Enabled() && WolfSSL.RsaEnabled() &&
            WolfSSL.EccEnabled());
        Assume.assumeTrue("DHE_RSA cipher suites not available",
            dheRsaSuitesAvailable());
        Assume.assumeTrue("ffdhe2048 named group not supported",
            ffdhe2048GroupSupported());

        synchronized (WolfSSLPQCTestUtil.GROUP_PROP_LOCK) {
            Assume.assumeTrue("TLS 1.2 FFDHE handshakes not supported by " +
                "native wolfSSL build", ffdheHandshakeSupported("TLSv1.2"));

            String prevWolf =
                WolfSSLPQCTestUtil.setCurvesProperty(null);
            String prevJdk =
                WolfSSLPQCTestUtil.setJdkNamedGroupsProperty("ffdhe2048");

            try {
                SSLContext ctx = tf.createSSLContext("TLSv1.2", PROVIDER);
                SSLEngine server = ctx.createSSLEngine();
                server.setUseClientMode(false);
                server.setNeedClientAuth(false);
                SSLEngine client =
                    ctx.createSSLEngine("wolfSSL named groups test", 11111);
                client.setUseClientMode(true);

                int ret = tf.testConnection(server, client,
                    suitesMatching("TLS_DHE_RSA_"),
                    new String[] { "TLSv1.2" }, APP_DATA);
                assertEquals("TLS 1.2 handshake with FFDHE-only " +
                    "jdk.tls.namedGroups and a KeyStore holding both RSA " +
                    "and ECC keys must succeed", 0, ret);

                String suite = client.getSession().getCipherSuite();
                assertTrue("negotiated cipher suite must be DHE_RSA, " +
                    "got: " + suite, suite.startsWith("TLS_DHE_RSA_") ||
                    suite.startsWith("DHE-RSA-"));
            }
            finally {
                WolfSSLPQCTestUtil.restoreCurvesProperty(prevWolf);
                WolfSSLPQCTestUtil.restoreJdkNamedGroupsProperty(prevJdk);
            }
        }
    }

    /**
     * True when native wolfSSL was compiled with DH support, using the
     * presence of DHE_RSA cipher suites as a proxy. FFDHE named groups
     * need DH for both TLS 1.2 DHE_RSA suites and TLS 1.3 FFDHE key
     * shares.
     */
    private static boolean dheRsaSuitesAvailable() {
        for (String suite : WolfSSL.getCiphersIana()) {
            if (suite.startsWith("TLS_DHE_RSA_")) {
                return true;
            }
        }
        return false;
    }

    /**
     * Return compiled-in cipher suites whose IANA names start with any of
     * the given prefixes.
     */
    private static String[] suitesMatching(String... prefixes) {

        ArrayList<String> matched = new ArrayList<>();

        for (String suite : WolfSSL.getCiphersIana()) {
            for (String prefix : prefixes) {
                if (suite.startsWith(prefix)) {
                    matched.add(suite);
                    break;
                }
            }
        }

        return matched.toArray(new String[matched.size()]);
    }

    /* Cached results of ffdheHandshakeSupported(), keyed by protocol */
    private static final HashMap<String, Boolean> ffdheCapable =
        new HashMap<>();

    /**
     * True when this environment can complete a handshake of the given
     * protocol with FFDHE-only named groups.
     *
     * Caller must hold WolfSSLPQCTestUtil.GROUP_PROP_LOCK.
     *
     * @param protocol "TLSv1.2" or "TLSv1.3"
     */
    private static boolean ffdheHandshakeSupported(String protocol)
        throws Exception {

        Boolean capable = ffdheCapable.get(protocol);
        if (capable != null) {
            return capable.booleanValue();
        }

        String prevJdk =
            WolfSSLPQCTestUtil.setJdkNamedGroupsProperty("ffdhe2048");

        try {
            SSLContext srvCtx = tf.createSSLContext(protocol, PROVIDER,
                tf.createTrustManager("SunX509", tf.caClientJKS, PROVIDER),
                tf.createKeyManager("SunX509", tf.serverRSAJKS, PROVIDER));
            SSLContext cliCtx = tf.createSSLContext(protocol, PROVIDER,
                tf.createTrustManager("SunX509", tf.caServerJKS, PROVIDER),
                tf.createKeyManager("SunX509", tf.clientRSAJKS, PROVIDER));

            SSLEngine server = srvCtx.createSSLEngine();
            server.setUseClientMode(false);
            server.setNeedClientAuth(false);
            SSLEngine client =
                cliCtx.createSSLEngine("wolfSSL named groups test", 11111);
            client.setUseClientMode(true);

            /* TLS 1.2 needs a DHE suite to use FFDHE, TLS 1.3 negotiates
             * the group independently of the cipher suite */
            String[] suites = null;
            if (protocol.equals("TLSv1.2")) {
                suites = suitesMatching("TLS_DHE_RSA_");
            }

            int ret = tf.testConnection(server, client, suites,
                new String[] { protocol }, APP_DATA);
            capable = Boolean.valueOf(ret == 0);
            ffdheCapable.put(protocol, capable);
        }
        finally {
            WolfSSLPQCTestUtil.restoreJdkNamedGroupsProperty(prevJdk);
        }

        return capable.booleanValue();
    }

    /**
     * True when native wolfSSL supports the ffdhe2048 TLS named group
     * (HAVE_FFDHE_2048), probed the same way wolfJSSE applies configured
     * groups to a session.
     */
    private static boolean ffdhe2048GroupSupported() {

        WolfSSLContext ctx = null;
        WolfSSLSession ssl = null;

        try {
            ctx = new WolfSSLContext(WolfSSL.SSLv23_ClientMethod());
            ssl = new WolfSSLSession(ctx);

            return (ssl.useSupportedCurves(
                new int[] { WolfSSL.WOLFSSL_FFDHE_2048 }) ==
                WolfSSL.SSL_SUCCESS);
        } catch (Exception e) {
            return false;
        } finally {
            /* Best-effort cleanup, must not throw out of this probe */
            if (ssl != null) {
                try {
                    ssl.freeSSL();
                } catch (Exception e) {
                    /* ignore */
                }
            }
            if (ctx != null) {
                try {
                    ctx.free();
                } catch (Exception e) {
                    /* ignore */
                }
            }
        }
    }

    /**
     * Same server RSA-alias preference as
     * testJdkTlsNamedGroupsFfdheOnlyTls12PrefersRsaCert, driven by the
     * lowest-precedence configuration source, the
     * wolfjsse.enabledSupportedCurves Security property.
     */
    @Test
    public void testWolfjsseCurvesPropertyFfdheOnlyTls12PrefersRsaCert()
        throws Exception {

        Assume.assumeTrue("TLS 1.2, RSA and ECC required in native wolfSSL",
            WolfSSL.TLSv12Enabled() && WolfSSL.RsaEnabled() &&
            WolfSSL.EccEnabled());
        Assume.assumeTrue("DHE_RSA cipher suites not available",
            dheRsaSuitesAvailable());
        Assume.assumeTrue("ffdhe2048 named group not supported",
            ffdhe2048GroupSupported());

        synchronized (WolfSSLPQCTestUtil.GROUP_PROP_LOCK) {
            Assume.assumeTrue("TLS 1.2 FFDHE handshakes not supported by " +
                "native wolfSSL build", ffdheHandshakeSupported("TLSv1.2"));

            String prevJdk =
                WolfSSLPQCTestUtil.setJdkNamedGroupsProperty(null);
            String prevWolf =
                WolfSSLPQCTestUtil.setCurvesProperty("ffdhe2048");

            try {
                SSLContext ctx = tf.createSSLContext("TLSv1.2", PROVIDER);
                SSLEngine server = ctx.createSSLEngine();
                server.setUseClientMode(false);
                server.setNeedClientAuth(false);
                SSLEngine client =
                    ctx.createSSLEngine("wolfSSL named groups test", 11111);
                client.setUseClientMode(true);

                int ret = tf.testConnection(server, client,
                    suitesMatching("TLS_DHE_RSA_"),
                    new String[] { "TLSv1.2" }, APP_DATA);
                assertEquals("TLS 1.2 handshake with FFDHE-only " +
                    "wolfjsse.enabledSupportedCurves and a KeyStore " +
                    "holding both RSA and ECC keys must succeed", 0, ret);

                String suite = client.getSession().getCipherSuite();
                assertTrue("negotiated cipher suite must be DHE_RSA, " +
                    "got: " + suite, suite.startsWith("TLS_DHE_RSA_") ||
                    suite.startsWith("DHE-RSA-"));
            }
            finally {
                WolfSSLPQCTestUtil.restoreCurvesProperty(prevWolf);
                WolfSSLPQCTestUtil.restoreJdkNamedGroupsProperty(prevJdk);
            }
        }
    }

    /**
     * Same server RSA-alias preference as
     * testJdkTlsNamedGroupsFfdheOnlyTls12PrefersRsaCert, driven by the
     * highest-precedence configuration source, per-engine
     * SSLParameters.setNamedGroups() (JDK 20+).
     */
    @Test
    public void testSetNamedGroupsFfdheOnlyTls12PrefersRsaCert()
        throws Exception {

        Assume.assumeTrue("Host JDK lacks SSLParameters.setNamedGroups",
            jdkHasNamedGroups);
        Assume.assumeTrue("TLS 1.2, RSA and ECC required in native wolfSSL",
            WolfSSL.TLSv12Enabled() && WolfSSL.RsaEnabled() &&
            WolfSSL.EccEnabled());
        Assume.assumeTrue("DHE_RSA cipher suites not available",
            dheRsaSuitesAvailable());
        Assume.assumeTrue("ffdhe2048 named group not supported",
            ffdhe2048GroupSupported());

        synchronized (WolfSSLPQCTestUtil.GROUP_PROP_LOCK) {
            Assume.assumeTrue("TLS 1.2 FFDHE handshakes not supported by " +
                "native wolfSSL build", ffdheHandshakeSupported("TLSv1.2"));

            String prevWolf =
                WolfSSLPQCTestUtil.setCurvesProperty(null);
            String prevJdk =
                WolfSSLPQCTestUtil.setJdkNamedGroupsProperty(null);

            try {
                SSLContext ctx = tf.createSSLContext("TLSv1.2", PROVIDER);
                SSLEngine server = ctx.createSSLEngine();
                server.setUseClientMode(false);
                server.setNeedClientAuth(false);
                SSLEngine client =
                    ctx.createSSLEngine("wolfSSL named groups test", 11111);
                client.setUseClientMode(true);

                setEngineNamedGroups(server, new String[] { "ffdhe2048" });
                setEngineNamedGroups(client, new String[] { "ffdhe2048" });

                int ret = tf.testConnection(server, client,
                    suitesMatching("TLS_DHE_RSA_"),
                    new String[] { "TLSv1.2" }, APP_DATA);
                assertEquals("TLS 1.2 handshake with FFDHE-only " +
                    "SSLParameters.setNamedGroups() and a KeyStore " +
                    "holding both RSA and ECC keys must succeed", 0, ret);

                String suite = client.getSession().getCipherSuite();
                assertTrue("negotiated cipher suite must be DHE_RSA, " +
                    "got: " + suite, suite.startsWith("TLS_DHE_RSA_") ||
                    suite.startsWith("DHE-RSA-"));
            }
            finally {
                WolfSSLPQCTestUtil.restoreCurvesProperty(prevWolf);
                WolfSSLPQCTestUtil.restoreJdkNamedGroupsProperty(prevJdk);
            }
        }
    }

    /**
     * On a TLS 1.3-only session, FFDHE-only named groups must not change
     * server certificate selection: TLS 1.3 negotiates the key exchange
     * group independently of the certificate type, so the default ECC
     * alias preference stays and the handshake completes with the ECDSA
     * certificate over an ffdhe2048 key share.
     */
    @Test
    public void testJdkTlsNamedGroupsFfdheOnlyTls13KeepsEccCert()
        throws Exception {

        Assume.assumeTrue("TLS 1.3, RSA and ECC required in native wolfSSL",
            WolfSSL.TLSv13Enabled() && WolfSSL.RsaEnabled() &&
            WolfSSL.EccEnabled());
        Assume.assumeTrue("ffdhe2048 named group not supported",
            ffdhe2048GroupSupported());

        synchronized (WolfSSLPQCTestUtil.GROUP_PROP_LOCK) {
            Assume.assumeTrue("TLS 1.3 FFDHE handshakes not supported by " +
                "native wolfSSL build", ffdheHandshakeSupported("TLSv1.3"));

            String prevWolf =
                WolfSSLPQCTestUtil.setCurvesProperty(null);
            String prevJdk =
                WolfSSLPQCTestUtil.setJdkNamedGroupsProperty("ffdhe2048");

            try {
                SSLContext ctx = tf.createSSLContext("TLSv1.3", PROVIDER);
                SSLEngine server = ctx.createSSLEngine();
                server.setUseClientMode(false);
                server.setNeedClientAuth(false);
                SSLEngine client =
                    ctx.createSSLEngine("wolfSSL named groups test", 11111);
                client.setUseClientMode(true);

                int ret = tf.testConnection(server, client, null,
                    new String[] { "TLSv1.3" }, APP_DATA);
                assertEquals("TLS 1.3 handshake with FFDHE-only " +
                    "jdk.tls.namedGroups must succeed", 0, ret);

                Certificate[] peerCerts =
                    client.getSession().getPeerCertificates();
                String keyAlgo = peerCerts[0].getPublicKey().getAlgorithm();
                assertEquals("TLS 1.3 server must keep default ECC cert " +
                    "preference with FFDHE-only named groups", "EC",
                    keyAlgo);
            }
            finally {
                WolfSSLPQCTestUtil.restoreCurvesProperty(prevWolf);
                WolfSSLPQCTestUtil.restoreJdkNamedGroupsProperty(prevJdk);
            }
        }
    }

    /**
     * When the configured named groups contain at least one ECC curve
     * alongside FFDHE groups, server certificate selection must keep the
     * default ECC preference and negotiate an ECDHE_ECDSA suite on
     * TLS 1.2.
     */
    @Test
    public void testJdkTlsNamedGroupsMixedEccFfdheTls12KeepsEccCert()
        throws Exception {

        Assume.assumeTrue("TLS 1.2, RSA and ECC required in native wolfSSL",
            WolfSSL.TLSv12Enabled() && WolfSSL.RsaEnabled() &&
            WolfSSL.EccEnabled());

        synchronized (WolfSSLPQCTestUtil.GROUP_PROP_LOCK) {
            String prevWolf =
                WolfSSLPQCTestUtil.setCurvesProperty(null);
            String prevJdk = WolfSSLPQCTestUtil.setJdkNamedGroupsProperty(
                "secp256r1,ffdhe2048");

            try {
                SSLContext ctx = tf.createSSLContext("TLSv1.2", PROVIDER);
                SSLEngine server = ctx.createSSLEngine();
                server.setUseClientMode(false);
                server.setNeedClientAuth(false);
                SSLEngine client =
                    ctx.createSSLEngine("wolfSSL named groups test", 11111);
                client.setUseClientMode(true);

                int ret = tf.testConnection(server, client,
                    suitesMatching("TLS_ECDHE_ECDSA_", "TLS_DHE_RSA_"),
                    new String[] { "TLSv1.2" }, APP_DATA);
                assertEquals("TLS 1.2 handshake with mixed ECC+FFDHE " +
                    "jdk.tls.namedGroups must succeed", 0, ret);

                String suite = client.getSession().getCipherSuite();
                assertTrue("negotiated cipher suite must be ECDHE_ECDSA " +
                    "when an ECC group is configured, got: " + suite,
                    suite.startsWith("TLS_ECDHE_ECDSA_") ||
                    suite.startsWith("ECDHE-ECDSA-"));
            }
            finally {
                WolfSSLPQCTestUtil.restoreCurvesProperty(prevWolf);
                WolfSSLPQCTestUtil.restoreJdkNamedGroupsProperty(prevJdk);
            }
        }
    }

    /**
     * When both static properties are set, jdk.tls.namedGroups overrides
     * wolfjsse.enabledSupportedCurves. A single source is applied per
     * session, the lists never accumulate.
     *
     * The wolfJSSE property is set to only an unknown token here. A list
     * yielding no usable groups throws SSLException when applied, so the
     * handshake can only succeed if the wolfJSSE property is never read
     * for the session, proving jdk.tls.namedGroups replaced it rather
     * than accumulating with it.
     *
     * Also verifies each property reader returns only its own property's
     * contents (no cross contamination between the two helpers).
     */
    @Test
    public void testJdkPropertyOverridesWolfjsseProperty() throws Exception {

        Assume.assumeTrue("ML-KEM not enabled in native wolfSSL",
            WolfSSL.MLKEMEnabled() && WolfSSL.TLSv13Enabled());

        synchronized (WolfSSLPQCTestUtil.GROUP_PROP_LOCK) {
            String prevWolf =
                WolfSSLPQCTestUtil.setCurvesProperty("bogusgroup");
            String prevJdk = WolfSSLPQCTestUtil.setJdkNamedGroupsProperty(
                "SECP256R1MLKEM768");
            try {
                /* Each helper returns only its own property's contents. */
                Method getSC = com.wolfssl.provider.jsse.WolfSSLUtil.class
                    .getDeclaredMethod("getSupportedCurves");
                getSC.setAccessible(true);
                String[] sc = (String[]) getSC.invoke(null);
                assertArrayEquals(
                    "getSupportedCurves must read only wolfJSSE property",
                    new String[] { "bogusgroup" }, sc);

                Method getJdk = com.wolfssl.provider.jsse.WolfSSLUtil.class
                    .getDeclaredMethod("getJdkTlsNamedGroups");
                getJdk.setAccessible(true);
                String[] jdk = (String[]) getJdk.invoke(null);
                assertArrayEquals(
                    "getJdkTlsNamedGroups must read only JDK property",
                    new String[] { "SECP256R1MLKEM768" }, jdk);

                /* End-to-end: only jdk.tls.namedGroups is applied. If the
                 * wolfJSSE property were also applied, its all-unknown
                 * list would yield no usable groups and fail the
                 * handshake. */
                SSLContext ctx = tf.createSSLContext("TLSv1.3", PROVIDER);
                SSLEngine server = ctx.createSSLEngine();
                server.setUseClientMode(false);
                server.setNeedClientAuth(false);
                SSLEngine client =
                    ctx.createSSLEngine("wolfSSL named groups test", 11111);
                client.setUseClientMode(true);

                int ret = tf.testConnection(server, client, null,
                    new String[] { "TLSv1.3" }, APP_DATA);
                assertEquals("jdk.tls.namedGroups must override " +
                    "wolfjsse.enabledSupportedCurves. Failure here " +
                    "indicates the wolfJSSE property (with an unknown " +
                    "token) was also applied", 0, ret);
            }
            finally {
                WolfSSLPQCTestUtil.restoreCurvesProperty(prevWolf);
                WolfSSLPQCTestUtil.restoreJdkNamedGroupsProperty(prevJdk);
            }
        }
    }

    /**
     * SSLParameters.setNamedGroups() must override jdk.tls.namedGroups,
     * the same way it overrides the wolfJSSE Security property. The JDK
     * System property is set to only an unknown token, which would yield
     * no usable groups and fail if applied. The handshake can only
     * succeed if the property is never read for this session because the
     * per-engine list replaced it.
     */
    @Test
    public void testPerEngineOverridesJdkProperty() throws Exception {

        Assume.assumeTrue("Host JDK lacks SSLParameters.setNamedGroups",
            jdkHasNamedGroups);
        Assume.assumeTrue("ML-KEM not enabled in native wolfSSL",
            WolfSSL.MLKEMEnabled() && WolfSSL.TLSv13Enabled());

        synchronized (WolfSSLPQCTestUtil.GROUP_PROP_LOCK) {
            String prevWolf = WolfSSLPQCTestUtil.setCurvesProperty(null);
            String prevJdk = WolfSSLPQCTestUtil.setJdkNamedGroupsProperty(
                "bogusgroup");

            try {
                SSLContext ctx = tf.createSSLContext("TLSv1.3", PROVIDER);
                SSLEngine server = ctx.createSSLEngine();
                server.setUseClientMode(false);
                server.setNeedClientAuth(false);
                SSLEngine client =
                    ctx.createSSLEngine("wolfSSL named groups test", 11111);
                client.setUseClientMode(true);

                String[] perEngine = new String[] { "SECP256R1MLKEM768" };
                setEngineNamedGroups(client, perEngine);
                setEngineNamedGroups(server, perEngine);

                int ret = tf.testConnection(server, client, null,
                    new String[] { "TLSv1.3" }, APP_DATA);
                assertEquals("Per-engine setNamedGroups must override " +
                    "jdk.tls.namedGroups. Failure here indicates the JDK " +
                    "property (with an unknown token) was also applied",
                    0, ret);
            }
            finally {
                WolfSSLPQCTestUtil.restoreCurvesProperty(prevWolf);
                WolfSSLPQCTestUtil.restoreJdkNamedGroupsProperty(prevJdk);
            }
        }
    }

    /**
     * An unknown token in jdk.tls.namedGroups must be ignored, matching
     * the JDK contract (SSLParameters.setNamedGroups() javadoc: providers
     * should ignore unknown named group names) and SunJSSE behavior. The
     * handshake must succeed using the remaining valid group. The
     * property is read per-handshake by the provider, so setting it
     * in-test takes effect on the next connection.
     */
    @Test
    public void testJdkTlsNamedGroupsUnknownTokenIgnored()
        throws Exception {

        Assume.assumeTrue("TLS 1.3 not enabled in native wolfSSL",
            WolfSSL.TLSv13Enabled());

        synchronized (WolfSSLPQCTestUtil.GROUP_PROP_LOCK) {
            String prevWolf = WolfSSLPQCTestUtil.setCurvesProperty(null);
            String prevJdk = WolfSSLPQCTestUtil.setJdkNamedGroupsProperty(
                "bogusgroup,secp256r1");
            try {
                SSLContext ctx = tf.createSSLContext("TLSv1.3", PROVIDER);
                SSLEngine server = ctx.createSSLEngine();
                server.setUseClientMode(false);
                server.setNeedClientAuth(false);
                SSLEngine client =
                    ctx.createSSLEngine("wolfSSL named groups test", 11111);
                client.setUseClientMode(true);

                int ret = tf.testConnection(server, client, null,
                    new String[] { "TLSv1.3" }, APP_DATA);
                assertEquals("Unknown token in jdk.tls.namedGroups must " +
                    "be ignored and the handshake must succeed using the " +
                    "remaining valid group", 0, ret);
            }
            finally {
                WolfSSLPQCTestUtil.restoreCurvesProperty(prevWolf);
                WolfSSLPQCTestUtil.restoreJdkNamedGroupsProperty(prevJdk);
            }
        }
    }

    /**
     * A jdk.tls.namedGroups list containing only unknown tokens yields no
     * usable groups and must fail with SSLException during handshake
     * setup, matching SunJSSE which throws when jdk.tls.namedGroups
     * contains no supported named groups.
     *
     * WolfSSLTestFactory.testConnection() catches the SSLException thrown
     * out of SSLEngine wrap()/unwrap() and converts it to a -1 return.
     */
    @Test
    public void testJdkTlsNamedGroupsAllUnknownFailsClosed()
        throws Exception {

        Assume.assumeTrue("TLS 1.3 not enabled in native wolfSSL",
            WolfSSL.TLSv13Enabled());

        synchronized (WolfSSLPQCTestUtil.GROUP_PROP_LOCK) {
            String prevWolf = WolfSSLPQCTestUtil.setCurvesProperty(null);
            String prevJdk = WolfSSLPQCTestUtil.setJdkNamedGroupsProperty(
                "bogusgroup1,bogusgroup2");
            try {
                SSLContext ctx = tf.createSSLContext("TLSv1.3", PROVIDER);
                SSLEngine server = ctx.createSSLEngine();
                server.setUseClientMode(false);
                server.setNeedClientAuth(false);
                SSLEngine client =
                    ctx.createSSLEngine("wolfSSL named groups test", 11111);
                client.setUseClientMode(true);

                int ret = tf.testConnection(server, client, null,
                    new String[] { "TLSv1.3" }, APP_DATA);
                assertEquals("jdk.tls.namedGroups with only unknown " +
                    "tokens must fail with SSLException during handshake " +
                    "setup (surfaced by testConnection as -1)", -1, ret);
            }
            finally {
                WolfSSLPQCTestUtil.restoreCurvesProperty(prevWolf);
                WolfSSLPQCTestUtil.restoreJdkNamedGroupsProperty(prevJdk);
            }
        }
    }

    /**
     * A jdk.tls.namedGroups value that is non-empty but contains no
     * usable tokens (only commas/whitespace) must fail closed rather
     * than being silently treated as unset, which would fall through
     * to lower-precedence configuration or provider defaults. An
     * empty-string property value still means unset.
     */
    @Test
    public void testJdkTlsNamedGroupsWhitespaceOnlyFailsClosed()
        throws Exception {

        Assume.assumeTrue("TLS 1.3 not enabled in native wolfSSL",
            WolfSSL.TLSv13Enabled());

        synchronized (WolfSSLPQCTestUtil.GROUP_PROP_LOCK) {
            String prevWolf = WolfSSLPQCTestUtil.setCurvesProperty(null);
            String prevJdk = WolfSSLPQCTestUtil.setJdkNamedGroupsProperty(
                " , , ");
            try {
                SSLContext ctx = tf.createSSLContext("TLSv1.3", PROVIDER);
                SSLEngine server = ctx.createSSLEngine();
                server.setUseClientMode(false);
                server.setNeedClientAuth(false);
                SSLEngine client =
                    ctx.createSSLEngine("wolfSSL named groups test", 11111);
                client.setUseClientMode(true);

                int ret = tf.testConnection(server, client, null,
                    new String[] { "TLSv1.3" }, APP_DATA);
                assertEquals("Whitespace/comma-only jdk.tls.namedGroups " +
                    "must fail closed with SSLException during handshake " +
                    "setup (surfaced by testConnection as -1), not be " +
                    "treated as unset", -1, ret);
            }
            finally {
                WolfSSLPQCTestUtil.restoreCurvesProperty(prevWolf);
                WolfSSLPQCTestUtil.restoreJdkNamedGroupsProperty(prevJdk);
            }
        }
    }
}
