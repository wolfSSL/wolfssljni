/* WolfSSLProviderTest.java
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

import static org.junit.Assert.*;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.io.ObjectStreamConstants;
import java.io.Serializable;
import java.io.StringReader;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.net.ssl.SSLContext;

import com.wolfssl.provider.jsse.WolfSSLProvider;
import com.wolfssl.test.TimedTestWatcher;

/**
 * Tests that wolfJSSE provider services are read-only after construction.
 */
public class WolfSSLProviderTest {

    /* Algorithm name that wolfJSSE never registers */
    private static final String FAKE_ALG = "WOLFJSSE-TEST-NOT-REGISTERED";
    private static final String FAKE_KEY = "SSLContext." + FAKE_ALG;
    private static final String FAKE_CLASS = "java.lang.Object";

    /* Public and protected methods of Provider and its superclasses that do
     * not change services. Every other one must be overridden by
     * WolfSSLProvider (see testAllMutatorsOverridden()). The last four are
     * Android-only (hidden): they track registration in Security and fill
     * lookup caches. */
    private static final Set<String> READ_ONLY_METHODS =
        new HashSet<String>(Arrays.asList(
            "clone", "configure", "contains", "containsKey", "containsValue",
            "elements", "entrySet", "equals", "finalize", "forEach", "get",
            "getClass", "getInfo", "getName", "getOrDefault", "getProperty",
            "getService", "getServices", "getVersion", "getVersionStr",
            "hashCode", "isConfigured", "isEmpty", "keySet", "keys", "list",
            "notify", "notifyAll", "propertyNames", "rehash", "save", "size",
            "store", "storeToXML", "stringPropertyNames", "toString",
            "values", "wait",
            "setRegistered", "setUnregistered", "isRegistered",
            "warmUpServiceProvision"));

    @Rule
    public TestRule testWatcher = TimedTestWatcher.create();

    private interface Mutation {
        void run() throws Exception;
    }

    @BeforeClass
    public static void testProviderInstallationAtRuntime() {

        System.out.println("WolfSSLProvider Class");

        /* install wolfJSSE provider at runtime, highest priority */
        Security.insertProviderAt(new WolfSSLProvider(), 1);

        Provider p = Security.getProvider("wolfJSSE");
        assertNotNull(p);
    }

    private static WolfSSLProvider getWolfJSSE() {
        return (WolfSSLProvider)Security.getProvider("wolfJSSE");
    }

    /* New, unregistered provider. Tests that try to change services use it,
     * so a lock regression cannot damage the registered wolfJSSE provider
     * that other tests use. */
    private static WolfSSLProvider newProvider() {
        return new WolfSSLProvider();
    }

    /* Return the key of a registered service entry, ex: "SSLContext.TLS" */
    private static String registeredServiceKey(Provider p) {

        for (Provider.Service s : p.getServices()) {
            String key = s.getType() + "." + s.getAlgorithm();
            if (p.get(key) != null) {
                return key;
            }
        }

        fail("wolfJSSE has no registered services");
        return null;
    }

    private static void assertRejected(String what, Mutation m) {
        try {
            m.run();
            fail(what + " should throw SecurityException");
        } catch (SecurityException e) {
            /* expected */
        } catch (Exception e) {
            fail(what + " threw " + e + " instead of SecurityException");
        }
    }

    /* Collection views are read-only in Provider itself, which throws
     * UnsupportedOperationException */
    private static void assertViewRejected(String what, Mutation m) {
        try {
            m.run();
            fail(what + " should not be supported");
        } catch (UnsupportedOperationException | SecurityException e) {
            /* expected */
        } catch (Exception e) {
            fail(what + " threw " + e + " instead of " +
                "UnsupportedOperationException");
        }
    }

    /* Call a protected WolfSSLProvider method, rethrowing what it threw */
    private static void invoke(Method m, Object obj, Object arg)
        throws Exception {
        try {
            m.invoke(obj, arg);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception) {
                throw (Exception)cause;
            }
            throw e;
        }
    }

    /* Serialize the provider with every occurrence of value replaced by
     * FAKE_CLASS, as in a tampered stream, then deserialize it */
    private static Provider tamperedCopy(Provider p, final Object value)
        throws Exception {

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos) {
                {
                    enableReplaceObject(true);
                }
                @Override
                protected Object replaceObject(Object obj) {
                    return value.equals(obj) ? FAKE_CLASS : obj;
                }
            }) {
            oos.writeObject(p);
        }

        try (ObjectInputStream ois = new ObjectInputStream(
                new ByteArrayInputStream(bos.toByteArray()))) {
            return (Provider)ois.readObject();
        }
    }

    @Test
    public void testServicesCannotBeAdded() throws Exception {

        final WolfSSLProvider p = newProvider();
        final int servicesBefore = p.getServices().size();
        final Map<Object, Object> m = new HashMap<Object, Object>();
        m.put(FAKE_KEY, FAKE_CLASS);
        final String props = FAKE_KEY + "=" + FAKE_CLASS + "\n";
        final String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<!DOCTYPE properties SYSTEM " +
            "\"http://java.sun.com/dtd/properties.dtd\">\n" +
            "<properties><entry key=\"" + FAKE_KEY + "\">" + FAKE_CLASS +
            "</entry></properties>\n";

        assertRejected("put", () -> p.put(FAKE_KEY, FAKE_CLASS));
        assertRejected("putAll", () -> p.putAll(m));
        assertRejected("putIfAbsent",
            () -> p.putIfAbsent(FAKE_KEY, FAKE_CLASS));
        assertRejected("setProperty",
            () -> p.setProperty(FAKE_KEY, FAKE_CLASS));
        assertRejected("compute",
            () -> p.compute(FAKE_KEY, (k, v) -> FAKE_CLASS));
        assertRejected("computeIfAbsent",
            () -> p.computeIfAbsent(FAKE_KEY, k -> FAKE_CLASS));
        assertRejected("merge",
            () -> p.merge(FAKE_KEY, FAKE_CLASS, (a, b) -> b));
        assertRejected("load(InputStream)", () -> p.load(
            new ByteArrayInputStream(props.getBytes(StandardCharsets.UTF_8))));
        assertRejected("load(Reader)", () -> p.load(new StringReader(props)));
        assertRejected("loadFromXML", () -> p.loadFromXML(
            new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8))));

        /* A clone of a locked provider is also locked */
        final Provider c = (Provider)p.clone();
        assertRejected("put on clone", () -> c.put(FAKE_KEY, FAKE_CLASS));
        assertNull(c.getService("SSLContext", FAKE_ALG));

        assertNull(p.get(FAKE_KEY));
        assertNull(p.getService("SSLContext", FAKE_ALG));
        try {
            SSLContext.getInstance(FAKE_ALG, p);
            fail("SSLContext " + FAKE_ALG + " should not be available");
        } catch (NoSuchAlgorithmException e) {
            /* expected */
        }
        assertEquals(servicesBefore, p.getServices().size());
    }

    @Test
    public void testServicesCannotBeChangedOrRemoved() throws Exception {

        final WolfSSLProvider p = newProvider();
        final int servicesBefore = p.getServices().size();
        final String key = registeredServiceKey(p);
        final Object value = p.get(key);

        assertRejected("replace", () -> p.replace(key, FAKE_CLASS));
        assertRejected("replace(key, old, new)",
            () -> p.replace(key, value, FAKE_CLASS));
        assertRejected("computeIfPresent",
            () -> p.computeIfPresent(key, (k, v) -> FAKE_CLASS));
        assertRejected("compute", () -> p.compute(key, (k, v) -> null));
        assertRejected("replaceAll", () -> p.replaceAll((k, v) -> v));
        assertRejected("remove", () -> p.remove(key));
        assertRejected("remove(key, value)", () -> p.remove(key, value));
        assertRejected("clear", () -> p.clear());

        assertViewRejected("keySet().remove", () -> p.keySet().remove(key));
        assertViewRejected("values().remove", () -> p.values().remove(value));
        assertViewRejected("entrySet() iterator remove", () -> {
            Iterator<Map.Entry<Object, Object>> it = p.entrySet().iterator();
            it.next();
            it.remove();
        });
        assertViewRejected("entrySet() Entry.setValue",
            () -> p.entrySet().iterator().next().setValue(FAKE_CLASS));

        assertEquals(value, p.get(key));
        assertEquals(servicesBefore, p.getServices().size());
    }

    @Test
    public void testPutServiceAndRemoveServiceRejected() throws Exception {

        final WolfSSLProvider p = newProvider();
        final int servicesBefore = p.getServices().size();
        final Method putService = WolfSSLProvider.class.getDeclaredMethod(
            "putService", Provider.Service.class);
        final Method removeService = WolfSSLProvider.class
            .getDeclaredMethod("removeService", Provider.Service.class);
        putService.setAccessible(true);
        removeService.setAccessible(true);

        final Provider.Service added = new Provider.Service(p,
            "SSLContext", FAKE_ALG, FAKE_CLASS, null, null);
        final Provider.Service existing = p.getServices().iterator().next();

        assertRejected("putService", () -> invoke(putService, p, added));
        assertRejected("removeService",
            () -> invoke(removeService, p, existing));

        assertNull(p.getService("SSLContext", FAKE_ALG));
        assertNotNull(p.getService(existing.getType(),
            existing.getAlgorithm()));
        assertEquals(servicesBefore, p.getServices().size());
    }

    @Test
    public void testAllMutatorsOverridden() {

        /* Fails if this JDK's Provider (or a superclass) has a public or
         * protected method that WolfSSLProvider does not override and that
         * is not known to be read-only, for example a mutator added in a new
         * Java release */
        List<String> missing = new ArrayList<String>();
        for (Class<?> c = Provider.class; c != null; c = c.getSuperclass()) {
            for (Method m : c.getDeclaredMethods()) {
                int mod = m.getModifiers();
                if (Modifier.isStatic(mod) || m.isSynthetic() ||
                    m.isBridge() || READ_ONLY_METHODS.contains(m.getName())) {
                    continue;
                }
                if (!Modifier.isPublic(mod) && !Modifier.isProtected(mod)) {
                    continue;
                }
                try {
                    WolfSSLProvider.class.getDeclaredMethod(m.getName(),
                        m.getParameterTypes());
                } catch (NoSuchMethodException e) {
                    missing.add(c.getSimpleName() + "." + m.getName() +
                        Arrays.toString(m.getParameterTypes()));
                }
            }
        }
        assertTrue("Methods that may change services are not overridden " +
            "by WolfSSLProvider: " + missing, missing.isEmpty());
    }

    @Test
    public void testDeserializedProviderIsRegisteredInstance()
        throws Exception {

        final WolfSSLProvider p = getWolfJSSE();
        final String key = registeredServiceKey(p);
        final Object value = p.get(key);

        /* readResolve() must return the registered provider and ignore
         * the serialized entries */
        final Provider copy = tamperedCopy(p, value);

        assertSame(p, copy);
        assertEquals(value, copy.get(key));
        assertRejected("put on deserialized provider",
            () -> copy.put(FAKE_KEY, FAKE_CLASS));
    }

    @Test
    public void testDeserializedProviderIsNewWhenNotRegistered()
        throws Exception {

        final WolfSSLProvider p = newProvider();
        final String key = registeredServiceKey(p);
        final Object value = p.get(key);

        /* Remove the registered wolfJSSE provider for this test, so
         * readResolve() must build a new provider */
        Provider registered = getWolfJSSE();
        int pos = Arrays.asList(Security.getProviders()).indexOf(registered)
            + 1;
        assertTrue("wolfJSSE not registered", pos > 0);
        Security.removeProvider("wolfJSSE");
        try {
            final Provider copy = tamperedCopy(p, value);

            assertTrue(copy instanceof WolfSSLProvider);
            assertNotSame(p, copy);
            assertNotSame(registered, copy);
            assertEquals(value, copy.get(key));
            assertRejected("put on deserialized provider",
                () -> copy.put(FAKE_KEY, FAKE_CLASS));
        } finally {
            Security.insertProviderAt(registered, pos);
        }
    }

    /* Serializable object that refers back to the provider being serialized,
     * saves that reference when it is deserialized, before the provider's
     * readResolve() runs */
    private static class BackReference implements Serializable {
        private static final long serialVersionUID = 1L;
        private static Provider captured;
        private final Provider ref;

        BackReference(Provider ref) {
            this.ref = ref;
        }

        private void readObject(ObjectInputStream in)
            throws IOException, ClassNotFoundException {
            in.defaultReadObject();
            captured = ref;
        }
    }

    @Test
    public void testDeserializedBackReferenceHasNoServices()
        throws Exception {

        final WolfSSLProvider p = getWolfJSSE();
        final String key = registeredServiceKey(p);
        final Object value = p.get(key);

        /* Replace one service class name with an object that refers back to
         * the provider. The deserialized object it captures must not serve
         * any entries from the stream. */
        BackReference.captured = null;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos) {
                {
                    enableReplaceObject(true);
                }
                @Override
                protected Object replaceObject(Object obj) {
                    return value.equals(obj) ? new BackReference(p) : obj;
                }
            }) {
            oos.writeObject(p);
        }
        try (ObjectInputStream ois = new ObjectInputStream(
                new ByteArrayInputStream(bos.toByteArray()))) {
            assertSame(p, ois.readObject());
        }

        final Provider captured = BackReference.captured;
        assertNotNull(captured);
        assertNotSame(p, captured);
        assertTrue(captured.getServices().isEmpty());
        assertNull(captured.get(key));
        assertRejected("put on captured provider",
            () -> captured.put(FAKE_KEY, FAKE_CLASS));
        assertRejected("putAll on captured provider", () -> captured.putAll(
            Collections.singletonMap(FAKE_KEY, FAKE_CLASS)));
    }

    /* Serializable object that calls put() on the provider being
     * deserialized, from its own readObject() */
    private static class PutOnRead implements Serializable {
        private static final long serialVersionUID = 1L;
        private static Provider captured;
        private static boolean rejected;
        private final Provider ref;

        PutOnRead(Provider ref) {
            this.ref = ref;
        }

        private void readObject(ObjectInputStream in)
            throws IOException, ClassNotFoundException {
            in.defaultReadObject();
            captured = ref;
            try {
                ref.put(FAKE_KEY, FAKE_CLASS);
            } catch (SecurityException e) {
                rejected = true;
            }
        }
    }

    @Test
    public void testDeserializationCallbackCannotAddServices()
        throws Exception {

        final WolfSSLProvider p = getWolfJSSE();

        /* Write a stream whose WolfSSLProvider class descriptor declares
         * an extra Object field holding a PutOnRead. It is read, and
         * PutOnRead.readObject() runs, during WolfSSLProvider.readObject() */
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos) {
                @Override
                protected void writeClassDescriptor(ObjectStreamClass desc)
                    throws IOException {
                    if (!desc.getName().equals(
                            WolfSSLProvider.class.getName())) {
                        super.writeClassDescriptor(desc);
                        return;
                    }
                    writeUTF(desc.getName());
                    writeLong(desc.getSerialVersionUID());
                    writeByte(ObjectStreamConstants.SC_SERIALIZABLE);
                    writeShort(1);
                    writeByte('L');
                    writeUTF("extra");
                    writeObject("Ljava/lang/Object;");
                }
            }) {
            oos.writeObject(p);
            /* Value of the extra field */
            oos.writeObject(new PutOnRead(p));
        }

        PutOnRead.captured = null;
        PutOnRead.rejected = false;
        try (ObjectInputStream ois = new ObjectInputStream(
                new ByteArrayInputStream(bos.toByteArray()))) {
            assertSame(p, ois.readObject());
        }
        assertNotNull(PutOnRead.captured);
        assertTrue("put() from a deserialization callback was not rejected",
            PutOnRead.rejected);
        assertNull(PutOnRead.captured.get(FAKE_KEY));
    }
}
