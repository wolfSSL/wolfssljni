/* ProviderTest.java
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
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

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLContext;

/**
 * This class tests the wolfSSL provider installation.  It lists all providers
 * installed on the system, tries to look up the wolfSSL provider, and if
 * found, prints out the information about the wolfSSL provider.
 * Finally, it tests what provider is registered to provide TLS to Java.
 *
 * This app can be useful for testing if wolfJSSE has been installed
 * correctly at the system level.
 */
public class ProviderTest {

    public static void main(String args [])
    {
        /* Get all providers */
        Provider [] providers = Security.getProviders();

        System.out.println("\nAll Installed Java Security Providers:");
        System.out.println("---------------------------------------\n");
        for(Provider prov:providers)
        {
            System.out.println(prov);
        }

        /* Test if wolfSSL is a Provider */
        System.out.println("\nInfo about wolfSSL Provider (wolfJSSE):");
        System.out.println("----------------------------------------\n");
        Provider p = Security.getProvider("wolfJSSE");
        if (p == null) {
            System.out.println("No wolfJSSE provider registered in system");
        } else {
            System.out.println("Provider:");
            System.out.println(p);
            System.out.println("Info:");
            System.out.println(p.getInfo());
            System.out.println("Services:");
            System.out.println(p.getServices());
            System.out.println("Version:");
            System.out.println(p.getVersion());
        }

        /* Test which Provider provides TLS versions */
        System.out.println("\nWhat Provider is providing TLS?");
        System.out.println("--------------------------------\n");
        try {
            /* TLS default */
            SSLContext s = SSLContext.getInstance("TLS");
            Provider prov = s.getProvider();
            System.out.println("SSLContext TLS Provider = " + prov);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ProviderTest.class.getName()).log(Level.SEVERE,
                             null, ex);
        }

        try {
            /* TLS 1.0 - NOTE: compiled out by default in native wolfSSL */
            SSLContext s = SSLContext.getInstance("TLSv1");
            Provider prov = s.getProvider();
            System.out.println("SSLContext TLSv1 Provider = " + prov);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ProviderTest.class.getName()).log(Level.SEVERE,
                             null, ex);
        }

        try {
            /* TLS 1.1 */
            SSLContext s = SSLContext.getInstance("TLSv1.1");
            Provider prov = s.getProvider();
            System.out.println("SSLContext TLSv1.1 Provider = " + prov);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ProviderTest.class.getName()).log(Level.SEVERE,
                             null, ex);
        }

        try {
            /* TLS 1.2 */
            SSLContext s = SSLContext.getInstance("TLSv1.2");
            Provider prov = s.getProvider();
            System.out.println("SSLContext TLSv1.2 Provider = " + prov);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ProviderTest.class.getName()).log(Level.SEVERE,
                             null, ex);
        }

        try {
            /* TLS 1.3 */
            SSLContext s = SSLContext.getInstance("TLSv1.3");
            Provider prov = s.getProvider();
            System.out.println("SSLContext TLSv1.3 Provider = " + prov);

        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ProviderTest.class.getName()).log(Level.SEVERE,
                             null, ex);
        }
    }
}

