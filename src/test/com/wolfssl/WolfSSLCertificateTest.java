/* WolfSSLCertificate.java
 *
 * Copyright (C) 2006-2018 wolfSSL Inc.
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

package com.wolfssl;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import static org.junit.Assert.fail;
import org.junit.Test;

/**
 *
 * @author sweetness
 */
public class WolfSSLCertificateTest {
    public final static int TEST_FAIL    = -1;
    public final static int TEST_SUCCESS =  0;

    public final static String cliCert = "./examples/certs/client-cert.der";
    public final static String bogusFile = "/dev/null";
    private WolfSSLCertificate cert;
    
    @Test
    public void testWolfSSLCertificate() throws WolfSSLException {

        System.out.println("WolfSSLCertificate Class");

        test_WolfSSLCertificate_new();
        test_getSerial();
        test_notBefore();
        test_notAfter();
        test_getVersion();
        test_getSignature();
        test_toString();
    }
    
    
    public void test_WolfSSLCertificate_new() {
        File f = new File(cliCert);
        byte[] der = null;
        
        System.out.print("\tWolfSSLCertificate_new");
        try {
            der = Files.readAllBytes(f.toPath());
        } catch (IOException ex) {
            System.out.println("\t\t... failed");
            fail("Unable to read file " + cliCert);
            Logger.getLogger(WolfSSLCertificateTest.class.getName()).log(Level.SEVERE, null, ex);
        }
        

        try {
            this.cert = new WolfSSLCertificate(der);
        } catch (WolfSSLException ex) {
            System.out.println("\t\t... failed");
            fail("Unable to initialize class");
            Logger.getLogger(WolfSSLCertificateTest.class.getName()).log(Level.SEVERE, null, ex);
        }
        System.out.println("\t\t... passed");
    }
    
    public void test_getSerial() {
        byte[] expected = new byte[]{(byte)0xaa, (byte)0xc4, (byte)0xbf,
            (byte)0x4c, (byte)0x50, (byte)0xbd, (byte)0x55, (byte)0x77};
        byte[] serial;
        int i;
        BigInteger bigi = cert.getSerial();
        
        System.out.print("\tgetSerial");
        serial = bigi.toByteArray();
        for (i = 0; i < serial.length && i < expected.length; i++) {
            if (serial[i] != expected[i]) {
                System.out.println("\t\t\t... failed");
                fail("Unexpected serial number");
            }
        }
        System.out.println("\t\t\t... passed");
    }
    
    public void test_notBefore() {
        Date date = cert.notBefore();
        Date expected = new Date("Fri Apr 13 09:23:09 MDT 2018");
        System.out.print("\tnotBefore");        
        if (date.compareTo(expected) != 0) {
            System.out.println("\t\t\t... failed");
            fail("Unexpected not before date");
        }
        System.out.println("\t\t\t... passed");
    }
    
        
    public void test_notAfter() {
        Date date = cert.notAfter();
        Date expected = new Date("Thu Jan 07 08:23:09 MST 2021");
        System.out.print("\tnotAfter");
        if (date.compareTo(expected) != 0) {
            System.out.println("\t\t\t... failed");
            fail("Unexpected not after date");
        }
        System.out.println("\t\t\t... passed");
    }
    
    public void test_getVersion() {
        int version = cert.getVersion();
      
        System.out.print("\tgetVersion");
        if (version != 3) {
            System.out.println("\t\t\t... failed");
            fail("Unexpected version number");
        }
        System.out.println("\t\t\t... passed");
    }
    
    public void test_getSignature() {
        byte[] sig = cert.getSignature();
        byte[] expected = new byte[] {
            (byte)0x80, (byte)0x52, (byte)0x54, (byte)0x61, (byte)0x2A,
            (byte)0x77, (byte)0x80, (byte)0x53, (byte)0x44, (byte)0xA9,
            (byte)0x80, (byte)0x6D, (byte)0x45, (byte)0xFF, (byte)0x0D,
            (byte)0x25, (byte)0x7D, (byte)0x1A, (byte)0x8F, (byte)0x23,
            (byte)0x93, (byte)0x53, (byte)0x74, (byte)0x35, (byte)0x12,
            (byte)0x6F, (byte)0xF0, (byte)0x2E, (byte)0x20, (byte)0xEA,
            (byte)0xED, (byte)0x80, (byte)0x63, (byte)0x69, (byte)0x88,
            (byte)0xE6, (byte)0x0C, (byte)0xA1, (byte)0x49, (byte)0x30,
            (byte)0xE0, (byte)0x82, (byte)0xDB, (byte)0x68, (byte)0x0F,
            (byte)0x7E, (byte)0x84, (byte)0xAC, (byte)0xFF, (byte)0xFF,
            (byte)0x7B, (byte)0x42, (byte)0xFA, (byte)0x7E, (byte)0x2F,
            (byte)0xB2, (byte)0x52, (byte)0x9F, (byte)0xD2, (byte)0x79,
            (byte)0x5E, (byte)0x35, (byte)0x12, (byte)0x27, (byte)0x36,
            (byte)0xBC, (byte)0xDF, (byte)0x96, (byte)0x58, (byte)0x44,
            (byte)0x96, (byte)0x55, (byte)0xC8, (byte)0x4A, (byte)0x94,
            (byte)0x02, (byte)0x5F, (byte)0x4A, (byte)0x9D, (byte)0xDC,
            (byte)0xD3, (byte)0x3A, (byte)0xF7, (byte)0x6D, (byte)0xAC,
            (byte)0x8B, (byte)0x79, (byte)0x6E, (byte)0xFC, (byte)0xBE,
            (byte)0x8F, (byte)0x23, (byte)0x58, (byte)0x6A, (byte)0x8A,
            (byte)0xF5, (byte)0x38, (byte)0x0A, (byte)0x42, (byte)0xF6,
            (byte)0x98, (byte)0x74, (byte)0x88, (byte)0x53, (byte)0x2E,
            (byte)0x02, (byte)0xAF, (byte)0xE1, (byte)0x0E, (byte)0xBE,
            (byte)0x6F, (byte)0xCC, (byte)0x74, (byte)0x33, (byte)0x7C,
            (byte)0xEC, (byte)0xB4, (byte)0xCB, (byte)0xA7, (byte)0x49,
            (byte)0x6D, (byte)0x82, (byte)0x42, (byte)0x4F, (byte)0xEB,
            (byte)0x73, (byte)0x29, (byte)0xC3, (byte)0x32, (byte)0x00,
            (byte)0x2B, (byte)0x15, (byte)0xF8, (byte)0x88, (byte)0x7A,
            (byte)0x8F, (byte)0x6D, (byte)0x20, (byte)0x1B, (byte)0xAE,
            (byte)0x65, (byte)0x5F, (byte)0xC5, (byte)0xD0, (byte)0x8A,
            (byte)0xD1, (byte)0xE2, (byte)0x64, (byte)0x6D, (byte)0xA3,
            (byte)0xA8, (byte)0xFE, (byte)0x64, (byte)0xE1, (byte)0xA9,
            (byte)0x5B, (byte)0xE6, (byte)0xD0, (byte)0x23, (byte)0xD6,
            (byte)0x02, (byte)0x72, (byte)0x5A, (byte)0xEC, (byte)0x03,
            (byte)0x8E, (byte)0x87, (byte)0x67, (byte)0x19, (byte)0x8D,
            (byte)0xE4, (byte)0xA8, (byte)0x99, (byte)0x15, (byte)0xC1,
            (byte)0x3D, (byte)0x91, (byte)0x48, (byte)0x99, (byte)0x8D,
            (byte)0xFE, (byte)0xAE, (byte)0x1C, (byte)0xBF, (byte)0xF6,
            (byte)0x28, (byte)0x1B, (byte)0x45, (byte)0xBE, (byte)0xAD,
            (byte)0xEF, (byte)0x72, (byte)0x83, (byte)0x9A, (byte)0xF6,
            (byte)0xC7, (byte)0x3B, (byte)0x51, (byte)0xA3, (byte)0x6E,
            (byte)0x7A, (byte)0x73, (byte)0xBD, (byte)0x83, (byte)0xAA,
            (byte)0x97, (byte)0xFD, (byte)0x63, (byte)0xB4, (byte)0xF4,
            (byte)0x6B, (byte)0x1C, (byte)0x14, (byte)0x81, (byte)0x9A,
            (byte)0xEF, (byte)0x14, (byte)0x24, (byte)0xD3, (byte)0xE1,
            (byte)0x8B, (byte)0xF4, (byte)0x04, (byte)0x04, (byte)0x84,
            (byte)0x54, (byte)0x0F, (byte)0x61, (byte)0xA2, (byte)0xA8,
            (byte)0xF2, (byte)0x50, (byte)0x37, (byte)0x0C, (byte)0x17,
            (byte)0x0C, (byte)0xBC, (byte)0xE0, (byte)0xC2, (byte)0x84,
            (byte)0x85, (byte)0xF4, (byte)0x0B, (byte)0xAE, (byte)0x00,
            (byte)0xCA, (byte)0x9F, (byte)0x27, (byte)0xE2, (byte)0x44,
            (byte)0x4F, (byte)0x15, (byte)0x0B, (byte)0x8B, (byte)0x1D,
            (byte)0xB4
        };
        System.out.print("\tgetSignature");
        int i;
        for (i = 0; i < sig.length && i < expected.length; i++) {
            if (sig[i] != expected[i]) {
                System.out.println("\t\t\t... failed");
                fail("Unexpected signature");             
            }
        }
        System.out.println("\t\t\t... passed");
    }
    
    public void test_toString() {
        System.out.print("\ttoString");
        System.out.println("\t\t\t... passed");
        System.out.println("" + cert.toString());
    }
}
