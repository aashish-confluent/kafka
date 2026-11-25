/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.kafka.server.authorizer.internals;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Timeout(value = 40)
public class HostPatternsTest {

    private static final String EXPANDED = "2001:db8:0:0:0:0:0:1";

    @Test
    public void testIpv6SpellingsShareOneCanonicalForm() {
        for (String spelling : new String[] {
            "2001:db8::1", "2001:DB8::1", EXPANDED, "2001:0db8:0000:0000:0000:0000:0000:0001",
            "2001:db8:0::1", "2001:db8::0:1", "2001:db8::1%eth0", "2001:db8::1%3"}) {
            assertEquals(EXPANDED, HostPatterns.canonicalize(spelling), spelling);
        }
    }

    @Test
    public void testZoneIsIgnored() {
        for (String spelling : new String[] {"fe80::1", "FE80::1%eth0", "fe80::1%eth1", "fe80:0:0:0:0:0:0:1%2"}) {
            assertEquals("fe80:0:0:0:0:0:0:1", HostPatterns.canonicalize(spelling), spelling);
        }
    }

    @Test
    public void testClientAddressZoneIsIgnored() throws UnknownHostException {
        byte[] bytes = InetAddress.getByName("fe80::1").getAddress();
        assertEquals("fe80:0:0:0:0:0:0:1", HostPatterns.canonicalize(Inet6Address.getByAddress(null, bytes, 2)));
        assertEquals("fe80:0:0:0:0:0:0:1", HostPatterns.canonicalize(InetAddress.getByAddress(bytes)));
    }

    @Test
    public void testMalformedScopeIsNotALiteral() {
        for (String host : new String[] {"fe80::1%", "fe80::1%eth 0", "fe80::1%%2", "2001:db8::1%", "10.0.0.1%eth0"}) {
            assertSame(host, HostPatterns.canonicalize(host), host);
        }
    }

    @Test
    public void testLeadingZerosInIpv4AreDecimal() {
        assertEquals("10.0.0.1", HostPatterns.canonicalize("010.0.0.1"));
        assertEquals("1.2.3.4", HostPatterns.canonicalize("01.002.0003.04"));
        assertEquals("255.0.0.1", HostPatterns.canonicalize("0255.0.0.1"));
        assertEquals("0.0.0.1", HostPatterns.canonicalize("000.000.000.001"));
        assertEquals("10.0.0.1", HostPatterns.canonicalize("::ffff:010.0.0.1"));
        assertEquals("0:0:0:0:0:0:a00:1", HostPatterns.canonicalize("::010.0.0.1"));
        assertEquals(HostPatterns.canonicalize("10.0.0.1"), HostPatterns.canonicalize("010.00.000.0001"));
    }

    @Test
    public void testIpv4MappedIpv6CollapsesToIpv4() {
        for (String spelling : new String[] {
            "::ffff:10.0.0.1", "::FFFF:10.0.0.1", "::ffff:a00:1", "0:0:0:0:0:ffff:a00:1", "10.0.0.1"}) {
            assertEquals("10.0.0.1", HostPatterns.canonicalize(spelling), spelling);
        }
    }

    @Test
    public void testPeerAddressMatchesAclSpelling() throws UnknownHostException {
        byte[] bytes = InetAddress.getByName("2001:db8::1").getAddress();
        InetAddress scoped = Inet6Address.getByAddress(null, bytes, 2);
        assertTrue(scoped.getHostAddress().contains("%"));
        assertEquals(HostPatterns.canonicalize("2001:db8::1"), HostPatterns.canonicalize(scoped));
        assertEquals("10.0.0.1", HostPatterns.canonicalize(InetAddress.getByName("::ffff:10.0.0.1")));
    }

    @Test
    public void testNonLiteralsAreReturnedUnchanged() {
        for (String host : new String[] {
            "*", "", "example.com", "localhost", "10.0.0.0/8", "2001:db8::/32", "[2001:db8::1]",
            "2001:db8::1::", "2001:db8:::1", "::g", "1:2", "12345::1", "1.2.3", "1.2.3.4.5", "256.1.1.1",
            "256.1.1.1", "0256.0.0.1", "1.2.3.99999999999", "::ffff:0256.0.0.1", "::01.2.3.256", ".::1", ".1:2", "-:1", "_:1", "a.b:1", "1.2.3.4 ", " 2001:db8::1", "::1%", "2001:db8::1\n"}) {
            assertSame(host, HostPatterns.canonicalize(host), host);
        }
    }

    @Test
    public void testIsIpLiteral() {
        for (String host : new String[] {"10.0.0.1", "2001:db8::1", "2001:DB8::1%eth0", "::ffff:10.0.0.1", "::"}) {
            assertTrue(HostPatterns.isIpLiteral(host), host);
        }
        for (String host : new String[] {"*", "", "example.com", "10.0.0.0/8", "2001:db8::1::", "1.2.3", "::1%", null}) {
            assertFalse(HostPatterns.isIpLiteral(host), String.valueOf(host));
        }
    }

    @Test
    public void testNullIsReturnedUnchanged() {
        assertNull(HostPatterns.canonicalize((String) null));
    }

    @Test
    public void testHostnameIsNeverResolved() {
        // "localhost" would resolve to a loopback literal if the resolver were consulted.
        assertEquals("localhost", HostPatterns.canonicalize("localhost"));
        assertNull(HostPatterns.parseLiteral("localhost"));
        assertNull(HostPatterns.parseLiteral("a:b.example.com"));
        // Start with a non-hex character, so an unbracketed getByName would hand them to the resolver.
        assertNull(HostPatterns.parseLiteral(".::1"));
        assertNull(HostPatterns.parseLiteral("-:1"));
    }

    @Test
    public void testCanonicalizeIsIdempotent() {
        for (String host : new String[] {"2001:DB8::1%2", "::ffff:1.2.3.4", "1.2.3.4", "*", "example.com"}) {
            String once = HostPatterns.canonicalize(host);
            assertEquals(once, HostPatterns.canonicalize(once), host);
        }
    }
}
