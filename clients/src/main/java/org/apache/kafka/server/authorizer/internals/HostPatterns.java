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

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.regex.Pattern;

/**
 * Canonical form of the host component of an ACL, so that every textual spelling of one IP address
 * (compressed, expanded, upper-case, IPv4-mapped, with a scope id) compares equal.
 *
 * <p>The canonical form of an address is the {@link InetAddress#getHostAddress()} rendering of its
 * binary form, which is also how the authorizers render the peer address. IPv4-mapped IPv6
 * addresses collapse to IPv4, matching what the JDK reports for such a peer.
 *
 * <p>Scope ids (the {@code %eth0} or {@code %2} suffix of an IPv6 literal) are ignored, as
 * {@link Inet6Address#equals} does, so {@code fe80::1}, {@code fe80::1%eth0} and {@code fe80::1%2} are
 * the same host.
 *
 * <p>Leading zeros in an IPv4 octet are read as decimal and dropped from the canonical form, as the JDK
 * reads them (also in the embedded IPv4 part of an IPv6 literal): {@code 010.0.0.1} is
 * {@code 10.0.0.1}. Some other tools read a leading zero as octal, where {@code 010} would be 8, but
 * ACL hosts are compared with addresses the JDK parsed, so an ACL host has to mean what the JDK takes
 * it to mean; an octet above 255 is not an address and the host is left unchanged.
 *
 * <p>Only literals are interpreted: a hostname is never resolved and is returned unchanged.
 */
public final class HostPatterns {

    private static final int NOT_IPV4 = 0;
    private static final int CANONICAL_IPV4 = 1;
    private static final int IPV4_WITH_LEADING_ZEROS = 2;

    private static final Pattern SCOPE_ID = Pattern.compile("[0-9A-Za-z_.-]+");

    private HostPatterns() {}

    /**
     * Canonicalizes an ACL host. The wildcard, the empty string, CIDR ranges, hostnames and anything
     * that is not a well-formed IP literal are returned unchanged.
     */
    public static String canonicalize(String aclHost) {
        // The wildcard is by far the most common ACL host and is built on per-request paths, so answer it first.
        if (aclHost == null || "*".equals(aclHost) || aclHost.contains("/")) {
            return aclHost;
        }
        byte[] ipv4 = new byte[4];
        int kind = scanIpv4(aclHost, ipv4);
        if (kind == CANONICAL_IPV4) {
            return aclHost;
        }
        byte[] address = kind == IPV4_WITH_LEADING_ZEROS ? ipv4 : parseIpv6Literal(aclHost);
        if (address == null) {
            return aclHost;
        }
        return render(address);
    }

    /** Whether the host is a well-formed IPv4 or IPv6 literal (a scope id suffix is tolerated). */
    public static boolean isIpLiteral(String host) {
        return host != null && parseLiteral(host) != null;
    }

    /** Canonicalizes the peer address of a request. */
    public static String canonicalize(InetAddress address) {
        return render(address.getAddress());
    }

    /**
     * Returns the binary form of an IPv4 or IPv6 literal (a well-formed scope id suffix is accepted and ignored here), or null if the
     * input is not a well-formed literal. An IPv4-mapped IPv6 literal yields 4 bytes.
     */
    static byte[] parseLiteral(String host) {
        byte[] ipv4 = new byte[4];
        if (scanIpv4(host, ipv4) != NOT_IPV4) {
            return ipv4;
        }
        return parseIpv6Literal(host);
    }

    private static byte[] parseIpv6Literal(String host) {
        int scope = host.indexOf('%');
        if (scope >= 0 && !SCOPE_ID.matcher(host.substring(scope + 1)).matches()) {
            return null;
        }
        String address = scope < 0 ? host : host.substring(0, scope);
        // Also keeps the common non-literals ("*", hostnames) off the exception path below.
        if (address.indexOf(':') < 0) {
            return null;
        }
        try {
            // Bracketed, the JDK only accepts an IPv6 literal and never falls back to the resolver, which an
            // unbracketed string it does not recognize as a literal (such as ".::1") would reach. Same on JDK 11 and 21.
            // InetAddress.ofLiteral would be stricter but needs Java 22 and the module (clients) targets Java 11.
            return InetAddress.getByName("[" + address + "]").getAddress();
        } catch (UnknownHostException e) {
            return null;
        }
    }

    // Hand-rolled on purpose; the JDK has no strict IPv4 literal parser callable from Java 11:
    // - InetAddress.getByName on an IPv4-looking string reaches the resolver ("256.1.1.1") and accepts
    //   loose forms ("1.2" is 1.0.0.2).
    // - getByName("[::ffff:" + host + "]") is strict and never resolves, but throws for every host that is
    //   not a literal ("*", hostnames), which is far more expensive than rejecting it here (about 540 ns
    //   against 20 ns in a rough JDK 21 comparison).
    // Like the JDK, it reads leading zeros as decimal (see the class Javadoc). Single pass without
    // allocation, as it runs for every authorized request: a dotted quad of four octets of at most three
    // significant digits each, each at most 255. Fills out and says whether the input was already canonical.
    private static int scanIpv4(String host, byte[] out) {
        int length = host.length();
        if (length < 7) {
            return NOT_IPV4;
        }
        boolean canonical = true;
        int octets = 0;
        int value = 0;
        int significantDigits = 0;
        int digits = 0;
        // The end of the input is handled as one more separator.
        for (int i = 0; i <= length; i++) {
            char c = i < length ? host.charAt(i) : '.';
            if (c >= '0' && c <= '9') {
                digits++;
                if (significantDigits > 0 || c != '0') {
                    significantDigits++;
                    value = value * 10 + (c - '0');
                    if (significantDigits > 3 || value > 255) {
                        return NOT_IPV4;
                    }
                }
            } else if (c == '.' && digits > 0 && octets < 4) {
                canonical &= digits == Math.max(significantDigits, 1);
                out[octets++] = (byte) value;
                value = 0;
                significantDigits = 0;
                digits = 0;
            } else {
                return NOT_IPV4;
            }
        }
        if (octets != 4) {
            return NOT_IPV4;
        }
        return canonical ? CANONICAL_IPV4 : IPV4_WITH_LEADING_ZEROS;
    }

    private static String render(byte[] address) {
        try {
            return InetAddress.getByAddress(address).getHostAddress();
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Invalid address length " + address.length, e);
        }
    }
}
