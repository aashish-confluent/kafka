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

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.regex.Pattern;

/**
 * Canonical form of the host of an ACL, so that every spelling of one IP address (compressed,
 * expanded, upper-case, IPv4-mapped, with leading zeros) compares equal.
 *
 * <p>The canonical form is the {@link InetAddress#getHostAddress()} form of the address without a
 * zone, which is also how the client address of a request is rendered. IPv4-mapped IPv6 addresses
 * collapse to IPv4. The zone of an IPv6 address is ignored, as {@link java.net.Inet6Address#equals}
 * does. Leading zeros in an IPv4 octet are read as decimal, and an IPv4 literal has at most 15
 * characters, as the JDK reads them. Only literals are interpreted: a hostname is never resolved.
 */
public final class HostPatterns {

    private static final int NOT_IPV4 = 0;
    private static final int CANONICAL_IPV4 = 1;
    private static final int IPV4_WITH_LEADING_ZEROS = 2;

    private static final String IPV4_MAPPED_PREFIX = "0:0:0:0:0:ffff:";
    private static final Pattern SCOPE_ID = Pattern.compile("[0-9A-Za-z_.-]+");

    private HostPatterns() {}

    /**
     * Canonicalizes an ACL host. The wildcard, CIDR ranges, hostnames and anything that is not a
     * well-formed IP literal are returned unchanged.
     */
    public static String canonicalize(String aclHost) {
        if (aclHost == null || aclHost.length() < 2 || aclHost.contains("/")) {
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
        String canonical = render(address);
        return canonical.equals(aclHost) ? aclHost : canonical;
    }

    /**
     * Canonicalizes the client address of a request.
     */
    public static String canonicalize(InetAddress address) {
        String hostAddress = address.getHostAddress();
        if (address instanceof Inet4Address) {
            return hostAddress;
        }
        int scope = hostAddress.indexOf('%');
        String withoutScope = scope < 0 ? hostAddress : hostAddress.substring(0, scope);
        return withoutScope.startsWith(IPV4_MAPPED_PREFIX) ? render(address.getAddress()) : withoutScope;
    }

    private static byte[] parseIpv6Literal(String host) {
        int scope = host.indexOf('%');
        if (scope >= 0 && !SCOPE_ID.matcher(host.substring(scope + 1)).matches()) {
            return null;
        }
        String address = scope < 0 ? host : host.substring(0, scope);
        if (address.indexOf(':') < 0 || !hasOnlyIpv6Chars(address)) {
            return null;
        }
        try {
            return InetAddress.getByName("[" + address + "]").getAddress();
        } catch (UnknownHostException e) {
            return null;
        }
    }

    private static boolean hasOnlyIpv6Chars(String address) {
        for (int i = 0; i < address.length(); i++) {
            char c = address.charAt(i);
            boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!hex && c != ':' && c != '.') {
                return false;
            }
        }
        return true;
    }

    private static int scanIpv4(String host, byte[] out) {
        int length = host.length();
        if (length < 7 || length > 15) {
            return NOT_IPV4;
        }
        boolean canonical = true;
        int octets = 0;
        int value = 0;
        int digits = 0;
        for (int i = 0; i <= length; i++) {
            char c = i < length ? host.charAt(i) : '.';
            if (c >= '0' && c <= '9') {
                canonical &= digits == 0 || value != 0;
                digits++;
                value = value * 10 + (c - '0');
                if (value > 255) {
                    return NOT_IPV4;
                }
            } else if (c == '.' && digits > 0 && octets < 4) {
                out[octets++] = (byte) value;
                value = 0;
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
