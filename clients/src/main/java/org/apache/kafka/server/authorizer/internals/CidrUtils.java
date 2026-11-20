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

import org.apache.commons.net.util.SubnetUtils;
import org.apache.commons.net.util.SubnetUtils6;

import java.net.InetAddress;
import java.net.UnknownHostException;

public final class CidrUtils {

    private CidrUtils() {}

    private static boolean isIpv6(String cidrPattern) {
        return cidrPattern.contains(":");
    }

    /**
     * Validates a CIDR pattern by parsing it and constructing the appropriate SubnetUtils.
     * Throws {@link IllegalArgumentException} if the pattern is invalid.
     */
    public static void validate(String cidrPattern) {
        if (isIpv6(cidrPattern)) {
            new SubnetUtils6(cidrPattern);
        } else {
            new SubnetUtils(cidrPattern);
        }
    }

    /**
     * Checks whether a host IP address falls within a CIDR range.
     * Returns false if the pattern is null, not a CIDR notation, or invalid.
     */
    public static boolean isInRange(String host, String cidrPattern) {
        if (cidrPattern == null || !cidrPattern.contains("/")) {
            return false;
        }
        try {
            if (isIpv6(cidrPattern)) {
                return new SubnetUtils6(cidrPattern).getInfo().isInRange(host);
            } else {
                SubnetUtils subnet = new SubnetUtils(cidrPattern);
                subnet.setInclusiveHostCount(true);
                return subnet.getInfo().isInRange(host);
            }
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Checks whether an ACL host matches a host IP address. The ACL host matches if it is the
     * wildcard, the same string, a CIDR range that contains the address, or an IPv6 address
     * literal without a scope id that denotes the same address.
     */
    public static boolean matchesHost(String aclHost, String host) {
        return "*".equals(aclHost) || aclHost.equals(host) || isInRange(host, aclHost)
            || host.equals(canonicalIpv6Address(aclHost));
    }

    /**
     * Returns an IPv6 address literal in the form returned by {@link InetAddress#getHostAddress()},
     * or the host unchanged if it is not an IPv6 address literal or has a scope id.
     */
    private static String canonicalIpv6Address(String host) {
        if (!isIpv6(host) || host.contains("/") || host.contains("%")) {
            return host;
        }
        try {
            return InetAddress.getByName("[" + host + "]").getHostAddress();
        } catch (UnknownHostException e) {
            return host;
        }
    }
}
