/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2026 3A Systems, LLC.
 */
package org.identityconnectors.framework.impl.api.remote;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;

/**
 * Matches a host name or IP address against the names in an X.509 server
 * certificate the way RFC 6125 / RFC 2818 (and JSSE's "HTTPS" endpoint
 * identification) do: IP addresses against subjectAltName iPAddress entries,
 * host names against subjectAltName dNSName entries, falling back to the
 * subject CN only when the certificate carries no dNSName at all.
 * <p>
 * This is a diagnostic aid for deployments that switched hostname
 * verification off; the enforcing check is done by JSSE during the handshake.
 */
final class CertificateHostnameMatcher {

    private static final int SAN_DNS_NAME = 2;
    private static final int SAN_IP_ADDRESS = 7;
    private static final Pattern IPV4_LITERAL = Pattern.compile("(\\d{1,3}\\.){3}\\d{1,3}");

    private CertificateHostnameMatcher() {
    }

    /**
     * Returns whether {@code host} (a DNS name or an IP literal) is one of the
     * names the certificate was issued for.
     */
    static boolean matches(String host, X509Certificate certificate) {
        if (isIpLiteral(host)) {
            for (String address : subjectAltNames(certificate, SAN_IP_ADDRESS)) {
                if (sameAddress(host, address)) {
                    return true;
                }
            }
            return false;
        }
        List<String> dnsNames = subjectAltNames(certificate, SAN_DNS_NAME);
        if (dnsNames.isEmpty()) {
            String commonName = commonName(certificate);
            return commonName != null && matchesDnsName(host, commonName);
        }
        for (String dnsName : dnsNames) {
            if (matchesDnsName(host, dnsName)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Describes the subject and subjectAltName entries of the certificate for
     * log messages, e.g.
     * {@code subject 'CN=localhost', subjectAltName [dns:localhost, ip:127.0.0.1]}.
     */
    static String describe(X509Certificate certificate) {
        StringBuilder description = new StringBuilder("subject '")
                .append(certificate.getSubjectX500Principal().getName(X500Principal.RFC2253))
                .append('\'');
        List<String> names = new ArrayList<String>();
        for (String dnsName : subjectAltNames(certificate, SAN_DNS_NAME)) {
            names.add("dns:" + dnsName);
        }
        for (String address : subjectAltNames(certificate, SAN_IP_ADDRESS)) {
            names.add("ip:" + address);
        }
        if (names.isEmpty()) {
            description.append(", no subjectAltName");
        } else {
            description.append(", subjectAltName ").append(names);
        }
        return description.toString();
    }

    private static boolean isIpLiteral(String host) {
        return host.indexOf(':') >= 0 || IPV4_LITERAL.matcher(host).matches();
    }

    private static boolean sameAddress(String host, String address) {
        String literal = host;
        if (literal.startsWith("[") && literal.endsWith("]")) {
            literal = literal.substring(1, literal.length() - 1);
        }
        try {
            // both operands are literals, so no name resolution happens here
            return InetAddress.getByName(literal).equals(InetAddress.getByName(address));
        } catch (UnknownHostException e) {
            return false;
        }
    }

    /**
     * Case-insensitive comparison; a {@code *} in the leftmost label of the
     * certificate name stands for exactly one label of the host.
     */
    private static boolean matchesDnsName(String host, String name) {
        String lowerHost = host.toLowerCase(Locale.ENGLISH);
        String lowerName = name.toLowerCase(Locale.ENGLISH);
        if (!lowerName.startsWith("*.")) {
            return lowerHost.equals(lowerName);
        }
        String suffix = lowerName.substring(1);
        if (suffix.indexOf('.', 1) < 0) {
            // "*.com": a wildcard must not cover a whole top-level domain
            return false;
        }
        int firstDot = lowerHost.indexOf('.');
        return firstDot > 0 && lowerHost.substring(firstDot).equals(suffix);
    }

    private static List<String> subjectAltNames(X509Certificate certificate, int type) {
        List<String> names = new ArrayList<String>();
        Collection<List<?>> entries;
        try {
            entries = certificate.getSubjectAlternativeNames();
        } catch (CertificateParsingException e) {
            return names;
        }
        if (entries == null) {
            return names;
        }
        for (List<?> entry : entries) {
            if (entry.size() >= 2 && Integer.valueOf(type).equals(entry.get(0))
                    && entry.get(1) instanceof String) {
                names.add((String) entry.get(1));
            }
        }
        return names;
    }

    /** The most specific CN of the subject, or {@code null}. */
    private static String commonName(X509Certificate certificate) {
        String subject = certificate.getSubjectX500Principal().getName(X500Principal.RFC2253);
        try {
            List<Rdn> rdns = new LdapName(subject).getRdns();
            // RFC 2253 lists the most specific RDN first, LdapName stores it last
            for (int i = rdns.size() - 1; i >= 0; i--) {
                Rdn rdn = rdns.get(i);
                if ("CN".equalsIgnoreCase(rdn.getType()) && rdn.getValue() instanceof String) {
                    return (String) rdn.getValue();
                }
            }
        } catch (InvalidNameException e) {
            // fall through: no usable CN
        }
        return null;
    }
}
