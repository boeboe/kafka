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
package org.apache.kafka.common.security.authenticator;

import org.apache.kafka.common.security.auth.AuthenticationContext;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.common.security.auth.KafkaPrincipalBuilder;
import org.apache.kafka.common.security.auth.SslAuthenticationContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

/**
 * Spiffe specific implementation of {@link KafkaPrincipalBuilder} which provides basic support for
 * SSL authentication based on <a href="https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/#spiffe-id">
 * SPIFFE ID's</a>, which is a X509 Subject Alternate Name (SAN) URI value in the client certificate.
 *
 * If no X509 SPIFFE based SAN URI is found, fall back to X500 Subject principle. If multiple X509 SPIFFE based
 * SAN URIs are found, the first one is returned as principle.
 */
public class SpiffePrincipalBuilder implements KafkaPrincipalBuilder {
    private static final Logger LOG = LoggerFactory.getLogger(SpiffePrincipalBuilder.class);
    private static final String SPIFFE_TYPE = "SPIFFE";

    public KafkaPrincipal build(AuthenticationContext context) {
        if (!(context instanceof SslAuthenticationContext)) {
            LOG.trace("Non-SSL connection coerced to ANONYMOUS");
            return KafkaPrincipal.ANONYMOUS;
        }

        SSLSession sslSession = ((SslAuthenticationContext) context).session();
        X509Certificate cert = firstX509(sslSession);
        if (cert == null) {
            LOG.trace("First peer certificate missing / not x509");
            return KafkaPrincipal.ANONYMOUS;
        }

        String spiffeId = spiffeId(cert);
        if (spiffeId == null) {
            return new KafkaPrincipal(KafkaPrincipal.USER_TYPE, cert.getSubjectX500Principal().getName());
        }

        return new KafkaPrincipal(SPIFFE_TYPE, spiffeId);
    }

    private X509Certificate firstX509(SSLSession session) {
        try {
            Certificate[] peerCerts = session.getPeerCertificates();
            if (peerCerts.length == 0) {
                return null;
            }
            Certificate first = peerCerts[0];
            if (!(first instanceof X509Certificate)) {
                return null;
            }
            return (X509Certificate) first;
        } catch (SSLPeerUnverifiedException e) {
            LOG.warn("Failed to extract certificate", e);
            return null;
        }
    }

    private String spiffeId(X509Certificate cert) {
        try {
            Collection<List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans == null) {
                return null;
            }

            return sans.stream()
                    .map(san -> (String) san.get(1))
                    .filter(uri -> uri.startsWith("spiffe://"))
                    .findFirst()
                    .orElse(null);
        } catch (CertificateParsingException e) {
            LOG.warn("Failed to parse SAN", e);
            return null;
        }
    }
}