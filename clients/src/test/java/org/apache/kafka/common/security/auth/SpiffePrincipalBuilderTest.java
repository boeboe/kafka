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
package org.apache.kafka.common.security.auth;

import org.apache.kafka.common.security.authenticator.SpiffePrincipalBuilder;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLSession;
import javax.security.auth.x500.X500Principal;
import java.net.InetAddress;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class SpiffePrincipalBuilderTest {

    @Test
    public void testPrincipleWithOneSanSpiffe() throws Exception {
        SSLSession session = mock(SSLSession.class);
        X509Certificate x509Certificate = mock(X509Certificate.class);
        List<List<?>> sansSpiffe1 = new ArrayList<>(Collections.singletonList(
                new ArrayList<>(Arrays.asList(6, "spiffe://acme.com/billing/payments"))));
        List<List<?>> sansSpiffe2 = new ArrayList<>(Collections.singletonList(
                new ArrayList<>(Arrays.asList(6, "spiffe://cluster.local/ns/billing/sa/payments"))));

        when(session.getPeerCertificates())
                .thenReturn(new Certificate[]{x509Certificate})
                .thenReturn(new Certificate[]{x509Certificate});
        when(x509Certificate.getSubjectAlternativeNames())
                .thenReturn(sansSpiffe1)
                .thenReturn(sansSpiffe2);

        SpiffePrincipalBuilder builder = new SpiffePrincipalBuilder();
        SslAuthenticationContext sslContext = new SslAuthenticationContext(session, InetAddress.getLocalHost(),
                SecurityProtocol.PLAINTEXT.name());

        KafkaPrincipal principal = builder.build(sslContext);
        assertEquals("spiffe://acme.com/billing/payments", principal.getName());

        principal = builder.build(sslContext);
        assertEquals("spiffe://cluster.local/ns/billing/sa/payments", principal.getName());

        verify(session, times(2)).getPeerCertificates();
        verify(x509Certificate, times(2)).getSubjectAlternativeNames();
        verify(session, times(0)).getPeerPrincipal();
    }

    @Test
    public void testPrincipleWithMixedSanSpiffe() throws Exception {
        SSLSession session = mock(SSLSession.class);
        X509Certificate x509Certificate = mock(X509Certificate.class);

        List<List<?>> sansMixedSpiffe = new ArrayList<>(Arrays.asList(
                new ArrayList<>(Arrays.asList(6, "spiffe://acme.com/billing/payments")),
                new ArrayList<>(Arrays.asList(2, "example.com"))
        ));

        when(session.getPeerCertificates()).thenReturn(new Certificate[]{x509Certificate});
        when(x509Certificate.getSubjectAlternativeNames()).thenReturn(sansMixedSpiffe);

        SpiffePrincipalBuilder builder = new SpiffePrincipalBuilder();
        SslAuthenticationContext sslContext = new SslAuthenticationContext(session, InetAddress.getLocalHost(),
                SecurityProtocol.PLAINTEXT.name());

        KafkaPrincipal principal = builder.build(sslContext);
        assertEquals("spiffe://acme.com/billing/payments", principal.getName());

        verify(session, times(1)).getPeerCertificates();
        verify(x509Certificate, times(1)).getSubjectAlternativeNames();
        verify(session, times(0)).getPeerPrincipal();
    }

    @Test
    public void testPrincipleWithMultipleSanSpiffe() throws Exception {
        SSLSession session = mock(SSLSession.class);
        X509Certificate x509Certificate = mock(X509Certificate.class);

        List<List<?>> sansMixedSpiffe = new ArrayList<>(Arrays.asList(
                new ArrayList<>(Arrays.asList(6, "spiffe://acme.com/billing/payments")),
                new ArrayList<>(Arrays.asList(6, "spiffe://cluster.local/ns/billing/sa/payments"))
        ));

        when(session.getPeerCertificates()).thenReturn(new Certificate[]{x509Certificate});
        when(x509Certificate.getSubjectAlternativeNames()).thenReturn(sansMixedSpiffe);

        SpiffePrincipalBuilder builder = new SpiffePrincipalBuilder();
        SslAuthenticationContext sslContext = new SslAuthenticationContext(session, InetAddress.getLocalHost(),
                SecurityProtocol.PLAINTEXT.name());

        KafkaPrincipal principal = builder.build(sslContext);
        assertEquals("spiffe://acme.com/billing/payments", principal.getName());

        verify(session, times(1)).getPeerCertificates();
        verify(x509Certificate, times(1)).getSubjectAlternativeNames();
        verify(session, times(0)).getPeerPrincipal();
    }

    @Test
    public void testPrincipleWithSanNoSpiffe() throws Exception {
        SSLSession session = mock(SSLSession.class);
        X509Certificate x509Certificate = mock(X509Certificate.class);
        List<List<?>> sansNoSpiffe = new ArrayList<>(Collections.singletonList(
                new ArrayList<>(Arrays.asList(2, "example.com"))));
        X500Principal x500Principal = mock(X500Principal.class);

        when(session.getPeerCertificates()).thenReturn(new Certificate[]{x509Certificate});
        when(x509Certificate.getSubjectAlternativeNames()).thenReturn(sansNoSpiffe);
        when(x509Certificate.getSubjectX500Principal()).thenReturn(x500Principal);
        when(x500Principal.getName()).thenReturn("foo");

        SpiffePrincipalBuilder builder = new SpiffePrincipalBuilder();
        SslAuthenticationContext sslContext = new SslAuthenticationContext(session, InetAddress.getLocalHost(),
                SecurityProtocol.PLAINTEXT.name());

        KafkaPrincipal principal = builder.build(sslContext);
        assertEquals("foo", principal.getName());

        verify(session, times(1)).getPeerCertificates();
        verify(x509Certificate, times(1)).getSubjectAlternativeNames();
        verify(x509Certificate, times(1)).getSubjectX500Principal();
        verify(x500Principal, times(1)).getName();
    }

    @Test
    public void testPrincipleNoSanNoSpiffe() throws Exception {
        SSLSession session = mock(SSLSession.class);
        X509Certificate x509Certificate = mock(X509Certificate.class);
        X500Principal x500Principal = mock(X500Principal.class);

        when(session.getPeerCertificates()).thenReturn(new Certificate[]{x509Certificate});
        when(x509Certificate.getSubjectAlternativeNames()).thenReturn(null);
        when(x509Certificate.getSubjectX500Principal()).thenReturn(x500Principal);
        when(x500Principal.getName()).thenReturn("foo");

        SpiffePrincipalBuilder builder = new SpiffePrincipalBuilder();
        SslAuthenticationContext sslContext = new SslAuthenticationContext(session, InetAddress.getLocalHost(),
                SecurityProtocol.PLAINTEXT.name());

        KafkaPrincipal principal = builder.build(sslContext);
        assertEquals("foo", principal.getName());

        verify(session, times(1)).getPeerCertificates();
        verify(x509Certificate, times(1)).getSubjectAlternativeNames();
        verify(x509Certificate, times(1)).getSubjectX500Principal();
        verify(x500Principal, times(1)).getName();
    }
}

