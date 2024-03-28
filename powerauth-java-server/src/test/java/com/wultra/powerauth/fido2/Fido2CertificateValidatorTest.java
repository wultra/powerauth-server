/*
 * PowerAuth Server and related software components
 * Copyright (C) 2024 Wultra s.r.o.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package com.wultra.powerauth.fido2;

import io.getlime.security.powerauth.app.server.Application;
import io.getlime.security.powerauth.app.server.service.fido2.Fido2CertificateValidator;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.*;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test of FIDO2 certificate validator.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@SpringBootTest(classes = Application.class)
@ActiveProfiles("test")
class Fido2CertificateValidatorTest {

    private static final byte[] AAGUID_TEST = Base64.getDecoder().decode("YnNkZmRlNGNhM2Q5YWEyYQ==");

    final SecureRandom secureRandom = new SecureRandom();

    @Autowired
    private Fido2CertificateValidator certValidator;

    @Test
    void selfSignedCertificateValidTest() throws Exception {
        final X509Certificate cert = generateCertificate("OU=Authenticator Attestation, CN=Test Authenticator, O=Wultra, C=CZ", AAGUID_TEST);
        assertTrue(certValidator.isValid(cert, Collections.emptyList(), List.of(cert), AAGUID_TEST));
    }

    @Test
    void missingCountryTest() throws Exception {
        final X509Certificate cert = generateCertificate("OU=Authenticator Attestation, CN=Test Authenticator, O=Wultra", AAGUID_TEST);
        assertFalse(certValidator.isValid(cert, Collections.emptyList(), List.of(cert), null));
    }

    @Test
    void missingOrganizationTest() throws Exception {
        final X509Certificate cert = generateCertificate("OU=Authenticator Attestation, CN=Test Authenticator, C=CZ", AAGUID_TEST);
        assertFalse(certValidator.isValid(cert, Collections.emptyList(), List.of(cert), null));
    }

    @Test
    void invalidOrganizationalUnitTest() throws Exception {
        final X509Certificate cert = generateCertificate("OU=Invalid, CN=Test Authenticator, O=Wultra, C=CZ", AAGUID_TEST);
        assertFalse(certValidator.isValid(cert, Collections.emptyList(), List.of(cert), null));
    }

    @Test
    void invalidAaguidTest() throws Exception {
        final byte[] randomBytes = new byte[16];
        secureRandom.nextBytes(randomBytes);
        final X509Certificate cert = generateCertificate("OU=Authenticator Attestation, CN=Test Authenticator, O=Wultra, C=CZ", randomBytes);
        assertFalse(certValidator.isValid(cert, Collections.emptyList(), List.of(cert), AAGUID_TEST));
    }

    @Test
    void caExtensionEnabledTest() throws Exception {
        final X509Certificate cert = generateCertificate("OU=Authenticator Attestation, CN=Test Authenticator, O=Wultra, C=CZ", AAGUID_TEST, true);
        assertFalse(certValidator.isValid(cert, Collections.emptyList(), List.of(cert), AAGUID_TEST));
    }

    private X509Certificate generateCertificate(String x500Name, byte[] aaguid) throws Exception {
        return generateCertificate(x500Name, aaguid, false);
    }

    private X509Certificate generateCertificate(String x500Name, byte[] aaguid, boolean caExtension) throws Exception {
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        final KeyPair keyPair = keyGen.generateKeyPair();
        final X500Name subject = new X500Name(x500Name);
        final BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        final Date notBefore = new Date();
        final Date notAfter = new Date(notBefore.getTime() + 100 * 365L * 24 * 60 * 60 * 1000);
        final X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(subject, serial, notBefore, notAfter, subject, keyPair.getPublic());
        final KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
        certBuilder.addExtension(Extension.keyUsage, true, keyUsage);
        if (aaguid != null) {
            certBuilder.addExtension(new ASN1ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4"), false, new DEROctetString(aaguid));
        }
        if (caExtension) {
            BasicConstraints basicConstraints = new BasicConstraints(true);
            certBuilder.addExtension(Extension.basicConstraints, true, basicConstraints);
        }
        final ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
    }
}
