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

package io.getlime.security.powerauth.app.server.service.fido2;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.naming.InvalidNameException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;
import java.security.KeyStore;
import java.security.cert.*;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Validator for X.509 certificates used in FIDO2.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component
@Slf4j
public class Fido2CertificateValidator {

    private static final String FIDO2_EXTENSION_ID_AAGUID = "1.3.6.1.4.1.45724.1.1.4";

    /**
     * Validate a FIDO2 certificate.
     *
     * @param cert         Attestation certificate.
     * @param certChain    Intermediate certificate chain from request, if required.
     * @param trustedCerts List of trusted root CA certificates.
     * @param aaguid       AAGUID value.
     * @return Validation result.
     */
    public boolean isValid(X509Certificate cert, List<X509Certificate> certChain, List<X509Certificate> trustedCerts, byte[] aaguid) {
        return validateCertRequirements(cert) && validateTrustPath(cert, certChain, trustedCerts) && validateAaguid(cert, aaguid);
    }

    /**
     * Validate certificate parameters based on "8.2.1. Packed Attestation Statement Certificate Requirements".
     *
     * @param cert Attestation certificate.
     * @return Whether certificate is valid.
     */
    private boolean validateCertRequirements(X509Certificate cert) {
        final X500Principal subjectPrincipal = cert.getSubjectX500Principal();
        // Version MUST be set to 3 (which is indicated by an ASN.1 INTEGER with value 2).
        if (cert.getVersion() != 3) {
            logger.warn("Invalid certificate version, subject name: {}, version: {}", subjectPrincipal.getName(), cert.getVersion());
            return false;
        }
        // Subject-C: ISO 3166 code specifying the country where the Authenticator vendor is incorporated (PrintableString)
        final String country = getValue(cert, "C");
        if (!StringUtils.hasText(country)) {
            logger.warn("Subject-C must be present in certificate, subject name: {}", subjectPrincipal.getName());
            return false;
        }
        // Subject-O: Legal name of the Authenticator vendor (UTF8String)
        final String organization = getValue(cert, "O");
        if (!StringUtils.hasText(organization)) {
            logger.warn("Subject-O must be present in certificate, subject name: {}", subjectPrincipal.getName());
            return false;
        }
        // Subject-OU: Literal string “Authenticator Attestation” (UTF8String)
        final String organizationUnit = getValue(cert, "OU");
        if (!"Authenticator Attestation".equals(organizationUnit)) {
            logger.warn("Subject-OU value is not valid in certificate, subject name: {}", subjectPrincipal.getName());
            return false;
        }
        // Subject-CN: A UTF8String of the vendor’s choosing
        final String subjectCommonName = getValue(cert, "CN");
        if (!StringUtils.hasText(subjectCommonName)) {
            logger.warn("Subject-CN must be present in certificate, subject name: {}", subjectPrincipal.getName());
            return false;
        }
        // The Basic Constraints extension MUST have the CA component set to false.
        if (cert.getBasicConstraints() != -1) {
            logger.warn("Attestation certificate must not be a CA certificate, subject name: {}", subjectPrincipal.getName());
            return false;
        }
        return true;
    }

    /**
     * Validate certificate trust path.
     *
     * @param cert         Attestation certificate.
     * @param certChain    Intermediate certificate chain from request, if required.
     * @param rootCerts    List of trusted root CA certificates.
     * @return Whether certificate trust path was successfully verified.
     */
    private boolean validateTrustPath(X509Certificate cert, List<X509Certificate> certChain, List<X509Certificate> rootCerts) {
        try {
            final KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null, null);

            final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            final List<X509Certificate> untrustedCerts = new ArrayList<>();
            untrustedCerts.add(cert);
            untrustedCerts.addAll(certChain);
            final CertPath certPath = certificateFactory.generateCertPath(untrustedCerts);
            final Set<TrustAnchor> trustAnchors = new HashSet<>();
            rootCerts.forEach(rootCert -> trustAnchors.add(new TrustAnchor(rootCert, null)));
            final PKIXParameters params = new PKIXParameters(trustAnchors);
            params.setRevocationEnabled(false);
            final CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            validator.validate(certPath, params);
            return true;
        } catch (Exception e) {
            logger.debug(e.getMessage(), e);
            logger.warn("Certificate validation failed, error: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Validate AAGUID value for request against attestation certificate.
     *
     * @param cert   FIDO2 attestation certificate.
     * @param aaguid AAGUID value.
     * @return Whether AAGUID validation succeeded.
     */
    private boolean validateAaguid(X509Certificate cert, byte[] aaguid) {
        // If attestnCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) verify that the value of this extension matches the aaguid in authenticatorData.
        final String aaguidCert = extractAAGUIDFromCert(cert);
        if (aaguidCert != null) {
            return aaguidCert.equals(bytesToHex(aaguid));
        }
        return true;
    }

    private String getValue(X509Certificate cert, String name) {
        try {
            LdapName subjectDN = new LdapName(cert.getSubjectX500Principal().getName());
            Map<String, Object> map = subjectDN.getRdns().stream().flatMap(rdn -> toMap(rdn).entrySet().stream()).collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
            return (String) map.get(name);
        } catch (InvalidNameException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private Map<String, Object> toMap(Rdn rdn) {
        try {
            final Map<String, Object> map = new HashMap<>();
            final Attributes attributes = rdn.toAttributes();
            final NamingEnumeration<String> ids = rdn.toAttributes().getIDs();
            while (ids.hasMore()) {
                String id = ids.next();
                map.put(id, attributes.get(id).get());
            }
            return map;
        } catch (NamingException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private String extractAAGUIDFromCert(X509Certificate cert) {
        final byte[] extensionValue = cert.getExtensionValue(FIDO2_EXTENSION_ID_AAGUID);
        if (extensionValue == null) {
            return null;
        }
        return extractAAGUID(extensionValue);
    }

    private static String extractAAGUID(byte[] extensionValue) {
        if (extensionValue != null && extensionValue.length > 2) {
            // Skip the first two bytes (tag and length) and extract the AAGUID value
            final byte[] aaguidBytes = new byte[extensionValue.length - 2];
            System.arraycopy(extensionValue, 2, aaguidBytes, 0, aaguidBytes.length);
            // Convert bytes to hexadecimal string
            return bytesToHex(aaguidBytes);
        }
        return null;
    }

    private static String bytesToHex(byte[] bytes) {
        final StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

}