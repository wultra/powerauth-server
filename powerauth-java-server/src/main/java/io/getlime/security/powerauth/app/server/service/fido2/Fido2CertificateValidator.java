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

import java.security.KeyStore;
import java.security.cert.*;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Validator for X.509 certificates used in FIDO2.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component
@Slf4j
public class Fido2CertificateValidator {

    /**
     * Validate a FIDO2 certificate.
     * @param cert FIDO2 certificate.
     * @return Validation result.
     */
    public boolean isValid(X509Certificate cert, List<X509Certificate> caCerts) {
        try {
            final KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null, null);

            final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            final CertPath certPath = certificateFactory.generateCertPath(List.of(cert));
            final Set<TrustAnchor> trustAnchors = new HashSet<>();
            caCerts.forEach(caCert -> {
                TrustAnchor trustAnchor = new TrustAnchor(caCert, null);
                trustAnchors.add(trustAnchor);
            });
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

}