/*
 * PowerAuth Server and related software components
 * Copyright (C) 2023 Wultra s.r.o.
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

package com.webauthn4j.test.authenticator.webauthn;

import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.statement.PackedAttestationStatement;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.test.client.RegistrationEmulationOption;

import java.security.cert.X509Certificate;

/**
 * Self-attested packed authenticator.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class SelfAttestedPackedAuthenticator extends WebAuthnModelAuthenticator {

    @Override
    public AttestationStatement createAttestationStatement(AttestationStatementRequest attestationStatementRequest, RegistrationEmulationOption registrationEmulationOption) {
        byte[] signature;
        if (registrationEmulationOption.isSignatureOverrideEnabled()) {
            signature = registrationEmulationOption.getSignature();
        } else {
            signature = TestDataUtil.calculateSignature(attestationStatementRequest.getCredentialKeyPair().getPrivate(), attestationStatementRequest.getSignedData());
        }

        return new PackedAttestationStatement(COSEAlgorithmIdentifier.ES256, signature, null);
    }

    @Override
    X509Certificate createAttestationCertificate(AttestationStatementRequest attestationStatementRequest, AttestationOption attestationOption) {
        return null;
    }

}