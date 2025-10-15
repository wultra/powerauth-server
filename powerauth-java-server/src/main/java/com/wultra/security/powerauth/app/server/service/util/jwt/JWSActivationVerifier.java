/*
 * PowerAuth Server and related software components
 * Copyright (C) 2025 Wultra s.r.o.
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

package com.wultra.security.powerauth.app.server.service.util.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;
import com.wultra.security.powerauth.app.server.database.model.KeyType;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.service.crypto.CryptographyService;

import java.util.Set;

import static com.wultra.security.powerauth.app.server.service.util.jwt.JWSActivationSigner.*;

/**
 * Verifier for JWT for PowerAuth activations.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class JWSActivationVerifier implements JWSVerifier {

    private final CryptographyService cryptoService;
    private final ActivationRecordEntity activation;
    private final JCAContext jcaContext = new JCAContext();

    private static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS = Set.of(
            new JWSAlgorithm(JWT_ALGORITHM_NAME_ES256),
            new JWSAlgorithm(JWT_ALGORITHM_NAME_ES384),
            new JWSAlgorithm(JWT_ALGORITHM_NAME_MLDSA_65)
    );

    public JWSActivationVerifier(CryptographyService cryptoService, ActivationRecordEntity activation) {
        this.cryptoService = cryptoService;
        this.activation = activation;
    }

    @Override
    public boolean verify(JWSHeader header, byte[] signedData, Base64URL signature) throws JOSEException {
        try {
            final KeyType keyType = convertToKeyType(header);
            final byte[] signatureBytes = signature.decode();
            return cryptoService.verifySignatureForActivation(keyType, signedData, signatureBytes, activation);
        } catch (Exception e) {
            throw new JOSEException("Verification failed", e);
        }
    }

    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return SUPPORTED_ALGORITHMS;
    }

    @Override
    public JCAContext getJCAContext() {
        return jcaContext;
    }

    private KeyType convertToKeyType(JWSHeader jwsHeader) {
        return switch (jwsHeader.getAlgorithm().getName()) {
            case JWT_ALGORITHM_NAME_ES256 -> KeyType.ECDSA_P256;
            case JWT_ALGORITHM_NAME_ES384 -> KeyType.ECDSA_P384;
            case JWT_ALGORITHM_NAME_MLDSA_65 -> KeyType.MLDSA_65;
            default -> throw new IllegalArgumentException("Unsupported JWT algorithm: " + jwsHeader.getAlgorithm().getName());
        };
    }
}