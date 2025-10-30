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
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;
import com.wultra.security.powerauth.app.server.database.model.KeyType;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.service.crypto.CryptographyService;

import java.util.Set;

/**
 * Signer for JWT for PowerAuth activations.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class JWSActivationSigner implements JWSSigner {

    private final CryptographyService cryptoService;
    private final ActivationRecordEntity activation;
    private static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS = Set.of(
            JWSAlgorithm.ES256,
            JWSAlgorithm.ES384,
            JWSAlgorithmMLDSA.MLDSA65,
            JWSAlgorithmMLDSA.MLDSA87
    );
    private final JCAContext jcaContext = new JCAContext();

    public JWSActivationSigner(CryptographyService cryptoService, ActivationRecordEntity activation) {
        this.cryptoService = cryptoService;
        this.activation = activation;
    }

    @Override
    public Base64URL sign(JWSHeader header, byte[] dataToSign) throws JOSEException {
        try {
            final byte[] derSignature = cryptoService.generateSignatureForActivation(convertToKeyType(header), dataToSign, activation);
            final JWSAlgorithm alg = header.getAlgorithm();
            final byte[] jwsSignature;
            if (JWSAlgorithm.Family.EC.contains(alg)) {
                jwsSignature = ECDSA.transcodeSignatureToConcat(derSignature, ECDSA.getSignatureByteArrayLength(alg));
            } else {
                jwsSignature = derSignature;
            }

            return Base64URL.encode(jwsSignature);
        } catch (Exception e) {
            throw new JOSEException("Signature generation failed", e);
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
            case "ES256" -> KeyType.ECDSA_P256;
            case "ES384" -> KeyType.ECDSA_P384;
            case "ML-DSA-65" -> KeyType.MLDSA_65;
            case "ML-DSA-87" -> KeyType.MLDSA_87;
            default -> throw new IllegalArgumentException("Unsupported JWT algorithm: " + jwsHeader.getAlgorithm().getName());
        };
    }

}