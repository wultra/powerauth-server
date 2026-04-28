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
 */

package com.wultra.security.powerauth.app.server.service.util.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.impl.AlgorithmSupportMessage;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.v4.api.PqcDsa;
import com.wultra.security.powerauth.crypto.lib.v4.ml.MlDsa;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;

import java.security.PrivateKey;
import java.util.Set;

import static com.wultra.security.powerauth.app.server.service.util.jwt.JWSAlgorithmMLDSA.MLDSA65;
import static com.wultra.security.powerauth.app.server.service.util.jwt.JWSAlgorithmMLDSA.MLDSA87;

/**
 * Implementation of the {@link JWSSigner} to support {@link PqcDsa}.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@AllArgsConstructor
@Slf4j
public class MLDSASigner implements JWSSigner {

    private static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS = Set.of(MLDSA65, MLDSA87);
    private final JCAContext jcaContext = new JCAContext();

    private final PrivateKey privateKey;

    private static final PqcDsa pqcDsaMlL3;
    private static final PqcDsa pqcDsaMlL5;

    static {
        try {
            pqcDsaMlL3 = new MlDsa(MLDSAParameterSpec.ml_dsa_65);
            pqcDsaMlL5 = new MlDsa(MLDSAParameterSpec.ml_dsa_87);
        } catch (GenericCryptoException e) {
            logger.error("Failed to initialize ML-DSA: {}", e.getMessage(), e);
            throw new ExceptionInInitializerError(e);
        }
    }

    @Override
    public Base64URL sign(final JWSHeader header, final byte[] signingInput) throws JOSEException {
        final JWSAlgorithm alg = header.getAlgorithm();

        if (!supportedJWSAlgorithms().contains(alg)) {
            throw new JOSEException(AlgorithmSupportMessage.unsupportedJWSAlgorithm(alg, this.supportedJWSAlgorithms()));
        }

        try {
            final byte[] signature = switch (alg.getName()) {
                case "ML-DSA-65" -> pqcDsaMlL3.sign(privateKey, signingInput);
                case "ML-DSA-87" -> pqcDsaMlL5.sign(privateKey, signingInput);
                default -> throw new JOSEException(AlgorithmSupportMessage.unsupportedJWSAlgorithm(alg, this.supportedJWSAlgorithms()));
            };
            return Base64URL.encode(signature);
        } catch (GenericCryptoException e) {
            throw new JOSEException(e.getMessage(), e);
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

}
