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

package com.wultra.security.powerauth.app.server.service.crypto;

import com.nimbusds.jose.JWSAlgorithm;
import com.wultra.security.powerauth.app.server.database.model.KeyType;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.util.jwt.JWSAlgorithmMLDSA;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Objects;
import java.util.Map;

/**
 * Service for computing asymmetric signatures.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@AllArgsConstructor
public class AsymmetricSignatureService {

    private final AlgorithmQueryService algorithmQueryService;
    private final CryptographyServiceFactory cryptographyServiceFactory;

    /**
     * Compute activation signatures.
     * @param activation Activation entity.
     * @return Map of activation signatures.
     * @throws GenericServiceException In case signatures computing fails.
     */
    public Map<String, String> computeSignaturesForActivation(ActivationRecordEntity activation) throws GenericServiceException {
        final ApplicationEntity application = activation.getApplication();
        final String activationCode = Objects.requireNonNull(activation.getActivationCode(), "Activation code must not be null");

        final Map<String, String> signatures = new LinkedHashMap<>();

        final List<SharedSecretAlgorithm> supportedAlgorithms = algorithmQueryService.getSupportedAlgorithms(application);

        // Compute activation signatures for supported algorithms
        if (supportedAlgorithms.contains(SharedSecretAlgorithm.EC_P256)) {
            final byte[] signatureP256 = cryptographyServiceFactory.getService(SharedSecretAlgorithm.EC_P256)
                    .generateSignatureForApplication(
                            KeyType.ECDSA_P256,
                            activationCode.getBytes(StandardCharsets.UTF_8),
                            application);
            signatures.put(JWSAlgorithm.ES256.getName(), Base64.getEncoder().encodeToString(signatureP256));
        }
        if (supportedAlgorithms.contains(SharedSecretAlgorithm.EC_P384)
                || supportedAlgorithms.contains(SharedSecretAlgorithm.EC_P384_ML_L3)
                || supportedAlgorithms.contains(SharedSecretAlgorithm.EC_P384_ML_L5)) {
            final CryptographyService cryptographyServiceP384 = cryptographyServiceFactory.getService(SharedSecretAlgorithm.EC_P384);
            final byte[] signatureP384 = cryptographyServiceP384.generateSignatureForApplication(
                    KeyType.ECDSA_P384,
                    activationCode.getBytes(StandardCharsets.UTF_8),
                    application);
            signatures.put(JWSAlgorithm.ES384.getName(), Base64.getEncoder().encodeToString(signatureP384));
        }
        if (supportedAlgorithms.contains(SharedSecretAlgorithm.EC_P384_ML_L3)) {
            final CryptographyService cryptographyServiceP384MlL3 = cryptographyServiceFactory.getService(SharedSecretAlgorithm.EC_P384_ML_L3);
            final byte[] signatureMldsa65 = cryptographyServiceP384MlL3.generateSignatureForApplication(
                    KeyType.MLDSA_65,
                    activationCode.getBytes(StandardCharsets.UTF_8),
                    application);
            signatures.put(JWSAlgorithmMLDSA.MLDSA65.getName(), Base64.getEncoder().encodeToString(signatureMldsa65));
        }
        if (supportedAlgorithms.contains(SharedSecretAlgorithm.EC_P384_ML_L5)) {
            final CryptographyService cryptographyServiceP384MlL5 = cryptographyServiceFactory.getService(SharedSecretAlgorithm.EC_P384_ML_L5);
            final byte[] signatureMldsa87 = cryptographyServiceP384MlL5.generateSignatureForApplication(
                    KeyType.MLDSA_87,
                    activationCode.getBytes(StandardCharsets.UTF_8),
                    application);
            signatures.put(JWSAlgorithmMLDSA.MLDSA87.getName(), Base64.getEncoder().encodeToString(signatureMldsa87));
        }
        return signatures;
    }

}
