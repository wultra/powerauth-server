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

package com.wultra.security.powerauth.app.server.service.crypto.v4;

import com.wultra.security.powerauth.app.server.converter.ActivationSharedSecretConverter;
import com.wultra.security.powerauth.app.server.database.model.SharedSecretRecord;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.client.model.entity.v4.request.SharedSecretRequest;
import com.wultra.security.powerauth.client.model.entity.v4.response.SharedSecretResponse;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.api.SharedSecret;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.DefaultSharedSecretRequest;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.DefaultSharedSecretResponse;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.ResponseCryptogram;
import com.wultra.security.powerauth.crypto.lib.v4.sharedsecret.SharedSecretFactory;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.util.Pair;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.List;

/**
 * Utility class for shared secret key derivation.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@AllArgsConstructor
@Slf4j
@Service
public class SharedSecretService {

    private final LocalizationProvider localizationProvider;
    private final ActivationSharedSecretConverter activationSharedSecretConverter;

    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();

    private static final SharedSecret SHARED_SECRET_ECDHE = SharedSecretFactory.getEcdhe();
    private static final SharedSecret SHARED_SECRET_HYBRID_ML_L3 = SharedSecretFactory.getHybridMlL3();
    private static final SharedSecret SHARED_SECRET_HYBRID_ML_L5 = SharedSecretFactory.getHybridMlL5();

    /**
     * Extract the activation secret key from activation entity.
     *
     * @param activation Activation entity.
     * @return Activation shared secret key.
     * @throws GenericServiceException Thrown in case key conversion fails.
     */
    public SecretKey extractActivationSecretKey(ActivationRecordEntity activation) throws GenericServiceException {
        final SharedSecretRecord activationSharedSecret = new SharedSecretRecord(activation.getSharedSecretEncryption(), activation.getSharedSecret());
        final String activationSecretBase64 = activationSharedSecretConverter.fromDBValue(activationSharedSecret, activation.getUserId(), activation.getActivationId());
        final byte[] activationSecretBytes = Base64.getDecoder().decode(activationSecretBase64);
        return KEY_CONVERTOR.convertBytesToSharedSecretKey(activationSecretBytes);
    }

    /**
     * Derive shared secret.
     * @param sharedSecretRequest Shared secret request.
     * @return Pair with shared secret response and response cryptogram.
     * @throws GenericServiceException Throw in case shared secret derivation fails.
     */
    public Pair<SharedSecretResponse, ResponseCryptogram> deriveSharedSecret(SharedSecretRequest sharedSecretRequest) throws GenericServiceException {
        final SharedSecretAlgorithm algorithm = SharedSecretAlgorithm.valueOf(sharedSecretRequest.getAlgorithm());

        final DefaultSharedSecretRequest sharedSecretRequestObject = new DefaultSharedSecretRequest();
        sharedSecretRequestObject.setAlgorithm(algorithm);
        final ResponseCryptogram responseCryptogram;
        final SharedSecretResponse secretResponse = switch (algorithm) {
            case EC_P384 -> {
                try {
                    sharedSecretRequestObject.setEncapsulationKeys(List.of(sharedSecretRequest.getEncapsulationKeys().get(0)));
                    responseCryptogram = SHARED_SECRET_ECDHE.generateResponseCryptogram(sharedSecretRequestObject);

                    final DefaultSharedSecretResponse derivedResponse = (DefaultSharedSecretResponse) responseCryptogram.getSharedSecretResponse();
                    final SharedSecretResponse sharedSecretResponse = new SharedSecretResponse();
                    sharedSecretResponse.setSalt(derivedResponse.getSalt());
                    sharedSecretResponse.setEncapsulatedKeys(List.of(derivedResponse.getEncapsulatedKeys().get(0)));
                    yield sharedSecretResponse;
                } catch (GenericCryptoException ex) {
                    logger.error("Cryptography error occurred", ex);
                    throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
                }
            }
            case EC_P384_ML_L3, EC_P384_ML_L5 -> {
                try {
                    sharedSecretRequestObject.setEncapsulationKeys(List.of(sharedSecretRequest.getEncapsulationKeys().get(0), sharedSecretRequest.getEncapsulationKeys().get(1)));
                    responseCryptogram = switch (algorithm) {
                        case EC_P384_ML_L3 -> SHARED_SECRET_HYBRID_ML_L3.generateResponseCryptogram(sharedSecretRequestObject);
                        case EC_P384_ML_L5 -> SHARED_SECRET_HYBRID_ML_L5.generateResponseCryptogram(sharedSecretRequestObject);
                        default -> throw new IllegalStateException("Unexpected algorithm during shared secret response processing: " + algorithm);
                    };

                    final DefaultSharedSecretResponse derivedResponse = (DefaultSharedSecretResponse) responseCryptogram.getSharedSecretResponse();
                    final SharedSecretResponse sharedSecretResponse = new SharedSecretResponse();
                    sharedSecretResponse.setSalt(derivedResponse.getSalt());
                    sharedSecretResponse.setEncapsulatedKeys(List.of(derivedResponse.getEncapsulatedKeys().get(0), derivedResponse.getEncapsulatedKeys().get(1)));
                    yield sharedSecretResponse;
                } catch (GenericCryptoException ex) {
                    logger.error("Cryptography error occurred", ex);
                    throw localizationProvider.buildExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
                }
            }
            default -> {
                logger.warn("Unsupported algorithm: {}", sharedSecretRequest.getAlgorithm());
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
        };
        return Pair.of(secretResponse, responseCryptogram);
    }

    /**
     * Validate shared secret request.
     * @param sharedSecretRequest Shared secret request.
     * @param activationId Activation identifier.
     * @throws GenericServiceException Thrown in case shared secret request is invalid.
     */
    public void validateSharedSecretRequest(SharedSecretRequest sharedSecretRequest, String activationId) throws GenericServiceException {
        if (sharedSecretRequest.getAlgorithm() == null || sharedSecretRequest.getEncapsulationKeys() == null) {
            logger.warn("Invalid shared secret request, activation ID: {}", activationId);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }

        final SharedSecretAlgorithm algorithm;
        try {
            algorithm = SharedSecretAlgorithm.valueOf(sharedSecretRequest.getAlgorithm());
        } catch (IllegalArgumentException ex) {
            logger.warn("Unsupported shared secret algorithm '{}' for activation ID: {}", sharedSecretRequest.getAlgorithm(), activationId);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }

        final int keyCount = sharedSecretRequest.getEncapsulationKeys().size();
        switch (algorithm) {
            case EC_P384 -> {
                if (keyCount != 1) {
                    logger.warn("Invalid key count {} for algorithm {}, activation ID: {}", keyCount, algorithm, activationId);
                    throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
                }
            }
            case EC_P384_ML_L3, EC_P384_ML_L5 -> {
                if (keyCount != 2) {
                    logger.warn("Invalid key count {} for algorithm {}, activation ID: {}", keyCount, algorithm, activationId);
                    throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
                }
            }
            case ML_L3, ML_L5 -> {
                logger.warn("Experimental algorithm {} is not allowed in production, activation ID: {}", algorithm, activationId);
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            default -> {
                logger.warn("Unsupported algorithm {}, activation ID: {}", algorithm, activationId);
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
        }
    }

}
