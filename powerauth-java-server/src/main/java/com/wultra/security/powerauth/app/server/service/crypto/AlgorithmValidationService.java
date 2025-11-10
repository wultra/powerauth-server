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

import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Service for checking supported algorithms.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
@AllArgsConstructor
public class AlgorithmValidationService {

    private final AlgorithmQueryService algorithmQueryService;
    private final LocalizationProvider localizationProvider;

    /**
     * Validate support of shared secret algorithm for an application.
     * @param application Application.
     * @param algorithm Shared secret algorithm.
     * @throws GenericServiceException In case algorithm is not supported.
     */
    public void validateAlgorithmForApplication(ApplicationEntity application, SharedSecretAlgorithm algorithm) throws GenericServiceException {
        if (!algorithmQueryService.isAlgorithmSupported(application, algorithm)) {
            logger.warn("Cryptography algorithm is not allowed, application ID: {}, algorithm: {}", application.getId(), algorithm);
            throw localizationProvider.buildExceptionForCode(ServiceError.CRYPTOGRAPHY_ALGORITHM_NOT_SUPPORTED);
        }
    }

    /**
     * Validate support of shared secret algorithm for an activation.
     * @param activation Activation.
     * @param algorithm Shared secret algorithm.
     * @throws GenericServiceException In case algorithm is not supported.
     */
    public void validateAlgorithmForActivation(ActivationRecordEntity activation, SharedSecretAlgorithm algorithm) throws GenericServiceException {
        validateAlgorithmForApplication(activation.getApplication(), algorithm);

        if (!algorithmMatchesActivation(activation, algorithm)) {
            logger.warn("Cryptography algorithm does not match activation, activation ID: {}, algorithm: {}", activation.getActivationId(), algorithm);
            throw localizationProvider.buildExceptionForCode(ServiceError.CRYPTOGRAPHY_ALGORITHM_NOT_SUPPORTED);
        }
    }

    /**
     * Check whether shared secret algorithm matches the algorithm stored during activation.
     * @param activation Activation.
     * @param sharedSecretAlgorithm Shared secret algorithm.
     * @return Whether shared secret algorithm matches the algorithm stored during activation
     */
    private boolean algorithmMatchesActivation(ActivationRecordEntity activation, SharedSecretAlgorithm sharedSecretAlgorithm) {
        if (activation.getCryptoAlgorithm() == null) {
            // Legacy algorithm support for compatibility reasons
            return activation.getVersion() == 3 && sharedSecretAlgorithm == SharedSecretAlgorithm.EC_P256;
        }
        return sharedSecretAlgorithm == activation.getCryptoAlgorithm();
    }

}
