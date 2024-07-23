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

package io.getlime.security.powerauth.app.server.service.behavior.tasks;

import com.wultra.security.powerauth.client.model.enumeration.Protocols;
import io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Validation of activation context.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component
@Slf4j
public class ActivationContextValidator {

    /**
     * Validate that protocol is powerauth.
     * @param protocol Protocol.
     * @param localizationProvider Localization provider.
     * @throws GenericServiceException Thrown when protocol is invalid.
     */
    public void validatePowerAuthProtocol(final String protocol, final LocalizationProvider localizationProvider) throws GenericServiceException {
        if (!Protocols.isPowerAuth(protocol)) {
            logger.warn("Invalid protocol: {}, expected: powerauth", protocol);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
    }

    /**
     * Validate that protocol is fido2.
     * @param protocol Protocol.
     * @param localizationProvider Localization provider.
     * @throws GenericServiceException Thrown when protocol is invalid.
     */
    public void validateFido2Protocol(final String protocol, final LocalizationProvider localizationProvider) throws GenericServiceException {
        if (!Protocols.isFido2(protocol)) {
            logger.warn("Invalid protocol: {}, expected: fido2", protocol);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
    }

    /**
     * Validate that activation status is ACTIVE.
     * @param activationStatus Actual validation status.
     * @param activationId Activation identifier.
     * @param localizationProvider Localization provider.
     * @throws GenericServiceException Thrown when activation status is invalid.
     */
    public void validateActiveStatus(final ActivationStatus activationStatus, final String activationId, final LocalizationProvider localizationProvider) throws GenericServiceException {
        // Check if the activation is in correct state
        if (activationStatus != ActivationStatus.ACTIVE) {
            logger.info("Activation is not ACTIVE, activation ID: {}", activationId);
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
        }
    }

    /**
     * Validate activation version.
     * @param actualVersion Actual version.
     * @param expectedVersion Expected version.
     * @param activationId Activation identifier.
     * @param localizationProvider Localization provider.
     * @throws GenericServiceException Thrown when activation version is invalid.
     */
    public void validateVersion(final int actualVersion, final int expectedVersion, final String activationId, final LocalizationProvider localizationProvider) throws GenericServiceException {
        if (actualVersion != expectedVersion) {
            logger.info("Activation version is invalid, activation ID: {}, expected: {}, actual: {}", activationId, expectedVersion, actualVersion);
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
        }
    }

    /**
     * Validate activation version.
     * @param activationVersion Version of activation.
     * @param localizationProvider Localization provider.
     * @throws GenericServiceException Thrown when activation version is invalid.
     */
    public void validateVersionValid(final int activationVersion, final LocalizationProvider localizationProvider) throws GenericServiceException {
        if (activationVersion < 2 || activationVersion > 3) {
            logger.warn("Invalid activation version: {}", activationVersion);
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
        }
    }

}
