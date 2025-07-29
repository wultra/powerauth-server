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

package com.wultra.security.powerauth.app.server.service.replay;

import com.wultra.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import com.wultra.security.powerauth.app.server.database.model.enumeration.UniqueValueType;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.model.UniqueValueParam;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

/**
 * Service for checking unique cryptography values to prevent replay attacks.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
@AllArgsConstructor
@ConditionalOnProperty(prefix = "powerauth.service.crypto", name = "replayVerificationService", havingValue = "default", matchIfMissing = true)
class DefaultReplayVerificationService implements ReplayVerificationService {

    private final ReplayPersistenceService replayPersistenceService;
    private final LocalizationProvider localizationProvider;
    private final PowerAuthServiceConfiguration powerAuthServiceConfiguration;

    @Override
    public void checkAndPersistUniqueValue(String protocolVersion, Date requestTimestamp, UniqueValueParam param) throws GenericServiceException {
        logger.debug("Checking and persisting unique value, request type: {}, request timestamp: {}, identifier: {}", param.getUniqueValueType(), requestTimestamp, param.getIdentifier());

        checkTimestamp(protocolVersion, requestTimestamp, param.getUniqueValueType());

        final byte uniqueValueType = (byte) param.getUniqueValueType().ordinal();
        final byte[] ephemeralPublicKeyBytes = param.getEphemeralPublicKey() != null ? Base64.getDecoder().decode(param.getEphemeralPublicKey()) : new byte[0];
        final byte[] nonceBytes = param.getNonce() != null ? Base64.getDecoder().decode(param.getNonce()) : new byte[0];
        final byte[] identifierBytes = param.getIdentifier() != null ? param.getIdentifier().getBytes(StandardCharsets.UTF_8) : new byte[0];

        final ByteBuffer uniqueValBuffer = ByteBuffer.allocate( 1 + ephemeralPublicKeyBytes.length + nonceBytes.length + identifierBytes.length);
        uniqueValBuffer.put(uniqueValueType);
        uniqueValBuffer.put(ephemeralPublicKeyBytes);
        uniqueValBuffer.put(nonceBytes);
        uniqueValBuffer.put(identifierBytes);

        final String uniqueValue = Base64.getEncoder().encodeToString(uniqueValBuffer.array());
        if (replayPersistenceService.uniqueValueExists(uniqueValue)) {
            logger.warn("Duplicate request not allowed to prevent replay attacks, request type: {}, request timestamp: {}, unique value: {}", param.getUniqueValueType(), requestTimestamp, uniqueValue);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        if (!replayPersistenceService.persistUniqueValue(param.getUniqueValueType(), protocolVersion, uniqueValue)) {
            logger.warn("Unique value could not be persisted, request type: {}, request timestamp: {}, unique value: {}", param.getUniqueValueType(), requestTimestamp, uniqueValue);
            // The whole transaction is rolled back in case of this unexpected state
            throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        }
        logger.debug("Persisted unique value, request type: {}, request timestamp: {}, unique value: {}", param.getUniqueValueType(), requestTimestamp, uniqueValue);
    }

    /**
     * Check timestamp using the following rules:
     *
     * <p>Version 3.0 and 3.1:
     * <ul>
     * <li>If TIMESTAMP < CURRENT_TIMESTAMP - EXTENDED_EXPIRATION, then reject request</li>
     * <li>If TIMESTAMP > CURRENT_TIMESTAMP + EXTENDED_EXPIRATION, then reject request</li>
     * </ul>
     *
     * <p>Version 3.2+:
     * <ul>
     * <li>If TIMESTAMP < CURRENT_TIMESTAMP - EXPIRATION, then reject request</li>
     * <li>If TIMESTAMP > CURRENT_TIMESTAMP + EXPIRATION, then reject request</li>
     * </ul>
     *
     * @param protocolVersion Protocol version.
     * @param requestTimestamp Request timestamp.
     * @throws GenericServiceException Thrown in case request is rejected due to its timestamp.
     */
    private void checkTimestamp(String protocolVersion, Date requestTimestamp, UniqueValueType uniqueValueType) throws GenericServiceException {
        if (requestTimestamp == null) {
            // Rollback is not required, error occurs before writing to database
            logger.warn("Rejected request due to missing timestamp, protocol version: {}", protocolVersion);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        final Instant now = Instant.now();
        final Instant requestTime = requestTimestamp.toInstant();
        final Instant limitOldest;
        final Instant limitNewest;
        if ("3.0".equals(protocolVersion) || "3.1".equals(protocolVersion)) {
            // Only MAC_TOKEN uses extended expiration, ECIES timestamps are checked only in protocol versions 3.2+
            // The presence or absence of ECIES timestamps is checked before decryption in PowerAuth crypto library:
            // https://github.com/wultra/powerauth-crypto/blob/develop/powerauth-java-crypto/src/main/java/com/wultra/security/powerauth/crypto/lib/encryptor/ecies/EciesRequestResponseValidator.java
            if (uniqueValueType != UniqueValueType.MAC_TOKEN) {
                // Rollback is not required, error occurs before writing to database
                logger.warn("Rejected request due to invalid unique value type: {}, protocol version: {}", uniqueValueType, protocolVersion);
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            limitOldest = now.minus(powerAuthServiceConfiguration.getRequestExpirationExtended());
            limitNewest = now.plus(powerAuthServiceConfiguration.getRequestExpirationExtended());
        } else {
            limitOldest = now.minus(powerAuthServiceConfiguration.getRequestExpiration());
            limitNewest = now.plus(powerAuthServiceConfiguration.getRequestExpiration());
        }
        if (requestTime.isBefore(limitOldest) || requestTime.isAfter(limitNewest)) {
            // Rollback is not required, error occurs before writing to database
            logger.warn("Rejected request due to invalid timestamp: {}, allowed range: {} - {}, protocol version: {}", requestTime, limitOldest, limitNewest, protocolVersion);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
    }

}