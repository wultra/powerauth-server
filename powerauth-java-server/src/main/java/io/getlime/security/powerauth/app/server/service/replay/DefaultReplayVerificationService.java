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

package io.getlime.security.powerauth.app.server.service.replay;

import io.getlime.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import io.getlime.security.powerauth.app.server.database.model.enumeration.UniqueValueType;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
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
    public void checkAndPersistUniqueValue(UniqueValueType type, Date requestTimestamp, String ephemeralPublicKey, String nonce, String identifier) throws GenericServiceException {
        logger.debug("Checking and persisting unique value, request type: {}, identifier: {}", type, identifier);
        final Date expiration = Date.from(Instant.now().plus(powerAuthServiceConfiguration.getRequestExpirationInMilliseconds(), ChronoUnit.MILLIS));
        if (requestTimestamp.after(expiration)) {
            // Rollback is not required, error occurs before writing to database
            logger.warn("Expired ECIES request received, timestamp: {}", requestTimestamp);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        final byte[] ephemeralPublicKeyBytes = ephemeralPublicKey != null ? Base64.getDecoder().decode(ephemeralPublicKey) : new byte[0];
        final byte[] nonceBytes = nonce != null ? Base64.getDecoder().decode(nonce) : new byte[0];
        final byte[] identifierBytes = identifier != null ? identifier.getBytes(StandardCharsets.UTF_8) : new byte[0];

        final ByteBuffer uniqueValBuffer = ByteBuffer.allocate(ephemeralPublicKeyBytes.length + nonceBytes.length + identifierBytes.length);
        uniqueValBuffer.put(ephemeralPublicKeyBytes);
        uniqueValBuffer.put(nonceBytes);
        uniqueValBuffer.put(identifierBytes);

        final String uniqueValue = Base64.getEncoder().encodeToString(uniqueValBuffer.array());
        if (replayPersistenceService.uniqueValueExists(uniqueValue)) {
            logger.warn("Duplicate request not allowed to prevent replay attacks, request type: {}, identifier: {}", type, identifier);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        if (!replayPersistenceService.persistUniqueValue(type, uniqueValue)) {
            logger.warn("Unique value could not be persisted, request type: {}, identifier: {}", type, identifier);
            // The whole transaction is rolled back in case of this unexpected state
            throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        }
    }

}