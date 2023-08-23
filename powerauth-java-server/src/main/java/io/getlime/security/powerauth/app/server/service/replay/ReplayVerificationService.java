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
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
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
@ConditionalOnProperty(
        value = "powerauth.service.crypto.replay-attack-protection.enabled",
        havingValue = "true"
)
public class ReplayVerificationService {

    private final ReplayPersistenceService replayPersistenceService;
    private final LocalizationProvider localizationProvider;
    private final PowerAuthServiceConfiguration config;

    /**
     * Service constructor.
     * @param replayPersistenceService Replay persistence service.
     * @param localizationProvider Localization provider.
     * @param powerAuthServiceConfiguration PowerAuth service configuration.
     */
    @Autowired
    public ReplayVerificationService(ReplayPersistenceService replayPersistenceService, LocalizationProvider localizationProvider, PowerAuthServiceConfiguration powerAuthServiceConfiguration) {
        this.replayPersistenceService = replayPersistenceService;
        this.localizationProvider = localizationProvider;
        this.config = powerAuthServiceConfiguration;
    }

    /**
     * Check whether unique value exists for MAC Token request.
     * @param type Unique value type.
     * @param requestTimestamp Request timestamp.
     * @param nonce Nonce bytes encoded in Base64.
     * @param identifier Identifier for the record.
     * @throws GenericServiceException Thrown in case unique value exists.
     */
    public void checkAndPersistUniqueValue(UniqueValueType type, Date requestTimestamp, String nonce, String identifier) throws GenericServiceException {
        checkAndPersistUniqueValue(type, requestTimestamp, null, nonce, identifier);
    }

    /**
     * Check whether unique value exists for ECIES request.
     * @param type Unique value type.
     * @param requestTimestamp Request timestamp.
     * @param ephemeralPublicKey Ephemeral public key bytes encoded in Base64.
     * @param nonce Nonce bytes encoded in Base64.
     * @param identifier Identifier for the record.
     * @throws GenericServiceException Thrown in case unique value exists.
     */
    public void checkAndPersistUniqueValue(UniqueValueType type, Date requestTimestamp, String ephemeralPublicKey, String nonce, String identifier) throws GenericServiceException {
        final Date expiration = Date.from(Instant.now().plus(config.getRequestExpiration()));
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
            logger.warn("Duplicate request not allowed to prevent replay attacks");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        if (!replayPersistenceService.persistUniqueValue(type, uniqueValue)) {
            logger.warn("Unique value could not be persisted");
            // The whole transaction is rolled back in case of this unexpected state
            throw localizationProvider.buildRollbackingExceptionForCode(ServiceError.GENERIC_CRYPTOGRAPHY_ERROR);
        }
    }


}
