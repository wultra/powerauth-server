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

import com.wultra.security.powerauth.app.server.database.model.entity.TemporaryKeyEntity;
import com.wultra.security.powerauth.app.server.database.repository.TemporaryKeyRepository;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.Objects;
import java.util.Optional;

/**
 * Service for handling temporary keys.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@AllArgsConstructor
@Slf4j
public abstract class TemporaryKeyService {

    private final LocalizationProvider localizationProvider;
    private final TemporaryKeyRepository temporaryKeyRepository;

    /**
     * Request a temporary key.
     * @param jwt JWT temporary key request.
     * @return JWT temporary key response.
     * @throws GenericServiceException In case of cryptography error.
     */
    public abstract String requestTemporaryKey(String jwt) throws GenericServiceException;

    /**
     * Fetch a temporary private key.
     * @param id Temporary key ID.
     * @param appKey Application key.
     * @param activationId Activation ID.
     * @return Temporary private key.
     * @throws GenericServiceException In case of cryptography error.
     */
    public abstract PrivateKey extractTemporaryPrivateKey(String id, String appKey, String activationId) throws GenericServiceException;

    /**
     * Fetch a temporary shared secret.
     * @param id Temporary key ID.
     * @param appKey Application key.
     * @param activationId Activation ID.
     * @return Temporary shared secret.
     * @throws GenericServiceException In case of cryptography error.
     */
    public abstract SecretKey extractTemporarySharedSecret(String id, String appKey, String activationId) throws GenericServiceException;

    /**
     * Get the temporary private key, decrypt if required.
     * @param id Key ID.
     * @param appKey App key.
     * @param activationId Activation ID.
     * @return Temporary private key.
     * @throws GenericServiceException In case some parameters did not match.
     * @throws InvalidKeySpecException In case the private key could not be converted.
     * @throws CryptoProviderException In case the crypto provider is not configured properly.
     */
    protected TemporaryKeyEntity fetchTemporaryKey(String id, String appKey, String activationId) throws GenericServiceException, InvalidKeySpecException, CryptoProviderException {
        final Date currentTimestamp = new Date();
        final Optional<TemporaryKeyEntity> temporaryKeyEntity = temporaryKeyRepository.findById(id);
        if (temporaryKeyEntity.isEmpty()) {
            logger.error("Missing temporary key pair with ID: {}", id);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.MISSING_TEMPORARY_KEY);
        }
        final TemporaryKeyEntity temporaryKey = temporaryKeyEntity.get();
        if (temporaryKey.getTimestampExpires().before(currentTimestamp)) {
            logger.error("Requesting expired temporary key pair with ID: {}", id);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.MISSING_TEMPORARY_KEY);
        }
        if (!Objects.equals(temporaryKey.getAppKey(), appKey) || !Objects.equals(temporaryKey.getActivationId(), activationId)) {
            logger.error("Temporary key does not match request parameters, app key expected: {}, received: {}, activation ID expected: {}, received: {}",
                    temporaryKey.getAppKey(), appKey,
                    temporaryKey.getActivationId(), activationId);
            // Rollback is not required, database is not used for writing
            throw localizationProvider.buildExceptionForCode(ServiceError.MISSING_TEMPORARY_KEY);
        }
        return temporaryKey;
    }
}
