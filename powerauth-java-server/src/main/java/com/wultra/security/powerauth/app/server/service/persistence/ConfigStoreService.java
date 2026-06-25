/*
 * PowerAuth Server and related software components
 * Copyright (C) 2026 Wultra s.r.o.
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
package com.wultra.security.powerauth.app.server.service.persistence;

import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ConfigStoreEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ConfigScope;
import com.wultra.security.powerauth.app.server.database.repository.ConfigStoreRepository;
import com.wultra.security.powerauth.app.server.service.encryption.DatabaseEncryptionService;
import com.wultra.security.powerauth.app.server.service.encryption.DefaultEncryptionKeySupplier;
import com.wultra.security.powerauth.app.server.service.encryption.EncryptableString;
import com.wultra.security.powerauth.app.server.service.encryption.EncryptionKeySupplier;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.List;
import java.util.Optional;

/**
 * Persistence service for the configuration store with encryption at rest. Each record is encrypted
 * with a per-record key, and it is transparently encrypted and decrypted by this service.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
@AllArgsConstructor
public class ConfigStoreService {

    private final ConfigStoreRepository configStoreRepository;
    private final DatabaseEncryptionService encryptionService;

    /**
     * Find the configuration store records visible in the application scope for the given application.
     *
     * @param applicationId Application ID.
     * @return List of decrypted application-scope config store records.
     */
    @Transactional(readOnly = true)
    public List<ConfigStoreItem> findVisibleForApplication(final String applicationId) {
        return findApplicationLevel(applicationId, ConfigScope.APPLICATION)
                .map(List::of)
                .orElseGet(List::of);
    }

    /**
     * Find the configuration store records visible in the activation scope for the given activation.
     *
     * @param applicationId Application ID.
     * @param activationId Activation ID.
     * @return List of decrypted activation-scope config store records.
     */
    @Transactional(readOnly = true)
    public List<ConfigStoreItem> findVisibleForActivation(final String applicationId, final String activationId) {
        return decryptAll(configStoreRepository.findVisibleForActivation(applicationId, activationId));
    }

    /**
     * Find the per-activation configuration store record for the given activation.
     *
     * @param activationId Activation ID.
     * @return Optional decrypted per-activation config store record.
     */
    @Transactional(readOnly = true)
    public Optional<ConfigStoreItem> findByActivationId(final String activationId) {
        return configStoreRepository.findByActivationId(activationId)
                .flatMap(this::convert);
    }

    /**
     * Find the application-level configuration store record for the given application and scope.
     *
     * @param applicationId Application ID.
     * @param scope Configuration scope.
     * @return Optional decrypted application-level config store record.
     */
    @Transactional(readOnly = true)
    public Optional<ConfigStoreItem> findApplicationLevel(final String applicationId, final ConfigScope scope) {
        return configStoreRepository.findByApplicationAndScope(applicationId, scope)
                .flatMap(this::convert);
    }

    /**
     * Find all application-level configuration store records for the given application.
     *
     * @param applicationId Application ID.
     * @return List of decrypted application-level config store records.
     */
    @Transactional(readOnly = true)
    public List<ConfigStoreItem> findAllForApplication(final String applicationId) {
        return decryptAll(configStoreRepository.findAllForApplication(applicationId));
    }

    /**
     * Create or update a configuration store record, encrypting the {@code config_data} document at rest.
     *
     * @param source Decrypted config store wrapper to persist.
     * @throws GenericServiceException Thrown in case encryption fails.
     */
    @Transactional
    public void createOrUpdate(final ConfigStoreItem source) throws GenericServiceException {
        configStoreRepository.save(convert(source));
    }

    /**
     * Delete the per-activation configuration store record bound to the given activation.
     *
     * @param activationId Activation ID.
     */
    @Transactional
    public void deleteByActivationId(final String activationId) {
        configStoreRepository.deleteByActivationId(activationId);
    }

    /**
     * Decrypt a list of entities.
     */
    private List<ConfigStoreItem> decryptAll(final List<ConfigStoreEntity> entities) {
        return entities.stream()
                .map(this::convert)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .toList();
    }

    /**
     * Convert a decrypted wrapper into an entity, encrypting the {@code config_data} document at rest.
     */
    private ConfigStoreEntity convert(final ConfigStoreItem source) throws GenericServiceException {
        final ConfigStoreEntity entity = new ConfigStoreEntity();
        entity.setRid(source.id());
        entity.setApplication(source.application());
        entity.setActivation(source.activation());
        entity.setScope(source.scope());

        final boolean isNew = source.id() == null;
        entity.setTimestampCreated(isNew || source.timestampCreated() == null ? new Date() : source.timestampCreated());
        entity.setTimestampLastUpdated(isNew ? null : new Date());

        final EncryptionKeySupplier keySupplier = encryptionKeySupplier(entity);
        final EncryptableString encrypted = encryptionService.encrypt(source.configData(), keySupplier, encryptionService.getDefaultEncryptionAlgorithm());
        entity.setConfigData(encrypted.encryptedData());
        entity.setEncryptionAlgorithm(encrypted.encryptionAlgorithm());
        return entity;
    }

    /**
     * Convert an entity into a decrypted wrapper, decrypting the {@code config_data} document. Returns an
     * empty optional if the record cannot be decrypted.
     */
    private Optional<ConfigStoreItem> convert(final ConfigStoreEntity source) {
        try {
            final EncryptionKeySupplier keySupplier = encryptionKeySupplier(source);
            final String configData = encryptionService.decrypt(source.getConfigData(), keySupplier, source.getEncryptionAlgorithm());
            return Optional.of(ConfigStoreItem.builder()
                    .id(source.getRid())
                    .application(source.getApplication())
                    .activation(source.getActivation())
                    .scope(source.getScope())
                    .configData(configData)
                    .timestampCreated(source.getTimestampCreated())
                    .timestampLastUpdated(source.getTimestampLastUpdated())
                    .build());
        } catch (GenericServiceException e) {
            logger.error("Error while decrypting config store record ID: {}", source.getRid(), e);
            return Optional.empty();
        }
    }

    /**
     * Build the per-record encryption key supplier: the key is derived from the application and,
     * for per-device records, additionally from the activation, so each record is encrypted with a distinct key.
     */
    private static EncryptionKeySupplier encryptionKeySupplier(final ConfigStoreEntity source) {
        final String applicationId = source.getApplication().getId();
        final String scope = source.getScope().name();
        final ActivationRecordEntity activation = source.getActivation();
        if (activation != null) {
            final String activationId = activation.getActivationId();
            return new DefaultEncryptionKeySupplier(
                    List.of(applicationId, activationId),
                    List.of("pa_config_store", "config_data", applicationId, scope, activationId)
            );
        }
        return new DefaultEncryptionKeySupplier(
                List.of(applicationId),
                List.of("pa_config_store", "config_data", applicationId, scope)
        );
    }

    /**
     * Decrypted wrapper of {@link ConfigStoreEntity}.
     *
     * @param id Config store record identifier ({@code null} for a new record).
     * @param application Owning an application entity.
     * @param activation Owning activation entity, or {@code null} for an application-level record.
     * @param scope Configuration scope.
     * @param configData Decrypted configuration JSON document.
     * @param timestampCreated Record creation timestamp.
     * @param timestampLastUpdated Record last-update timestamp.
     */
    @Builder(toBuilder = true)
    public record ConfigStoreItem(
            Long id,
            ApplicationEntity application,
            ActivationRecordEntity activation,
            ConfigScope scope,
            String configData,
            Date timestampCreated,
            Date timestampLastUpdated) {
    }

}
