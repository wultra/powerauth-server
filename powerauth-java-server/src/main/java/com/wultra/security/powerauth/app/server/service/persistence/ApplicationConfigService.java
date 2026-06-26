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
 */
package com.wultra.security.powerauth.app.server.service.persistence;

import com.wultra.security.powerauth.app.server.database.model.converter.ListToJsonConverter;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationConfigEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import com.wultra.security.powerauth.app.server.database.repository.ApplicationConfigRepository;
import com.wultra.security.powerauth.app.server.service.encryption.*;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

/**
 * Service for application configuration.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@Service
@Slf4j
@AllArgsConstructor
public class ApplicationConfigService {

    private final ApplicationConfigRepository applicationConfigRepository;
    private final ListToJsonConverter listToJsonConverter;
    private final DatabaseEncryptionService encryptionService;

    /**
     * Find application configuration by application ID.
     *
     * @param applicationId Application ID.
     * @param key Config key.
     * @return Application config or empty.
     */
    @Transactional(readOnly = true)
    public Optional<ApplicationConfig> findByApplicationIdAndKey(final String applicationId, final String key) {
        return applicationConfigRepository.findByApplicationIdAndKey(applicationId, key)
                .map(this::convert);
    }

    /**
     * Find application configurations by application ID.
     *
     * @param applicationId Application ID.
     * @return List of application config entities.
     */
    @Transactional(readOnly = true)
    public List<ApplicationConfig> findByApplicationId(final String applicationId) {
        return applicationConfigRepository.findByApplicationId(applicationId).stream()
                .map(this::convert)
                .toList();
    }

    @Transactional
    public void createOrUpdate(final ApplicationConfig source) throws GenericServiceException {
        applicationConfigRepository.save(convert(source));
    }

    private ApplicationConfigEntity convert(final ApplicationConfig source) throws GenericServiceException {
        final ApplicationConfigEntity entity = new ApplicationConfigEntity();
        entity.setId(source.id());
        entity.setApplication(source.application());
        entity.setKey(source.key());

        final String plaintext = listToJsonConverter.convertToDatabaseColumn(source.values());
        final EncryptionKeySupplier encryptionKeySupplier = encryptionKeySupplier(entity);
        final EncryptableString encrypted = encryptionService.encrypt(plaintext, encryptionKeySupplier, encryptionService.getDefaultEncryptionAlgorithm());
        entity.setValues(encrypted.encryptedData());
        entity.setEncryptionAlgorithm(encrypted.encryptionAlgorithm());
        return entity;
    }

    private ApplicationConfig convert(final ApplicationConfigEntity source) {
        try {
            final EncryptionKeySupplier keySupplier = encryptionKeySupplier(source);
            final String decrypted = encryptionService.decrypt(source.getValues(), keySupplier, source.getEncryptionAlgorithm());
            final List<Object> values = listToJsonConverter.convertToEntityAttribute(decrypted);
            return new ApplicationConfig(source.getId(), source.getApplication(), source.getKey(), values);
        } catch (GenericServiceException e) {
            logger.warn("Problem decrypting config ID: {}", source.getId());
            return null;
        }
    }

    private static EncryptionKeySupplier encryptionKeySupplier(final ApplicationConfigEntity source) {
        return new DefaultEncryptionKeySupplier(
                List.of(source.getApplication().getId()),
                List.of("pa_application_config", "config_values", source.getApplication().getId())
        );
    }

    /**
     * Decrypted wrapper of {@link ApplicationConfigEntity}.
     *
     * @param id Application config identifier.
     * @param application Application entity.
     * @param key Configuration key.
     * @param values Configuration values.
     */
    public record ApplicationConfig(
            Long id,
            ApplicationEntity application,
            String key,
            List<Object> values) {}
}
