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
package com.wultra.security.powerauth.app.server.service.behavior.tasks;

import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationConfigEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import com.wultra.security.powerauth.app.server.database.repository.ApplicationConfigRepository;
import com.wultra.security.powerauth.app.server.database.repository.ApplicationRepository;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.persistence.ApplicationConfigService;
import com.wultra.security.powerauth.client.model.entity.ApplicationConfigurationItem;
import com.wultra.security.powerauth.client.model.request.CreateApplicationConfigRequest;
import com.wultra.security.powerauth.client.model.request.GetApplicationConfigRequest;
import com.wultra.security.powerauth.client.model.request.RemoveApplicationConfigRequest;
import com.wultra.security.powerauth.client.model.response.CreateApplicationConfigResponse;
import com.wultra.security.powerauth.client.model.response.GetApplicationConfigResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static com.wultra.powerauth.fido2.rest.model.enumeration.Fido2ConfigKeys.*;

/**
 * Behavior class implementing management of application configuration.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
@AllArgsConstructor
public class ApplicationConfigServiceBehavior {

    public static final String CONFIG_DISABLE_BIOMETRY_UNLOCK_KEK_DEVICE_PRIVATE = "disable_biometry_unlock_kek_device_private";
    public static final String CONFIG_KEY_OAUTH2_PROVIDERS = "oauth2_providers";
    public static final String CONFIG_KEY_ACTIVATION_TRANSFER = "activation_transfer";

    private static final Set<String> ALLOWED_CONFIGURATION_KEYS = Set.of(
            CONFIG_KEY_ALLOWED_ATTESTATION_FMT, CONFIG_KEY_ALLOWED_AAGUIDS, CONFIG_KEY_ROOT_CA_CERTS,
            CONFIG_KEY_OAUTH2_PROVIDERS, CONFIG_DISABLE_BIOMETRY_UNLOCK_KEK_DEVICE_PRIVATE,
            CONFIG_KEY_ACTIVATION_TRANSFER);

    private final LocalizationProvider localizationProvider;
    private final ApplicationConfigService applicationConfigService;
    private final ApplicationRepository applicationRepository;
    private final ApplicationConfigRepository applicationConfigRepository;

    /**
     * Get application configuration.
     * @param request Request for obtaining an application configuration.
     * @return Get application configuration response.
     */
    @Transactional(readOnly = true)
    public GetApplicationConfigResponse getApplicationConfig(final GetApplicationConfigRequest request) {
        try {
            final String applicationId = request.getApplicationId();
            final List<ApplicationConfigService.ApplicationConfig> applicationConfigs = applicationConfigService.findByApplicationId(applicationId);
            final GetApplicationConfigResponse response = new GetApplicationConfigResponse();
            response.setApplicationId(applicationId);
            final List<ApplicationConfigurationItem> responseConfigs = new ArrayList<>();
            applicationConfigs.forEach(config -> {
                final ApplicationConfigurationItem item = new ApplicationConfigurationItem();
                item.setKey(config.key());
                item.setValues(config.values());
                responseConfigs.add(item);
            });
            response.setApplicationConfigs(responseConfigs);
            return response;
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        }
    }

    /**
     * Create an application configuration.
     * @param request Request for creating application configuration
     * @return Create application configuration response.
     * @throws GenericServiceException In case of a business logic error.
     */
    @Transactional
    public CreateApplicationConfigResponse createApplicationConfig(final CreateApplicationConfigRequest request) throws GenericServiceException {
        try {
            final String applicationId = request.getApplicationId();
            final String key = request.getKey();
            final List<Object> values = request.getValues();
            validateConfigKey(key);
            final ApplicationEntity application = applicationRepository.findById(applicationId).orElseThrow(() -> {
                logger.info("Application not found, application ID: {}", applicationId);
                // Rollback is not required, error occurs before writing to database
                return localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
            });
            final Optional<ApplicationConfigService.ApplicationConfig> matchedConfig = applicationConfigService.findByApplicationId(applicationId).stream()
                    .filter(config -> config.key().equals(key))
                    .findFirst();
            if (matchedConfig.isPresent()) {
                final ApplicationConfigService.ApplicationConfig existing = matchedConfig.get();
                applicationConfigService.createOrUpdate(new ApplicationConfigService.ApplicationConfig(existing.id(), existing.application(), existing.key(), values));
            } else {
                applicationConfigService.createOrUpdate(new ApplicationConfigService.ApplicationConfig(null, application, key, values));
            }

            final CreateApplicationConfigResponse response = new CreateApplicationConfigResponse();
            response.setApplicationId(applicationId);
            response.setKey(key);
            response.setValues(values);
            return response;
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        }
    }

    /**
     * Delete an application configuration.
     * @param request Remove application config request.
     * @throws GenericServiceException In case of a business logic error.
     */
    @Transactional
    public void removeApplicationConfig(final RemoveApplicationConfigRequest request) throws GenericServiceException {
        try {
            final String applicationId = request.getApplicationId();
            final String key = request.getKey();
            validateConfigKey(key);
            final Optional<ApplicationEntity> appOptional = applicationRepository.findById(applicationId);
            if (appOptional.isEmpty()) {
                logger.info("Application not found, application ID: {}", applicationId);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
            }
            final List<ApplicationConfigEntity> configs = applicationConfigRepository.findByApplicationId(applicationId);
            configs.stream().filter(config -> config.getKey().equals(key)).forEach(applicationConfigRepository::delete);
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        }
    }

    /**
     * Validate that the configuration key is valid.
     * @param key Configuration key.
     * @throws GenericServiceException Thrown in case configuration key is invalid.
     */
    private void validateConfigKey(String key) throws GenericServiceException {
        if (!ALLOWED_CONFIGURATION_KEYS.contains(key)) {
            logger.warn("Unknown configuration key in request: {}", key);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
    }

}
