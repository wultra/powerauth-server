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
package io.getlime.security.powerauth.app.server.service.behavior.tasks;

import com.wultra.security.powerauth.client.model.entity.ApplicationConfigurationItem;
import com.wultra.security.powerauth.client.model.request.CreateApplicationConfigRequest;
import com.wultra.security.powerauth.client.model.request.GetApplicationConfigRequest;
import com.wultra.security.powerauth.client.model.request.RemoveApplicationConfigRequest;
import com.wultra.security.powerauth.client.model.response.CreateApplicationConfigResponse;
import com.wultra.security.powerauth.client.model.response.GetApplicationConfigResponse;
import io.getlime.core.rest.model.base.response.Response;
import io.getlime.security.powerauth.app.server.database.model.entity.ApplicationConfigEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import io.getlime.security.powerauth.app.server.database.repository.ApplicationConfigRepository;
import io.getlime.security.powerauth.app.server.database.repository.ApplicationRepository;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.app.server.service.persistence.ApplicationConfigService;
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

    private static final String CONFIG_KEY_OAUTH2_PROVIDERS = "oauth2_providers";

    private static final Set<String> ALLOWED_CONFIGURATION_KEYS = Set.of(
            CONFIG_KEY_ALLOWED_ATTESTATION_FMT, CONFIG_KEY_ALLOWED_AAGUIDS, CONFIG_KEY_ROOT_CA_CERTS, CONFIG_KEY_OAUTH2_PROVIDERS);

    private final LocalizationProvider localizationProvider;
    private final ApplicationConfigService applicationConfigService;
    private final ApplicationRepository applicationRepository;
    private final ApplicationConfigRepository applicationConfigRepository;

    /**
     * Get application configuration.
     * @param request Request for obtaining an application configuration.
     * @return Get application configuration response.
     * @throws GenericServiceException In case of a business logic error.
     */
    @Transactional(readOnly = true)
    public GetApplicationConfigResponse getApplicationConfig(final GetApplicationConfigRequest request) throws GenericServiceException {
        try {
            final String applicationId = request.getApplicationId();
            if (applicationId == null) {
                logger.warn("Invalid application ID in getApplicationConfig");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
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
            if (applicationId == null) {
                logger.warn("Invalid application ID in createApplicationConfig");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
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
     * @return Response.
     * @throws GenericServiceException In case of a business logic error.
     */
    @Transactional
    public Response removeApplicationConfig(final RemoveApplicationConfigRequest request) throws GenericServiceException {
        try {
            final String applicationId = request.getApplicationId();
            final String key = request.getKey();
            if (applicationId == null) {
                logger.warn("Invalid application ID in deleteApplicationConfig");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            validateConfigKey(key);
            final Optional<ApplicationEntity> appOptional = applicationRepository.findById(applicationId);
            if (appOptional.isEmpty()) {
                logger.info("Application not found, application ID: {}", applicationId);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
            }
            final List<ApplicationConfigEntity> configs = applicationConfigRepository.findByApplicationId(applicationId);
            configs.stream().filter(config -> config.getKey().equals(key)).forEach(applicationConfigRepository::delete);
            return new Response();
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
        if (key == null) {
            logger.warn("Missing configuration key in request");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        if (!ALLOWED_CONFIGURATION_KEYS.contains(key)) {
            logger.warn("Unknown configuration key in request: {}", key);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
    }

}
