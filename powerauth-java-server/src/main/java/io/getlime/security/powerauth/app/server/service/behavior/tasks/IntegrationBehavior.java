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
 */
package io.getlime.security.powerauth.app.server.service.behavior.tasks;

import com.wultra.security.powerauth.client.model.entity.Integration;
import com.wultra.security.powerauth.client.model.request.CreateIntegrationRequest;
import com.wultra.security.powerauth.client.model.request.RemoveIntegrationRequest;
import com.wultra.security.powerauth.client.model.response.CreateIntegrationResponse;
import com.wultra.security.powerauth.client.model.response.GetIntegrationListResponse;
import com.wultra.security.powerauth.client.model.response.RemoveIntegrationResponse;
import io.getlime.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import io.getlime.security.powerauth.app.server.database.model.entity.IntegrationEntity;
import io.getlime.security.powerauth.app.server.database.repository.IntegrationRepository;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

/**
 * Class that manages the service logic related to integration management.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Service
@Slf4j
public class IntegrationBehavior {

    private final IntegrationRepository integrationRepository;
    private final LocalizationProvider localizationProvider;
    private PowerAuthServiceConfiguration configuration;

    @Autowired
    public IntegrationBehavior(IntegrationRepository integrationRepository, LocalizationProvider localizationProvider) {
        this.integrationRepository = integrationRepository;
        this.localizationProvider = localizationProvider;
    }

    @Autowired
    public void setConfiguration(PowerAuthServiceConfiguration configuration) {
        this.configuration = configuration;
    }

    /**
     * Creates a new integration record for application with given name, and automatically generates credentials.
     * @param request CreateIntegraionRequest instance specifying name of new integration.
     * @return Newly created integration information.
     */
    @Transactional
    public CreateIntegrationResponse createIntegration(CreateIntegrationRequest request) throws GenericServiceException {
        try {
            if (request.getName() == null) {
                logger.warn("Invalid request parameter name in method createIntegration");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }

            final IntegrationEntity entity = new IntegrationEntity();
            entity.setName(request.getName());
            entity.setId(UUID.randomUUID().toString());
            entity.setClientToken(UUID.randomUUID().toString());
            entity.setClientSecret(UUID.randomUUID().toString());
            integrationRepository.save(entity);
            final CreateIntegrationResponse response = new CreateIntegrationResponse();
            response.setId(entity.getId());
            response.setName(entity.getName());
            response.setClientToken(entity.getClientToken());
            response.setClientSecret(entity.getClientSecret());
            return response;
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    /**
     * Get the list of all current integrations.
     * @return List of all current integrations.
     */
    @Transactional(readOnly = true)
    public GetIntegrationListResponse getIntegrationList() throws GenericServiceException {
        try {
            final Iterable<IntegrationEntity> integrations = integrationRepository.findAll();
            final GetIntegrationListResponse response = new GetIntegrationListResponse();
            response.setRestrictedAccess(configuration.getRestrictAccess());
            for (IntegrationEntity i : integrations) {
                final Integration item = new Integration();
                item.setId(i.getId());
                item.setName(i.getName());
                item.setClientToken(i.getClientToken());
                item.setClientSecret(i.getClientSecret());
                response.getItems().add(item);
            }
            return response;
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

    /**
     * Remove integration with given ID.
     * @param request Request specifying the integration to be removed.
     * @return Information about removal status.
     */
    @Transactional
    public RemoveIntegrationResponse removeIntegration(RemoveIntegrationRequest request) throws GenericServiceException {
        try {
            final RemoveIntegrationResponse response = new RemoveIntegrationResponse();
            response.setId(request.getId());
            final Optional<IntegrationEntity> integrationEntityOptional = integrationRepository.findById(request.getId());
            if (integrationEntityOptional.isPresent()) {
                integrationRepository.delete(integrationEntityOptional.get());
                response.setRemoved(true);
            } else {
                response.setRemoved(false);
            }
            return response;
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage(), ex.getLocalizedMessage());
        }
    }

}
