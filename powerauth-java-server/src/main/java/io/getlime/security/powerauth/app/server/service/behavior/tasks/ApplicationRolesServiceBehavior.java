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

import com.wultra.security.powerauth.client.model.request.AddApplicationRolesRequest;
import com.wultra.security.powerauth.client.model.request.ListApplicationRolesRequest;
import com.wultra.security.powerauth.client.model.request.RemoveApplicationRolesRequest;
import com.wultra.security.powerauth.client.model.request.UpdateApplicationRolesRequest;
import com.wultra.security.powerauth.client.model.response.AddApplicationRolesResponse;
import com.wultra.security.powerauth.client.model.response.ListApplicationRolesResponse;
import com.wultra.security.powerauth.client.model.response.RemoveApplicationRolesResponse;
import com.wultra.security.powerauth.client.model.response.UpdateApplicationRolesResponse;
import io.getlime.security.powerauth.app.server.database.RepositoryCatalogue;
import io.getlime.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import io.getlime.security.powerauth.app.server.database.repository.ApplicationRepository;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Behavior class implementing management of application roles.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
public class ApplicationRolesServiceBehavior {

    private final RepositoryCatalogue repositoryCatalogue;
    private final LocalizationProvider localizationProvider;

    @Autowired
    public ApplicationRolesServiceBehavior(RepositoryCatalogue repositoryCatalogue, LocalizationProvider localizationProvider) {
        this.repositoryCatalogue = repositoryCatalogue;
        this.localizationProvider = localizationProvider;
    }

    /**
     * List application roles.
     * @param request Request with application ID.
     * @return List application roles response.
     * @throws GenericServiceException In case of a business logic error.
     */
    @Transactional
    public ListApplicationRolesResponse listApplicationRoles(ListApplicationRolesRequest request) throws GenericServiceException {
        try {
            final String applicationId = request.getApplicationId();
            if (applicationId == null) {
                logger.warn("Invalid application ID in listApplicationRoles");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            final Optional<ApplicationEntity> applicationOptional = repositoryCatalogue.getApplicationRepository().findById(applicationId);
            if (applicationOptional.isEmpty()) {
                logger.info("Application not found, application ID: {}", applicationId);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
            }
            final ApplicationEntity application = applicationOptional.get();
            final ListApplicationRolesResponse response = new ListApplicationRolesResponse();
            response.getApplicationRoles().addAll(application.getRoles());
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage());
        }
    }

    /**
     * Add application roles.
     * @param request Request with application ID and application roles.
     * @return Add application roles response.
     * @throws GenericServiceException In case of a business logic error.
     */
    @Transactional
    public AddApplicationRolesResponse addApplicationRoles(AddApplicationRolesRequest request) throws GenericServiceException {
        try {
            final String applicationId = request.getApplicationId();
            final List<String> applicationRoles = request.getApplicationRoles();
            if (applicationId == null) {
                logger.warn("Invalid request parameter applicationId in method addApplicationRoles");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            if (applicationRoles == null || applicationRoles.isEmpty()) {
                logger.warn("Invalid request parameter applicationRoles in method addApplicationRoles");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            final ApplicationRepository applicationRepository = repositoryCatalogue.getApplicationRepository();
            final Optional<ApplicationEntity> applicationOptional = applicationRepository.findById(applicationId);
            if (applicationOptional.isEmpty()) {
                logger.info("Application not found, application ID: {}", applicationId);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
            }
            final ApplicationEntity application = applicationOptional.get();
            final List<String> currentRoles = application.getRoles();
            final List<String> newRoles = applicationRoles.stream().filter(role -> !currentRoles.contains(role)).toList();
            final List<String> allRoles = new ArrayList<>(currentRoles);
            allRoles.addAll(newRoles);
            Collections.sort(allRoles);
            application.getRoles().clear();
            application.getRoles().addAll(allRoles);
            applicationRepository.save(application);
            final AddApplicationRolesResponse response = new AddApplicationRolesResponse();
            response.setApplicationId(applicationId);
            response.getApplicationRoles().addAll(application.getRoles());
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage());
        }
    }

    /**
     * Update application roles.
     * @param request Request with application ID and application roles.
     * @return Update application roles response.
     * @throws GenericServiceException In case of a business logic error.
     */
    @Transactional
    public UpdateApplicationRolesResponse updateApplicationRoles(UpdateApplicationRolesRequest request) throws GenericServiceException {
        try {
            final String applicationId = request.getApplicationId();
            final List<String> applicationRoles = request.getApplicationRoles();
            if (applicationId == null) {
                logger.warn("Invalid request parameter applicationId in method updateApplicationRoles");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            if (applicationRoles == null || applicationRoles.isEmpty()) {
                logger.warn("Invalid request parameter applicationRoles in method updateApplicationRoles");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            final UpdateApplicationRolesResponse response = new UpdateApplicationRolesResponse();
            final ApplicationRepository applicationRepository = repositoryCatalogue.getApplicationRepository();
            response.setApplicationId(applicationId);
            final Optional<ApplicationEntity> applicationOptional = applicationRepository.findById(applicationId);
            if (applicationOptional.isEmpty()) {
                logger.info("Application not found, application ID: {}", applicationId);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
            }
            Collections.sort(applicationRoles);
            final ApplicationEntity application = applicationOptional.get();
            application.getRoles().clear();
            application.getRoles().addAll(applicationRoles);
            applicationRepository.save(application);
            response.getApplicationRoles().addAll(applicationRoles);
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage());
        }
    }

    /**
     * Delete application roles.
     * @param request Request with application ID and application roles.
     * @return Delete application roles response.
     * @throws GenericServiceException In case of a business logic error.
     */
    @Transactional
    public RemoveApplicationRolesResponse removeApplicationRoles(RemoveApplicationRolesRequest request) throws GenericServiceException {
        try {
            final String applicationId = request.getApplicationId();
            final List<String> applicationRoles = request.getApplicationRoles();
            if (applicationId == null) {
                logger.warn("Invalid request parameter applicationId in method removeApplicationRoles");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            if (applicationRoles == null || applicationRoles.isEmpty()) {
                logger.warn("Invalid request parameter applicationRoles in method removeApplicationRoles");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            final ApplicationRepository applicationRepository = repositoryCatalogue.getApplicationRepository();
            final Optional<ApplicationEntity> applicationOptional = applicationRepository.findById(applicationId);
            if (applicationOptional.isEmpty()) {
                logger.info("Application not found, application ID: {}", applicationId);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
            }
            final ApplicationEntity application = applicationOptional.get();
            application.getRoles().removeAll(applicationRoles);
            applicationRepository.save(application);
            final RemoveApplicationRolesResponse response = new RemoveApplicationRolesResponse();
            response.setApplicationId(applicationId);
            response.getApplicationRoles().addAll(application.getRoles());
            return response;
        } catch (GenericServiceException ex) {
            // already logged
            throw ex;
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage());
        }
    }

}
