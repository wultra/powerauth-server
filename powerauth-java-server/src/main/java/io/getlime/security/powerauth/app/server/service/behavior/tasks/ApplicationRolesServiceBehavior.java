/*
 * PowerAuth Server and related software components
 * Copyright (C) 2021 Wultra s.r.o.
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Behavior class implementing management of application roles.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component("applicationRolesServiceBehavior")
public class ApplicationRolesServiceBehavior {

    private static final Logger logger = LoggerFactory.getLogger(ApplicationRolesServiceBehavior.class);

    private final RepositoryCatalogue repositoryCatalogue;
    private final LocalizationProvider localizationProvider;

    @Autowired
    public ApplicationRolesServiceBehavior(RepositoryCatalogue repositoryCatalogue, LocalizationProvider localizationProvider) {
        this.repositoryCatalogue = repositoryCatalogue;
        this.localizationProvider = localizationProvider;
    }

    /**
     * List application roles.
     * @param applicationId Application ID.
     * @return List application roles response.
     * @throws GenericServiceException In case of a business logic error.
     */
    public ListApplicationRolesResponse listApplicationRoles(long applicationId) throws GenericServiceException {
        if (applicationId <= 0) {
            logger.warn("Invalid application ID in listApplicationRoles");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        final Optional<ApplicationEntity> applicationOptional = repositoryCatalogue.getApplicationRepository().findById(applicationId);
        if (!applicationOptional.isPresent()) {
            logger.info("Application not found, application ID: {}", applicationId);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
        }
        final ApplicationEntity application = applicationOptional.get();
        final ListApplicationRolesResponse response = new ListApplicationRolesResponse();
        response.getApplicationRoles().addAll(application.getRoles());
        return response;
    }

    /**
     * Add application roles.
     * @param applicationId Application ID.
     * @param applicationRoles Application roles.
     * @return Add application roles response.
     * @throws GenericServiceException In case of a business logic error.
     */
    public AddApplicationRolesResponse addApplicationRoles(long applicationId, List<String> applicationRoles) throws GenericServiceException {
        if (applicationId <= 0) {
            logger.warn("Invalid application ID in addApplicationRoles");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        final ApplicationRepository applicationRepository = repositoryCatalogue.getApplicationRepository();
        final Optional<ApplicationEntity> applicationOptional =  applicationRepository.findById(applicationId);
        if (!applicationOptional.isPresent()) {
            logger.info("Application not found, application ID: {}", applicationId);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
        }
        final ApplicationEntity application = applicationOptional.get();
        final List<String> currentRoles = application.getRoles();
        final List<String> newRoles = applicationRoles.stream().filter(role -> !currentRoles.contains(role)).collect(Collectors.toList());
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
    }

    /**
     * Update application roles.
     * @param applicationId Application ID.
     * @param applicationRoles Application roles.
     * @return Update application roles response.
     * @throws GenericServiceException In case of a business logic error.
     */
    public UpdateApplicationRolesResponse updateApplicationRoles(long applicationId, List<String> applicationRoles) throws GenericServiceException {
        if (applicationId <= 0) {
            logger.warn("Invalid application ID in updateApplicationRoles");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        final UpdateApplicationRolesResponse response = new UpdateApplicationRolesResponse();
        final ApplicationRepository applicationRepository = repositoryCatalogue.getApplicationRepository();
        response.setApplicationId(applicationId);
        final Optional<ApplicationEntity> applicationOptional =  applicationRepository.findById(applicationId);
        if (!applicationOptional.isPresent()) {
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
    }

    /**
     * Delete application roles.
     * @param applicationId Application ID.
     * @param applicationRoles Application roles.
     * @return Delete application roles response.
     * @throws GenericServiceException In case of a business logic error.
     */
    public RemoveApplicationRolesResponse removeApplicationRoles(long applicationId, List<String> applicationRoles) throws GenericServiceException {
        if (applicationId <= 0) {
            logger.warn("Invalid application ID in removeApplicationRoles");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        final ApplicationRepository applicationRepository = repositoryCatalogue.getApplicationRepository();
        final Optional<ApplicationEntity> applicationOptional =  applicationRepository.findById(applicationId);
        if (!applicationOptional.isPresent()) {
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
    }

}
