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

import com.wultra.security.powerauth.client.model.response.AddActivationFlagsResponse;
import com.wultra.security.powerauth.client.model.response.ListActivationFlagsResponse;
import com.wultra.security.powerauth.client.model.response.RemoveActivationFlagsResponse;
import com.wultra.security.powerauth.client.model.response.UpdateActivationFlagsResponse;
import io.getlime.security.powerauth.app.server.database.RepositoryCatalogue;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.repository.ActivationRepository;
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
import java.util.stream.Collectors;

/**
 * Behavior class implementing management of activation flags.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component("activationFlagsServiceBehavior")
public class ActivationFlagsServiceBehavior {

    private static final Logger logger = LoggerFactory.getLogger(ActivationFlagsServiceBehavior.class);

    private final RepositoryCatalogue repositoryCatalogue;
    private final LocalizationProvider localizationProvider;

    @Autowired
    public ActivationFlagsServiceBehavior(RepositoryCatalogue repositoryCatalogue, LocalizationProvider localizationProvider) {
        this.repositoryCatalogue = repositoryCatalogue;
        this.localizationProvider = localizationProvider;
    }

    /**
     * List activation flags.
     * @param activationId Activation ID.
     * @return List activation flags response.
     * @throws GenericServiceException In case of a business logic error.
     */
    public ListActivationFlagsResponse listActivationFlags(String activationId) throws GenericServiceException {
        if (activationId == null || activationId.isEmpty()) {
            logger.warn("Missing activation ID in listActivationFlags");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        final ListActivationFlagsResponse response = new ListActivationFlagsResponse();
        final ActivationRecordEntity activation = repositoryCatalogue.getActivationRepository().findActivationWithoutLock(activationId);
        if (activation == null) {
            logger.info("Activation not found, activation ID: {}", activationId);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
        }
        response.setActivationId(activationId);
        response.getActivationFlags().addAll(activation.getFlags());
        return response;
    }

    /**
     * Add activation flags.
     * @param activationId Activation ID.
     * @param activationFlags Activation flags.
     * @return Add activation flags response.
     * @throws GenericServiceException In case of a business logic error.
     */
    public AddActivationFlagsResponse addActivationFlags(String activationId, List<String> activationFlags) throws GenericServiceException {
        if (activationId == null || activationId.isEmpty()) {
            logger.info("Missing activation ID for adding activation flags");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        final AddActivationFlagsResponse response = new AddActivationFlagsResponse();
        final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();
        response.setActivationId(activationId);
        final ActivationRecordEntity activation = activationRepository.findActivationWithLock(activationId);
        if (activation == null) {
            logger.info("Activation not found, activation ID: {}", activationId);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
        }
        final List<String> currentFlags = activation.getFlags();
        final List<String> newFlags = activationFlags.stream().filter(flag -> !currentFlags.contains(flag)).collect(Collectors.toList());
        final List<String> allFlags = new ArrayList<>(currentFlags);
        allFlags.addAll(newFlags);
        Collections.sort(allFlags);
        activation.getFlags().clear();
        activation.getFlags().addAll(allFlags);
        activationRepository.save(activation);
        response.getActivationFlags().addAll(activation.getFlags());
        return response;
    }

    /**
     * Update activation flags.
     * @param activationId Activation ID.
     * @param activationFlags Activation flags.
     * @return Update activation flags response.
     * @throws GenericServiceException In case of a business logic error.
     */
    public UpdateActivationFlagsResponse updateActivationFlags(String activationId, List<String> activationFlags) throws GenericServiceException {
        if (activationId == null || activationId.isEmpty()) {
            logger.info("Missing activation ID for updating activation flags");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        final UpdateActivationFlagsResponse response = new UpdateActivationFlagsResponse();
        final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();
        response.setActivationId(activationId);
        final ActivationRecordEntity activation = activationRepository.findActivationWithLock(activationId);
        if (activation == null) {
            logger.info("Activation not found, activation ID: {}", activationId);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
        }
        Collections.sort(activationFlags);
        activation.getFlags().clear();
        activation.getFlags().addAll(activationFlags);
        activationRepository.save(activation);
        response.getActivationFlags().addAll(activationFlags);
        return response;
    }

    /**
     * Delete activation flags.
     * @param activationId Activation ID.
     * @param activationFlags Activation flags.
     * @return Delete activation flags response.
     * @throws GenericServiceException In case of a business logic error.
     */
    public RemoveActivationFlagsResponse removeActivationFlags(String activationId, List<String> activationFlags) throws GenericServiceException {
        if (activationId == null || activationId.isEmpty()) {
            logger.info("Missing activation ID for deleting activation flags");
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        final RemoveActivationFlagsResponse response = new RemoveActivationFlagsResponse();
        final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();
        response.setActivationId(activationId);
        final ActivationRecordEntity activation = activationRepository.findActivationWithLock(activationId);
        if (activation == null) {
            logger.info("Activation not found, activation ID: {}", activationId);
            // Rollback is not required, error occurs before writing to database
            throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
        }
        activation.getFlags().removeAll(activationFlags);
        activationRepository.save(activation);
        response.getActivationFlags().addAll(activation.getFlags());
        return response;
    }

}
