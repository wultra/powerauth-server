/*
 * PowerAuth Server and related software components
 * Copyright (C) 2020 Wultra s.r.o.
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

import com.wultra.core.audit.base.model.AuditDetail;
import com.wultra.core.audit.base.model.AuditLevel;
import com.wultra.security.powerauth.client.model.request.AddActivationFlagsRequest;
import com.wultra.security.powerauth.client.model.request.ListActivationFlagsRequest;
import com.wultra.security.powerauth.client.model.request.RemoveActivationFlagsRequest;
import com.wultra.security.powerauth.client.model.request.UpdateActivationFlagsRequest;
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
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Behavior class implementing management of activation flags.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
public class ActivationFlagsServiceBehavior {

    private final RepositoryCatalogue repositoryCatalogue;
    private final LocalizationProvider localizationProvider;
    private final AuditingServiceBehavior audit;

    @Autowired
    public ActivationFlagsServiceBehavior(RepositoryCatalogue repositoryCatalogue, LocalizationProvider localizationProvider, AuditingServiceBehavior audit) {
        this.repositoryCatalogue = repositoryCatalogue;
        this.localizationProvider = localizationProvider;
        this.audit = audit;
    }

    /**
     * List activation flags.
     * @param request Request with activation ID.
     * @return List activation flags response.
     * @throws GenericServiceException In case of a business logic error.
     */
    @Transactional
    public ListActivationFlagsResponse listActivationFlags(ListActivationFlagsRequest request) throws GenericServiceException {
        try {
            final String activationId = request.getActivationId();
            if (activationId == null || activationId.isEmpty()) {
                logger.warn("Missing activation ID in listActivationFlags");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            final ActivationRecordEntity activation = repositoryCatalogue.getActivationRepository().findActivationWithoutLock(activationId);
            if (activation == null) {
                logger.info("Activation not found, activation ID: {}", activationId);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            }
            final ListActivationFlagsResponse response = new ListActivationFlagsResponse();
            response.setActivationId(activationId);
            response.getActivationFlags().addAll(activation.getFlags());
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
     * Add activation flags.
     * @param request Request with activation ID and activation flags.
     * @return Add activation flags response.
     * @throws GenericServiceException In case of a business logic error.
     */
    @Transactional
    public AddActivationFlagsResponse addActivationFlags(AddActivationFlagsRequest request) throws GenericServiceException {
        try {
            final String activationId = request.getActivationId();
            final List<String> activationFlags = request.getActivationFlags();
            if (activationId == null) {
                logger.warn("Invalid request parameter activationId in method addActivationFlags");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            if (activationFlags == null || activationFlags.isEmpty()) {
                logger.warn("Invalid request parameter activationFlags in method addActivationFlags");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();
            final ActivationRecordEntity activation = activationRepository.findActivationWithLock(activationId);
            if (activation == null) {
                logger.info("Activation not found, activation ID: {}", activationId);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            }
            final List<String> currentFlags = activation.getFlags();
            final List<String> newFlags = activationFlags.stream().filter(flag -> !currentFlags.contains(flag)).collect(Collectors.toList());
            if (!newFlags.isEmpty()) { // only in case there are new flags
                final AuditDetail auditDetail = AuditDetail.builder()
                        .type(AuditType.ACTIVATION.getCode())
                        .param("activationId", activationId)
                        .param("flags", newFlags)
                        .param("addedFlags", activationFlags)
                        .build();
                audit.log(AuditLevel.INFO, "Adding activation flags: {} to activation {}", auditDetail, newFlags, activationId);
                final List<String> allFlags = new ArrayList<>(currentFlags);
                allFlags.addAll(newFlags);
                Collections.sort(allFlags);
                activation.getFlags().clear();
                activation.getFlags().addAll(allFlags);
                activationRepository.save(activation);
            }
            final AddActivationFlagsResponse response = new AddActivationFlagsResponse();
            response.setActivationId(activationId);
            response.getActivationFlags().addAll(activation.getFlags());
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
     * Update activation flags.
     * @param request Request with activation ID and activation flags.
     * @return Update activation flags response.
     * @throws GenericServiceException In case of a business logic error.
     */
    @Transactional
    public UpdateActivationFlagsResponse updateActivationFlags(UpdateActivationFlagsRequest request) throws GenericServiceException {
        try {
            final String activationId = request.getActivationId();
            final List<String> activationFlags = request.getActivationFlags();
            if (activationId == null || activationId.isEmpty()) {
                logger.warn("Invalid request parameter activationId in method updateActivationFlags");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            if (activationFlags == null || activationFlags.isEmpty()) {
                logger.warn("Invalid request parameter activationFlags in method updateActivationFlags");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();
            final ActivationRecordEntity activation = activationRepository.findActivationWithLock(activationId);
            if (activation == null) {
                logger.info("Activation not found, activation ID: {}", activationId);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            }
            final AuditDetail auditDetail = AuditDetail.builder()
                    .type(AuditType.ACTIVATION.getCode())
                    .param("activationId", activationId)
                    .param("flags", activationFlags)
                    .build();
            audit.log(AuditLevel.INFO, "Setting new activation flags: {} to activation {}", auditDetail, activationFlags, activationId);
            Collections.sort(activationFlags);
            activation.getFlags().clear();
            activation.getFlags().addAll(activationFlags);
            activationRepository.save(activation);

            final UpdateActivationFlagsResponse response = new UpdateActivationFlagsResponse();
            response.setActivationId(activationId);
            response.getActivationFlags().addAll(activationFlags);
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
     * Delete activation flags.
     * @param request Request with activation ID and activation flags.
     * @return Delete activation flags response.
     * @throws GenericServiceException In case of a business logic error.
     */
    @Transactional
    public RemoveActivationFlagsResponse removeActivationFlags(RemoveActivationFlagsRequest request) throws GenericServiceException {
        try {
            final String activationId = request.getActivationId();
            final List<String> activationFlags = request.getActivationFlags();
            if (activationId == null || activationId.isEmpty()) {
                logger.warn("Invalid request parameter activationId in method removeActivationFlags");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            if (activationFlags == null || activationFlags.isEmpty()) {
                logger.warn("Invalid request parameter activationFlags in method removeActivationFlags");
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            final ActivationRepository activationRepository = repositoryCatalogue.getActivationRepository();
            final ActivationRecordEntity activation = activationRepository.findActivationWithLock(activationId);
            if (activation == null) {
                logger.info("Activation not found, activation ID: {}", activationId);
                // Rollback is not required, error occurs before writing to database
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            }
            final AuditDetail auditDetail = AuditDetail.builder()
                    .type(AuditType.ACTIVATION.getCode())
                    .param("activationId", activationId)
                    .param("removedFlags", activationFlags)
                    .build();
            audit.log(AuditLevel.INFO, "Removing activation flags: {} from activation {}", auditDetail, activationFlags, activationId);
            activation.getFlags().removeAll(activationFlags);
            activationRepository.save(activation);

            final RemoveActivationFlagsResponse response = new RemoveActivationFlagsResponse();
            response.setActivationId(activationId);
            response.getActivationFlags().addAll(activation.getFlags());
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
