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

import com.wultra.security.powerauth.client.model.request.OperationTemplateCreateRequest;
import com.wultra.security.powerauth.client.model.request.OperationTemplateDeleteRequest;
import com.wultra.security.powerauth.client.model.request.OperationTemplateDetailRequest;
import com.wultra.security.powerauth.client.model.request.OperationTemplateUpdateRequest;
import com.wultra.security.powerauth.client.model.response.OperationTemplateDetailResponse;
import com.wultra.security.powerauth.client.model.response.OperationTemplateListResponse;
import com.wultra.security.powerauth.client.model.validator.OperationTemplateCreateRequestValidator;
import com.wultra.security.powerauth.client.model.validator.OperationTemplateDeleteRequestValidator;
import com.wultra.security.powerauth.client.model.validator.OperationTemplateDetailRequestValidator;
import com.wultra.security.powerauth.client.model.validator.OperationTemplateUpdateRequestValidator;
import io.getlime.security.powerauth.app.server.converter.OperationTemplateConverter;
import io.getlime.security.powerauth.app.server.database.model.entity.OperationTemplateEntity;
import io.getlime.security.powerauth.app.server.database.repository.OperationTemplateRepository;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

/**
 * Behavior class implementing the operation template related processes.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Service
@Slf4j
public class OperationTemplateServiceBehavior {

    private final OperationTemplateRepository templateRepository;
    private final OperationTemplateConverter operationTemplateConverter;
    private LocalizationProvider localizationProvider;

    @Autowired
    public OperationTemplateServiceBehavior(OperationTemplateRepository templateRepository, OperationTemplateConverter operationTemplateConverter) {
        this.templateRepository = templateRepository;
        this.operationTemplateConverter = operationTemplateConverter;
    }

    @Autowired
    public void setLocalizationProvider(LocalizationProvider localizationProvider) {
        this.localizationProvider = localizationProvider;
    }

    /**
     * Return the list of all templates in the system.
     *
     * @return List of operation templates.
     */
    @Transactional
    public OperationTemplateListResponse getAllTemplates() throws GenericServiceException {
        try {
            final Iterable<OperationTemplateEntity> allTemplates = templateRepository.findAll();
            final OperationTemplateListResponse result = new OperationTemplateListResponse();
            allTemplates.forEach(template -> {
                final OperationTemplateDetailResponse ot = operationTemplateConverter.convertFromDB(template);
                result.add(ot);
            });
            return result;
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        } catch (Exception ex) {
            logger.error("Unknown error occurred", ex);
            throw new GenericServiceException(ServiceError.UNKNOWN_ERROR, ex.getMessage());
        }
    }

    /**
     * Return the detail of a template with given ID.
     *
     * @return List of operation templates.
     */
    @Transactional
    public OperationTemplateDetailResponse getTemplateDetail(OperationTemplateDetailRequest request) throws GenericServiceException {
        try {
            final String error = OperationTemplateDetailRequestValidator.validate(request);
            if (error != null) {
                throw new GenericServiceException(ServiceError.INVALID_REQUEST, error);
            }
            final Long id = request.getId();
            final Optional<OperationTemplateEntity> template = templateRepository.findById(id);
            if (template.isEmpty()) {
                throw localizationProvider.buildExceptionForCode(ServiceError.OPERATION_TEMPLATE_NOT_FOUND);
            }
            return operationTemplateConverter.convertFromDB(template.get());
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
     * Create a new operation template.
     * @param request New operation template attributes.
     * @return New operation template.
     */
    @Transactional
    public OperationTemplateDetailResponse createOperationTemplate(OperationTemplateCreateRequest request) throws GenericServiceException {
        try {
            final String error = OperationTemplateCreateRequestValidator.validate(request);
            if (error != null) {
                throw new GenericServiceException(ServiceError.INVALID_REQUEST, error);
            }
            final String templateName = request.getTemplateName();
            final Optional<OperationTemplateEntity> templateByName = templateRepository.findTemplateByName(templateName);
            if (templateByName.isPresent()) {
                throw localizationProvider.buildExceptionForCode(ServiceError.OPERATION_TEMPLATE_ALREADY_EXISTS);
            }
            OperationTemplateEntity operationTemplateEntity = operationTemplateConverter.convertToDB(request);
            operationTemplateEntity = templateRepository.save(operationTemplateEntity);
            return operationTemplateConverter.convertFromDB(operationTemplateEntity);
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
     * Update existing operation template.
     * @param request Request to update existing operation template.
     * @return Updated operation template.
     */
    @Transactional
    public OperationTemplateDetailResponse updateOperationTemplate(OperationTemplateUpdateRequest request) throws GenericServiceException {
        try {
            final String error = OperationTemplateUpdateRequestValidator.validate(request);
            if (error != null) {
                throw new GenericServiceException(ServiceError.INVALID_REQUEST, error);
            }

            final Long id = request.getId();

            // Check if the template exists
            final Optional<OperationTemplateEntity> template = templateRepository.findById(id);
            if (template.isEmpty()) {
                throw localizationProvider.buildExceptionForCode(ServiceError.OPERATION_TEMPLATE_NOT_FOUND);
            }

            // Convert and store the new template
            final OperationTemplateEntity modifiedEntity = operationTemplateConverter.convertToDB(template.get(), request);
            final OperationTemplateEntity savedEntity = templateRepository.save(modifiedEntity);
            return operationTemplateConverter.convertFromDB(savedEntity);
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
     * Delete operation template by ID.
     *
     * @param request Request with operation ID to be deleted.
     */
    @Transactional
    public void removeOperationTemplate(OperationTemplateDeleteRequest request) throws GenericServiceException {
        try {
            final String error = OperationTemplateDeleteRequestValidator.validate(request);
            if (error != null) {
                throw new GenericServiceException(ServiceError.INVALID_REQUEST, error);
            }

            final Long id = request.getId();
            final Optional<OperationTemplateEntity> templateEntity = templateRepository.findById(id);
            if (templateEntity.isPresent()) {
                templateRepository.deleteById(id);
            } else {
                throw localizationProvider.buildExceptionForCode(ServiceError.OPERATION_TEMPLATE_NOT_FOUND);
            }
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
