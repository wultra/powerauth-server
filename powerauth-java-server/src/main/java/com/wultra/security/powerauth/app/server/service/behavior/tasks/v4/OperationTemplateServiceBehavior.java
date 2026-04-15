/*
 * PowerAuth Server and related software components
 * Copyright (C) 2025 Wultra s.r.o.
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

package com.wultra.security.powerauth.app.server.service.behavior.tasks.v4;

import com.wultra.security.powerauth.app.server.converter.v4.OperationTemplateConverter;
import com.wultra.security.powerauth.app.server.database.model.entity.OperationTemplateEntity;
import com.wultra.security.powerauth.app.server.database.repository.OperationTemplateRepository;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.client.model.request.v4.OperationTemplateCreateRequest;
import com.wultra.security.powerauth.client.model.request.OperationTemplateDeleteRequest;
import com.wultra.security.powerauth.client.model.request.OperationTemplateDetailRequest;
import com.wultra.security.powerauth.client.model.request.v4.OperationTemplateUpdateRequest;
import com.wultra.security.powerauth.client.model.response.v4.OperationTemplateDetailResponse;
import com.wultra.security.powerauth.client.model.response.v4.OperationTemplateListResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

/**
 * Behavior class implementing the operation template related processes.
 *
 * @author Petr Dvorak, petr@wultra.com
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service("operationTemplateServiceBehaviorV4")
@Slf4j
@AllArgsConstructor
public class OperationTemplateServiceBehavior {

    private final OperationTemplateRepository templateRepository;
    private LocalizationProvider localizationProvider;

    /**
     * Return the list of all templates in the system.
     *
     * @return List of operation templates.
     */
    @Transactional(readOnly = true)
    public OperationTemplateListResponse getAllTemplates() throws GenericServiceException {
        try {
            final Iterable<OperationTemplateEntity> allTemplates = templateRepository.findAll();
            final OperationTemplateListResponse result = new OperationTemplateListResponse();
            allTemplates.forEach(template -> {
                final OperationTemplateDetailResponse ot = OperationTemplateConverter.convertFromDB(template);
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
    @Transactional(readOnly = true)
    public OperationTemplateDetailResponse getTemplateDetail(OperationTemplateDetailRequest request) throws GenericServiceException {
        try {
            final Long id = request.getId();
            final Optional<OperationTemplateEntity> template = templateRepository.findById(id);
            if (template.isEmpty()) {
                throw localizationProvider.buildExceptionForCode(ServiceError.OPERATION_TEMPLATE_NOT_FOUND);
            }
            return OperationTemplateConverter.convertFromDB(template.get());
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
            final String templateName = request.getTemplateName();
            final Optional<OperationTemplateEntity> templateByName = templateRepository.findTemplateByName(templateName);
            if (templateByName.isPresent()) {
                throw localizationProvider.buildExceptionForCode(ServiceError.OPERATION_TEMPLATE_ALREADY_EXISTS);
            }
            OperationTemplateEntity operationTemplateEntity = OperationTemplateConverter.convertToDB(request);
            operationTemplateEntity = templateRepository.save(operationTemplateEntity);
            return OperationTemplateConverter.convertFromDB(operationTemplateEntity);
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
            final Long id = request.getId();

            // Check if the template exists
            final Optional<OperationTemplateEntity> template = templateRepository.findById(id);
            if (template.isEmpty()) {
                throw localizationProvider.buildExceptionForCode(ServiceError.OPERATION_TEMPLATE_NOT_FOUND);
            }

            // Convert and store the new template
            final OperationTemplateEntity modifiedEntity = OperationTemplateConverter.convertToDB(template.get(), request);
            final OperationTemplateEntity savedEntity = templateRepository.save(modifiedEntity);
            return OperationTemplateConverter.convertFromDB(savedEntity);
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
