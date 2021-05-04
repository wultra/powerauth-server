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

package io.getlime.security.powerauth.app.server.service.behavior.tasks.v3;

import com.wultra.security.powerauth.client.model.request.OperationTemplateCreateRequest;
import com.wultra.security.powerauth.client.model.request.OperationTemplateDetailRequest;
import com.wultra.security.powerauth.client.model.request.OperationTemplateUpdateRequest;
import com.wultra.security.powerauth.client.model.response.OperationTemplateDetailResponse;
import com.wultra.security.powerauth.client.model.request.OperationTemplateDeleteRequest;
import com.wultra.security.powerauth.client.model.response.OperationTemplateListResponse;
import io.getlime.security.powerauth.app.server.converter.v3.OperationTemplateConverter;
import io.getlime.security.powerauth.app.server.database.model.entity.OperationTemplateEntity;
import io.getlime.security.powerauth.app.server.database.repository.OperationTemplateRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * Behavior class implementing the operation template related processes.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Service
public class OperationTemplateBehavior {

    private final OperationTemplateRepository templateRepository;
    private final OperationTemplateConverter operationTemplateConverter;

    @Autowired
    public OperationTemplateBehavior(OperationTemplateRepository templateRepository, OperationTemplateConverter operationTemplateConverter) {
        this.templateRepository = templateRepository;
        this.operationTemplateConverter = operationTemplateConverter;
    }

    /**
     * Return the list of all templates in the system.
     *
     * @return List of operation templates.
     */
    public OperationTemplateListResponse getAllTemplates() {
        final Iterable<OperationTemplateEntity> allTemplates = templateRepository.findAll();
        final OperationTemplateListResponse result = new OperationTemplateListResponse();
        allTemplates.forEach(template -> {
            final OperationTemplateDetailResponse ot = operationTemplateConverter.convertFromDB(template);
            result.add(ot);
        });
        return result;
    }

    /**
     * Return the detail of a template with given ID.
     *
     * @return List of operation templates.
     */
    public OperationTemplateDetailResponse getTemplateDetail(OperationTemplateDetailRequest request) {
        final Long id = request.getId();
        final Optional<OperationTemplateEntity> template = templateRepository.findById(id);
        return template.map(operationTemplateConverter::convertFromDB).orElse(null);
    }

    /**
     * Create a new operation template.
     * @param request New operation template attributes.
     * @return New operation template.
     */
    public OperationTemplateDetailResponse createOperationTemplate(OperationTemplateCreateRequest request) {
        OperationTemplateEntity operationTemplateEntity = operationTemplateConverter.convertToDB(request);
        operationTemplateEntity = templateRepository.save(operationTemplateEntity);
        return operationTemplateConverter.convertFromDB(operationTemplateEntity);
    }

    /**
     * Update existing operation template.
     * @param request Request to update existing operation template.
     * @return Updated operation template.
     */
    public OperationTemplateDetailResponse updateOperationTemplate(OperationTemplateUpdateRequest request) {
        final Long id = request.getId();
        final Optional<OperationTemplateEntity> template = templateRepository.findById(id);
        if (template.isPresent()) {
            final OperationTemplateEntity operationTemplateEntity = operationTemplateConverter.convertToDB(request);
            final OperationTemplateEntity savedEntity = templateRepository.save(operationTemplateEntity);
            return operationTemplateConverter.convertFromDB(savedEntity);
        } else {
            return null;
        }
    }

    /**
     * Delete operation template by ID.
     *
     * @param request Request with operation ID to be deleted.
     */
    public void removeOperationTemplate(OperationTemplateDeleteRequest request) {
        final Long id = request.getId();
        templateRepository.deleteById(id);
    }


}
