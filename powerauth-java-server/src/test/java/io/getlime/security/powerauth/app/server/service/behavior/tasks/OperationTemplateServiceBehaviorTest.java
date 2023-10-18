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

import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import com.wultra.security.powerauth.client.model.request.OperationTemplateCreateRequest;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link OperationTemplateServiceBehavior}.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@SpringBootTest
class OperationTemplateServiceBehaviorTest {

    @Autowired
    private OperationTemplateServiceBehavior service;

    @Test
    void testDuplicateOperationTemplateCreation() throws Exception {
        final String templateName = "login";

        service.createOperationTemplate(createOperationTemplateCreateRequest("login"));
        assertFalse(service.getAllTemplates().isEmpty());

        final GenericServiceException exception = assertThrows(GenericServiceException.class, () ->
                service.createOperationTemplate(createOperationTemplateCreateRequest(templateName)));
        assertEquals(ServiceError.OPERATION_TEMPLATE_ALREADY_EXISTS, exception.getCode());
    }

    private static OperationTemplateCreateRequest createOperationTemplateCreateRequest(String templateName) {
        final OperationTemplateCreateRequest request = new OperationTemplateCreateRequest();
        request.setTemplateName(templateName);
        request.setOperationType(templateName);
        request.setDataTemplate("A2");
        request.getSignatureType().add(SignatureType.POSSESSION_KNOWLEDGE);
        request.setMaxFailureCount(5L);
        request.setExpiration(300L);
        return request;
    }

}
