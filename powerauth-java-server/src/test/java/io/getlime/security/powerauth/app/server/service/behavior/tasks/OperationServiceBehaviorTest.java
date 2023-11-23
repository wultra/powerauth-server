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
import com.wultra.security.powerauth.client.model.request.OperationCreateRequest;
import com.wultra.security.powerauth.client.model.request.OperationDetailRequest;
import com.wultra.security.powerauth.client.model.request.OperationTemplateCreateRequest;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test for {@link OperationServiceBehavior}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@SpringBootTest
class OperationServiceBehaviorTest {

    private static final String APP_ID = UUID.randomUUID().toString();

    private final OperationServiceBehavior operationService;
    private final OperationTemplateServiceBehavior templateService;
    private final ApplicationServiceBehavior applicationService;

    @Autowired
    public OperationServiceBehaviorTest(OperationServiceBehavior operationService, OperationTemplateServiceBehavior templateService, ApplicationServiceBehavior applicationService) {
        this.operationService = operationService;
        this.templateService = templateService;
        this.applicationService = applicationService;
    }

    @Test
    @Transactional
    void testOperationClaim() throws Exception {
        createApplication();
        createOperationTemplateForLogin();
        final String operationId = createOperation();

        final String userId = "user_" + UUID.randomUUID();
        final OperationDetailRequest detailRequest = new OperationDetailRequest();
        detailRequest.setOperationId(operationId);
        detailRequest.setUserId(userId);
        // Check operation claim
        assertEquals(userId, operationService.getOperation(detailRequest).getUserId());
    }

    private String createOperation() throws GenericServiceException {
        final OperationCreateRequest operationCreateRequest = new OperationCreateRequest();
        operationCreateRequest.setApplications(Collections.singletonList(APP_ID));
        operationCreateRequest.setTemplateName("login");
        operationCreateRequest.setTimestampExpires(new Date(Instant.now()
                .plusSeconds(TimeUnit.MINUTES.toSeconds(60)).toEpochMilli()));
        return operationService.createOperation(operationCreateRequest).getId();
    }

    private void createApplication() throws GenericServiceException {
        applicationService.createApplication(APP_ID, new KeyConvertor());
    }

    private void createOperationTemplateForLogin() throws GenericServiceException {
        final OperationTemplateCreateRequest request = new OperationTemplateCreateRequest();
        request.setTemplateName("login");
        request.setOperationType("login");
        request.setDataTemplate("A2");
        request.getSignatureType().add(SignatureType.POSSESSION_KNOWLEDGE);
        request.setMaxFailureCount(5L);
        request.setExpiration(300L);
        templateService.createOperationTemplate(request);
    }
}
