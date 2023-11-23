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
import com.wultra.security.powerauth.client.model.enumeration.UserActionResult;
import com.wultra.security.powerauth.client.model.request.OperationApproveRequest;
import com.wultra.security.powerauth.client.model.request.OperationCreateRequest;
import com.wultra.security.powerauth.client.model.request.OperationDetailRequest;
import com.wultra.security.powerauth.client.model.request.OperationTemplateCreateRequest;
import com.wultra.security.powerauth.client.model.response.OperationDetailResponse;
import com.wultra.security.powerauth.client.model.response.OperationUserActionResponse;
import io.getlime.security.powerauth.app.server.database.model.entity.OperationEntity;
import io.getlime.security.powerauth.app.server.database.repository.OperationRepository;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import jakarta.transaction.Transactional;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.jdbc.Sql;

import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Test for {@link OperationServiceBehavior}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@SpringBootTest
@Sql
@Transactional
class OperationServiceBehaviorTest {

    private static final String APP_ID = UUID.randomUUID().toString();
    private static final String TEMPLATE_NAME = "login_" + UUID.randomUUID().toString();

    private final OperationServiceBehavior operationService;
    private final OperationTemplateServiceBehavior templateService;
    private final ApplicationServiceBehavior applicationService;
    private final OperationRepository operationRepository;

    @Autowired
    public OperationServiceBehaviorTest(OperationServiceBehavior operationService, OperationTemplateServiceBehavior templateService, ApplicationServiceBehavior applicationService, OperationRepository operationRepository) throws GenericServiceException {
        this.operationService = operationService;
        this.templateService = templateService;
        this.applicationService = applicationService;
        this.operationRepository = operationRepository;
        createApplication();
        createOperationTemplateForLogin();
    }

    /**
     * Tests the creation of an operation with a specified activation ID.
     * Verifies that the operation is correctly created and stored with the provided activation ID.
     */
    @Test
    void testCreateOperationWithActivationId() throws GenericServiceException {
        final OperationCreateRequest request = new OperationCreateRequest();
        request.setActivationId("testActivationId");
        request.setTemplateName("test-template");
        request.setUserId("test-user");

        final OperationDetailResponse operationDetailResponse = operationService.createOperation(request);
        final OperationEntity savedEntity = operationRepository.findOperation(operationDetailResponse.getId()).get();
        assertTrue(operationRepository.findOperation(operationDetailResponse.getId()).isPresent());
        assertEquals("testActivationId", savedEntity.getActivationId());
    }

    /**
     * Tests the creation of an operation without specifying an activation ID.
     * Verifies that the operation is correctly created and stored without an activation ID.
     */
    @Test
    void testCreateOperationWithoutActivationId() throws GenericServiceException {
        final OperationCreateRequest request = new OperationCreateRequest();
        request.setTemplateName("test-template");
        request.setUserId("test-user");

        final OperationDetailResponse operationDetailResponse = operationService.createOperation(request);
        assertTrue(operationRepository.findOperation(operationDetailResponse.getId()).isPresent());
        final OperationEntity savedEntity = operationRepository.findOperation(operationDetailResponse.getId()).get();
        assertNull(savedEntity.getActivationId());
    }

    /**
     * Tests the approval of an operation with a matching activation ID.
     * Verifies that the operation is successfully approved when the provided activation ID matches the stored one.
     */
    @Test
    void testApproveOperationWithMatchingActivationIdSuccess() throws GenericServiceException {
        final OperationCreateRequest request = new OperationCreateRequest();
        request.setActivationId("testActivationId");
        request.setTemplateName("test-template");
        request.setUserId("test-user");
        request.setApplications(Collections.singletonList(APP_ID));

        final OperationDetailResponse operationDetailResponse = operationService.createOperation(request);
        assertTrue(operationRepository.findOperation(operationDetailResponse.getId()).isPresent());
        final OperationEntity savedEntity = operationRepository.findOperation(operationDetailResponse.getId()).get();
        assertEquals("testActivationId", savedEntity.getActivationId());

        OperationApproveRequest operationApproveRequest = new OperationApproveRequest();
        operationApproveRequest.setOperationId(savedEntity.getId());
        operationApproveRequest.getAdditionalData().put("activationId", savedEntity.getActivationId());
        operationApproveRequest.setApplicationId(APP_ID);
        operationApproveRequest.setUserId(savedEntity.getUserId());
        operationApproveRequest.setSignatureType(SignatureType.POSSESSION_KNOWLEDGE);
        operationApproveRequest.setData("A2");

        final OperationUserActionResponse operationUserActionResponse = operationService.attemptApproveOperation(operationApproveRequest);
        assertNotNull(operationUserActionResponse);
        assertEquals(UserActionResult.APPROVED, operationUserActionResponse.getResult());
    }

    /**
     * Tests the approval of an operation without an activation ID in the OperationEntity.
     * Verifies that the operation is successfully approved even without an activation ID.
     */
    @Test
    void testApproveOperationEntityWithoutActivationIdSuccess() throws GenericServiceException {
        final OperationCreateRequest request = new OperationCreateRequest();
        request.setTemplateName("test-template");
        request.setUserId("test-user");
        request.setApplications(Collections.singletonList(APP_ID));

        final OperationDetailResponse operationDetailResponse = operationService.createOperation(request);
        assertTrue(operationRepository.findOperation(operationDetailResponse.getId()).isPresent());
        final OperationEntity savedEntity = operationRepository.findOperation(operationDetailResponse.getId()).get();
        assertNull(savedEntity.getActivationId());

        OperationApproveRequest operationApproveRequest = new OperationApproveRequest();
        operationApproveRequest.setOperationId(savedEntity.getId());
        operationApproveRequest.getAdditionalData().put("activationId", savedEntity.getActivationId());
        operationApproveRequest.setApplicationId(APP_ID);
        operationApproveRequest.setUserId(savedEntity.getUserId());
        operationApproveRequest.setSignatureType(SignatureType.POSSESSION_KNOWLEDGE);
        operationApproveRequest.setData("A2");

        final OperationUserActionResponse operationUserActionResponse = operationService.attemptApproveOperation(operationApproveRequest);
        assertNotNull(operationUserActionResponse);
        assertEquals(UserActionResult.APPROVED, operationUserActionResponse.getResult());
    }

    /**
     * Tests the failure of operation approval due to a non-matching activation ID.
     * Verifies that the operation approval fails when the provided activation ID does not match the stored one.
     */
    @Test
    void testApproveOperationWithoutMatchingActivationIdFailure() throws GenericServiceException {
        final OperationCreateRequest request = new OperationCreateRequest();
        request.setActivationId("testActivationId");
        request.setTemplateName("test-template");
        request.setUserId("test-user");
        request.setApplications(Collections.singletonList(APP_ID));

        final OperationDetailResponse operationDetailResponse = operationService.createOperation(request);
        assertTrue(operationRepository.findOperation(operationDetailResponse.getId()).isPresent());
        final OperationEntity savedEntity = operationRepository.findOperation(operationDetailResponse.getId()).get();
        assertEquals("testActivationId", savedEntity.getActivationId());

        final OperationApproveRequest operationApproveRequest = new OperationApproveRequest();
        operationApproveRequest.setOperationId(savedEntity.getId());
        operationApproveRequest.getAdditionalData().put("activationId2", savedEntity.getActivationId());
        operationApproveRequest.setApplicationId(APP_ID);
        operationApproveRequest.setUserId(savedEntity.getUserId());
        operationApproveRequest.setSignatureType(SignatureType.POSSESSION_KNOWLEDGE);
        operationApproveRequest.setData("A2");

        final OperationUserActionResponse operationUserActionResponse = operationService.attemptApproveOperation(operationApproveRequest);
        final OperationEntity updatedEntity = operationRepository.findOperation(operationDetailResponse.getId()).get();
        assertEquals("testActivationId", savedEntity.getActivationId());
        assertNotNull(operationUserActionResponse);
        assertEquals(UserActionResult.APPROVAL_FAILED, operationUserActionResponse.getResult());
        assertEquals(1, updatedEntity.getFailureCount());
    }

    /**
     * Tests the failure of operation approval due to a non-matching activation ID, with maximum failure count reached.
     * Verifies that the operation fails completely when the provided activation ID does not match and maximum failure attempts are reached.
     */
    @Test
    void testApproveOperationWithoutMatchingActivationIdFailureMax() throws GenericServiceException {
        final OperationCreateRequest request = new OperationCreateRequest();
        request.setActivationId("testActivationId");
        request.setTemplateName("test-template");
        request.setUserId("test-user");
        request.setApplications(Collections.singletonList(APP_ID));

        final OperationDetailResponse operationDetailResponse = operationService.createOperation(request);
        assertTrue(operationRepository.findOperation(operationDetailResponse.getId()).isPresent());
        final OperationEntity entity = operationRepository.findOperation(operationDetailResponse.getId()).get();
        assertEquals("testActivationId", entity.getActivationId());
        entity.setFailureCount(4L);

        final OperationApproveRequest operationApproveRequest = new OperationApproveRequest();
        operationApproveRequest.setOperationId(entity.getId());
        operationApproveRequest.getAdditionalData().put("activationId2", entity.getActivationId());
        operationApproveRequest.setApplicationId(APP_ID);
        operationApproveRequest.setUserId(entity.getUserId());
        operationApproveRequest.setSignatureType(SignatureType.POSSESSION_KNOWLEDGE);
        operationApproveRequest.setData("A2");

        final OperationUserActionResponse operationUserActionResponse = operationService.attemptApproveOperation(operationApproveRequest);
        assertNotNull(operationUserActionResponse);
        assertEquals(UserActionResult.OPERATION_FAILED, operationUserActionResponse.getResult());
    }

    @Test
    void testOperationClaim() throws Exception {
        final String operationId = createLoginOperation();

        final String userId = "user_" + UUID.randomUUID();
        final OperationDetailRequest detailRequest = new OperationDetailRequest();
        detailRequest.setOperationId(operationId);
        detailRequest.setUserId(userId);
        // Check operation claim
        assertEquals(userId, operationService.getOperation(detailRequest).getUserId());
    }

    private void createApplication() throws GenericServiceException {
        boolean appExists = applicationService.getApplicationList().getApplications().stream()
                .anyMatch(app -> app.getApplicationId().equals(APP_ID));
        if (!appExists) {
            applicationService.createApplication(APP_ID, new KeyConvertor());
        }
    }

    private String createLoginOperation() throws GenericServiceException {
        final OperationCreateRequest operationCreateRequest = new OperationCreateRequest();
        operationCreateRequest.setApplications(Collections.singletonList(APP_ID));
        operationCreateRequest.setTemplateName(TEMPLATE_NAME);
        operationCreateRequest.setTimestampExpires(new Date(Instant.now()
                .plusSeconds(TimeUnit.MINUTES.toSeconds(60)).toEpochMilli()));
        return operationService.createOperation(operationCreateRequest).getId();
    }

    private void createOperationTemplateForLogin() throws GenericServiceException {
        boolean templateExists = templateService.getAllTemplates().stream()
                .anyMatch(t -> t.getTemplateName().equals(TEMPLATE_NAME));
        if (!templateExists) {
            final OperationTemplateCreateRequest request = new OperationTemplateCreateRequest();
            request.setTemplateName(TEMPLATE_NAME);
            request.setOperationType("login");
            request.setDataTemplate("A2");
            request.getSignatureType().add(SignatureType.POSSESSION_KNOWLEDGE);
            request.setMaxFailureCount(5L);
            request.setExpiration(300L);
            templateService.createOperationTemplate(request);
        }
    }

}
