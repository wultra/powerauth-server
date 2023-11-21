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
import com.wultra.security.powerauth.client.model.response.OperationDetailResponse;
import com.wultra.security.powerauth.client.model.response.OperationUserActionResponse;
import io.getlime.security.powerauth.app.server.database.model.entity.OperationEntity;
import io.getlime.security.powerauth.app.server.database.repository.OperationRepository;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import jakarta.transaction.Transactional;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.jdbc.Sql;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link OperationServiceBehavior}.
 *
 * @author Jan Dusil, jan.dusil@wultra.com
 */
@SpringBootTest
@Sql
@Transactional
class OperationServiceBehaviorTest {

    @Autowired
    private OperationServiceBehavior tested;

    @Autowired
    private OperationRepository operationRepository;

    /**
     * Tests the creation of an operation with a specified activation ID.
     * Verifies that the operation is correctly created and stored with the provided activation ID.
     */
    @Test
    void testCreateOperationWithActivationId() throws GenericServiceException {
        OperationCreateRequest request = new OperationCreateRequest();
        request.setActivationId("testActivationId");
        request.setTemplateName("test-template");
        request.setUserId("test-user");

        final OperationDetailResponse operationDetailResponse = tested.createOperation(request);
        assertTrue(operationRepository.findOperation(operationDetailResponse.getId()).isPresent());
        final OperationEntity savedEntity = operationRepository.findOperation(operationDetailResponse.getId()).get();
        assertEquals("testActivationId", savedEntity.getActivationId());
    }

    /**
     * Tests the creation of an operation without specifying an activation ID.
     * Verifies that the operation is correctly created and stored without an activation ID.
     */
    @Test
    void testCreateOperationWithoutActivationId() throws GenericServiceException {
        OperationCreateRequest request = new OperationCreateRequest();
        request.setTemplateName("test-template");
        request.setUserId("test-user");

        final OperationDetailResponse operationDetailResponse = tested.createOperation(request);
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
        OperationCreateRequest request = new OperationCreateRequest();
        request.setActivationId("testActivationId");
        request.setTemplateName("test-template");
        request.setUserId("test-user");
        request.setApplications(Collections.singletonList("PA_Tests"));

        final OperationDetailResponse operationDetailResponse = tested.createOperation(request);
        assertTrue(operationRepository.findOperation(operationDetailResponse.getId()).isPresent());
        final OperationEntity savedEntity = operationRepository.findOperation(operationDetailResponse.getId()).get();
        assertEquals("testActivationId", savedEntity.getActivationId());

        OperationApproveRequest operationApproveRequest = new OperationApproveRequest();
        operationApproveRequest.setOperationId(savedEntity.getId());
        operationApproveRequest.getAdditionalData().put("activationId", savedEntity.getActivationId());
        operationApproveRequest.setApplicationId("PA_Tests");
        operationApproveRequest.setUserId(savedEntity.getUserId());
        operationApproveRequest.setSignatureType(SignatureType.POSSESSION_KNOWLEDGE);
        operationApproveRequest.setData("A2");

        final OperationUserActionResponse operationUserActionResponse = tested.attemptApproveOperation(operationApproveRequest);
        assertNotNull(operationUserActionResponse);
        assertEquals(UserActionResult.APPROVED, operationUserActionResponse.getResult());
    }

    /**
     * Tests the approval of an operation without an activation ID in the OperationEntity.
     * Verifies that the operation is successfully approved even without an activation ID.
     */
    @Test
    void testApproveOperationEntityWithoutActivationIdSuccess() throws GenericServiceException {
        OperationCreateRequest request = new OperationCreateRequest();
        request.setTemplateName("test-template");
        request.setUserId("test-user");
        request.setApplications(Collections.singletonList("PA_Tests"));

        final OperationDetailResponse operationDetailResponse = tested.createOperation(request);
        assertTrue(operationRepository.findOperation(operationDetailResponse.getId()).isPresent());
        final OperationEntity savedEntity = operationRepository.findOperation(operationDetailResponse.getId()).get();
        assertNull(savedEntity.getActivationId());

        OperationApproveRequest operationApproveRequest = new OperationApproveRequest();
        operationApproveRequest.setOperationId(savedEntity.getId());
        operationApproveRequest.getAdditionalData().put("activationId", savedEntity.getActivationId());
        operationApproveRequest.setApplicationId("PA_Tests");
        operationApproveRequest.setUserId(savedEntity.getUserId());
        operationApproveRequest.setSignatureType(SignatureType.POSSESSION_KNOWLEDGE);
        operationApproveRequest.setData("A2");

        final OperationUserActionResponse operationUserActionResponse = tested.attemptApproveOperation(operationApproveRequest);
        assertNotNull(operationUserActionResponse);
        assertEquals(UserActionResult.APPROVED, operationUserActionResponse.getResult());
    }

    /**
     * Tests the failure of operation approval due to a non-matching activation ID.
     * Verifies that the operation approval fails when the provided activation ID does not match the stored one.
     */
    @Test
    void testApproveOperationWithoutMatchingActivationIdFailure() throws GenericServiceException {
        OperationCreateRequest request = new OperationCreateRequest();
        request.setActivationId("testActivationId");
        request.setTemplateName("test-template");
        request.setUserId("test-user");
        request.setApplications(Collections.singletonList("PA_Tests"));

        final OperationDetailResponse operationDetailResponse = tested.createOperation(request);
        assertTrue(operationRepository.findOperation(operationDetailResponse.getId()).isPresent());
        final OperationEntity savedEntity = operationRepository.findOperation(operationDetailResponse.getId()).get();
        assertEquals("testActivationId", savedEntity.getActivationId());

        OperationApproveRequest operationApproveRequest = new OperationApproveRequest();
        operationApproveRequest.setOperationId(savedEntity.getId());
        operationApproveRequest.getAdditionalData().put("activationId2", savedEntity.getActivationId());
        operationApproveRequest.setApplicationId("PA_Tests");
        operationApproveRequest.setUserId(savedEntity.getUserId());
        operationApproveRequest.setSignatureType(SignatureType.POSSESSION_KNOWLEDGE);
        operationApproveRequest.setData("A2");

        final OperationUserActionResponse operationUserActionResponse = tested.attemptApproveOperation(operationApproveRequest);
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
        OperationCreateRequest request = new OperationCreateRequest();
        request.setActivationId("testActivationId");
        request.setTemplateName("test-template");
        request.setUserId("test-user");
        request.setApplications(Collections.singletonList("PA_Tests"));

        final OperationDetailResponse operationDetailResponse = tested.createOperation(request);
        assertTrue(operationRepository.findOperation(operationDetailResponse.getId()).isPresent());
        OperationEntity entity = operationRepository.findOperation(operationDetailResponse.getId()).get();
        assertEquals("testActivationId", entity.getActivationId());
        entity.setFailureCount(4L);


        OperationApproveRequest operationApproveRequest = new OperationApproveRequest();
        operationApproveRequest.setOperationId(entity.getId());
        operationApproveRequest.getAdditionalData().put("activationId2", entity.getActivationId());
        operationApproveRequest.setApplicationId("PA_Tests");
        operationApproveRequest.setUserId(entity.getUserId());
        operationApproveRequest.setSignatureType(SignatureType.POSSESSION_KNOWLEDGE);
        operationApproveRequest.setData("A2");

        final OperationUserActionResponse operationUserActionResponse = tested.attemptApproveOperation(operationApproveRequest);
        assertNotNull(operationUserActionResponse);
        assertEquals(UserActionResult.OPERATION_FAILED, operationUserActionResponse.getResult());
    }

}
