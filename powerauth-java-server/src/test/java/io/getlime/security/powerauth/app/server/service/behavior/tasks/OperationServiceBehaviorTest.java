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

import com.wultra.core.http.common.headers.UserAgent;
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import com.wultra.security.powerauth.client.model.enumeration.UserActionResult;
import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.response.OperationDetailResponse;
import com.wultra.security.powerauth.client.model.response.OperationListResponse;
import com.wultra.security.powerauth.client.model.response.OperationUserActionResponse;
import io.getlime.security.powerauth.app.server.database.model.entity.OperationEntity;
import io.getlime.security.powerauth.app.server.database.repository.OperationRepository;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import jakarta.transaction.Transactional;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.jdbc.Sql;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link OperationServiceBehavior}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@SpringBootTest
@Sql
@Transactional
@ActiveProfiles("test")
class OperationServiceBehaviorTest {

    private static final String APP_ID = UUID.randomUUID().toString();
    private static final String TEMPLATE_NAME = "login_" + UUID.randomUUID();

    // values defined in OperationServiceBehaviorTest.sql
    private static final String ACTIVATION_ID = "68c5ca56-b419-4653-949f-49061a4be886";
    private static final String USER_ID = "testUser";

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
    void testCreateOperationWithActivationId() throws Exception {
        final OperationCreateRequest request = new OperationCreateRequest();
        request.setActivationId(ACTIVATION_ID);
        request.setApplications(List.of(APP_ID));
        request.setTemplateName("test-template");
        request.setUserId(USER_ID);

        final OperationDetailResponse operationDetailResponse = operationService.createOperation(request);
        final Optional<OperationEntity> savedEntity = operationRepository.findOperationWithoutLock(operationDetailResponse.getId());

        assertTrue(savedEntity.isPresent());
        assertEquals(ACTIVATION_ID, savedEntity.get().getActivationId());
        assertNull(operationDetailResponse.getProximityOtp());
        assertEquals(USER_ID, savedEntity.get().getUserId());
    }

    @Test
    void testCreateOperationWithoutActivationIdAndExplicitProximityCheck() throws Exception {
        final OperationCreateRequest request = new OperationCreateRequest();
        request.setTemplateName("test-template");
        request.setApplications(List.of(APP_ID));
        request.setUserId("test-user");
        request.setProximityCheckEnabled(true);

        final OperationDetailResponse operationDetailResponse = operationService.createOperation(request);
        assertNotNull(operationDetailResponse.getProximityOtp());

        final OperationDetailRequest detailRequest = new OperationDetailRequest();
        detailRequest.setOperationId(operationDetailResponse.getId());

        final OperationDetailResponse operationDetail = operationService.operationDetail(detailRequest);
        assertNotNull(operationDetail);
        assertNotNull(operationDetail.getProximityOtp());
        assertNull(operationDetail.getActivationId());
        assertEquals("test-user", operationDetail.getUserId());
    }

    @Test
    void testCreateOperationWithoutActivationIdAndImplicitProximityCheck() throws Exception {
        final OperationCreateRequest request = new OperationCreateRequest();
        request.setTemplateName("test-template-proximity-check");
        request.setApplications(List.of(APP_ID));
        request.setUserId("test-user");

        final OperationDetailResponse operationDetailResponse = operationService.createOperation(request);
        assertNotNull(operationDetailResponse.getProximityOtp());

        final OperationDetailRequest detailRequest = new OperationDetailRequest();
        detailRequest.setOperationId(operationDetailResponse.getId());

        final OperationDetailResponse operationDetail = operationService.operationDetail(detailRequest);
        assertNotNull(operationDetail);
        assertNotNull(operationDetail.getProximityOtp());
        assertNull(operationDetail.getActivationId());
        assertEquals("test-user", operationDetail.getUserId());
    }

    @Test
    void testCreateOperationWithActivationIdButInvalidUser() {
        final OperationCreateRequest request = new OperationCreateRequest();
        request.setApplications(List.of(APP_ID));
        request.setActivationId(ACTIVATION_ID);
        request.setTemplateName("test-template");
        request.setUserId("invalid-user"); // different userId from ActivationRecordEntity#userId

        final GenericServiceException thrown = assertThrows(GenericServiceException.class, () ->
                operationService.createOperation(request));
        assertEquals("ERR0024", thrown.getCode());
    }

    @Test
    void testCreateOperationWithActivationIdButMissingUser() throws Exception {
        final OperationCreateRequest request = new OperationCreateRequest();
        request.setApplications(List.of(APP_ID));
        request.setActivationId(ACTIVATION_ID);
        request.setTemplateName("test-template");
        request.setUserId(null); // validating that user ID is missing but filled from activation later on

        final OperationDetailResponse result = operationService.createOperation(request);

        assertNotNull(result.getId());
        assertEquals(ACTIVATION_ID, result.getActivationId());
        assertEquals(1, result.getApplications().size());
        assertEquals(APP_ID, result.getApplications().get(0));
        assertEquals("testUser", result.getUserId());
    }

    /**
     * Tests the creation of an operation without specifying an activation ID.
     * Verifies that the operation is correctly created and stored without an activation ID.
     */
    @Test
    void testCreateOperationWithoutActivationId() throws Exception {
        final OperationCreateRequest request = new OperationCreateRequest();
        request.setTemplateName("test-template");
        request.setApplications(List.of(APP_ID));
        request.setUserId("test-user");

        final OperationDetailResponse operationDetailResponse = operationService.createOperation(request);
        assertTrue(operationRepository.findOperationWithoutLock(operationDetailResponse.getId()).isPresent());
        final OperationEntity savedEntity = operationRepository.findOperationWithoutLock(operationDetailResponse.getId()).get();
        assertNull(savedEntity.getActivationId());
        assertEquals("test-user", savedEntity.getUserId());
    }

    @Test
    void testCreateOperation_invalidParameterTextCharacters() {
        final OperationCreateRequest request = new OperationCreateRequest();
        request.setTemplateName("test-template");
        request.setApplications(List.of(APP_ID));
        request.setUserId("test-user");
        // All characters with ASCII code < 32 (except line feed) are forbidden (e.g. \t should not be in the string)
        request.getParameters().put("TEXT", "foo\thoo");

        assertThrows(GenericServiceException.class, () -> operationService.createOperation(request));
    }

    @Test
    void testCreateOperation_escapeTextCharacters() throws Exception {
        final OperationCreateRequest request = new OperationCreateRequest();
        request.setTemplateName("test-template-text");
        request.setApplications(List.of(APP_ID));
        request.setUserId("test-user");
        request.getParameters().put("text", """
                \\foo*hoo
                new-line""");

        final OperationDetailResponse operationDetailResponse = operationService.createOperation(request);
        assertTrue(operationRepository.findOperationWithoutLock(operationDetailResponse.getId()).isPresent());
        final OperationEntity savedEntity = operationRepository.findOperationWithoutLock(operationDetailResponse.getId()).get();

        assertEquals("A0*T\\\\foo\\*hoo\\nnew-line", savedEntity.getData());
    }

    /**
     * Tests the approval of an operation with a matching activation ID.
     * Verifies that the operation is successfully approved when the provided activation ID matches the stored one.
     */
    @Test
    void testApproveOperationWithMatchingActivationIdSuccess() throws Exception {
        final OperationCreateRequest request = new OperationCreateRequest();
        request.setActivationId(ACTIVATION_ID);
        request.setTemplateName("test-template");
        request.setUserId(USER_ID);
        request.setApplications(Collections.singletonList(APP_ID));

        final OperationDetailResponse operationDetailResponse = operationService.createOperation(request);
        assertTrue(operationRepository.findOperationWithoutLock(operationDetailResponse.getId()).isPresent());
        final OperationEntity savedEntity = operationRepository.findOperationWithoutLock(operationDetailResponse.getId()).get();
        assertEquals(ACTIVATION_ID, savedEntity.getActivationId());

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
    void testApproveOperationEntityWithoutActivationIdSuccess() throws Exception {
        final OperationCreateRequest request = new OperationCreateRequest();
        request.setTemplateName("test-template");
        request.setUserId("test-user");
        request.setApplications(Collections.singletonList(APP_ID));

        final OperationDetailResponse operationDetailResponse = operationService.createOperation(request);
        assertTrue(operationRepository.findOperationWithoutLock(operationDetailResponse.getId()).isPresent());
        final OperationEntity savedEntity = operationRepository.findOperationWithoutLock(operationDetailResponse.getId()).get();
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
    void testApproveOperationWithoutMatchingActivationIdFailure() throws Exception {
        final OperationCreateRequest request = new OperationCreateRequest();
        request.setActivationId(ACTIVATION_ID);
        request.setTemplateName("test-template");
        request.setUserId(USER_ID);
        request.setApplications(Collections.singletonList(APP_ID));

        final OperationDetailResponse operationDetailResponse = operationService.createOperation(request);
        assertTrue(operationRepository.findOperationWithoutLock(operationDetailResponse.getId()).isPresent());
        final OperationEntity savedEntity = operationRepository.findOperationWithoutLock(operationDetailResponse.getId()).get();
        assertEquals(ACTIVATION_ID, savedEntity.getActivationId());

        final OperationApproveRequest operationApproveRequest = new OperationApproveRequest();
        operationApproveRequest.setOperationId(savedEntity.getId());
        operationApproveRequest.getAdditionalData().put("activationId2", savedEntity.getActivationId());
        operationApproveRequest.setApplicationId(APP_ID);
        operationApproveRequest.setUserId(savedEntity.getUserId());
        operationApproveRequest.setSignatureType(SignatureType.POSSESSION_KNOWLEDGE);
        operationApproveRequest.setData("A2");

        final OperationUserActionResponse operationUserActionResponse = operationService.attemptApproveOperation(operationApproveRequest);
        final OperationEntity updatedEntity = operationRepository.findOperationWithoutLock(operationDetailResponse.getId()).get();
        assertEquals(ACTIVATION_ID, savedEntity.getActivationId());
        assertNotNull(operationUserActionResponse);
        assertEquals(UserActionResult.APPROVAL_FAILED, operationUserActionResponse.getResult());
        assertEquals(1, updatedEntity.getFailureCount());
    }

    /**
     * Tests the failure of operation approval due to a non-matching activation ID, with maximum failure count reached.
     * Verifies that the operation fails completely when the provided activation ID does not match and maximum failure attempts are reached.
     */
    @Test
    void testApproveOperationWithoutMatchingActivationIdFailureMax() throws Exception {
        final OperationCreateRequest request = new OperationCreateRequest();
        request.setActivationId(ACTIVATION_ID);
        request.setTemplateName("test-template");
        request.setUserId(USER_ID);
        request.setApplications(Collections.singletonList(APP_ID));

        final OperationDetailResponse operationDetailResponse = operationService.createOperation(request);
        assertTrue(operationRepository.findOperationWithoutLock(operationDetailResponse.getId()).isPresent());
        final OperationEntity entity = operationRepository.findOperationWithoutLock(operationDetailResponse.getId()).get();
        assertEquals(ACTIVATION_ID, entity.getActivationId());
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

    /**
     * Tests finding all operations for a user with specified filters.
     */
    @Test
    void testFindAllOperationsForUserWithFilters() throws Exception {
        final String activationId1 = "e43a5dec-afea-4a10-a80b-b2183399f16b";
        final String activationId2 = "68c5ca56-b419-4653-949f-49061a4be886";
        final List<String> applicationIds = List.of("PA_Tests");
        final Pageable pageable = PageRequest.of(0, 10);

        final OperationListForUserRequest request1 = new OperationListForUserRequest();
        request1.setUserId(USER_ID);
        request1.setApplications(applicationIds);
        request1.setActivationId(activationId1);
        request1.setPageNumber(pageable.getPageNumber());
        request1.setPageSize(pageable.getPageSize());
        final OperationListResponse operationListResponse1 = operationService.findAllOperationsForUser(request1);

        assertNotNull(operationListResponse1);
        assertEquals(2, operationListResponse1.size());

        final OperationListForUserRequest request2 = new OperationListForUserRequest();
        request2.setUserId(USER_ID);
        request2.setApplications(applicationIds);
        request2.setActivationId(activationId2);
        request2.setPageNumber(pageable.getPageNumber());
        request2.setPageSize(pageable.getPageSize());
        final OperationListResponse operationListResponse2 = operationService.findAllOperationsForUser(request2);

        assertNotNull(operationListResponse2);
        assertEquals(4, operationListResponse2.size());
    }

    /**
     * Tests finding all operations for a user without applying any filters.
     */
    @Test
    void testFindAllOperationsForUserWithoutFilters() throws Exception {
        final List<String> applicationIds = List.of("PA_Tests");
        final Pageable pageable = PageRequest.of(0, 10);

        final OperationListForUserRequest request1 = new OperationListForUserRequest();
        request1.setUserId(USER_ID);
        request1.setApplications(applicationIds);
        request1.setPageNumber(pageable.getPageNumber());
        request1.setPageSize(pageable.getPageSize());

        final OperationListResponse operationListResponse = operationService.findAllOperationsForUser(request1);

        assertNotNull(operationListResponse);
        assertEquals(7, operationListResponse.size());
    }

    /**
     * Tests the pagination functionality for finding all operations for a user.
     */
    @Test
    void testFindAllOperationsForUserPageable() throws Exception {
        final List<String> applicationIds = List.of("PA_Tests");
        final Pageable pageable1 = PageRequest.of(0, 2);

        final OperationListForUserRequest request1 = new OperationListForUserRequest();
        request1.setUserId(USER_ID);
        request1.setApplications(applicationIds);
        request1.setPageNumber(pageable1.getPageNumber());
        request1.setPageSize(pageable1.getPageSize());
        final OperationListResponse operationListResponse1 = operationService.findAllOperationsForUser(request1);

        assertNotNull(operationListResponse1);
        assertEquals(2, operationListResponse1.size());

        final Pageable pageable2 = PageRequest.of(1, 2);

        final OperationListForUserRequest request = new OperationListForUserRequest();
        request.setUserId(USER_ID);
        request.setApplications(applicationIds);
        request.setPageNumber(pageable2.getPageNumber());
        request.setPageSize(pageable2.getPageSize());

        final OperationListResponse operationListResponse2 = operationService.findAllOperationsForUser(request);

        assertNotNull(operationListResponse2);
        assertEquals(2, operationListResponse2.size());
        final Calendar calendar = Calendar.getInstance();
        calendar.setTime(operationListResponse2.get(0).getTimestampCreated());
        final int year = calendar.get(Calendar.YEAR);
        assertEquals(2025, year);
    }

    /**
     * Tests sorting functionality for finding all operations for a user.
     */
    @Test
    void testFindAllOperationsForUserSorting() throws Exception {
        final List<String> applicationIds = List.of("PA_Tests");
        final Pageable pageable = PageRequest.of(0, 2);

        final OperationListForUserRequest request1 = new OperationListForUserRequest();
        request1.setUserId(USER_ID);
        request1.setApplications(applicationIds);
        request1.setPageNumber(pageable.getPageNumber());
        request1.setPageSize(pageable.getPageSize());
        final OperationListResponse operationListResponse = operationService.findAllOperationsForUser(request1);

        assertTrue(operationListResponse.get(0).getTimestampCreated().after(operationListResponse.get(1).getTimestampCreated()));
        final Calendar calendar = Calendar.getInstance();
        calendar.setTime(operationListResponse.get(0).getTimestampCreated());
        final int year = calendar.get(Calendar.YEAR);
        assertEquals(2027, year);
    }

    /**
     * Tests the scenario when an application does not exist in the database.
     */
    @Test
    void testFindAllOperationsForUserApplicationNotExisting() {
        final String activationId1 = "e43a5dec-afea-4a10-a80b-b2183399f16b";
        final List<String> applicationIds = List.of("NOT_EXISTING");
        final Pageable pageable = PageRequest.of(0, 10);

        final OperationListForUserRequest request1 = new OperationListForUserRequest();
        request1.setUserId(USER_ID);
        request1.setApplications(applicationIds);
        request1.setActivationId(activationId1);
        request1.setPageNumber(pageable.getPageNumber());
        request1.setPageSize(pageable.getPageSize());

        assertThrows(GenericServiceException.class, () -> operationService.findAllOperationsForUser(request1));
    }

    /**
     * Tests finding pending operations for a user with specified filters.
     */
    @Test
    void testFindAPendingOperationsForUserWithFilters() throws Exception {
        final String activationId = "e43a5dec-afea-4a10-a80b-b2183399f16b";
        final List<String> applicationIds = List.of("PA_Tests");
        final Pageable pageable = PageRequest.of(0, 10);

        final OperationListForUserRequest request1 = new OperationListForUserRequest();
        request1.setUserId(USER_ID);
        request1.setApplications(applicationIds);
        request1.setActivationId(activationId);
        request1.setPageNumber(pageable.getPageNumber());
        request1.setPageSize(pageable.getPageSize());
        final OperationListResponse operationListResponse = operationService.findPendingOperationsForUser(request1);

        assertNotNull(operationListResponse);
        assertEquals(0, operationListResponse.size());
    }

    /**
     * Tests finding pending operations for a user without applying any filters.
     */
    @Test
    void testFindPendingOperationsForUserWithoutFilters() throws Exception {
        final List<String> applicationIds = List.of("PA_Tests");
        final Pageable pageable = PageRequest.of(0, 10);

        final OperationListForUserRequest request1 = new OperationListForUserRequest();
        request1.setUserId(USER_ID);
        request1.setApplications(applicationIds);
        request1.setPageNumber(pageable.getPageNumber());
        request1.setPageSize(pageable.getPageSize());
        final OperationListResponse operationListResponse = operationService.findPendingOperationsForUser(request1);

        assertNotNull(operationListResponse);
        assertEquals(2, operationListResponse.size());
    }

    /**
     * Tests the pagination functionality for finding pending operations for a user.
     */
    @Test
    void testFindPendingOperationsForUserPageable() throws Exception {
        final List<String> applicationIds = List.of("PA_Tests");
        final Pageable pageable1 = PageRequest.of(0, 1);

        final OperationListForUserRequest request1 = new OperationListForUserRequest();
        request1.setUserId(USER_ID);
        request1.setApplications(applicationIds);
        request1.setPageNumber(pageable1.getPageNumber());
        request1.setPageSize(pageable1.getPageSize());
        final OperationListResponse operationListResponse1 = operationService.findPendingOperationsForUser(request1);

        assertNotNull(operationListResponse1);
        assertEquals(1, operationListResponse1.size());

        final Pageable pageable2 = PageRequest.of(1, 1);

        final OperationListForUserRequest request = new OperationListForUserRequest();
        request.setUserId(USER_ID);
        request.setApplications(applicationIds);
        request.setPageNumber(pageable2.getPageNumber());
        request.setPageSize(pageable2.getPageSize());
        final OperationListResponse operationListResponse2 = operationService.findPendingOperationsForUser(request);

        assertNotNull(operationListResponse2);
        assertEquals(1, operationListResponse2.size());
        final Calendar calendar = Calendar.getInstance();
        calendar.setTime(operationListResponse2.get(0).getTimestampCreated());
        final int year = calendar.get(Calendar.YEAR);
        assertEquals(2021, year);
    }

    /**
     * Tests sorting functionality for finding pending operations for a user.
     */
    @Test
    void testFindPendingOperationsForUserSorting() throws Exception {
        final List<String> applicationIds = List.of("PA_Tests");
        final Pageable pageable = PageRequest.of(0, 2);

        final OperationListForUserRequest request1 = new OperationListForUserRequest();
        request1.setUserId(USER_ID);
        request1.setApplications(applicationIds);
        request1.setPageNumber(pageable.getPageNumber());
        request1.setPageSize(pageable.getPageSize());
        final OperationListResponse operationListResponse = operationService.findPendingOperationsForUser(request1);

        assertTrue(operationListResponse.get(0).getTimestampCreated().after(operationListResponse.get(1).getTimestampCreated()));
        final Calendar calendar = Calendar.getInstance();
        calendar.setTime(operationListResponse.get(0).getTimestampCreated());
        final int year = calendar.get(Calendar.YEAR);
        assertEquals(2023, year);
    }

    /**
     * Tests the scenario when an application does not exist in the database for pending operations.
     */
    @Test
    void testFindPendingOperationsForUserApplicationNotExisting() throws Exception {
        final String activationId1 = "68c5ca56-b419-4653-949f-49061a4be886";
        final List<String> applicationIds = List.of("NOT_EXISTING");
        final Pageable pageable = PageRequest.of(0, 10);

        final OperationListForUserRequest request1 = new OperationListForUserRequest();
        request1.setUserId(USER_ID);
        request1.setApplications(applicationIds);
        request1.setActivationId(activationId1);
        request1.setPageNumber(pageable.getPageNumber());
        request1.setPageSize(pageable.getPageSize());

        assertThrows(GenericServiceException.class, () -> operationService.findPendingOperationsForUser(request1));
    }

    /**
     * Tests the functionality of skipping expired operations when finding pending operations for a user.
     */
    @Test
    void testFindPendingOperationsForUserExpiredOperation() throws Exception {
        final String activationId2 = "68c5ca56-b419-4653-949f-49061a4be886";
        final List<String> applicationIds = List.of("PA_Tests");
        final Pageable pageable = PageRequest.of(0, 10);

        final OperationListForUserRequest request1 = new OperationListForUserRequest();
        request1.setUserId(USER_ID);
        request1.setApplications(applicationIds);
        request1.setActivationId(activationId2);
        request1.setPageNumber(pageable.getPageNumber());
        request1.setPageSize(pageable.getPageSize());

        final OperationListResponse operationListResponse2 = operationService.findPendingOperationsForUser(request1);

        assertNotNull(operationListResponse2);
        assertEquals(1, operationListResponse2.size());
    }

    @Test
    void testOperationClaim() throws Exception {
        final String operationId = createLoginOperation();

        final String userId = "user_" + UUID.randomUUID();
        final OperationDetailRequest detailRequest = new OperationDetailRequest();
        detailRequest.setOperationId(operationId);
        detailRequest.setUserId(userId);
        // Check operation claim
        assertEquals(userId, operationService.operationDetail(detailRequest).getUserId());
    }

    @Test
    void testOperationApproveWithValidProximityOtp() throws Exception {
        final OperationDetailResponse operation = createOperation(true);
        final String operationId = operation.getId();
        final OperationDetailRequest detailRequest = new OperationDetailRequest();
        detailRequest.setOperationId(operationId);

        final OperationDetailResponse detailResponse = operationService.operationDetail(detailRequest);
        final String totp = detailResponse.getProximityOtp();
        assertNotNull(totp);

        final OperationApproveRequest approveRequest = createOperationApproveRequest(operationId);
        approveRequest.getAdditionalData().put("proximity_otp", totp);

        final OperationUserActionResponse actionResponse = operationService.attemptApproveOperation(approveRequest);

        assertEquals("APPROVED", actionResponse.getResult().toString());
    }

    @Test
    void testOperationApproveWithInvalidProximityOtp() throws Exception {
        final OperationDetailResponse operation = createOperation(true);

        final OperationDetailRequest detailRequest = new OperationDetailRequest();
        detailRequest.setOperationId(operation.getId());

        final String totp = operationService.operationDetail(detailRequest).getProximityOtp();
        assertNotNull(totp);

        final OperationApproveRequest approveRequest = createOperationApproveRequest(operation.getId());
        approveRequest.getAdditionalData().put("proximity_otp", "1111"); // invalid otp on purpose, it is too short

        final OperationUserActionResponse result = operationService.attemptApproveOperation(approveRequest);

        assertEquals("APPROVAL_FAILED", result.getResult().toString());
    }

    /**
     * Tests the parsing and addition of device information to the operation cancellation details.
     * This test follows simulates an operation cancellation request with a specific user agent string.
     * It checks that the device information extracted from the user agent is correctly appended
     * to the operation's additional data. Predefined expected device information is used for comparison
     * against the actual device information found in the operation's additional data after the cancellation process.
     *
     * @throws Exception if any error occurs during the test execution.
     */
    @Test
    void testParsingDeviceOperationCancelDetail() throws Exception {
        final String parseableUserAgent = "PowerAuthNetworking/1.1.7 (en; cellular) com.wultra.app.MobileToken.wtest/2.0.0 (Apple; iOS/16.6.1; iphone12,3)";
        final UserAgent.Device expectedDevice = new UserAgent.Device();
        expectedDevice.setVersion("2.0.0");
        expectedDevice.setNetworkVersion("1.1.7");
        expectedDevice.setLanguage("en");
        expectedDevice.setConnection("cellular");
        expectedDevice.setProduct("com.wultra.app.MobileToken.wtest");
        expectedDevice.setPlatform("Apple");
        expectedDevice.setOs("iOS");
        expectedDevice.setOsVersion("16.6.1");
        expectedDevice.setModel("iphone12,3");

        final OperationCreateRequest request = new OperationCreateRequest();
        request.setTemplateName("test-template");
        request.setUserId("test-user");
        request.setApplications(Collections.singletonList(APP_ID));
        final OperationDetailResponse operation = createOperation(false);

        final OperationCancelRequest cancelRequest = new OperationCancelRequest();
        cancelRequest.setOperationId(operation.getId());
        cancelRequest.getAdditionalData().put("userAgent", parseableUserAgent);
        final OperationDetailResponse operationCancelDetailResponse = operationService.cancelOperation(cancelRequest);

        assertNotNull(operationCancelDetailResponse.getAdditionalData().get("device"));
        assertEquals(expectedDevice, operationCancelDetailResponse.getAdditionalData().get("device"));

        final OperationDetailRequest detailRequest = new OperationDetailRequest();
        detailRequest.setOperationId(operation.getId());
        final OperationDetailResponse detailResponse = operationService.operationDetail(detailRequest);

        assertNotNull(detailResponse.getAdditionalData().get("device"));
        assertEquals(expectedDevice, detailResponse.getAdditionalData().get("device"));
    }

    @Test
    void testAnonymousOperationApprovedUserChanged() throws GenericServiceException {
        final OperationCreateRequest operationCreateRequest = new OperationCreateRequest();
        operationCreateRequest.setApplications(List.of("PA_Tests"));
        operationCreateRequest.setTemplateName("test-template");
        final OperationDetailResponse operation = operationService.createOperation(operationCreateRequest);
        final OperationApproveRequest approveRequest = new OperationApproveRequest();
        approveRequest.setOperationId(operation.getId());
        approveRequest.setUserId("test_user");
        approveRequest.setData("A2");
        approveRequest.setApplicationId("PA_Tests");
        approveRequest.setSignatureType(SignatureType.POSSESSION_KNOWLEDGE);
        final OperationUserActionResponse response = operationService.attemptApproveOperation(approveRequest);
        assertEquals(UserActionResult.APPROVED, response.getResult());
        final OperationDetailRequest detailRequest = new OperationDetailRequest();
        detailRequest.setOperationId(operation.getId());
        final OperationDetailResponse operationDetail = operationService.operationDetail(detailRequest);
        assertEquals("test_user", operationDetail.getUserId());
    }

    @Test
    void testAnonymousOperationFailedApproveUserNotChanged() throws GenericServiceException {
        final OperationCreateRequest operationCreateRequest = new OperationCreateRequest();
        operationCreateRequest.setApplications(List.of("PA_Tests"));
        operationCreateRequest.setTemplateName("test-template");
        final OperationDetailResponse operation = operationService.createOperation(operationCreateRequest);
        final OperationApproveRequest approveRequest = new OperationApproveRequest();
        approveRequest.setOperationId(operation.getId());
        approveRequest.setUserId("invalid_user");
        approveRequest.setData("invalid_data");
        approveRequest.setApplicationId("PA_Tests");
        approveRequest.setSignatureType(SignatureType.POSSESSION_KNOWLEDGE);
        final OperationUserActionResponse response = operationService.attemptApproveOperation(approveRequest);
        assertEquals(UserActionResult.APPROVAL_FAILED, response.getResult());
        final OperationDetailRequest detailRequest = new OperationDetailRequest();
        detailRequest.setOperationId(operation.getId());
        final OperationDetailResponse operationDetail = operationService.operationDetail(detailRequest);
        assertNull(operationDetail.getUserId());
    }

    @Test
    void testAnonymousOperationFailedOperationUserNotChanged() throws GenericServiceException {
        final OperationCreateRequest operationCreateRequest = new OperationCreateRequest();
        operationCreateRequest.setApplications(List.of("PA_Tests"));
        operationCreateRequest.setTemplateName("test-template");
        final OperationDetailResponse operation = operationService.createOperation(operationCreateRequest);
        for (int i = 0; i < 5; i++) {
            final OperationApproveRequest approveRequest = new OperationApproveRequest();
            approveRequest.setOperationId(operation.getId());
            approveRequest.setUserId("invalid_user");
            approveRequest.setData("invalid_data");
            approveRequest.setApplicationId("PA_Tests");
            approveRequest.setSignatureType(SignatureType.POSSESSION_KNOWLEDGE);
            final OperationUserActionResponse response = operationService.attemptApproveOperation(approveRequest);
            if (i == 4) {
                assertEquals(UserActionResult.OPERATION_FAILED, response.getResult());
            } else {
                assertEquals(UserActionResult.APPROVAL_FAILED, response.getResult());
            }
        }
        final OperationDetailRequest detailRequest = new OperationDetailRequest();
        detailRequest.setOperationId(operation.getId());
        final OperationDetailResponse operationDetail = operationService.operationDetail(detailRequest);
        assertNull(operationDetail.getUserId());
    }

    @Test
    void testAnonymousOperationRejectUserChanged() throws GenericServiceException {
        final OperationCreateRequest operationCreateRequest = new OperationCreateRequest();
        operationCreateRequest.setApplications(List.of("PA_Tests"));
        operationCreateRequest.setTemplateName("test-template");
        final OperationDetailResponse operation = operationService.createOperation(operationCreateRequest);
        final OperationRejectRequest rejectRequest = new OperationRejectRequest();
        rejectRequest.setOperationId(operation.getId());
        rejectRequest.setUserId("test_user");
        rejectRequest.setApplicationId("PA_Tests");
        final OperationUserActionResponse response = operationService.rejectOperation(rejectRequest);
        assertEquals(UserActionResult.REJECTED, response.getResult());
        final OperationDetailRequest detailRequest = new OperationDetailRequest();
        detailRequest.setOperationId(operation.getId());
        final OperationDetailResponse operationDetail = operationService.operationDetail(detailRequest);
        assertEquals("test_user", operationDetail.getUserId());
    }

    @Test
    void testAnonymousOperationRejectFailedUserNotChanged() throws GenericServiceException {
        final OperationCreateRequest operationCreateRequest = new OperationCreateRequest();
        operationCreateRequest.setApplications(List.of("PA_Tests"));
        operationCreateRequest.setTemplateName("test-template");
        final OperationDetailResponse operation = operationService.createOperation(operationCreateRequest);
        final OperationRejectRequest rejectRequest = new OperationRejectRequest();
        rejectRequest.setOperationId(operation.getId());
        rejectRequest.setUserId("test_user");
        rejectRequest.setApplicationId(APP_ID);
        final OperationUserActionResponse response = operationService.rejectOperation(rejectRequest);
        assertEquals(UserActionResult.REJECT_FAILED, response.getResult());
        final OperationDetailRequest detailRequest = new OperationDetailRequest();
        detailRequest.setOperationId(operation.getId());
        final OperationDetailResponse operationDetail = operationService.operationDetail(detailRequest);
        assertNull(operationDetail.getUserId());
    }

    private void createApplication() throws GenericServiceException {
        boolean appExists = applicationService.getApplicationList().getApplications().stream()
                .anyMatch(app -> app.getApplicationId().equals(APP_ID));
        if (!appExists) {
            final CreateApplicationRequest request = new CreateApplicationRequest();
            request.setApplicationId(APP_ID);
            applicationService.createApplication(request);
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

    private OperationDetailResponse createOperation(final boolean proximityOtp) throws Exception {
        final OperationCreateRequest operationCreateRequest = new OperationCreateRequest();
        operationCreateRequest.setApplications(List.of("PA_Tests"));
        operationCreateRequest.setTemplateName("test-template");
        operationCreateRequest.setUserId("test-user");
        operationCreateRequest.setProximityCheckEnabled(proximityOtp);
        return operationService.createOperation(operationCreateRequest);
    }

    private static OperationApproveRequest createOperationApproveRequest(final String operationId) {
        final OperationApproveRequest approveRequest = new OperationApproveRequest();
        approveRequest.setOperationId(operationId);
        approveRequest.setUserId("test-user");
        approveRequest.setApplicationId("PA_Tests");
        approveRequest.setData("A2");
        approveRequest.setSignatureType(SignatureType.POSSESSION_KNOWLEDGE);
        return approveRequest;
    }

}
