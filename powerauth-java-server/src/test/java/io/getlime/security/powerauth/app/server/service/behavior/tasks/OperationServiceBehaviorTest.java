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
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
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
import static org.junit.jupiter.api.Assertions.assertNotNull;

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
    private static final String ACTIVATION_ID = "68c5ca56-b419-4653-949f-49061a4be886"; // created by @Sql

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

    /**
     * Tests finding all operations for a user with specified filters.
     */
    @Test
    void testFindAllOperationsForUserWithFilters() throws Exception {
        final String userId = "testUser";
        final String activationId1 = "e43a5dec-afea-4a10-a80b-b2183399f16b";
        final String activationId2 = "68c5ca56-b419-4653-949f-49061a4be886";
        final List<String> applicationIds = List.of("PA_Tests");
        final Pageable pageable = PageRequest.of(0, 10);

        final OperationServiceBehavior.OperationListRequest request1 =
                new OperationServiceBehavior.OperationListRequest(userId, applicationIds, activationId1, pageable);
        final OperationListResponse operationListResponse1 = operationService.findAllOperationsForUser(request1);

        assertNotNull(operationListResponse1);
        assertEquals(2, operationListResponse1.size());

        final OperationServiceBehavior.OperationListRequest request2 =
                new OperationServiceBehavior.OperationListRequest(userId, applicationIds, activationId2, pageable);
        final OperationListResponse operationListResponse2 = operationService.findAllOperationsForUser(request2);

        assertNotNull(operationListResponse2);
        assertEquals(4, operationListResponse2.size());
    }

    /**
     * Tests finding all operations for a user without applying any filters.
     */
    @Test
    void testFindAllOperationsForUserWithoutFilters() throws Exception {
        final String userId = "testUser";
        final List<String> applicationIds = List.of("PA_Tests");
        final Pageable pageable = PageRequest.of(0, 10);

        final OperationServiceBehavior.OperationListRequest request =
                new OperationServiceBehavior.OperationListRequest(userId, applicationIds, null, pageable);
        final OperationListResponse operationListResponse = operationService.findAllOperationsForUser(request);

        assertNotNull(operationListResponse);
        assertEquals(7, operationListResponse.size());
    }

    /**
     * Tests the pagination functionality for finding all operations for a user.
     */
    @Test
    void testFindAllOperationsForUserPageable() throws Exception {
        final String userId = "testUser";
        final List<String> applicationIds = List.of("PA_Tests");
        final Pageable pageable1 = PageRequest.of(0, 2);

        final OperationServiceBehavior.OperationListRequest request1 =
                new OperationServiceBehavior.OperationListRequest(userId, applicationIds, null, pageable1);
        final OperationListResponse operationListResponse1 = operationService.findAllOperationsForUser(request1);

        assertNotNull(operationListResponse1);
        assertEquals(2, operationListResponse1.size());

        final Pageable pageable2 = PageRequest.of(1, 2);

        final OperationServiceBehavior.OperationListRequest request =
                new OperationServiceBehavior.OperationListRequest(userId, applicationIds, null, pageable2);
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
        final String userId = "testUser";
        final List<String> applicationIds = List.of("PA_Tests");
        final Pageable pageable = PageRequest.of(0, 2);

        final OperationServiceBehavior.OperationListRequest request =
                new OperationServiceBehavior.OperationListRequest(userId, applicationIds, null, pageable);
        final OperationListResponse operationListResponse = operationService.findAllOperationsForUser(request);

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
    void testFindAllOperationsForUserApplicationNotExisting() throws Exception {
        final String userId = "testUser";
        final String activationId1 = "e43a5dec-afea-4a10-a80b-b2183399f16b";
        final List<String> applicationIds = List.of("NOT_EXISTING");
        final Pageable pageable = PageRequest.of(0, 10);

        final OperationServiceBehavior.OperationListRequest request =
                new OperationServiceBehavior.OperationListRequest(userId, applicationIds, activationId1, pageable);

        assertThrows(GenericServiceException.class, () -> operationService.findAllOperationsForUser(request));
    }

    /**
     * Tests finding pending operations for a user with specified filters.
     */
    @Test
    void testFindAPendingOperationsForUserWithFilters() throws Exception {
        final String userId = "testUser";
        final String activationId = "e43a5dec-afea-4a10-a80b-b2183399f16b";
        final List<String> applicationIds = List.of("PA_Tests");
        final Pageable pageable = PageRequest.of(0, 10);

        final OperationServiceBehavior.OperationListRequest request1 =
                new OperationServiceBehavior.OperationListRequest(userId, applicationIds, activationId, pageable);
        final OperationListResponse operationListResponse = operationService.findPendingOperationsForUser(request1);

        assertNotNull(operationListResponse);
        assertEquals(0, operationListResponse.size());
    }

    /**
     * Tests finding pending operations for a user without applying any filters.
     */
    @Test
    void testFindPendingOperationsForUserWithoutFilters() throws Exception {
        final String userId = "testUser";
        final List<String> applicationIds = List.of("PA_Tests");
        final Pageable pageable = PageRequest.of(0, 10);

        final OperationServiceBehavior.OperationListRequest request =
                new OperationServiceBehavior.OperationListRequest(userId, applicationIds, null, pageable);
        final OperationListResponse operationListResponse = operationService.findPendingOperationsForUser(request);

        assertNotNull(operationListResponse);
        assertEquals(2, operationListResponse.size());
    }

    /**
     * Tests the pagination functionality for finding pending operations for a user.
     */
    @Test
    void testFindPendingOperationsForUserPageable() throws Exception {
        final String userId = "testUser";
        final List<String> applicationIds = List.of("PA_Tests");
        final Pageable pageable1 = PageRequest.of(0, 1);

        final OperationServiceBehavior.OperationListRequest request1 =
                new OperationServiceBehavior.OperationListRequest(userId, applicationIds, null, pageable1);
        final OperationListResponse operationListResponse1 = operationService.findPendingOperationsForUser(request1);

        assertNotNull(operationListResponse1);
        assertEquals(1, operationListResponse1.size());

        final Pageable pageable2 = PageRequest.of(1, 1);

        final OperationServiceBehavior.OperationListRequest request =
                new OperationServiceBehavior.OperationListRequest(userId, applicationIds, null, pageable2);
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
        final String userId = "testUser";
        final List<String> applicationIds = List.of("PA_Tests");
        final Pageable pageable = PageRequest.of(0, 2);

        final OperationServiceBehavior.OperationListRequest request =
                new OperationServiceBehavior.OperationListRequest(userId, applicationIds, null, pageable);
        final OperationListResponse operationListResponse = operationService.findPendingOperationsForUser(request);

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
        final String userId = "testUser";
        final String activationId1 = "68c5ca56-b419-4653-949f-49061a4be886";
        final List<String> applicationIds = List.of("NOT_EXISTING");
        final Pageable pageable = PageRequest.of(0, 10);

        final OperationServiceBehavior.OperationListRequest request =
                new OperationServiceBehavior.OperationListRequest(userId, applicationIds, activationId1, pageable);

        assertThrows(GenericServiceException.class, () -> operationService.findPendingOperationsForUser(request));
    }

    /**
     * Tests the functionality of skipping expired operations when finding pending operations for a user.
     */
    @Test
    void testFindPendingOperationsForUserExpiredOperation() throws Exception {
        final String userId = "testUser";
        final String activationId2 = "68c5ca56-b419-4653-949f-49061a4be886";
        final List<String> applicationIds = List.of("PA_Tests");
        final Pageable pageable = PageRequest.of(0, 10);

        final OperationServiceBehavior.OperationListRequest request =
                new OperationServiceBehavior.OperationListRequest(userId, applicationIds, activationId2, pageable);

        final OperationListResponse operationListResponse2 = operationService.findPendingOperationsForUser(request);

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
        assertEquals(userId, operationService.getOperation(detailRequest).getUserId());
    }

    @Test
    void testOperationClaim_activationId() throws Exception {
        final String operationId = createLoginOperation(ACTIVATION_ID);

        final String userId = "testUser";
        final OperationDetailRequest detailRequest = new OperationDetailRequest();
        detailRequest.setOperationId(operationId);
        detailRequest.setUserId(userId);

        assertEquals(userId, operationService.getOperation(detailRequest).getUserId());
    }

    @Test
    void testOperationClaim_activationId_invalidUserId() throws Exception {
        final String operationId = createLoginOperation(ACTIVATION_ID);

        final String userId = "user_" + UUID.randomUUID();
        final OperationDetailRequest detailRequest = new OperationDetailRequest();
        detailRequest.setOperationId(operationId);
        detailRequest.setUserId(userId);

        final GenericServiceException thrown = assertThrows(GenericServiceException.class, () ->
                operationService.getOperation(detailRequest).getUserId());

        assertEquals("ERR0024", thrown.getCode());
    }

    @Test
    void testOperationApproveWithValidProximityOtp() throws Exception {
        final OperationDetailResponse operation = createOperation(true);
        final String operationId = operation.getId();
        final OperationDetailRequest detailRequest = new OperationDetailRequest();
        detailRequest.setOperationId(operationId);

        final OperationDetailResponse detailResponse = operationService.getOperation(detailRequest);
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

        final String totp = operationService.getOperation(detailRequest).getProximityOtp();
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
        final OperationDetailResponse detailResponse = operationService.getOperation(detailRequest);

        assertNotNull(detailResponse.getAdditionalData().get("device"));
        assertEquals(expectedDevice, detailResponse.getAdditionalData().get("device"));
    }

    private void createApplication() throws GenericServiceException {
        boolean appExists = applicationService.getApplicationList().getApplications().stream()
                .anyMatch(app -> app.getApplicationId().equals(APP_ID));
        if (!appExists) {
            applicationService.createApplication(APP_ID, new KeyConvertor());
        }
    }

    private String createLoginOperation() throws GenericServiceException {
        return createLoginOperation(null);
    }

    private String createLoginOperation(final String activationId) throws GenericServiceException {
        final OperationCreateRequest operationCreateRequest = new OperationCreateRequest();
        operationCreateRequest.setActivationId(activationId);
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
