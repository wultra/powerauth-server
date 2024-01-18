/*
 * PowerAuth Server and related software components
 * Copyright (C) 2024 Wultra s.r.o.
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
package io.getlime.security.powerauth.app.server.controller.api;

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.entity.CallbackUrl;
import com.wultra.security.powerauth.client.model.enumeration.*;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.response.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link PowerAuthController}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
@ActiveProfiles("test")
@Transactional
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PowerAuthControllerTest {

    @Autowired
    private PowerAuthClient powerAuthClient;

    @Autowired
    private PowerAuthControllerTestConfig config;

    @BeforeAll
    void initializeData() throws Exception {
        config.createApplication(powerAuthClient);
        config.createLoginOperationTemplate(powerAuthClient);
    }

    /**
     * Tests the process of removing an activation.
     * <p>
     * This test carries out the following operations:
     * <ol>
     *   <li>Creates a request to remove an existing activation, using the activation ID from the configuration.</li>
     *   <li>Sends the removal request and asserts that the response confirms the activation's removal.</li>
     *   <li>Asserts that the activation ID in the removal response matches the one from the configuration.</li>
     *   <li>Fetches the current status of the activation to verify that it has been set to 'REMOVED'.</li>
     * </ol>
     * </p>
     *
     * @throws Exception if any error occurs during the test execution or if the assertions fail.
     */
    @Test
    void testRemoveActivation() throws Exception {
        config.initActivation(powerAuthClient);
        final RemoveActivationRequest removeActivationRequest = new RemoveActivationRequest();
        removeActivationRequest.setActivationId(config.getActivationId());
        removeActivationRequest.setExternalUserId(null);

        final RemoveActivationResponse removeActivationResponse = powerAuthClient.removeActivation(removeActivationRequest);
        assertTrue(removeActivationResponse.isRemoved());
        assertEquals(config.getActivationId(), removeActivationResponse.getActivationId());

        final GetActivationStatusRequest activationStatusRequest = new GetActivationStatusRequest();
        activationStatusRequest.setActivationId(config.getActivationId());

        final GetActivationStatusResponse statusResponse = powerAuthClient.getActivationStatus(activationStatusRequest);
        assertEquals(ActivationStatus.REMOVED, statusResponse.getActivationStatus());
    }

    /**
     * Tests the pagination functionality in retrieving an activation list for a specific user.
     * <p>
     * The test executes the following steps:
     * <ol>
     *   <li>Prepares a base request for fetching user activations, using user and application IDs from the configuration.</li>
     *   <li>Creates 10 new activations for the user to ensure multiple pages of data.</li>
     *   <li>Fetches the first page of activations, specifying page number and size, and validates the number of activations returned.</li>
     *   <li>Fetches the second page of activations with a different page number but same page size, again validating the number of activations returned.</li>
     *   <li>Asserts that the activations on the two pages are not identical, verifying the functionality of pagination.</li>
     *   <li>Removes the created activations to maintain test isolation and ensure clean up after test execution.</li>
     * </ol>
     * </p>
     *
     * @throws Exception if any error occurs during the test execution, the initiation of activations, the removal of activations, or if the assertions fail.
     */
    @Test
    void testActivationListForUserPagination() throws Exception {
        final GetActivationListForUserRequest baseRequest = new GetActivationListForUserRequest();
        baseRequest.setUserId(PowerAuthControllerTestConfig.USER_ID);
        baseRequest.setApplicationId(config.getApplicationId());
        final List<String> activationIds = new ArrayList<>();

        for (int i = 0; i < 10; i++) {
            final InitActivationRequest initActivationRequest = new InitActivationRequest();
            initActivationRequest.setApplicationId(config.getApplicationId());
            initActivationRequest.setUserId(PowerAuthControllerTestConfig.USER_ID);
            final InitActivationResponse initResponse = powerAuthClient.initActivation(initActivationRequest);
            activationIds.add(initResponse.getActivationId());
        }

        final GetActivationListForUserRequest requestPage1 = new GetActivationListForUserRequest();
        requestPage1.setUserId(baseRequest.getUserId());
        requestPage1.setApplicationId(baseRequest.getApplicationId());
        requestPage1.setPageNumber(0);
        requestPage1.setPageSize(5);

        final GetActivationListForUserResponse activationListForUserResponse1 = powerAuthClient
                .getActivationListForUser(requestPage1);
        assertEquals(5, activationListForUserResponse1.getActivations().size());

        final GetActivationListForUserRequest requestPage2 = new GetActivationListForUserRequest();
        requestPage2.setUserId(baseRequest.getUserId());
        requestPage2.setApplicationId(baseRequest.getApplicationId());
        requestPage2.setPageNumber(1);
        requestPage2.setPageSize(5);

        final GetActivationListForUserResponse activationListForUserResponse2 = powerAuthClient
                .getActivationListForUser(requestPage2);
        assertEquals(5, activationListForUserResponse2.getActivations().size());

        assertNotEquals(activationListForUserResponse2.getActivations(), activationListForUserResponse1.getActivations());

        for (final String id : activationIds) {
            final RemoveActivationResponse removeActivationResponse = powerAuthClient.removeActivation(id, PowerAuthControllerTestConfig.USER_ID);
            assertTrue(removeActivationResponse.isRemoved());
        }
    }

    /**
     * Tests the activation lookup process based on specific criteria.
     *
     * <p>This test executes the following actions:</p>
     * <ol>
     *   <li>Constructs a request to look up activations, specifying criteria such as user IDs,
     *       application IDs, activation status, and a timestamp. The timestamp is set to 10 seconds
     *       before the current time to include recent activations.</li>
     *   <li>Sends the lookup request and verifies the response to ensure it contains the expected
     *       number of activations meeting the specified criteria.</li>
     *   <li>Asserts that the number of activations in the response matches the expected count,
     *       confirming the correct functionality of the lookup process.</li>
     * </ol>
     *
     * @throws Exception if any errors occur during the execution of the test or if the assertions fail.
     */
    @Test
    void testLookupActivations() throws Exception {
        config.initActivation(powerAuthClient);
        final LookupActivationsRequest lookupActivationsRequest = new LookupActivationsRequest();
        /* We are looking for an activation created during initialization of the test suite. */
        final Date timestampCreated = Date.from(LocalDateTime.now().minusSeconds(1).atZone(ZoneId.systemDefault()).toInstant());
        lookupActivationsRequest.setUserIds(List.of(PowerAuthControllerTestConfig.USER_ID));
        lookupActivationsRequest.setApplicationIds(List.of(config.getApplicationId()));
        lookupActivationsRequest.setActivationStatus(ActivationStatus.CREATED);
        lookupActivationsRequest.setTimestampLastUsedAfter(timestampCreated);

        final LookupActivationsResponse lookupActivationsResponse = powerAuthClient.lookupActivations(lookupActivationsRequest);
        assertEquals(1, lookupActivationsResponse.getActivations().size());
        config.removeActivation(powerAuthClient);
    }

    /**
     * Tests the process of updating the status of specific activations.
     *
     * <p>This test performs the following actions:</p>
     * <ol>
     *   <li>Creates a request to update the status of specified activations to 'BLOCKED', using the activation ID from the configuration.</li>
     *   <li>Sends the update request and verifies that the response confirms the successful update of the activation statuses.</li>
     *   <li>Retrieves the current status of the activation to validate that it has been updated to 'BLOCKED' as expected.</li>
     * </ol>
     *
     * @throws Exception if any error occurs during the test execution or if the assertions fail.
     */
    @Test
    void testUpdateActivationStatus() throws Exception {
        config.initActivation(powerAuthClient);
        final UpdateStatusForActivationsRequest updateStatusForActivationsRequest = new UpdateStatusForActivationsRequest();
        updateStatusForActivationsRequest.setActivationIds(List.of(config.getActivationId()));
        updateStatusForActivationsRequest.setActivationStatus(ActivationStatus.BLOCKED);

        final UpdateStatusForActivationsResponse updateStatusForActivationsResponse =
                powerAuthClient.updateStatusForActivations(updateStatusForActivationsRequest);
        assertTrue(updateStatusForActivationsResponse.isUpdated());

        final GetActivationStatusRequest activationStatusRequest = new GetActivationStatusRequest();
        activationStatusRequest.setActivationId(config.getActivationId());
        final GetActivationStatusResponse statusResponse = powerAuthClient.getActivationStatus(activationStatusRequest);
        assertEquals(ActivationStatus.BLOCKED, statusResponse.getActivationStatus());
        config.removeActivation(powerAuthClient);
    }

    /**
     * Tests the process of retrieving activation history for a specific activation ID.
     * <p>
     * This test performs the following steps:
     * <ol>
     *   <li>Defines a time range, starting 10 seconds before the current time and ending 10 seconds after.</li>
     *   <li>Constructs an activation history request with the specified activation ID and the defined time range.</li>
     *   <li>Sends the request to retrieve the activation history.</li>
     *   <li>Asserts that the response contains exactly one history item.</li>
     *   <li>Verifies that the activation ID of the history item matches the activation ID used in the request.</li>
     * </ol>
     * </p>
     *
     * @throws Exception if any error occurs during the test execution or if the assertions fail.
     */
    @Test
    void testActivationHistory() throws Exception {
        config.initActivation(powerAuthClient);
        final Date before = Date.from(LocalDateTime.now().minusSeconds(1).atZone(ZoneId.systemDefault()).toInstant());
        final Date after = Date.from(LocalDateTime.now().plusSeconds(1).atZone(ZoneId.systemDefault()).toInstant());
        final ActivationHistoryRequest activationHistoryRequest = new ActivationHistoryRequest();
        activationHistoryRequest.setActivationId(config.getActivationId());
        activationHistoryRequest.setTimestampFrom(before);
        activationHistoryRequest.setTimestampTo(after);

        final ActivationHistoryResponse activationHistoryResponse = powerAuthClient.getActivationHistory(activationHistoryRequest);
        assertEquals(1, activationHistoryResponse.getItems().size());
        assertEquals(config.getActivationId(), activationHistoryResponse.getItems().get(0).getActivationId());
        config.removeActivation(powerAuthClient);
    }

    /**
     * Tests the process of blocking and unblocking an activation.
     * <p>
     * This test follows these steps:
     * <ol>
     *   <li>Prepares and sends a request to block an activation, specifying the activation ID and a blocking reason.</li>
     *   <li>Verifies that the response indicates the activation was successfully blocked.</li>
     *   <li>Asserts the consistency of the activation ID and blocking reason in the block response.</li>
     *   <li>Fetches the current status of the activation to confirm that it has been changed to 'BLOCKED'.</li>
     *   <li>Prepares and sends a request to unblock the same activation.</li>
     *   <li>Verifies that the unblock response indicates the activation was successfully unblocked.</li>
     *   <li>Fetches the activation status again to confirm that it has reverted to 'ACTIVE'.</li>
     * </ol>
     * </p>
     *
     * @throws Exception if any error occurs during the test execution or if the assertions fail.
     */
    @Test
    void testBlockAndUnblockActivation() throws Exception {
        config.initActivation(powerAuthClient);
        final UpdateStatusForActivationsRequest updateStatusForActivationsRequest = new UpdateStatusForActivationsRequest();
        updateStatusForActivationsRequest.setActivationIds(List.of(config.getActivationId()));
        updateStatusForActivationsRequest.setActivationStatus(ActivationStatus.ACTIVE);

        final UpdateStatusForActivationsResponse updateStatusForActivationsResponse =
                powerAuthClient.updateStatusForActivations(updateStatusForActivationsRequest);
        assertTrue(updateStatusForActivationsResponse.isUpdated());

        final BlockActivationRequest blockActivationRequest = new BlockActivationRequest();
        final String blockingReason = "Test-blocking";
        blockActivationRequest.setActivationId(config.getActivationId());
        blockActivationRequest.setReason(blockingReason);

        final BlockActivationResponse blockActivationResponse = powerAuthClient.blockActivation((blockActivationRequest));
        assertEquals(config.getActivationId(), blockActivationResponse.getActivationId());
        assertEquals(blockingReason, blockActivationResponse.getBlockedReason());
        assertEquals(ActivationStatus.BLOCKED, blockActivationResponse.getActivationStatus());

        final GetActivationStatusRequest activationStatusRequest = new GetActivationStatusRequest();
        activationStatusRequest.setActivationId(config.getActivationId());
        final GetActivationStatusResponse statusResponse = powerAuthClient.getActivationStatus(activationStatusRequest);
        assertEquals(ActivationStatus.BLOCKED, statusResponse.getActivationStatus());

        final UnblockActivationRequest unblockActivationRequest = new UnblockActivationRequest();
        unblockActivationRequest.setActivationId(config.getActivationId());
        final UnblockActivationResponse unblockActivationResponse = powerAuthClient.unblockActivation(unblockActivationRequest);
        assertEquals(config.getActivationId(), unblockActivationResponse.getActivationId());
        assertEquals(ActivationStatus.ACTIVE, unblockActivationResponse.getActivationStatus());

        final GetActivationStatusResponse statusResponse2 = powerAuthClient.getActivationStatus(activationStatusRequest);
        assertEquals(ActivationStatus.ACTIVE, statusResponse2.getActivationStatus());
        config.removeActivation(powerAuthClient);
    }

    /**
     * Tests the process of retrieving activation history for a specific activation ID.
     * <p>
     * This test performs the following steps:
     * <ol>
     *   <li>Defines a time range, starting 10 seconds before the current time and ending 10 seconds after.</li>
     *   <li>Constructs an activation history request with the specified activation ID and the defined time range.</li>
     *   <li>Sends the request to retrieve the activation history.</li>
     *   <li>Asserts that the response contains exactly one history item.</li>
     *   <li>Verifies that the activation ID of the history item matches the activation ID used in the request.</li>
     * </ol>
     * </p>
     *
     * @throws Exception if any error occurs during the test execution or if the assertions fail.
     */
    @Test
    void testUpdateActivation() throws Exception {
        config.initActivation(powerAuthClient);
        final UpdateStatusForActivationsRequest updateStatusForActivationsRequest = new UpdateStatusForActivationsRequest();
        updateStatusForActivationsRequest.setActivationIds(List.of(config.getActivationId()));
        updateStatusForActivationsRequest.setActivationStatus(ActivationStatus.ACTIVE);

        final UpdateStatusForActivationsResponse updateStatusForActivationsResponse =
                powerAuthClient.updateStatusForActivations(updateStatusForActivationsRequest);
        assertTrue(updateStatusForActivationsResponse.isUpdated());

        final UpdateActivationNameRequest updateActivationNameRequest = new UpdateActivationNameRequest();
        final String updatedName = "Updated_app_name";
        final String externalUserId = "external_user";
        updateActivationNameRequest.setActivationId(config.getActivationId());
        updateActivationNameRequest.setActivationName(updatedName);
        updateActivationNameRequest.setExternalUserId(externalUserId);

        final UpdateActivationNameResponse updateActivationNameResponse =
                powerAuthClient.updateActivationName(updateActivationNameRequest);
        assertEquals(updatedName, updateActivationNameResponse.getActivationName());
        assertEquals(config.getActivationId(), updateActivationNameResponse.getActivationId());
        assertEquals(ActivationStatus.ACTIVE, updateActivationNameResponse.getActivationStatus());
        config.removeActivation(powerAuthClient);
    }

    /**
     * Tests the handling of a bad request in the update activation functionality.
     * <p>
     * This test performs the following actions:
     * <ol>
     *   <li>Sends an incomplete request to the activation name update endpoint, which is expected to be invalid.</li>
     *   <li>Catches and asserts the thrown PowerAuthClientException to verify the response handling of a bad request.</li>
     *   <li>Checks that the exception message and localized message contain the expected error message.</li>
     *   <li>Verifies that the PowerAuthClientException contains the expected PowerAuth error code, confirming correct error identification.</li>
     * </ol>
     * The test expects a specific error code and message indicating that mandatory fields in the request object are blank.
     * </p>
     *
     * @throws Exception if any error occurs during the test execution or if the assertions fail.
     */
    @Test
    void testUpdateActivation_badRequest() throws Exception {
        final String expectedErrorMessage = "requestObject.activationId - must not be blank," +
                " requestObject.activationName - must not be blank, requestObject.externalUserId - must not be blank";
        final String expectedErrorCode = "ERR0024";
        final PowerAuthClientException thrownException = assertThrows(
                PowerAuthClientException.class,
                () -> powerAuthClient.updateActivationName(new UpdateActivationNameRequest())
        );
        assertEquals(expectedErrorMessage, thrownException.getMessage());
        assertEquals(expectedErrorMessage, thrownException.getLocalizedMessage());
        assertEquals(expectedErrorMessage, thrownException.getLocalizedMessage());
        assertTrue(thrownException.getPowerAuthError().isPresent());
        assertEquals(expectedErrorCode, thrownException.getPowerAuthError().get().getCode());
    }

    /**
     * Tests the operation approval process.
     * <p>
     * This test validates the functionality of approving an operation. It involves the following steps:
     * <ol>
     *   <li>Creation of a new operation.</li>
     *   <li>Construction of an operation approval request, which includes setting various parameters like operation ID, user ID, data, application ID, and signature type.</li>
     *   <li>Submission of the operation approval request to the PowerAuthClient's operation approval endpoint.</li>
     *   <li>Verification of the response to ensure that the operation was approved successfully. This includes checking the response status, the operation's data, template name, and operation ID.</li>
     *   <li>Confirmation that the operation entity in the database reflects the approved status.</li>
     * </ol>
     * This test ensures that the operation approval workflow functions correctly and that the operation's status is updated as expected in the system.
     *
     * @throws Exception if there is an issue with the PowerAuthClient's operation approval process or the initial operation creation.
     */
    @Test
    void testOperationApprove() throws Exception {
        final OperationDetailResponse operationDetailResponse = config.createOperation(powerAuthClient);
        final String operationId = operationDetailResponse.getId();
        final OperationApproveRequest operationApproveRequest = new OperationApproveRequest();
        operationApproveRequest.setOperationId(operationId);
        operationApproveRequest.setUserId(PowerAuthControllerTestConfig.USER_ID);
        operationApproveRequest.setData(PowerAuthControllerTestConfig.DATA);
        operationApproveRequest.setApplicationId(config.getApplicationId());
        operationApproveRequest.setSignatureType(SignatureType.POSSESSION_KNOWLEDGE);

        final OperationUserActionResponse operationUserActionResponse =
                powerAuthClient.operationApprove(operationApproveRequest);
        assertNotNull(operationUserActionResponse.getOperation());
        assertEquals(OperationStatus.APPROVED, operationUserActionResponse.getOperation().getStatus());
        assertEquals(PowerAuthControllerTestConfig.DATA, operationUserActionResponse.getOperation().getData());
        assertEquals(config.getLoginOperationTemplateName(), operationUserActionResponse.getOperation().getTemplateName());
        assertEquals(operationId, operationUserActionResponse.getOperation().getId());
    }

    /**
     * Tests the retrieval of operation details.
     * <p>
     * This test checks the functionality of fetching details for a specific operation. It proceeds as follows:
     * <ol>
     *   <li>Creates a new operation using the provided configuration.</li>
     *   <li>Constructs a request for operation details, using the operation ID obtained from the previous step.</li>
     *   <li>Retrieves the operation details by sending the request to the PowerAuth client.</li>
     *   <li>Asserts that the response contains the correct operation status, data, template name, and ID.</li>
     * </ol>
     * This test ensures that the operation details are correctly retrieved and match the expected values.
     *
     * @throws Exception if an error occurs in operation creation or detail retrieval, or if the assertions fail.
     */
    @Test
    void testGetOperationDetail() throws Exception {
        final OperationDetailResponse operation = config.createOperation(powerAuthClient);
        final OperationDetailRequest detailRequest = new OperationDetailRequest();
        final String operationId = operation.getId();
        detailRequest.setOperationId(operationId);
        detailRequest.setUserId(PowerAuthControllerTestConfig.USER_ID);

        final OperationDetailResponse detailResponse = powerAuthClient.operationDetail(detailRequest);
        assertEquals(OperationStatus.PENDING, detailResponse.getStatus());
        assertEquals(PowerAuthControllerTestConfig.DATA, detailResponse.getData());
        assertEquals(config.getLoginOperationTemplateName(), detailResponse.getTemplateName());
        assertEquals(operationId, detailResponse.getId());
    }

    /**
     * Tests the retrieval of operation details.
     * <p>
     * This test checks the functionality of fetching details for a specific operation. It proceeds as follows:
     * <ol>
     *   <li>Creates a new operation using the provided configuration.</li>
     *   <li>Constructs a request for operation details, using the operation ID obtained from the previous step.</li>
     *   <li>Retrieves the operation details by sending the request to the PowerAuth client.</li>
     *   <li>Asserts that the response contains the correct operation status, data, template name, and ID.</li>
     * </ol>
     * This test ensures that the operation details are correctly retrieved and match the expected values.
     *
     * @throws Exception if an error occurs in operation creation or detail retrieval, or if the assertions fail.
     */
    @Test
    void testCreateReadDelete() throws Exception {
        config.createCallback(powerAuthClient);
        final GetCallbackUrlListResponse callbackUrlListResponse = powerAuthClient.getCallbackUrlList(config.getApplicationId());

        boolean callbackFound = false;
        for (CallbackUrl callback : callbackUrlListResponse.getCallbackUrlList()) {
            if (PowerAuthControllerTestConfig.CALLBACK_NAME.equals(callback.getName())) {
                callbackFound = true;
                assertEquals(PowerAuthControllerTestConfig.CALLBACK_URL, callback.getCallbackUrl());
                assertEquals(config.getApplicationId(), callback.getApplicationId());
                assertEquals(1, callback.getAttributes().size());
                assertEquals("activationId", callback.getAttributes().get(0));
                config.removeCallback(powerAuthClient, callback.getId());
            }
            assertTrue(callbackFound);
        }
    }

    /**
     * Tests the update functionality for callback URLs.
     * <p>
     * This test verifies the ability to update the properties of a callback URL in the system. The sequential steps include:
     * <ol>
     *   <li>Creating a new callback URL and obtaining its initial properties.</li>
     *   <li>Updating the callback URL's properties, such as its name, URL, and attributes, using a mock HTTP POST request.</li>
     *   <li>Verifying that the updated properties are correctly reflected in the system. This is done by fetching the updated callback URL and comparing its properties with the expected values.</li>
     * </ol>
     * The test asserts that the callback URL's properties, once updated, match the new values provided, ensuring the system's update mechanism functions as expected.
     *
     * @throws Exception if any error occurs during the execution of the test, such as failure in updating the callback URL properties or if the assertions fail.
     */
    @Test
    void testCallbackUpdate() throws Exception {
        final CreateCallbackUrlResponse callbackUrlResponse = config.createCallback(powerAuthClient);
        final String updatedCallbackName = UUID.randomUUID().toString();
        final String updatedCallbackUrl = "http://test2.test2";
        final List<String> callbackAttributes = Arrays.asList("activationId", "userId", "deviceInfo", "platform");

        final UpdateCallbackUrlRequest updateCallbackUrlRequest = new UpdateCallbackUrlRequest();
        updateCallbackUrlRequest.setCallbackUrl(updatedCallbackUrl);
        updateCallbackUrlRequest.setAttributes(callbackAttributes);
        updateCallbackUrlRequest.setName(updatedCallbackName);
        updateCallbackUrlRequest.setId(callbackUrlResponse.getId());
        updateCallbackUrlRequest.setApplicationId(config.getApplicationId());
        updateCallbackUrlRequest.setAuthentication(null);

        final UpdateCallbackUrlResponse updateCallbackUrlResponse = powerAuthClient.updateCallbackUrl(updateCallbackUrlRequest);
        assertEquals(callbackAttributes, updateCallbackUrlResponse.getAttributes());
        assertEquals(4, updateCallbackUrlResponse.getAttributes().size());
        assertEquals(updatedCallbackUrl, updateCallbackUrlResponse.getCallbackUrl());
        assertEquals(config.getApplicationId(), updateCallbackUrlResponse.getApplicationId());
        assertEquals(updatedCallbackName, updateCallbackUrlResponse.getName());
    }

    /**
     * Tests the CRUD (Create, Read, Update, Delete) operations for application roles.
     * This process involves adding new roles, verifying their existence, updating them, and finally removing a role.
     *
     * <p>The test executes the following sequence:</p>
     * <ol>
     *   <li>Adds new application roles ('ROLE1', 'ROLE2') using the '/rest/v3/application/roles/create' endpoint.</li>
     *   <li>Confirms the successful addition of these roles by fetching the application's detail.</li>
     *   <li>Retrieves the current list of application roles to verify the recently added roles.</li>
     *   <li>Updates the application roles to a new set of roles ('ROLE5', 'ROLE6') and verifies the update.</li>
     *   <li>Removes one of the newly added roles ('ROLE5') and checks if the list of roles reflects this change.</li>
     * </ol>
     *
     * @throws Exception if any error occurs during the execution of the test.
     */
    @Test
    void testApplicationRolesCrud() throws Exception {
        final List<String> addedRoles = List.of("ROLE1", "ROLE2");
        final AddApplicationRolesRequest addApplicationRolesRequest = new AddApplicationRolesRequest();
        addApplicationRolesRequest.setApplicationId(config.getApplicationId());
        addApplicationRolesRequest.setApplicationRoles(addedRoles);

        final AddApplicationRolesResponse addApplicationRolesResponse =
                powerAuthClient.addApplicationRoles(addApplicationRolesRequest);
        assertEquals(config.getApplicationId(), addApplicationRolesResponse.getApplicationId());
        assertEquals(2, addApplicationRolesResponse.getApplicationRoles().size());
        assertTrue(addApplicationRolesResponse.getApplicationRoles().containsAll(addedRoles));

        final GetApplicationDetailRequest applicationDetailRequest = new GetApplicationDetailRequest();
        applicationDetailRequest.setApplicationId(config.getApplicationId());

        final GetApplicationDetailResponse applicationDetailResponse =
                powerAuthClient.getApplicationDetail(applicationDetailRequest);
        assertEquals(config.getApplicationId(), applicationDetailResponse.getApplicationId());
        assertEquals(2, applicationDetailResponse.getApplicationRoles().size());
        assertTrue(applicationDetailResponse.getApplicationRoles().containsAll(addedRoles));

        final ListApplicationRolesRequest applicationRolesRequest = new ListApplicationRolesRequest();
        applicationRolesRequest.setApplicationId(config.getApplicationId());

        final ListApplicationRolesResponse listApplicationRolesResponse =
                powerAuthClient.listApplicationRoles(applicationRolesRequest);
        assertEquals(2, listApplicationRolesResponse.getApplicationRoles().size());
        assertTrue(listApplicationRolesResponse.getApplicationRoles().containsAll(addedRoles));

        final UpdateApplicationRolesRequest updateApplicationRolesRequest = new UpdateApplicationRolesRequest();
        final List<String> addedRoles2 = List.of("ROLE5", "ROLE6");
        updateApplicationRolesRequest.setApplicationId(config.getApplicationId());
        updateApplicationRolesRequest.setApplicationRoles(addedRoles2);

        final UpdateApplicationRolesResponse updateApplicationRolesResponse =
                powerAuthClient.updateApplicationRoles(updateApplicationRolesRequest);
        assertEquals(config.getApplicationId(), updateApplicationRolesResponse.getApplicationId());
        assertEquals(2, updateApplicationRolesResponse.getApplicationRoles().size());
        assertTrue(updateApplicationRolesResponse.getApplicationRoles().containsAll(addedRoles2));

        final RemoveApplicationRolesRequest removeApplicationRolesRequest = new RemoveApplicationRolesRequest();
        removeApplicationRolesRequest.setApplicationId(config.getApplicationId());
        removeApplicationRolesRequest.setApplicationRoles(List.of("ROLE5"));

        final RemoveApplicationRolesResponse removeApplicationRolesResponse =
                powerAuthClient.removeApplicationRoles(removeApplicationRolesRequest);
        assertEquals(config.getApplicationId(), removeApplicationRolesResponse.getApplicationId());
        assertEquals(1, removeApplicationRolesResponse.getApplicationRoles().size());
        assertTrue(removeApplicationRolesResponse.getApplicationRoles().contains("ROLE6"));
    }

    /**
     * Tests the retrieval of the list of applications from the PowerAuth Server.
     *
     * <p>This test executes the following actions:</p>
     * <ol>
     *   <li>Sends a request to the PowerAuth Server to retrieve the list of all registered applications.</li>
     *   <li>Verifies that the response contains the expected number of applications.</li>
     *   <li>Checks if the application list includes the application with the ID specified in the test configuration.</li>
     * </ol>
     *
     * <p>This test assumes that there is only one application configured in the PowerAuth Server,
     * which is the application used in the test setup. The application ID is obtained from the test configuration.</p>
     *
     * @throws Exception if any error occurs during the execution of the test or if the assertions fail.
     */
    @Test
    void testApplicationList() throws Exception {
        final GetApplicationListResponse applicationListResponse = powerAuthClient.getApplicationList();
        assertEquals(1, applicationListResponse.getApplications().size());
        assertEquals(config.getApplicationId(), applicationListResponse.getApplications().get(0).getApplicationId());
    }

    /**
     * Tests the retrieval of application details based on an application key from the PowerAuth Server.
     *
     * <p>This test executes the following actions:</p>
     * <ol>
     *   <li>Constructs a request object with the application key obtained from the test configuration.</li>
     *   <li>Sends the request to the PowerAuth Server's endpoint responsible for looking up application details by application key.</li>
     *   <li>Verifies that the response contains the correct application ID associated with the provided application key.</li>
     * </ol>
     *
     * <p>The test assumes that an application key is already set up in the test configuration and
     * corresponds to a valid application registered in the PowerAuth Server.</p>
     *
     * @throws Exception if any error occurs during the execution of the test or if the assertions fail.
     */
    @Test
    void testApplicationVersionLookup() throws Exception {
        final LookupApplicationByAppKeyRequest applicationByAppKeyRequest = new LookupApplicationByAppKeyRequest();
        applicationByAppKeyRequest.setApplicationKey(config.getApplicationKey());

        final LookupApplicationByAppKeyResponse lookupActivationsResponse =
                powerAuthClient.lookupApplicationByAppKey(applicationByAppKeyRequest);
        assertEquals(config.getApplicationId(), lookupActivationsResponse.getApplicationId());
    }

    /**
     * Tests the management of support status for application versions in the PowerAuth Server.
     *
     * <p>This test executes the following actions:</p>
     * <ol>
     *   <li>Marks a specific application version as unsupported using the PowerAuth Server API, and verifies the operation's success.</li>
     *   <li>Subsequently marks the same application version as supported, again using the PowerAuth Server API, and verifies this operation as well.</li>
     *   <li>Checks that the application version's support status is updated correctly in both cases.</li>
     * </ol>
     *
     * <p>The test assumes that the application and version IDs are set up in the test configuration and correspond to a valid application version registered in the PowerAuth Server.</p>
     *
     * @throws Exception if any error occurs during the execution of the test or if the assertions fail.
     */
    @Test
    void testApplicationSupport() throws Exception {
        final UnsupportApplicationVersionRequest unsupportApplicationVersionRequest = new UnsupportApplicationVersionRequest();
        unsupportApplicationVersionRequest.setApplicationId(config.getApplicationId());
        unsupportApplicationVersionRequest.setApplicationVersionId(config.getApplicationVersionId());

        final UnsupportApplicationVersionResponse unsupportApplicationVersionResponse =
                powerAuthClient.unsupportApplicationVersion(unsupportApplicationVersionRequest);
        assertEquals(config.getApplicationVersionId(), unsupportApplicationVersionResponse.getApplicationVersionId());
        assertFalse(unsupportApplicationVersionResponse.isSupported());

        final SupportApplicationVersionRequest supportApplicationVersionRequest = new SupportApplicationVersionRequest();
        supportApplicationVersionRequest.setApplicationId(config.getApplicationId());
        supportApplicationVersionRequest.setApplicationVersionId(config.getApplicationVersionId());

        final SupportApplicationVersionResponse supportApplicationVersionResponse =
                powerAuthClient.supportApplicationVersion(supportApplicationVersionRequest);
        assertEquals(config.getApplicationVersionId(), supportApplicationVersionRequest.getApplicationVersionId());
        assertTrue(supportApplicationVersionResponse.isSupported());
    }

    /**
     * Tests the creation, retrieval, and deletion of application integrations in the PowerAuth Server.
     *
     * <p>This test executes the following actions:</p>
     * <ol>
     *   <li>Creates a new application integration using the PowerAuth Server API and verifies the operation's success.</li>
     *   <li>Retrieves a list of all current application integrations to confirm the presence of the newly created integration.</li>
     *   <li>Deletes the newly created integration and then retrieves the list of integrations again to ensure its removal.</li>
     * </ol>
     *
     * <p>The test ensures that the PowerAuth Server correctly handles the lifecycle of application integrations, including their creation, listing, and deletion. It checks the presence of necessary attributes in the integration response, such as the integration name, ID, client secret, and client token.</p>
     *
     * @throws Exception if any error occurs during the execution of the test or if the assertions fail.
     */
    @Test
    void testApplicationIntegration() throws Exception {
        final String integrationName = UUID.randomUUID().toString();
        final CreateIntegrationRequest createIntegrationRequest = new CreateIntegrationRequest();
        createIntegrationRequest.setName(integrationName);

        final CreateIntegrationResponse createIntegrationResponse = powerAuthClient.createIntegration(createIntegrationRequest);
        assertEquals(integrationName, createIntegrationResponse.getName());
        assertNotNull(createIntegrationResponse.getId());
        assertNotNull(createIntegrationResponse.getClientSecret());
        assertNotNull(createIntegrationResponse.getClientSecret());

        final GetIntegrationListResponse getIntegrationListResponse = powerAuthClient.getIntegrationList();
        assertNotNull(getIntegrationListResponse.getItems());
        assertEquals(1, getIntegrationListResponse.getItems().size());
        assertEquals(integrationName, getIntegrationListResponse.getItems().get(0).getName());
        assertEquals(createIntegrationResponse.getId(), getIntegrationListResponse.getItems().get(0).getId());
        assertEquals(createIntegrationResponse.getClientSecret(), getIntegrationListResponse.getItems().get(0).getClientSecret());
        assertEquals(createIntegrationResponse.getClientToken(), getIntegrationListResponse.getItems().get(0).getClientToken());

        final RemoveIntegrationRequest removeIntegrationRequest = new RemoveIntegrationRequest();
        removeIntegrationRequest.setId(createIntegrationResponse.getId());

        final RemoveIntegrationResponse removeIntegrationResponse = powerAuthClient.removeIntegration(removeIntegrationRequest);
        assertTrue(removeIntegrationResponse.isRemoved());
        assertEquals(createIntegrationResponse.getId(), removeIntegrationResponse.getId());
    }

    /**
     * Tests the complete lifecycle of recovery codes in the PowerAuth Server, including creation, lookup, and revocation.
     *
     * <p>The test follows these steps:</p>
     * <ol>
     *   <li>Creates a set of recovery codes for a specific user and verifies the successful creation and the expected attributes of the response, such as the number of PUks and the user ID.</li>
     *   <li>Looks up the created recovery codes using the user's ID and activation ID, ensuring the correct status of the recovery codes and PUks.</li>
     *   <li>Revokes the created recovery codes and confirms their successful revocation.</li>
     * </ol>
     *
     * <p>This test ensures that the PowerAuth Server can correctly handle the entire process of managing recovery codes, from creation to revocation, providing the expected responses at each step.</p>
     *
     * @throws Exception if any error occurs during the execution of the test or if the assertions fail.
     */
    @Test
    void testRecoveryCodeCreateLookupRevoke() throws Exception {
        final CreateRecoveryCodeRequest createRecoveryCodeRequest = new CreateRecoveryCodeRequest();
        createRecoveryCodeRequest.setApplicationId(config.getApplicationId());
        createRecoveryCodeRequest.setUserId(PowerAuthControllerTestConfig.USER_ID);
        createRecoveryCodeRequest.setPukCount(2L);

        final CreateRecoveryCodeResponse createRecoveryCodeResponse = powerAuthClient.createRecoveryCode(createRecoveryCodeRequest);
        assertEquals(2, createRecoveryCodeResponse.getPuks().size());
        assertEquals(PowerAuthControllerTestConfig.USER_ID, createRecoveryCodeResponse.getUserId());

        final LookupRecoveryCodesRequest lookupRecoveryCodesRequest = new LookupRecoveryCodesRequest();
        lookupRecoveryCodesRequest.setActivationId(config.getActivationId());
        lookupRecoveryCodesRequest.setUserId(PowerAuthControllerTestConfig.USER_ID);
        lookupRecoveryCodesRequest.setRecoveryCodeStatus(RecoveryCodeStatus.CREATED);
        lookupRecoveryCodesRequest.setRecoveryPukStatus(RecoveryPukStatus.VALID);

        final LookupRecoveryCodesResponse lookupRecoveryCodesResponse = powerAuthClient.lookupRecoveryCodes(lookupRecoveryCodesRequest);
        assertTrue(lookupRecoveryCodesResponse.getRecoveryCodes().size() > 0);

        final RevokeRecoveryCodesRequest revokeRecoveryCodesRequest = new RevokeRecoveryCodesRequest();
        revokeRecoveryCodesRequest.setRecoveryCodeIds(List.of(createRecoveryCodeResponse.getRecoveryCodeId()));

        final RevokeRecoveryCodesResponse revokeRecoveryCodesResponse = powerAuthClient.revokeRecoveryCodes(revokeRecoveryCodesRequest);
        assertTrue(revokeRecoveryCodesResponse.isRevoked());
    }

    /**
     * Tests the generation of non-personalized offline signature payloads in the PowerAuth Server.
     *
     * <p>The test executes the following steps:</p>
     * <ol>
     *   <li>Sends a request to generate a non-personalized offline signature payload, specifying the application ID and the data to be signed.</li>
     *   <li>Verifies that the response contains a valid offline data string and a nonce, both essential components for offline signature verification.</li>
     * </ol>
     *
     * <p>This test validates the PowerAuth Server's ability to generate the necessary data for offline signature scenarios where personalization of the payload (to a specific user or device) is not required.</p>
     *
     * @throws Exception if any unexpected error occurs during the execution of the test or if the response does not contain the expected data.
     */
    @Test
    void testNonPersonalizedOfflineSignaturePayload() throws Exception {
        final CreateNonPersonalizedOfflineSignaturePayloadRequest nonPersonalizedOfflineSignaturePayloadRequest =
                new CreateNonPersonalizedOfflineSignaturePayloadRequest();
        nonPersonalizedOfflineSignaturePayloadRequest.setApplicationId(config.getApplicationId());
        nonPersonalizedOfflineSignaturePayloadRequest.setData(PowerAuthControllerTestConfig.DATA);

        final CreateNonPersonalizedOfflineSignaturePayloadResponse nonPersonalizedOfflineSignaturePayloadResponse
                = powerAuthClient.createNonPersonalizedOfflineSignaturePayload(nonPersonalizedOfflineSignaturePayloadRequest);
        assertNotNull(nonPersonalizedOfflineSignaturePayloadResponse.getOfflineData());
        assertNotNull(nonPersonalizedOfflineSignaturePayloadResponse.getNonce());
    }

    /**
     * Tests the creation of a personalized offline signature payload.
     * <p>
     * This test sends a request to create a personalized offline signature payload for a specific activation
     * and verifies that the response contains the expected offline data and nonce.
     *
     * @throws Exception if the mockMvc.perform operation fails.
     */
    @Test
    void testPersonalizedOfflineSignaturePayload() throws Exception {
        config.initActivation(powerAuthClient);
        final CreatePersonalizedOfflineSignaturePayloadRequest personalizedOfflineSignaturePayloadRequest =
                new CreatePersonalizedOfflineSignaturePayloadRequest();
        personalizedOfflineSignaturePayloadRequest.setActivationId(config.getActivationId());
        personalizedOfflineSignaturePayloadRequest.setProximityCheck(null);
        personalizedOfflineSignaturePayloadRequest.setData(PowerAuthControllerTestConfig.DATA);

        final CreatePersonalizedOfflineSignaturePayloadResponse personalizedOfflineSignaturePayloadResponse
                = powerAuthClient.createPersonalizedOfflineSignaturePayload(personalizedOfflineSignaturePayloadRequest);
        assertNotNull(personalizedOfflineSignaturePayloadResponse.getOfflineData());
        assertNotNull(personalizedOfflineSignaturePayloadResponse.getNonce());
        config.removeActivation(powerAuthClient);
    }


    // TODO: @jandusil - handle activation verify offline signature test
   /* *//**
     * Tests the verification of an offline signature.
     * <p>
     * This test sends a signature verification request for an offline signature and checks
     * if the signature is validated correctly, expecting a false result for the test data.
     *
     * @throws Exception if the mockMvc.perform operation fails.
     *//*
    @Test
    void testVerifyOfflineSignature() throws Exception {
        config.initActivation(powerAuthClient);

       *//* final PrepareActivationRequest prepareActivationRequest = new PrepareActivationRequest();
        prepareActivationRequest.setApplicationKey(config.getApplicationKey());
        prepareActivationRequest.setActivationCode(config.getActivationId());*//*
        powerAuthClient.commitActivation(config.getActivationId(), "test");

        final VerifyOfflineSignatureRequest verifyOfflineSignatureRequest =
                new VerifyOfflineSignatureRequest();
        verifyOfflineSignatureRequest.setActivationId(config.getActivationId());
        verifyOfflineSignatureRequest.setAllowBiometry(false);
        verifyOfflineSignatureRequest.setSignature("123456");
        verifyOfflineSignatureRequest.setData("A2");


        final VerifyOfflineSignatureResponse verifyOfflineSignatureResponse =
                powerAuthClient.verifyOfflineSignature(verifyOfflineSignatureRequest);
        assertFalse(verifyOfflineSignatureResponse.isSignatureValid());
        assertEquals(config.getActivationId(), verifyOfflineSignatureResponse.getActivationId());
        config.removeActivation(powerAuthClient);
    }*/


}
