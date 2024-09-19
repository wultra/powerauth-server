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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.entity.CallbackUrl;
import com.wultra.security.powerauth.client.model.enumeration.*;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.response.*;
import com.wultra.security.powerauth.rest.client.PowerAuthRestClient;
import io.getlime.security.powerauth.app.server.service.model.request.ActivationLayer2Request;
import io.getlime.security.powerauth.crypto.lib.encryptor.ClientEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.EncryptorFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ServerEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptedRequest;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptorParameters;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.v3.ClientEncryptorSecrets;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.v3.ServerEncryptorSecrets;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for published controllers.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@Transactional
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PowerAuthControllerTest {

    private static final String POWERAUTH_REST_URL = "http://localhost:%d/rest";

    @LocalServerPort
    private int serverPort;

    private PowerAuthClient powerAuthClient;

    @Autowired
    private PowerAuthControllerTestConfig config;
    private final KeyConvertor keyConvertor = new KeyConvertor();
    private final EncryptorFactory encryptorFactory = new EncryptorFactory();
    private final KeyGenerator keyGenerator = new KeyGenerator();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeAll
    void initializeData() throws Exception {
        powerAuthClient = new PowerAuthRestClient(POWERAUTH_REST_URL.formatted(serverPort));
        createApplication();
        createLoginOperationTemplate();
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
        initActivation();
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
        assertThat(activationListForUserResponse2.getActivations(), hasSize(5));

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
        initActivation();
        final LookupActivationsRequest lookupActivationsRequest = new LookupActivationsRequest();
        /* We are looking for an activation created during initialization of the test suite. */
        final Date timestampCreated = Date.from(LocalDateTime.now().minusSeconds(1).atZone(ZoneId.systemDefault()).toInstant());
        lookupActivationsRequest.setUserIds(List.of(PowerAuthControllerTestConfig.USER_ID));
        lookupActivationsRequest.setApplicationIds(List.of(config.getApplicationId()));
        lookupActivationsRequest.setActivationStatus(ActivationStatus.CREATED);
        lookupActivationsRequest.setTimestampLastUsedAfter(timestampCreated);

        final LookupActivationsResponse lookupActivationsResponse = powerAuthClient.lookupActivations(lookupActivationsRequest);
        assertThat(lookupActivationsResponse.getActivations(), hasSize(1));
        removeActivation();
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
        initActivation();
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
        removeActivation();
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
        initActivation();
        final Date before = Date.from(LocalDateTime.now().minusSeconds(1).atZone(ZoneId.systemDefault()).toInstant());
        final Date after = Date.from(LocalDateTime.now().plusSeconds(1).atZone(ZoneId.systemDefault()).toInstant());
        final ActivationHistoryRequest activationHistoryRequest = new ActivationHistoryRequest();
        activationHistoryRequest.setActivationId(config.getActivationId());
        activationHistoryRequest.setTimestampFrom(before);
        activationHistoryRequest.setTimestampTo(after);

        final ActivationHistoryResponse activationHistoryResponse = powerAuthClient.getActivationHistory(activationHistoryRequest);
        assertThat(activationHistoryResponse.getItems(), hasSize(1));
        assertEquals(config.getActivationId(), activationHistoryResponse.getItems().get(0).getActivationId());
        removeActivation();
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
        initActivation();
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
        removeActivation();
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
        initActivation();
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
        removeActivation();
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
     */
    @Test
    void testUpdateActivation_badRequest() {
        final String expectedErrorMessage = "requestObject.activationId - must not be blank," +
                " requestObject.activationName - must not be blank, requestObject.externalUserId - must not be blank";
        final String expectedErrorCode = "ERR0024";
        final PowerAuthClientException thrownException = assertThrows(
                PowerAuthClientException.class,
                () -> powerAuthClient.updateActivationName(new UpdateActivationNameRequest())
        );
        assertEquals(expectedErrorMessage, thrownException.getMessage());
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
        final OperationDetailResponse operationDetailResponse = createOperation();
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
        final OperationDetailResponse operation = createOperation();
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
     * Tests the creation, reading, and deletion of callback URLs.
     * <p>
     * This test covers the complete lifecycle of a callback URL within the system, including:
     * <ol>
     *   <li>Creating a new callback URL using the provided configuration.</li>
     *   <li>Retrieving a list of all callback URLs to confirm the successful creation of the new URL.</li>
     *   <li>Identifying the created callback URL from the list and verifying its properties.</li>
     *   <li>Deleting the newly created callback URL and verifying its removal by fetching the list again.</li>
     * </ol>
     * The test ensures that the callback URL is correctly created, listed, and deleted in the system,
     * and that all associated details are accurately reflected.
     *
     * @throws Exception if an error occurs during the creation, retrieval, or deletion of the callback URL,
     *                   or if the assertions fail.
     */
    @Test
    void testCreateReadDelete() throws Exception {
        createCallback();
        final GetCallbackUrlListResponse callbackUrlListResponse = powerAuthClient.getCallbackUrlList(config.getApplicationId());

        assertNotNull(callbackUrlListResponse.getCallbackUrlList());
        final CallbackUrl foundCallback = callbackUrlListResponse.getCallbackUrlList().stream()
                .filter(callback -> PowerAuthControllerTestConfig.CALLBACK_NAME.equals(callback.getName()))
                .findAny()
                .orElseThrow(() -> new AssertionError("Callback not found"));

        assertEquals(PowerAuthControllerTestConfig.CALLBACK_URL, foundCallback.getCallbackUrl());
        assertEquals(config.getApplicationId(), foundCallback.getApplicationId());
        assertThat(foundCallback.getAttributes(), hasSize(1));
        assertEquals("activationId", foundCallback.getAttributes().get(0));
        removeCallback(foundCallback.getId());
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
        final CreateCallbackUrlResponse callbackUrlResponse = createCallback();
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
        updateCallbackUrlRequest.setType(CallbackUrlType.ACTIVATION_STATUS_CHANGE.toString());

        final UpdateCallbackUrlResponse updateCallbackUrlResponse = powerAuthClient.updateCallbackUrl(updateCallbackUrlRequest);
        assertEquals(callbackAttributes, updateCallbackUrlResponse.getAttributes());
        assertThat(updateCallbackUrlResponse.getAttributes(), hasSize(4));
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
        assertThat(addApplicationRolesResponse.getApplicationRoles(), hasSize(2));
        assertTrue(addApplicationRolesResponse.getApplicationRoles().containsAll(addedRoles));

        final GetApplicationDetailRequest applicationDetailRequest = new GetApplicationDetailRequest();
        applicationDetailRequest.setApplicationId(config.getApplicationId());

        final GetApplicationDetailResponse applicationDetailResponse =
                powerAuthClient.getApplicationDetail(applicationDetailRequest);
        assertEquals(config.getApplicationId(), applicationDetailResponse.getApplicationId());
        assertThat(applicationDetailResponse.getApplicationRoles(), hasSize(2));
        assertTrue(applicationDetailResponse.getApplicationRoles().containsAll(addedRoles));

        final ListApplicationRolesRequest applicationRolesRequest = new ListApplicationRolesRequest();
        applicationRolesRequest.setApplicationId(config.getApplicationId());

        final ListApplicationRolesResponse listApplicationRolesResponse =
                powerAuthClient.listApplicationRoles(applicationRolesRequest);
        assertThat(listApplicationRolesResponse.getApplicationRoles(), hasSize(2));
        assertTrue(listApplicationRolesResponse.getApplicationRoles().containsAll(addedRoles));

        final UpdateApplicationRolesRequest updateApplicationRolesRequest = new UpdateApplicationRolesRequest();
        final List<String> addedRoles2 = List.of("ROLE5", "ROLE6");
        updateApplicationRolesRequest.setApplicationId(config.getApplicationId());
        updateApplicationRolesRequest.setApplicationRoles(addedRoles2);

        final UpdateApplicationRolesResponse updateApplicationRolesResponse =
                powerAuthClient.updateApplicationRoles(updateApplicationRolesRequest);
        assertEquals(config.getApplicationId(), updateApplicationRolesResponse.getApplicationId());
        assertThat(updateApplicationRolesResponse.getApplicationRoles(), hasSize(2));
        assertTrue(updateApplicationRolesResponse.getApplicationRoles().containsAll(addedRoles2));

        final RemoveApplicationRolesRequest removeApplicationRolesRequest = new RemoveApplicationRolesRequest();
        removeApplicationRolesRequest.setApplicationId(config.getApplicationId());
        removeApplicationRolesRequest.setApplicationRoles(List.of("ROLE5"));

        final RemoveApplicationRolesResponse removeApplicationRolesResponse =
                powerAuthClient.removeApplicationRoles(removeApplicationRolesRequest);
        assertEquals(config.getApplicationId(), removeApplicationRolesResponse.getApplicationId());
        assertThat(removeApplicationRolesResponse.getApplicationRoles(), hasSize(1));
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
        assertThat(applicationListResponse.getApplications(), hasSize(1));
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
        assertThat(getIntegrationListResponse.getItems(), hasSize(1));
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
        assertThat(createRecoveryCodeResponse.getPuks(), hasSize(2));
        assertEquals(PowerAuthControllerTestConfig.USER_ID, createRecoveryCodeResponse.getUserId());

        final LookupRecoveryCodesRequest lookupRecoveryCodesRequest = new LookupRecoveryCodesRequest();
        lookupRecoveryCodesRequest.setActivationId(config.getActivationId());
        lookupRecoveryCodesRequest.setUserId(PowerAuthControllerTestConfig.USER_ID);
        lookupRecoveryCodesRequest.setRecoveryCodeStatus(RecoveryCodeStatus.CREATED);
        lookupRecoveryCodesRequest.setRecoveryPukStatus(RecoveryPukStatus.VALID);

        final LookupRecoveryCodesResponse lookupRecoveryCodesResponse = powerAuthClient.lookupRecoveryCodes(lookupRecoveryCodesRequest);
        assertThat(lookupRecoveryCodesResponse.getRecoveryCodes(), hasSize(greaterThan(0)));

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
     * Tests the generation of personalized offline signature payloads in the PowerAuth Server.
     *
     * <p>This test comprises the following key steps:</p>
     * <ol>
     *   <li>Initializes an activation to generate a personalized context for the offline signature.</li>
     *   <li>Sends a request to generate a personalized offline signature payload, specifying the activation ID and the data to be signed.</li>
     *   <li>Verifies that the response includes a valid offline data string and a nonce, which are crucial for offline signature processes.</li>
     *   <li>Ensures clean-up by removing the activation created for the test.</li>
     * </ol>
     *
     * <p>This test is crucial to ensure the PowerAuth Server correctly handles the generation of offline signature payloads that are personalized to a specific activation, typically representing a user or device.</p>
     *
     * @throws Exception if any unexpected error occurs during the execution of the test or if the response fails to contain the expected personalized offline data.
     */
    @Test
    void testPersonalizedOfflineSignaturePayload() throws Exception {
        initActivation();
        final CreatePersonalizedOfflineSignaturePayloadRequest personalizedOfflineSignaturePayloadRequest =
                new CreatePersonalizedOfflineSignaturePayloadRequest();
        personalizedOfflineSignaturePayloadRequest.setActivationId(config.getActivationId());
        personalizedOfflineSignaturePayloadRequest.setProximityCheck(null);
        personalizedOfflineSignaturePayloadRequest.setData(PowerAuthControllerTestConfig.DATA);

        final CreatePersonalizedOfflineSignaturePayloadResponse personalizedOfflineSignaturePayloadResponse
                = powerAuthClient.createPersonalizedOfflineSignaturePayload(personalizedOfflineSignaturePayloadRequest);
        assertNotNull(personalizedOfflineSignaturePayloadResponse.getOfflineData());
        assertNotNull(personalizedOfflineSignaturePayloadResponse.getNonce());
        removeActivation();
    }

    /**
     * Tests the verification of an offline signature.
     * <p>
     * This method tests the verification process of an offline signature in the PowerAuth system.
     * It involves several steps:
     * <ul>
     *   <li>Initializing activation with configuration settings.</li>
     *   <li>Generating a public key pair and converting it to byte array.</li>
     *   <li>Setting up encryption parameters and creating an encrypted activation request.</li>
     *   <li>Preparing and committing activation using PowerAuth Client.</li>
     *   <li>Sending a request to verify an offline signature with test data and checking the response.</li>
     * </ul>
     * The test expects the verification of the offline signature to be invalid (false) for the provided test data.
     * </p>
     *
     * @throws Exception if there is an issue during the setup or execution of the test, such as failure in activation initialization, encryption, or if the PowerAuth Client encounters an error.
     */
    @Test
    void testVerifyOfflineSignature() throws Exception {
        initActivation();

        final EncryptedRequest encryptedRequest = generateEncryptedRequestActivationLayer(config.getActivationName());

        final PrepareActivationRequest prepareActivationRequest = new PrepareActivationRequest();
        prepareActivationRequest.setActivationCode(config.getActivationCode());
        prepareActivationRequest.setApplicationKey(config.getApplicationKey());
        prepareActivationRequest.setTimestamp(encryptedRequest.getTimestamp());
        prepareActivationRequest.setProtocolVersion(PowerAuthControllerTestConfig.PROTOCOL_VERSION);
        prepareActivationRequest.setEncryptedData(encryptedRequest.getEncryptedData());
        prepareActivationRequest.setMac(encryptedRequest.getMac());
        prepareActivationRequest.setNonce(encryptedRequest.getNonce());
        prepareActivationRequest.setEphemeralPublicKey(encryptedRequest.getEphemeralPublicKey());

        final PrepareActivationResponse prepareResponse = powerAuthClient.prepareActivation(prepareActivationRequest);
        assertEquals(ActivationStatus.PENDING_COMMIT, prepareResponse.getActivationStatus());

        final CommitActivationResponse commitResponse = powerAuthClient.commitActivation(config.getActivationId(), null);
        assertEquals(config.getActivationId(), commitResponse.getActivationId());

        final VerifyOfflineSignatureRequest verifyOfflineSignatureRequest =
                new VerifyOfflineSignatureRequest();
        verifyOfflineSignatureRequest.setActivationId(config.getActivationId());
        verifyOfflineSignatureRequest.setAllowBiometry(false);
        verifyOfflineSignatureRequest.setSignature("123456");
        verifyOfflineSignatureRequest.setData(PowerAuthControllerTestConfig.DATA);

        final VerifyOfflineSignatureResponse verifyOfflineSignatureResponse =
                powerAuthClient.verifyOfflineSignature(verifyOfflineSignatureRequest);
        assertFalse(verifyOfflineSignatureResponse.isSignatureValid());
        assertEquals(config.getActivationId(), verifyOfflineSignatureResponse.getActivationId());

        removeActivation();
    }

    /**
     * Tests the creation of an activation in the PowerAuth system.
     * <p>
     * This test method performs the following steps to verify the activation creation process:
     * <ol>
     *   <li>Generates a device key pair and converts the public key to a byte array.</li>
     *   <li>Creates an activation layer 2 request with the generated public key and activation name.</li>
     *   <li>Encrypts the activation request using client-side encryption.</li>
     *   <li>Sends the create activation request to the PowerAuth server with the necessary parameters including the encrypted data and user ID.</li>
     *   <li>Verifies the creation of the activation by checking the response from the server, ensuring the activation ID, user ID, application ID, and activation status are as expected.</li>
     *   <li>Retrieves and checks the activation status to ensure it is pending for commit.</li>
     *   <li>Commits the activation and verifies that the activation process is completed successfully.</li>
     * </ol>
     * </p>
     * The test asserts that the activation is created and transitioned through the expected statuses, from pending commit to active.
     *
     * @throws Exception if an error occurs during any step of the activation creation and verification process.
     */
    @Test
    void testCreateActivation() throws Exception {
        final Date expireDate = Date.from(LocalDateTime.now().plusMinutes(5).atZone(ZoneId.systemDefault()).toInstant());
        final String activationName = "TEST_ACTIVATION";
        final EncryptedRequest encryptedRequest = generateEncryptedRequestActivationLayer(activationName);

        final CreateActivationRequest createActivationRequest = new CreateActivationRequest();
        createActivationRequest.setUserId(PowerAuthControllerTestConfig.USER_ID);
        createActivationRequest.setMaxFailureCount(5L);
        createActivationRequest.setMac(encryptedRequest.getMac());
        createActivationRequest.setNonce(encryptedRequest.getNonce());
        createActivationRequest.setEncryptedData(encryptedRequest.getEncryptedData());
        createActivationRequest.setEphemeralPublicKey(encryptedRequest.getEphemeralPublicKey());
        createActivationRequest.setTimestampActivationExpire(expireDate);
        createActivationRequest.setTimestamp(encryptedRequest.getTimestamp());
        createActivationRequest.setProtocolVersion(PowerAuthControllerTestConfig.PROTOCOL_VERSION);
        createActivationRequest.setApplicationKey(config.getApplicationKey());

        final CreateActivationResponse createActivationResponse = powerAuthClient.createActivation(createActivationRequest);
        assertNotNull(createActivationResponse.getActivationId());
        assertEquals(PowerAuthControllerTestConfig.USER_ID, createActivationResponse.getUserId());
        assertEquals(config.getApplicationId(), createActivationResponse.getApplicationId());
        assertEquals(ActivationStatus.PENDING_COMMIT, createActivationResponse.getActivationStatus());

        final GetActivationStatusResponse statusResponse = powerAuthClient.getActivationStatus(createActivationResponse.getActivationId());
        assertEquals(ActivationStatus.PENDING_COMMIT, statusResponse.getActivationStatus());
        assertEquals(createActivationResponse.getActivationId(), statusResponse.getActivationId());

        final CommitActivationResponse commitResponse = powerAuthClient
                .commitActivation(createActivationResponse.getActivationId(), PowerAuthControllerTestConfig.USER_ID);
        assertTrue(commitResponse.isActivated());
        assertEquals(createActivationResponse.getActivationId(), commitResponse.getActivationId());
    }

    /**
     * Tests the process of updating an activation OTP (One-Time Password) and committing the activation in PowerAuth system.
     * <p>
     * The method performs the following operations:
     * <ol>
     *   <li>Initializes an activation with a specific configuration using the PowerAuth client.</li>
     *   <li>Generates an encrypted request for the activation including necessary parameters like activation name, code, application key, and others.</li>
     *   <li>Sends a 'prepare activation' request and verifies that the activation status is 'PENDING_COMMIT'.</li>
     *   <li>Updates the activation OTP by sending an 'update activation OTP' request and checks the response to ensure the OTP update is successful.</li>
     *   <li>Sends a 'commit activation' request with the updated OTP and verifies that the activation is successfully activated.</li>
     * </ol>
     * </p>
     * This test ensures that the activation can be updated with a new OTP and then successfully committed using this new OTP.
     *
     * @throws Exception if an error occurs during the preparation, OTP update, or activation commitment process.
     */
    @Test
    void testUpdateActivationOtpAndCommit() throws Exception {
        initActivation();
        final String activationOtp = "12345678";
        final EncryptedRequest encryptedRequest = generateEncryptedRequestActivationLayer(config.getActivationName());

        final PrepareActivationRequest prepareActivationRequest = new PrepareActivationRequest();
        prepareActivationRequest.setActivationCode(config.getActivationCode());
        prepareActivationRequest.setApplicationKey(config.getApplicationKey());
        prepareActivationRequest.setTimestamp(encryptedRequest.getTimestamp());
        prepareActivationRequest.setProtocolVersion(PowerAuthControllerTestConfig.PROTOCOL_VERSION);
        prepareActivationRequest.setEncryptedData(encryptedRequest.getEncryptedData());
        prepareActivationRequest.setMac(encryptedRequest.getMac());
        prepareActivationRequest.setNonce(encryptedRequest.getNonce());
        prepareActivationRequest.setEphemeralPublicKey(encryptedRequest.getEphemeralPublicKey());

        final PrepareActivationResponse prepareResponse = powerAuthClient.prepareActivation(prepareActivationRequest);
        assertEquals(ActivationStatus.PENDING_COMMIT, prepareResponse.getActivationStatus());

        final UpdateActivationOtpRequest updateActivationOtpRequest = new UpdateActivationOtpRequest();
        updateActivationOtpRequest.setActivationId(config.getActivationId());
        updateActivationOtpRequest.setActivationOtp(activationOtp);
        updateActivationOtpRequest.setExternalUserId(PowerAuthControllerTestConfig.USER_ID);

        final UpdateActivationOtpResponse otpResponse = powerAuthClient.updateActivationOtp(updateActivationOtpRequest);
        assertTrue(otpResponse.isUpdated());
        assertEquals(config.getActivationId(), otpResponse.getActivationId());

        final CommitActivationRequest commitActivationRequest = new CommitActivationRequest();
        commitActivationRequest.setActivationOtp(activationOtp);
        commitActivationRequest.setActivationId(config.getActivationId());
        commitActivationRequest.setExternalUserId(PowerAuthControllerTestConfig.USER_ID);

        final CommitActivationResponse commitResponse = powerAuthClient.commitActivation(commitActivationRequest);
        assertTrue(commitResponse.isActivated());
        assertEquals(config.getActivationId(), commitResponse.getActivationId());
    }

    /**
     * Tests the retrieval and utilization of the ECIES (Elliptic Curve Integrated Encryption Scheme) decryptor in the PowerAuth system.
     * <p>
     * This test performs the following operations:
     * <ol>
     *   <li>Generates test data and encrypts it using the client-side ECIES encryption process.</li>
     *   <li>Constructs a request to retrieve the ECIES decryptor from the PowerAuth server, including necessary parameters like protocol version, application key, and encrypted data details.</li>
     *   <li>Sends the request to the PowerAuth server and retrieves the ECIES decryptor response, including the secret key and shared information.</li>
     *   <li>Decrypts the previously encrypted data using the server-side ECIES decryptor with the retrieved keys and verifies the correctness of the decryption.</li>
     * </ol>
     * </p>
     * The test ensures that the ECIES decryptor can be correctly obtained from the PowerAuth server and used to decrypt data encrypted by the client, validating the integrity and functionality of the ECIES encryption/decryption process.
     *
     * @throws Exception if an error occurs during the encryption, decryption, or communication with the PowerAuth server.
     */
    @Test
    void testGetEciesDecryptor() throws Exception {
        final String requestData = "test_data";

        final ClientEncryptor clientEncryptor = encryptorFactory.getClientEncryptor(
                EncryptorId.APPLICATION_SCOPE_GENERIC,
                new EncryptorParameters(PowerAuthControllerTestConfig.PROTOCOL_VERSION, config.getApplicationKey(), null, null),
                new ClientEncryptorSecrets(wrapPublicKeyString(), config.getApplicationSecret())
        );
        final EncryptedRequest encryptedRequest = clientEncryptor.encryptRequest(requestData.getBytes(StandardCharsets.UTF_8));
        final GetEciesDecryptorRequest eciesDecryptorRequest = new GetEciesDecryptorRequest();
        eciesDecryptorRequest.setProtocolVersion(PowerAuthControllerTestConfig.PROTOCOL_VERSION);
        eciesDecryptorRequest.setActivationId(null);
        eciesDecryptorRequest.setApplicationKey(config.getApplicationKey());
        eciesDecryptorRequest.setEphemeralPublicKey(encryptedRequest.getEphemeralPublicKey());
        eciesDecryptorRequest.setNonce(encryptedRequest.getNonce());
        eciesDecryptorRequest.setTimestamp(encryptedRequest.getTimestamp());
        final GetEciesDecryptorResponse decryptorResponse = powerAuthClient.getEciesDecryptor(eciesDecryptorRequest);

        final byte[] secretKey = Base64.getDecoder().decode(decryptorResponse.getSecretKey());
        final byte[] sharedInfo2Base = Base64.getDecoder().decode(decryptorResponse.getSharedInfo2());
        final ServerEncryptor serverEncryptor = encryptorFactory.getServerEncryptor(
                EncryptorId.APPLICATION_SCOPE_GENERIC,
                new EncryptorParameters(PowerAuthControllerTestConfig.PROTOCOL_VERSION, config.getApplicationKey(), null, null),
                new ServerEncryptorSecrets(secretKey, sharedInfo2Base)
        );
        final byte[] decryptedData = serverEncryptor.decryptRequest(encryptedRequest);
        assertArrayEquals(requestData.getBytes(StandardCharsets.UTF_8), decryptedData);
    }

    /**
     * Tests the retrieval of system status.
     * <p>
     * This test verifies the response from the system status endpoint. It checks for expected values
     * such as application name, status, and display name. Additionally, it ensures the timestamp
     * returned by the system status is the current date (ignoring the time part).
     * This is crucial for verifying the system's operational status and basic metadata.
     * </p>
     *
     * @throws Exception if an error occurs during the retrieval of the system status or if any of the assertions fail.
     */
    @Test
    void testSystemStatus() throws Exception {
        final GetSystemStatusResponse systemStatusResponse = powerAuthClient.getSystemStatus();
        assertEquals("OK", systemStatusResponse.getStatus());
        assertEquals("powerauth-server", systemStatusResponse.getApplicationName());
        assertEquals("PowerAuth Server", systemStatusResponse.getApplicationDisplayName());
        assertNotNull(systemStatusResponse.getTimestamp());
        final LocalDate localDateFromResponse = systemStatusResponse.getTimestamp().toInstant()
                .atZone(ZoneId.systemDefault()).toLocalDate();
        assertEquals(LocalDate.now(), localDateFromResponse);
    }

    /**
     * Tests the retrieval of a list of error codes.
     * <p>
     * This test sends a request to obtain a comprehensive list of error codes available in the system.
     * It verifies that the response contains a list with an expected minimum number of error entries,
     * ensuring a broad range of error scenarios is covered. The test specifically requests the error
     * codes in English language, but it can be adapted for other languages if needed.
     * </p>
     *
     * <p>The assertion for the minimum number of entries (more than 32) is based on the current
     * implementation and may need to be adjusted if the number of error codes changes in future versions.</p>
     *
     * @throws Exception if an error occurs during the retrieval of the error list or if the assertion for the minimum number of error entries fails.
     */
    @Test
    void testErrorList() throws Exception {
        final GetErrorCodeListRequest getErrorCodeListRequest = new GetErrorCodeListRequest();
        getErrorCodeListRequest.setLanguage(Locale.ENGLISH.getLanguage());

        final GetErrorCodeListResponse errorCodeListResponse = powerAuthClient.getErrorList(getErrorCodeListRequest);
        assertThat(errorCodeListResponse.getErrors(), hasSize(greaterThan(32)));
    }

    /* HELPER INITIALIZATION METHODS */

    /**
     * Creates a request object for creating an operation.
     * <p>
     * This helper method constructs and returns an {@link OperationCreateRequest} with
     * predefined application ID, template name, user ID, and proximity OTP settings.
     *
     * @param proximityOtpEnabled a boolean indicating whether proximity OTP is enabled
     * @return a configured {@link OperationCreateRequest} instance
     */
    private OperationCreateRequest createOperationCreateRequest(final boolean proximityOtpEnabled) {
        final OperationCreateRequest operationCreateRequest = new OperationCreateRequest();
        operationCreateRequest.setApplications(List.of(config.getApplicationId()));
        operationCreateRequest.setTemplateName(config.getLoginOperationTemplateName());
        operationCreateRequest.setUserId(PowerAuthControllerTestConfig.USER_ID);
        operationCreateRequest.setProximityCheckEnabled(proximityOtpEnabled);
        return operationCreateRequest;
    }

    /**
     * Creates a request object for creating a callback URL.
     * <p>
     * This helper method constructs and returns a {@link CreateCallbackUrlRequest} with
     * predefined callback URL, name, type, application ID, and other settings.
     *
     * @return a configured {@link CreateCallbackUrlRequest} instance
     */
    private CreateCallbackUrlRequest createCallbackUrlRequest() {
        final CreateCallbackUrlRequest callbackUrlRequest = new CreateCallbackUrlRequest();
        callbackUrlRequest.setCallbackUrl(PowerAuthControllerTestConfig.CALLBACK_URL);
        callbackUrlRequest.setName(PowerAuthControllerTestConfig.CALLBACK_NAME);
        callbackUrlRequest.setType(CallbackUrlType.ACTIVATION_STATUS_CHANGE.name());
        callbackUrlRequest.setApplicationId(config.getApplicationId());
        callbackUrlRequest.setAttributes(Collections.singletonList("activationId"));
        callbackUrlRequest.setAuthentication(null);
        return callbackUrlRequest;
    }

    /**
     * Initializes a new activation and verifies its status.
     * <p>
     * This method creates an activation for the provided user and application IDs and verifies
     * the response to ensure the activation is successfully initialized. It sets the activation
     * ID in the test configuration and asserts that the activation status is 'CREATED'.
     *
     * @throws Exception if any error occurs during activation initialization or verification
     */
    private void initActivation() throws Exception {
        final InitActivationRequest initActivationRequest = new InitActivationRequest();
        initActivationRequest.setUserId(PowerAuthControllerTestConfig.USER_ID);
        initActivationRequest.setApplicationId(config.getApplicationId());

        final InitActivationResponse initActivationResponse = powerAuthClient.initActivation(initActivationRequest);
        assertNotNull(initActivationResponse);
        assertNotNull(initActivationResponse.getActivationId());
        assertNotNull(initActivationResponse.getActivationSignature());
        assertNotNull(initActivationResponse.getApplicationId());
        assertEquals(PowerAuthControllerTestConfig.USER_ID, initActivationResponse.getUserId());
        assertEquals(config.getApplicationId(), initActivationResponse.getApplicationId());

        final GetActivationStatusResponse activationStatusResponse =
                powerAuthClient.getActivationStatus(initActivationResponse.getActivationId());

        assertEquals(ActivationStatus.CREATED, activationStatusResponse.getActivationStatus());
        config.setActivationId(activationStatusResponse.getActivationId());
        config.setActivationCode(activationStatusResponse.getActivationCode());
        config.setActivationName(activationStatusResponse.getActivationName());
    }

    /**
     * Creates an application in the PowerAuth Server if it does not already exist.
     * <p>
     * This method checks for the existence of an application and its version. If not present,
     * it creates them and sets relevant fields in the test configuration. It also ensures the
     * application version is supported and sets up activation recovery settings.
     *
     * @throws Exception if any error occurs during application creation or setup
     */
    private void createApplication() throws Exception {
        final GetApplicationListResponse applicationsListResponse = powerAuthClient.getApplicationList();
        final var applicationOptional = applicationsListResponse.getApplications().stream()
                .filter(app -> app.getApplicationId().equals(config.getApplicationName()))
                .findFirst();

        applicationOptional.ifPresent(app -> config.setApplicationId(app.getApplicationId()));
        final boolean applicationExists = applicationOptional.isPresent();

        if (!applicationExists) {
            final CreateApplicationResponse response = powerAuthClient.createApplication(config.getApplicationName());
            assertNotEquals("0", response.getApplicationId());
            assertEquals(config.getApplicationName(), response.getApplicationId());
            config.setApplicationId(response.getApplicationId());
        }

        final GetApplicationDetailResponse detail = powerAuthClient.getApplicationDetail(config.getApplicationId());
        final var versionOptional = detail.getVersions().stream()
                .filter(appVersion -> appVersion.getApplicationVersionId().equals(config.getApplicationVersion()))
                .findFirst();
        versionOptional.ifPresent(
                appVersion -> {
                    config.setApplicationVersionId(appVersion.getApplicationVersionId());
                    config.setApplicationKey(appVersion.getApplicationKey());
                    config.setApplicationSecret(appVersion.getApplicationSecret());
                });
        final boolean versionExists = versionOptional.isPresent();

        config.setMasterPublicKey(detail.getMasterPublicKey());
        if (!versionExists) {
            final CreateApplicationVersionResponse versionResponse = powerAuthClient.createApplicationVersion(config.getApplicationId(), config.getApplicationVersion());
            assertNotEquals("0", versionResponse.getApplicationVersionId());
            assertEquals(config.getApplicationVersion(), versionResponse.getApplicationVersionId());
            config.setApplicationVersionId(versionResponse.getApplicationVersionId());
            config.setApplicationKey(versionResponse.getApplicationKey());
            config.setApplicationSecret(versionResponse.getApplicationSecret());
        } else {
            powerAuthClient.supportApplicationVersion(config.getApplicationId(), config.getApplicationVersionId());
        }
        final GetRecoveryConfigResponse recoveryResponse = powerAuthClient.getRecoveryConfig(config.getApplicationId());
        if (!recoveryResponse.isActivationRecoveryEnabled() || !recoveryResponse.isRecoveryPostcardEnabled() || recoveryResponse.getPostcardPublicKey() == null || recoveryResponse.getRemotePostcardPublicKey() == null) {
            final UpdateRecoveryConfigRequest request = new UpdateRecoveryConfigRequest();
            request.setApplicationId(config.getApplicationId());
            request.setActivationRecoveryEnabled(true);
            request.setRecoveryPostcardEnabled(true);
            request.setAllowMultipleRecoveryCodes(false);
            request.setRemotePostcardPublicKey(PowerAuthControllerTestConfig.PUBLIC_KEY_RECOVERY_POSTCARD_BASE64);
            powerAuthClient.updateRecoveryConfig(request);
        }
    }

    /**
     * Creates a new callback URL in the PowerAuth Server and verifies its creation.
     * <p>
     * This method creates a callback URL with predefined settings and asserts the response
     * to ensure the callback URL is successfully created. It returns the response containing
     * the callback URL details.
     *
     * @return the response containing the created callback URL details
     * @throws Exception if any error occurs during callback URL creation
     */
    private CreateCallbackUrlResponse createCallback() throws Exception {
        final CreateCallbackUrlRequest callbackUrlRequest = createCallbackUrlRequest();
        final CreateCallbackUrlResponse response = powerAuthClient.createCallbackUrl(callbackUrlRequest);
        assertEquals(PowerAuthControllerTestConfig.CALLBACK_NAME, response.getName());
        assertEquals(PowerAuthControllerTestConfig.CALLBACK_URL, response.getCallbackUrl());
        assertEquals(config.getApplicationId(), response.getApplicationId());

        return response;
    }

    /**
     * Removes a specified callback URL from the PowerAuth Server.
     * <p>
     * This method deletes a callback URL using its ID and verifies the removal by asserting
     * the response.
     *
     * @param callbackId the ID of the callback URL to be removed
     * @throws Exception if any error occurs during callback URL removal
     */
    private void removeCallback(final String callbackId) throws Exception {
        final RemoveCallbackUrlRequest removeCallbackUrlRequest = new RemoveCallbackUrlRequest();
        removeCallbackUrlRequest.setId(callbackId);

        final RemoveCallbackUrlResponse removeCallbackUrlResponse = powerAuthClient.removeCallbackUrl(removeCallbackUrlRequest);
        assertEquals(callbackId, removeCallbackUrlResponse.getId());
        assertTrue(removeCallbackUrlResponse.isRemoved());
    }

    /**
     * Removes an activation from the PowerAuth Server.
     * <p>
     * This method deletes an activation using its ID and verifies the removal by asserting
     * the response.
     *
     * @throws Exception if any error occurs during activation removal
     */
    private void removeActivation() throws Exception {
        final RemoveActivationRequest removeActivationRequest = new RemoveActivationRequest();
        removeActivationRequest.setActivationId(config.getActivationId());
        final RemoveActivationResponse removeActivationResponse = powerAuthClient.removeActivation(removeActivationRequest);
        assertTrue(removeActivationResponse.isRemoved());
    }

    /**
     * Creates a new operation in the PowerAuth Server.
     * <p>
     * This method creates an operation with predefined settings and asserts the response
     * to ensure the operation is successfully created. It returns the response containing
     * operation details.
     *
     * @return the response containing the created operation details
     * @throws Exception if any error occurs during operation creation
     */
    private OperationDetailResponse createOperation() throws Exception {
        final OperationDetailResponse operationDetailResponse = powerAuthClient
                .createOperation(createOperationCreateRequest(false));
        assertNotNull(operationDetailResponse.getId());
        assertEquals(OperationStatus.PENDING, operationDetailResponse.getStatus());
        assertEquals(config.getLoginOperationTemplateName(), operationDetailResponse.getTemplateName());
        return operationDetailResponse;
    }

    /**
     * Creates a new login operation template in the PowerAuth Server.
     * <p>
     * This method creates a login operation template with predefined settings. It sets the
     * template name and ID in the test configuration and asserts the response to ensure
     * the template is successfully created.
     *
     * @throws Exception if any error occurs during operation template creation
     */
    private void createLoginOperationTemplate() throws Exception {
        final OperationTemplateCreateRequest request = new OperationTemplateCreateRequest();
        request.setTemplateName(UUID.randomUUID().toString());
        request.setOperationType("login");
        request.getSignatureType().addAll(Arrays.asList(SignatureType.values()));
        request.setDataTemplate(PowerAuthControllerTestConfig.DATA);
        request.setExpiration(300L);
        request.setMaxFailureCount(5L);

        final OperationTemplateDetailResponse operationTemplate = powerAuthClient.createOperationTemplate(request);
        config.setLoginOperationTemplateName(operationTemplate.getTemplateName());
        config.setLoginOperationTemplateId(operationTemplate.getId());
    }

    /**
     * Converts a string representation of a master public key into its corresponding {@link PublicKey} object.
     * <p>
     * This method uses the {@link KeyConvertor} to decode the base64-encoded string representation of the master public key
     * into a byte array, which is then converted to a {@link PublicKey} object.
     *
     * @return The {@link PublicKey} object corresponding to the decoded master public key.
     * @throws Exception if there is an error during the conversion process.
     */
    private PublicKey wrapPublicKeyString() throws Exception {
        return keyConvertor.convertBytesToPublicKey(Base64.getDecoder().decode(config.getMasterPublicKey()));
    }

    /**
     * Generates an encrypted request for the Activation Layer 2 using ECIES (Elliptic Curve Integrated Encryption Scheme).
     * <p>
     * This method performs the following steps:
     * <ol>
     *   <li>Generates a new key pair and converts the public key to a byte array.</li>
     *   <li>Creates an {@link ActivationLayer2Request} with the activation name and device public key.</li>
     *   <li>Initializes a {@link ClientEncryptor} for Activation Layer 2 encryption.</li>
     *   <li>Serializes the {@link ActivationLayer2Request} into a byte array.</li>
     *   <li>Encrypts the serialized request data using the client encryptor.</li>
     * </ol>
     * </p>
     * The method returns an {@link EncryptedRequest} containing the encrypted request data and additional encryption parameters.
     *
     * @param activationName The activation name for the request.
     * @return The {@link EncryptedRequest} containing the encrypted request data.
     * @throws Exception if there is an error during the encryption or serialization process.
     */
    private EncryptedRequest generateEncryptedRequestActivationLayer(final String activationName) throws Exception {
        final KeyPair keyPair = keyGenerator.generateKeyPair();
        final PublicKey publicKey = keyPair.getPublic();
        final byte[] publicKeyBytes = keyConvertor.convertPublicKeyToBytes(publicKey);
        final ActivationLayer2Request requestL2 = new ActivationLayer2Request();
        requestL2.setActivationName(activationName);
        requestL2.setDevicePublicKey(Base64.getEncoder().encodeToString(publicKeyBytes));

        final ClientEncryptor clientEncryptor = encryptorFactory.getClientEncryptor(
                EncryptorId.ACTIVATION_LAYER_2,
                new EncryptorParameters(PowerAuthControllerTestConfig.PROTOCOL_VERSION, config.getApplicationKey(), null, null),
                new ClientEncryptorSecrets(wrapPublicKeyString(), config.getApplicationSecret())
        );

        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        objectMapper.writeValue(baos, requestL2);
        return clientEncryptor.encryptRequest(baos.toByteArray());
    }

}
