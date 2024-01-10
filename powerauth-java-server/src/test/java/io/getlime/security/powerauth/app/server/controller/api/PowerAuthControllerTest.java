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
package io.getlime.security.powerauth.app.server.controller.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.core.audit.base.database.DatabaseAudit;
import com.wultra.security.powerauth.client.model.entity.CallbackUrl;
import com.wultra.security.powerauth.client.model.enumeration.*;
import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.response.*;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationHistoryEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.OperationEntity;
import io.getlime.security.powerauth.app.server.database.model.enumeration.OperationStatusDo;
import io.getlime.security.powerauth.app.server.service.PowerAuthService;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.CallbackUrlBehavior;
import io.getlime.security.powerauth.app.server.service.behavior.tasks.OperationServiceBehavior;
import jakarta.persistence.EntityManager;
import jakarta.persistence.Tuple;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.jdbc.Sql;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Test for {@link PowerAuthController}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@SpringBootTest
@AutoConfigureMockMvc
@Sql
@Transactional
@ActiveProfiles("test")
class PowerAuthControllerTest {

    private static final String APPLICATION_ID = "PA_Tests";
    private static final String USER_ID = "test-user";
    private static final String TEMPLATE_NAME = "test-template";
    private static final String DATA = "A2";
    private static final String CALLBACK_NAME = UUID.randomUUID().toString();
    private static final String CALLBACK_URL = "http://test.test";
    private static final String ACTIVATION_ID = "e43a5dec-afea-4a10-a80b-b2183399f16b";
    private static final String APPLICATION_VERSION_APPLICATION_KEY = "testKey";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private EntityManager entityManager;

    @Autowired
    private DatabaseAudit databaseAudit;

    @Autowired
    private OperationServiceBehavior operationServiceBehavior;

    @Autowired
    private CallbackUrlBehavior callbackUrlBehavior;

    @Autowired
    private PowerAuthService powerAuthService;

    /**
     * Tests the creation of a new activation.
     * <p>
     * This test sends a request to initialize a new activation and verifies the successful creation by checking
     * various properties of the activation response. It further checks the activation status to ensure it is set to 'CREATED'.
     *
     * @throws Exception if the mockMvc.perform operation fails.
     */
    @Test
    void testCreateActivation() throws Exception {
        final InitActivationRequest initActivationRequest = new InitActivationRequest();
        initActivationRequest.setUserId(USER_ID);
        initActivationRequest.setApplicationId(APPLICATION_ID);
        MvcResult result = mockMvc.perform(post("/rest/v3/activation/init")
                        .content(wrapInRequestObjectJson(initActivationRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.responseObject.activationId", notNullValue()))
                .andExpect(jsonPath("$.responseObject.activationSignature", notNullValue()))
                .andExpect(jsonPath("$.responseObject.activationCode", notNullValue()))
                .andExpect(jsonPath("$.responseObject.userId").value(USER_ID))
                .andExpect(jsonPath("$.responseObject.applicationId").value(APPLICATION_ID)).andReturn();

        final InitActivationResponse response = convertMvcResultToObject(result, InitActivationResponse.class);
        final GetActivationStatusRequest getActivationStatusRequest = new GetActivationStatusRequest();
        getActivationStatusRequest.setActivationId(response.getActivationId());

        mockMvc.perform(post("/rest/v3/activation/status")
                        .content(wrapInRequestObjectJson(getActivationStatusRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.responseObject.activationStatus").value("CREATED"));
    }

    /**
     * Tests the removal of an activation.
     * <p>
     * This test sends a request to remove an existing activation and verifies the removal action by checking the response.
     * It further confirms the removal by fetching the activation status and ensuring it is set to 'REMOVED'.
     *
     * @throws Exception if the mockMvc.perform operation fails.
     */
    @Test
    void testRemoveActivation() throws Exception {
        /* Activation created by the SQL script */
        final RemoveActivationRequest removeActivationRequest = new RemoveActivationRequest();
        removeActivationRequest.setActivationId(ACTIVATION_ID);
        removeActivationRequest.setExternalUserId(null);

        mockMvc.perform(post("/rest/v3/activation/remove")
                        .content(wrapInRequestObjectJson(removeActivationRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.responseObject.removed").value(true));
        final GetActivationStatusRequest activationStatusRequest = new GetActivationStatusRequest();
        activationStatusRequest.setActivationId(ACTIVATION_ID);
        final GetActivationStatusResponse statusResponse = powerAuthService.getActivationStatus(activationStatusRequest);
        assertEquals(ActivationStatus.REMOVED, statusResponse.getActivationStatus());
    }

    /**
     * Tests the retrieval of the activation list for a specific user.
     * <p>
     * This test sends a request to list all activations for a given user and verifies the response by checking the number of activations.
     *
     * @throws Exception if the mockMvc.perform operation fails.
     */
    @Test
    void testActivationListForUser() throws Exception {
        final GetActivationListForUserRequest getActivationListForUserRequest = new GetActivationListForUserRequest();
        /* Activation created by the SQL script */
        getActivationListForUserRequest.setUserId("TestUserV3_d8c2e122-b12a-47f1-bca7-e04637bffd14");
        mockMvc.perform(post("/rest/v3/activation/list")
                        .content(wrapInRequestObjectJson(getActivationListForUserRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.responseObject.activations.length()").value(1));
    }

    /**
     * Tests the pagination feature in the activation list retrieval for a user.
     * <p>
     * This test creates multiple activations for a user and then fetches them in paginated form, ensuring both pages contain the correct number of activations.
     * It verifies that the activations on different pages are not the same, confirming proper pagination functionality.
     *
     * @throws Exception if the mockMvc.perform operation fails.
     */
    @Test
    void testActivationListForUserPagination() throws Exception {
        // Prepare the base GetActivationListForUserRequest
        final GetActivationListForUserRequest baseRequest = new GetActivationListForUserRequest();
        baseRequest.setUserId(USER_ID);
        baseRequest.setApplicationId(APPLICATION_ID);

        // Create a list to store the activation IDs
        final List<String> activationIds = new ArrayList<>();

        // Create multiple activations for the test user
        for (int i = 0; i < 10; i++) {
            final InitActivationRequest initActivationRequest = new InitActivationRequest();
            initActivationRequest.setApplicationId(APPLICATION_ID);
            initActivationRequest.setUserId(USER_ID);
            final InitActivationResponse initResponse = powerAuthService.initActivation(initActivationRequest);
            activationIds.add(initResponse.getActivationId());
        }

        // Prepare the request for the first page of activations
        final GetActivationListForUserRequest requestPage1 = new GetActivationListForUserRequest();
        requestPage1.setUserId(baseRequest.getUserId());
        requestPage1.setApplicationId(baseRequest.getApplicationId());
        requestPage1.setPageNumber(0);
        requestPage1.setPageSize(5);

        // Fetch the first page of activations
        final MvcResult mvcResult1 = mockMvc.perform(post("/rest/v3/activation/list")
                        .content(wrapInRequestObjectJson(requestPage1))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.responseObject.activations.length()").value(5))
                .andReturn();

        // Prepare the request for the second page of activations
        final GetActivationListForUserRequest requestPage2 = new GetActivationListForUserRequest();
        requestPage2.setUserId(baseRequest.getUserId());
        requestPage2.setApplicationId(baseRequest.getApplicationId());
        requestPage2.setPageNumber(1);
        requestPage2.setPageSize(5);

        // Fetch the second page of activations
        final MvcResult mvcResult2 = mockMvc.perform(post("/rest/v3/activation/list")
                        .content(wrapInRequestObjectJson(requestPage2))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.responseObject.activations.length()").value(5))
                .andReturn();

        final GetActivationListForUserResponse responsePage1 = convertMvcResultToObject(mvcResult1,
                GetActivationListForUserResponse.class);
        final GetActivationListForUserResponse responsePage2 = convertMvcResultToObject(mvcResult2,
                GetActivationListForUserResponse.class);
        // Check that the activations on the different pages are not the same
        assertNotEquals(responsePage1.getActivations(), responsePage2.getActivations());
    }

    /**
     * Tests the lookup feature for activations based on specific criteria.
     * <p>
     * This test sends a request to look up activations based on user IDs, application IDs, activation status, and a timestamp.
     * It verifies the lookup by checking the number of activations that match the given criteria.
     *
     * @throws Exception if the mockMvc.perform operation fails.
     */
    @Test
    void testLookupActivations() throws Exception {
        final LookupActivationsRequest lookupActivationsRequest = new LookupActivationsRequest();
        final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");
        final LocalDateTime localDateTime = LocalDateTime.parse("2023-04-03 13:59:06.015", formatter);
        final Date timestampCreated = Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant());
        /* Activation created by the SQL script */
        lookupActivationsRequest.setUserIds(List.of("TestUserV3_d8c2e122-b12a-47f1-bca7-e04637bffd14"));
        lookupActivationsRequest.setApplicationIds(List.of(APPLICATION_ID));
        lookupActivationsRequest.setActivationStatus(ActivationStatus.ACTIVE);
        lookupActivationsRequest.setTimestampLastUsedAfter(timestampCreated);
        mockMvc.perform(post("/rest/v3/activation/lookup")
                        .content(wrapInRequestObjectJson(lookupActivationsRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.responseObject.activations.length()").value(1));
    }

    /**
     * Tests the update of activation status for given activation IDs.
     * <p>
     * This test sends a request to update the status of specified activations and confirms the update action by checking the response.
     * It further validates the new status of the activation by fetching its current status.
     *
     * @throws Exception if the mockMvc.perform operation fails.
     */
    @Test
    void testUpdateActivationStatus() throws Exception {
        final UpdateStatusForActivationsRequest updateStatusForActivationsRequest = new UpdateStatusForActivationsRequest();
        updateStatusForActivationsRequest.setActivationIds(List.of(ACTIVATION_ID));
        updateStatusForActivationsRequest.setActivationStatus(ActivationStatus.BLOCKED);
        /* Activation created by the SQL script */
        mockMvc.perform(post("/rest/v3/activation/status/update")
                        .content(wrapInRequestObjectJson(updateStatusForActivationsRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.responseObject.updated").value(true));

        final GetActivationStatusRequest activationStatusRequest = new GetActivationStatusRequest();
        activationStatusRequest.setActivationId(ACTIVATION_ID);
        final GetActivationStatusResponse statusResponse = powerAuthService.getActivationStatus(activationStatusRequest);
        assertEquals(ActivationStatus.BLOCKED, statusResponse.getActivationStatus());
    }

    /**
     * Tests the retrieval of activation history for a specific activation ID.
     * <p>
     * This test initializes a new activation, then sends a request to retrieve its history within a specified time range.
     * It confirms the history retrieval by checking the presence of activation history items.
     *
     * @throws Exception if the mockMvc.perform operation fails.
     */
    @Test
    void testActivationHistory() throws Exception {
        final InitActivationRequest initActivationRequest = new InitActivationRequest();
        initActivationRequest.setUserId(USER_ID);
        initActivationRequest.setApplicationId(APPLICATION_ID);

        final InitActivationResponse initResponse = powerAuthService.initActivation(initActivationRequest);
        final String activationId = initResponse.getActivationId();
        final GetActivationStatusRequest activationStatusRequest = new GetActivationStatusRequest();
        activationStatusRequest.setActivationId(activationId);
        final GetActivationStatusResponse statusResponse = powerAuthService.getActivationStatus(activationStatusRequest);
        assertEquals(ActivationStatus.CREATED, statusResponse.getActivationStatus());

        final Date before = Date.from(statusResponse.getTimestampCreated().toInstant().minus(Duration.ofDays(1)));
        final Date after = Date.from(before.toInstant().plus(Duration.ofDays(2)));
        final ActivationHistoryRequest activationHistoryRequest = new ActivationHistoryRequest();
        activationHistoryRequest.setActivationId(activationId);
        activationHistoryRequest.setTimestampFrom(before);
        activationHistoryRequest.setTimestampTo(after);

        mockMvc.perform(post("/rest/v3/activation/history")
                        .content(wrapInRequestObjectJson(activationHistoryRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.responseObject.items.length()").value(1))
                .andExpect(jsonPath("$.responseObject.items[0].activationId").value(activationId));

    }

    /**
     * Tests the block and unblock functionality for an activation.
     * <p>
     * This test first sends a request to block an activation and verifies the block action. It then sends a request to unblock the same activation
     * and verifies the unblock action, confirming the change in activation status after each operation.
     *
     * @throws Exception if the mockMvc.perform operation fails.
     */
    @Test
    void testBlockAndUnblockActivation() throws Exception {
        final BlockActivationRequest blockActivationRequest = new BlockActivationRequest();
        blockActivationRequest.setActivationId(ACTIVATION_ID);
        blockActivationRequest.setReason("Test");
        /* Block the activation created by the SQL script */
        mockMvc.perform(post("/rest/v3/activation/block")
                        .content(wrapInRequestObjectJson(blockActivationRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.responseObject.activationStatus").value("BLOCKED"));

        final GetActivationStatusRequest activationStatusRequest = new GetActivationStatusRequest();
        activationStatusRequest.setActivationId(ACTIVATION_ID);
        final GetActivationStatusResponse statusResponse = powerAuthService.getActivationStatus(activationStatusRequest);
        assertEquals(ActivationStatus.BLOCKED, statusResponse.getActivationStatus());

        final UnblockActivationRequest unblockActivationRequest = new UnblockActivationRequest();
        unblockActivationRequest.setActivationId(ACTIVATION_ID);

        mockMvc.perform(post("/rest/v3/activation/unblock")
                        .content(wrapInRequestObjectJson(unblockActivationRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.responseObject.activationStatus").value("ACTIVE"));

        final GetActivationStatusResponse statusResponse2 = powerAuthService.getActivationStatus(activationStatusRequest);
        assertEquals(ActivationStatus.ACTIVE, statusResponse2.getActivationStatus());
    }

    /**
     * Tests the update activation functionality.
     * <p>
     * This test performs a mock HTTP POST request to the activation name update endpoint.
     * It verifies if the response status is OK and if the activation name in the response object
     * matches the expected value. It also checks the database for the updated activation record
     * and ensures the audit log is correctly updated.
     *
     * @throws Exception if the mockMvc.perform operation fails.
     */
    @Test
    void testUpdateActivation() throws Exception {
        mockMvc.perform(post("/rest/v3/activation/name/update")
                        .content("""
                                {
                                  "requestObject": {
                                    "activationId": "e43a5dec-afea-4a10-a80b-b2183399f16b",
                                    "activationName": "my iPhone",
                                    "externalUserId": "joe-1"
                                  }
                                }
                                """)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("OK"))
                .andExpect(jsonPath("$.responseObject.activationName").value("my iPhone"));

        final ActivationRecordEntity activation = entityManager.find(ActivationRecordEntity.class, "e43a5dec-afea-4a10-a80b-b2183399f16b");
        assertEquals("my iPhone", activation.getActivationName());

        final List<ActivationHistoryEntity> historyEntries = entityManager.createQuery("select h from ActivationHistoryEntity h where h.activation = :activation", ActivationHistoryEntity.class)
                .setParameter("activation", activation)
                .getResultList();
        assertEquals(1, historyEntries.size());

        final ActivationHistoryEntity historyEntry = historyEntries.iterator().next();
        assertEquals("my iPhone", historyEntry.getActivationName());
        assertEquals("ACTIVATION_NAME_UPDATED", historyEntry.getEventReason());
        assertEquals("joe-1", historyEntry.getExternalUserId());

        databaseAudit.flush();
        final String expectedAuditMessage = "Updated activation with ID: e43a5dec-afea-4a10-a80b-b2183399f16b";
        @SuppressWarnings("unchecked") final List<Tuple> auditEntries = entityManager.createNativeQuery("select * from audit_log where message = :message", Tuple.class)
                .setParameter("message", expectedAuditMessage)
                .getResultList();
        assertEquals(1, auditEntries.size());

        final String param = auditEntries.get(0).get("param").toString();
        assertThat(param, containsString("\"activationId\":\"e43a5dec-afea-4a10-a80b-b2183399f16b\""));
        assertThat(param, containsString("\"activationName\":\"my iPhone\""));
        assertThat(param, containsString("\"reason\":\"ACTIVATION_NAME_UPDATED\""));
    }

    /**
     * Tests the update activation functionality with a bad request.
     * <p>
     * This test sends an incomplete request to the activation name update endpoint
     * and expects a BadRequest (400) response. It checks if the error response
     * contains the correct error message and error code.
     *
     * @throws Exception if the mockMvc.perform operation fails.
     */
    @Test
    void testUpdateActivation_badRequest() throws Exception {
        final String expectedErrorMessage = "requestObject.activationId - must not be blank, requestObject.activationName - must not be blank, requestObject.externalUserId - must not be blank";

        mockMvc.perform(post("/rest/v3/activation/name/update")
                        .content("""
                                {
                                  "requestObject": {}
                                }
                                """)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value("ERROR"))
                .andExpect(jsonPath("$.responseObject.code").value("ERR0024"))
                .andExpect(jsonPath("$.responseObject.message").value(expectedErrorMessage))
                .andExpect(jsonPath("$.responseObject.localizedMessage").value(expectedErrorMessage));
    }

    /**
     * Tests the operation approval functionality.
     * <p>
     * This test first creates an operation and then performs a mock HTTP POST request
     * to the operation approval endpoint. It verifies if the operation is approved successfully
     * by checking the response status and response object. It also confirms that the
     * operation entity in the database is updated accordingly.
     *
     * @throws Exception if the mockMvc.perform operation or operation creation fails.
     */
    @Test
    void testOperationApprove() throws Exception {
        final String operationId = operationServiceBehavior.
                createOperation(createOperationCreateRequest(false)).getId();
        final OperationApproveRequest operationApproveRequest = new OperationApproveRequest();
        operationApproveRequest.setOperationId(operationId);
        operationApproveRequest.setUserId(USER_ID);
        operationApproveRequest.setData(DATA);
        operationApproveRequest.setApplicationId(APPLICATION_ID);
        operationApproveRequest.setSignatureType(SignatureType.POSSESSION_KNOWLEDGE);

        mockMvc.perform(post("/rest/v3/operation/approve")
                        .content(wrapInRequestObjectJson(operationApproveRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.responseObject.operation.status").value("APPROVED"))
                .andExpect(jsonPath("$.responseObject.operation.data").value(DATA))
                .andExpect(jsonPath("$.responseObject.operation.templateName").value(TEMPLATE_NAME))
                .andExpect(jsonPath("$.responseObject.operation.id").value(operationId));

        final OperationEntity operation = entityManager.find(OperationEntity.class, operationId);
        assertEquals(TEMPLATE_NAME, operation.getTemplateName());
        assertEquals(DATA, operation.getData());
        assertEquals(OperationStatusDo.APPROVED, operation.getStatus());
    }

    /**
     * Tests the operation creation functionality.
     * <p>
     * This test performs a mock HTTP POST request to the operation creation endpoint.
     * It verifies if the response status is OK and if the operation is created with
     * a status of "PENDING". The test also confirms that the operation entity is
     * correctly created in the database with the expected template name.
     *
     * @throws Exception if the mockMvc.perform operation fails.
     */
    @Test
    void testOperationCreate() throws Exception {
        final OperationCreateRequest createRequest = createOperationCreateRequest(false);
        final MvcResult result = mockMvc.perform(post("/rest/v3/operation/create")
                        .content(wrapInRequestObjectJson(createRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))

                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("OK"))
                .andExpect(jsonPath("$.responseObject.status").value("PENDING")).andReturn();


        final String operationId = convertMvcResultToObject(result, OperationDetailResponse.class).getId();
        final OperationEntity operation = entityManager.find(OperationEntity.class, operationId);
        assertEquals("test-template", operation.getTemplateName());
    }

    /**
     * Tests the retrieval of operation details.
     * <p>
     * This test creates a new operation using the operation service behavior, then performs
     * a mock HTTP POST request to retrieve the details of this operation. It verifies if the
     * response contains the correct operation status, data, template name, and ID.
     *
     * @throws Exception if the test fails
     */
    @Test
    void testGetOperationDetail() throws Exception {
        final OperationDetailResponse operation = operationServiceBehavior.
                createOperation(createOperationCreateRequest(false));
        final OperationDetailRequest detailRequest = new OperationDetailRequest();
        final String operationId = operation.getId();
        detailRequest.setOperationId(operationId);
        detailRequest.setUserId(USER_ID);

        mockMvc.perform(post("/rest/v3/operation/detail")
                        .content(wrapInRequestObjectJson(detailRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.responseObject.status").value("PENDING"))
                .andExpect(jsonPath("$.responseObject.data").value(DATA))
                .andExpect(jsonPath("$.responseObject.templateName").value(TEMPLATE_NAME))
                .andExpect(jsonPath("$.responseObject.id").value(operationId));
    }

    /**
     * Tests the creation, reading, and deletion of callback URLs.
     * <p>
     * This test first creates a new callback URL using a mock HTTP POST request. It then
     * retrieves a list of all callback URLs to verify the creation. Finally, it performs
     * deletion of the created callback URL and verifies the removal.
     *
     * @throws Exception if the test fails
     */
    @Test
    void testCallbackCreateReadDelete() throws Exception {
        final CreateCallbackUrlRequest callbackUrlRequest = createCallbackUrlRequest();

        /* Create callback test */
        mockMvc.perform(post("/rest/v3/application/callback/create")
                        .content(wrapInRequestObjectJson(callbackUrlRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.responseObject.name").value(CALLBACK_NAME))
                .andExpect(jsonPath("$.responseObject.callbackUrl").value(CALLBACK_URL))
                .andExpect(jsonPath("$.responseObject.applicationId").value(APPLICATION_ID));

        final GetCallbackUrlListRequest getCallbackUrlListRequest = new GetCallbackUrlListRequest();
        getCallbackUrlListRequest.setApplicationId(APPLICATION_ID);

        /* Get callback list test */
        final MvcResult result = mockMvc.perform(post("/rest/v3/application/callback/list")
                        .content(wrapInRequestObjectJson(getCallbackUrlListRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk()).andReturn();

        final GetCallbackUrlListResponse callbackUrlListResponse = convertMvcResultToObject(result, GetCallbackUrlListResponse.class);

        boolean callbackFound = false;
        for (CallbackUrl callback : callbackUrlListResponse.getCallbackUrlList()) {
            if (CALLBACK_NAME.equals(callback.getName())) {
                callbackFound = true;
                assertEquals(CALLBACK_URL, callback.getCallbackUrl());
                assertEquals(APPLICATION_ID, callback.getApplicationId());
                assertEquals(1, callback.getAttributes().size());
                assertEquals("activationId", callback.getAttributes().get(0));
                /* Remove callback test*/
                final RemoveCallbackUrlRequest removeCallbackUrlRequest = new RemoveCallbackUrlRequest();
                final String callbackId = callback.getId();
                removeCallbackUrlRequest.setId(callbackId);
                mockMvc.perform(post("/rest/v3/application/callback/remove")
                                .content(wrapInRequestObjectJson(removeCallbackUrlRequest))
                                .contentType(MediaType.APPLICATION_JSON)
                                .accept(MediaType.APPLICATION_JSON))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.responseObject.id").value(callbackId));
            }
            assertTrue(callbackFound);
        }
    }

    /**
     * Tests the update functionality for callback URLs.
     * <p>
     * This test first creates a callback URL and then updates its properties using a mock
     * HTTP POST request. The test verifies if the updated properties (name, URL, attributes)
     * are correctly reflected in the system by fetching the list of callback URLs after the update.
     *
     * @throws Exception if the test fails
     */
    @Test
    void testCallbackUpdate() throws Exception {
        final CreateCallbackUrlRequest callbackUrlRequest = createCallbackUrlRequest();
        final CreateCallbackUrlResponse callbackUrlResponse = callbackUrlBehavior.createCallbackUrl(callbackUrlRequest);
        final GetCallbackUrlListResponse callbacks = callbackUrlBehavior.
                getCallbackUrlList(createCallbackUrlListRequest());

        /* Verify first created callback */
        boolean callbackFound = false;
        String callbackId = null;
        for (CallbackUrl callback : callbacks.getCallbackUrlList()) {
            if (CALLBACK_NAME.equals(callback.getName())) {
                callbackFound = true;
                callbackId = callback.getId();
                assertEquals(CALLBACK_URL, callback.getCallbackUrl());
                assertEquals(APPLICATION_ID, callback.getApplicationId());
                assertEquals(1, callback.getAttributes().size());
                assertEquals("activationId", callback.getAttributes().get(0));
            }
        }
        assertTrue(callbackFound);
        assertNotNull(callbackId);

        final String callbackName2 = UUID.randomUUID().toString();
        final String callbackUrl2 = "http://test2.test2";
        final UpdateCallbackUrlRequest updateCallbackUrlRequest = new UpdateCallbackUrlRequest();
        updateCallbackUrlRequest.setCallbackUrl(callbackUrl2);
        updateCallbackUrlRequest.setAttributes(Arrays.asList("activationId", "userId", "deviceInfo", "platform"));
        updateCallbackUrlRequest.setName(callbackName2);
        updateCallbackUrlRequest.setId(callbackId);
        updateCallbackUrlRequest.setApplicationId(APPLICATION_ID);
        updateCallbackUrlRequest.setAuthentication(null);

        /* Test update callback */
        mockMvc.perform(post("/rest/v3/application/callback/update")
                        .content(wrapInRequestObjectJson(updateCallbackUrlRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());

        final GetCallbackUrlListResponse callbacks2 = callbackUrlBehavior.
                getCallbackUrlList(createCallbackUrlListRequest());

        boolean callbackFound2 = false;
        for (CallbackUrl callback : callbacks2.getCallbackUrlList()) {
            if (callbackName2.equals(callback.getName())) {
                callbackFound2 = true;
                callbackId = callback.getId();
                assertEquals(callbackUrl2, callback.getCallbackUrl());
                assertEquals(APPLICATION_ID, callback.getApplicationId());
                assertEquals(4, callback.getAttributes().size());
                assertEquals(Arrays.asList("activationId", "userId", "deviceInfo", "platform"), callback.getAttributes());
            }
        }
        assertTrue(callbackFound2);
    }

    /**
     * Tests the CRUD operations for application roles.
     * This includes adding, getting, updating, and removing application roles.
     *
     * <p>The test follows these steps:</p>
     * <ol>
     *   <li>Adds application roles using the '/rest/v3/application/roles/create' endpoint.</li>
     *   <li>Verifies the addition of roles by fetching application details using the '/rest/v3/application/detail' endpoint.</li>
     *   <li>Fetches the list of application roles using the '/rest/v3/application/roles/list' endpoint to verify the current roles.</li>
     *   <li>Updates the application roles using the '/rest/v3/application/roles/update' endpoint.</li>
     *   <li>Verifies the update by comparing the expected and actual list of roles.</li>
     *   <li>Removes one of the application roles using the '/rest/v3/application/roles/remove' endpoint.</li>
     *   <li>Finally, verifies the removal by checking the remaining roles.</li>
     * </ol>
     *
     * <p>Note: The test assumes the presence of two additional roles defined in the SQL script used for setting up the test environment.</p>
     *
     * @throws Exception if any error occurs during the execution of the test.
     */
    @Test
    void testApplicationRolesCrud() throws Exception {
        final List<String> addedRoles = List.of("ROLE1", "ROLE2");
        final AddApplicationRolesRequest addApplicationRolesRequest = new AddApplicationRolesRequest();
        addApplicationRolesRequest.setApplicationId(APPLICATION_ID);
        addApplicationRolesRequest.setApplicationRoles(addedRoles);

        /* Test add app roles */
        mockMvc.perform(post("/rest/v3/application/roles/create")
                        .content(wrapInRequestObjectJson(addApplicationRolesRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.responseObject.applicationId").value(APPLICATION_ID))
                .andExpect(jsonPath("$.responseObject.applicationRoles").isArray())
                /* Two more roles are defined in the SQL script for this test */
                .andExpect(jsonPath("$.responseObject.applicationRoles", hasSize(4)))
                .andExpect(jsonPath("$.responseObject.applicationRoles", hasItems(addedRoles.toArray())));

        /* Test get app detail */
        final GetApplicationDetailRequest applicationDetailRequest = new GetApplicationDetailRequest();
        applicationDetailRequest.setApplicationId(APPLICATION_ID);
        mockMvc.perform(post("/rest/v3/application/detail")
                        .content(wrapInRequestObjectJson(applicationDetailRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.responseObject.applicationId").value(APPLICATION_ID))
                .andExpect(jsonPath("$.responseObject.applicationRoles").isArray())
                /* Two more roles are defined in the SQL script for this test */
                .andExpect(jsonPath("$.responseObject.applicationRoles", hasSize(4)))
                .andExpect(jsonPath("$.responseObject.applicationRoles", hasItems(addedRoles.toArray())));

        /* Test get app roles list */
        final ListApplicationRolesRequest applicationRolesRequest = new ListApplicationRolesRequest();
        applicationRolesRequest.setApplicationId(APPLICATION_ID);
        mockMvc.perform(post("/rest/v3/application/roles/list")
                        .content(wrapInRequestObjectJson(applicationRolesRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.responseObject.applicationRoles").isArray())
                /* Two more roles are defined in the SQL script for this test */
                .andExpect(jsonPath("$.responseObject.applicationRoles", hasSize(4)))
                .andExpect(jsonPath("$.responseObject.applicationRoles", hasItems(addedRoles.toArray())));

        /* Test update app roles */
        final UpdateApplicationRolesRequest updateApplicationRolesRequest = new UpdateApplicationRolesRequest();
        final List<String> addedRoles2 = List.of("ROLE5", "ROLE6");
        updateApplicationRolesRequest.setApplicationId(APPLICATION_ID);
        updateApplicationRolesRequest.setApplicationRoles(addedRoles2);
        mockMvc.perform(post("/rest/v3/application/roles/update")
                        .content(wrapInRequestObjectJson(updateApplicationRolesRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.responseObject.applicationRoles").isArray())
                .andExpect(jsonPath("$.responseObject.applicationRoles", hasSize(2)))
                .andExpect(jsonPath("$.responseObject.applicationRoles", hasItems(addedRoles2.toArray())));

        /* Test new list of app roles */
        final ListApplicationRolesResponse applicationRolesResponse = powerAuthService.
                listApplicationRoles(applicationRolesRequest);
        assertEquals(addedRoles2, applicationRolesResponse.getApplicationRoles());

        /* Test remove one of app roles */
        final RemoveApplicationRolesRequest removeApplicationRolesRequest = new RemoveApplicationRolesRequest();
        removeApplicationRolesRequest.setApplicationId(APPLICATION_ID);
        removeApplicationRolesRequest.setApplicationRoles(List.of("ROLE5"));
        mockMvc.perform(post("/rest/v3/application/roles/remove")
                        .content(wrapInRequestObjectJson(removeApplicationRolesRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.responseObject.applicationRoles").isArray())
                .andExpect(jsonPath("$.responseObject.applicationId").value(APPLICATION_ID))
                .andExpect(jsonPath("$.responseObject.applicationRoles", hasSize(1)))
                .andExpect(jsonPath("$.responseObject.applicationRoles", contains("ROLE6")));

        /* Test new list of app roles */
        final ListApplicationRolesResponse applicationRolesResponse2 = powerAuthService.
                listApplicationRoles(applicationRolesRequest);
        assertEquals(Collections.singletonList("ROLE6"), applicationRolesResponse2.getApplicationRoles());
    }

    /**
     * Tests the retrieval of the application list.
     * <p>
     * This test performs a mock HTTP POST request to retrieve the list of applications.
     * It verifies if the response contains the expected application ID and checks the size of the application list.
     *
     * @throws Exception if the mockMvc.perform operation fails.
     */
    @Test
    void testApplicationList() throws Exception {
        mockMvc.perform(post("/rest/v3/application/list")
                        .content(wrapInRequestObjectJson(new HashMap<>()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.responseObject.applications[0].applicationId").value(APPLICATION_ID))
                .andExpect(jsonPath("$.responseObject.applications", hasSize(1)));
    }

    /**
     * Tests the lookup of application version by application key.
     * <p>
     * This test sends a mock HTTP POST request to the application version detail endpoint with a specific application key.
     * It checks if the response correctly identifies the application ID associated with the provided application key.
     *
     * @throws Exception if the mockMvc.perform operation fails.
     */
    @Test
    void testApplicationVersionLookup() throws Exception {
        final LookupApplicationByAppKeyRequest applicationByAppKeyRequest = new LookupApplicationByAppKeyRequest();
        applicationByAppKeyRequest.setApplicationKey(APPLICATION_VERSION_APPLICATION_KEY);

        /* Application version app key created by the SQL script */
        mockMvc.perform(post("/rest/v3/application/detail/version")
                        .content(wrapInRequestObjectJson(applicationByAppKeyRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.responseObject.applicationId").value(APPLICATION_ID));
    }

    /**
     * Tests the support and unsupport operations for application versions.
     * <p>
     * This test first marks an application version as unsupported, verifying the action, and then marks the same version as supported, again verifying the action.
     * It ensures that the application version's support status is correctly updated and reflected in the system.
     *
     * @throws Exception if the mockMvc.perform operation fails.
     */
    @Test
    void testApplicationSupport() throws Exception {
        final String applicationVersionId = "default";
        final UnsupportApplicationVersionRequest unsupportApplicationVersionRequest = new UnsupportApplicationVersionRequest();
        unsupportApplicationVersionRequest.setApplicationId(APPLICATION_ID);
        unsupportApplicationVersionRequest.setApplicationVersionId(applicationVersionId);

        /* Application version app key created by the SQL script */
        mockMvc.perform(post("/rest/v3/application/version/unsupport")
                        .content(wrapInRequestObjectJson(unsupportApplicationVersionRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.responseObject.applicationVersionId").value(applicationVersionId))
                .andExpect(jsonPath("$.responseObject.supported").value(false));


        final SupportApplicationVersionRequest supportApplicationVersionRequest = new SupportApplicationVersionRequest();
        supportApplicationVersionRequest.setApplicationId(APPLICATION_ID);
        supportApplicationVersionRequest.setApplicationVersionId(applicationVersionId);

        /* Application version app key created by the SQL script */
        mockMvc.perform(post("/rest/v3/application/version/support")
                        .content(wrapInRequestObjectJson(supportApplicationVersionRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.responseObject.applicationVersionId").value(applicationVersionId))
                .andExpect(jsonPath("$.responseObject.supported").value(true));

    }

    /**
     * Tests the creation, listing, and removal of application integrations.
     * <p>
     * This test creates a new application integration, retrieves a list of integrations to verify its creation,
     * and then removes the created integration, again retrieving the list to verify its removal.
     *
     * @throws Exception if the mockMvc.perform operation fails.
     */
    @Test
    void testApplicationIntegration() throws Exception {
        final String integrationName = UUID.randomUUID().toString();
        final CreateIntegrationRequest createIntegrationRequest = new CreateIntegrationRequest();
        createIntegrationRequest.setName(integrationName);

        MvcResult result = mockMvc.perform(post("/rest/v3/integration/create")
                        .content(wrapInRequestObjectJson(createIntegrationRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.responseObject.name").value(integrationName))
                .andReturn();

        final String integrationId = convertMvcResultToObject(result,
                CreateIntegrationResponse.class).getId();

        mockMvc.perform(post("/rest/v3/integration/list")
                        .content(wrapInRequestObjectJson(new HashMap<>()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.responseObject.items").isNotEmpty())
                .andExpect(jsonPath(String.format("$.responseObject.items[?(@.name == '%s')]", integrationName)).exists());

        final RemoveIntegrationRequest removeIntegrationRequest = new RemoveIntegrationRequest();
        removeIntegrationRequest.setId(integrationId);
        mockMvc.perform(post("/rest/v3/integration/remove")
                        .content(wrapInRequestObjectJson(removeIntegrationRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.responseObject.removed").value(true))
                .andExpect(jsonPath("$.responseObject.id").value(integrationId));
    }

    /**
     * Tests the creation, lookup, and revocation of recovery codes.
     * <p>
     * This test creates recovery codes for a user, looks up the created codes, and then revokes them,
     * ensuring each step is processed correctly and the expected responses are received.
     *
     * @throws Exception if the mockMvc.perform operation fails.
     */
    @Test
    void testRecoveryCodeCreateLookupRevoke() throws Exception {
        final CreateRecoveryCodeRequest createRecoveryCodeRequest = new CreateRecoveryCodeRequest();
        createRecoveryCodeRequest.setApplicationId(APPLICATION_ID);
        createRecoveryCodeRequest.setUserId(USER_ID);
        createRecoveryCodeRequest.setPukCount(2L);

        final MvcResult result = mockMvc.perform(post("/rest/v3/recovery/create")
                        .content(wrapInRequestObjectJson(createRecoveryCodeRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.responseObject.userId").value(USER_ID))
                .andExpect(jsonPath("$.responseObject.userId").value(USER_ID))
                .andExpect(jsonPath("$.responseObject.puks.length()").value(2))
                .andReturn();

        final long recoveryCodeId = convertMvcResultToObject(result, CreateRecoveryCodeResponse.class)
                .getRecoveryCodeId();

        final LookupRecoveryCodesRequest lookupRecoveryCodesRequest = new LookupRecoveryCodesRequest();
        lookupRecoveryCodesRequest.setActivationId(ACTIVATION_ID);
        lookupRecoveryCodesRequest.setUserId(USER_ID);
        lookupRecoveryCodesRequest.setRecoveryCodeStatus(RecoveryCodeStatus.CREATED);
        lookupRecoveryCodesRequest.setRecoveryPukStatus(RecoveryPukStatus.VALID);

        mockMvc.perform(post("/rest/v3/recovery/lookup")
                        .content(wrapInRequestObjectJson(lookupRecoveryCodesRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.responseObject.recoveryCodes.length()", greaterThan(0)));

        final RevokeRecoveryCodesRequest revokeRecoveryCodesRequest = new RevokeRecoveryCodesRequest();
        revokeRecoveryCodesRequest.setRecoveryCodeIds(List.of(recoveryCodeId));

        mockMvc.perform(post("/rest/v3/recovery/revoke")
                        .content(wrapInRequestObjectJson(revokeRecoveryCodesRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.responseObject.revoked").value(true));
    }

    /**
     * Tests the retrieval and update of recovery configuration.
     * <p>
     * This test retrieves the current recovery configuration, updates it, and then retrieves it again to
     * verify that the updates were successfully applied.
     *
     * @throws Exception if the mockMvc.perform operation fails.
     */
    @Test
    void testRecoveryConfig() throws Exception {
        final GetRecoveryConfigRequest getRecoveryConfigRequest = new GetRecoveryConfigRequest();
        getRecoveryConfigRequest.setApplicationId(APPLICATION_ID);

        mockMvc.perform(post("/rest/v3/recovery/config/detail")
                        .content(wrapInRequestObjectJson(getRecoveryConfigRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.responseObject.postcardPublicKey", notNullValue()))
                .andExpect(jsonPath("$.responseObject.remotePostcardPublicKey", notNullValue()));

        final UpdateRecoveryConfigRequest updateRecoveryConfigRequest = new UpdateRecoveryConfigRequest();
        final String newTestKey = "newTestKey";
        updateRecoveryConfigRequest.setApplicationId(APPLICATION_ID);
        updateRecoveryConfigRequest.setRemotePostcardPublicKey(newTestKey);

        mockMvc.perform(post("/rest/v3/recovery/config/update")
                        .content(wrapInRequestObjectJson(updateRecoveryConfigRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.responseObject.updated").value(true));

        final GetRecoveryConfigResponse recoveryConfigResponse = powerAuthService.getRecoveryConfig(getRecoveryConfigRequest);
        assertNotNull(recoveryConfigResponse.getPostcardPublicKey());
        assertFalse(recoveryConfigResponse.isActivationRecoveryEnabled());
        assertFalse(recoveryConfigResponse.isRecoveryPostcardEnabled());
        assertFalse(recoveryConfigResponse.isAllowMultipleRecoveryCodes());
        assertEquals(newTestKey, recoveryConfigResponse.getRemotePostcardPublicKey());
    }

    /**
     * Tests the creation of a non-personalized offline signature payload.
     * <p>
     * This test sends a request to create a non-personalized offline signature payload and verifies
     * that the response contains the expected offline data and nonce.
     *
     * @throws Exception if the mockMvc.perform operation fails.
     */
    @Test
    void testNonPersonalizedOfflineSignaturePayload() throws Exception {
        final CreateNonPersonalizedOfflineSignaturePayloadRequest nonPersonalizedOfflineSignaturePayloadRequest =
                new CreateNonPersonalizedOfflineSignaturePayloadRequest();
        nonPersonalizedOfflineSignaturePayloadRequest.setApplicationId(APPLICATION_ID);
        nonPersonalizedOfflineSignaturePayloadRequest.setData(DATA);

        mockMvc.perform(post("/rest/v3/signature/offline/non-personalized/create")
                        .content(wrapInRequestObjectJson(nonPersonalizedOfflineSignaturePayloadRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.responseObject.offlineData", notNullValue()))
                .andExpect(jsonPath("$.responseObject.nonce", notNullValue()));
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
        final CreatePersonalizedOfflineSignaturePayloadRequest personalizedOfflineSignaturePayloadRequest =
                new CreatePersonalizedOfflineSignaturePayloadRequest();
        personalizedOfflineSignaturePayloadRequest.setActivationId(ACTIVATION_ID);
        personalizedOfflineSignaturePayloadRequest.setData(DATA);

        mockMvc.perform(post("/rest/v3/signature/offline/personalized/create")
                        .content(wrapInRequestObjectJson(personalizedOfflineSignaturePayloadRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.responseObject.offlineData", notNullValue()))
                .andExpect(jsonPath("$.responseObject.nonce", notNullValue()));
    }

    /**
     * Tests the verification of an offline signature.
     * <p>
     * This test sends a signature verification request for an offline signature and checks
     * if the signature is validated correctly, expecting a false result for the test data.
     *
     * @throws Exception if the mockMvc.perform operation fails.
     */
    @Test
    void testVerifyOfflineSignature() throws Exception {
        final VerifyOfflineSignatureRequest verifyOfflineSignatureRequest =
                new VerifyOfflineSignatureRequest();
        verifyOfflineSignatureRequest.setActivationId(ACTIVATION_ID);
        verifyOfflineSignatureRequest.setData(DATA);
        verifyOfflineSignatureRequest.setSignature("123456");
        verifyOfflineSignatureRequest.setAllowBiometry(false);

        mockMvc.perform(post("/rest/v3/signature/offline/verify")
                        .content(wrapInRequestObjectJson(verifyOfflineSignatureRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.responseObject.signatureValid").value(false))
                .andExpect(jsonPath("$.responseObject.activationId").value(ACTIVATION_ID));
    }

    /**
     * Tests the retrieval of system status.
     * <p>
     * This test checks if the system status can be successfully retrieved without any errors.
     *
     * @throws Exception if the mockMvc.perform operation fails.
     */
    @Test
    void testSystemStatus() throws Exception {
        mockMvc.perform(post("/rest/v3/status")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());
    }

    /**
     * Tests the retrieval of a list of error codes.
     * <p>
     * This test requests a list of error codes and verifies that the list is populated with a sufficient number of entries.
     *
     * @throws Exception if the mockMvc.perform operation fails.
     */
    @Test
    void testErrorList() throws Exception {
        final GetErrorCodeListRequest getErrorCodeListRequest = new GetErrorCodeListRequest();
        getErrorCodeListRequest.setLanguage(Locale.ENGLISH.getLanguage());
        mockMvc.perform(post("/rest/v3/error/list")
                        .content(wrapInRequestObjectJson(getErrorCodeListRequest))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.responseObject.errors.length()", greaterThan(32)));
    }

    /**
     * Creates a request object for creating an operation.
     * <p>
     * This helper method constructs and returns an {@link OperationCreateRequest} with
     * predefined application ID, template name, user ID, and proximity OTP settings.
     *
     * @param proximityOtp a boolean indicating whether proximity OTP is enabled
     * @return a configured {@link OperationCreateRequest} instance
     * @throws Exception if the operation creation request setup fails
     */
    private OperationCreateRequest createOperationCreateRequest(final boolean proximityOtp) throws Exception {
        final OperationCreateRequest operationCreateRequest = new OperationCreateRequest();
        operationCreateRequest.setApplications(List.of(APPLICATION_ID));
        operationCreateRequest.setTemplateName(TEMPLATE_NAME);
        operationCreateRequest.setUserId(USER_ID);
        operationCreateRequest.setProximityCheckEnabled(proximityOtp);
        return operationCreateRequest;
    }

    /**
     * Creates a request object for getting a list of callback URLs.
     * <p>
     * This helper method constructs and returns a {@link GetCallbackUrlListRequest} for a
     * specific application ID.
     *
     * @return a configured {@link GetCallbackUrlListRequest} instance
     */
    private static GetCallbackUrlListRequest createCallbackUrlListRequest() {
        final GetCallbackUrlListRequest getCallbackUrlListRequest = new GetCallbackUrlListRequest();
        getCallbackUrlListRequest.setApplicationId(APPLICATION_ID);
        return getCallbackUrlListRequest;
    }

    /**
     * Creates a request object for creating a callback URL.
     * <p>
     * This helper method constructs and returns a {@link CreateCallbackUrlRequest} with
     * predefined callback URL, name, type, application ID, and other settings.
     *
     * @return a configured {@link CreateCallbackUrlRequest} instance
     */
    private static CreateCallbackUrlRequest createCallbackUrlRequest() {
        final CreateCallbackUrlRequest callbackUrlRequest = new CreateCallbackUrlRequest();
        callbackUrlRequest.setCallbackUrl(CALLBACK_URL);
        callbackUrlRequest.setName(CALLBACK_NAME);
        callbackUrlRequest.setType(CallbackUrlType.ACTIVATION_STATUS_CHANGE.name());
        callbackUrlRequest.setApplicationId(APPLICATION_ID);
        callbackUrlRequest.setAttributes(Collections.singletonList("activationId"));
        callbackUrlRequest.setAuthentication(null);
        return callbackUrlRequest;
    }

    /**
     * Wraps an object in a 'requestObject' JSON structure.
     * <p>
     * This helper method wraps a given object within a 'requestObject' JSON structure, useful
     * for preparing request bodies for MockMvc calls.
     *
     * @param obj the object to be wrapped in the request JSON
     * @return a JSON string representation of the object wrapped in 'requestObject'
     * @throws Exception if JSON processing fails
     */
    private static String wrapInRequestObjectJson(final Object obj) throws Exception {
        final ObjectMapper objectMapper = new ObjectMapper();
        final Map<String, Object> wrapper = new HashMap<>();
        wrapper.put("requestObject", obj);
        return new ObjectMapper().writeValueAsString(wrapper);
    }

    /**
     * Converts an MvcResult to a specific response type.
     * <p>
     * This helper method takes an MvcResult from a MockMvc call and converts its response content
     * into a specified class type, assuming the response is in JSON format.
     *
     * @param result       the MvcResult from a MockMvc call
     * @param responseType the class type into which the response content should be converted
     * @return an instance of the specified type with the response content
     * @throws Exception if JSON processing fails
     */
    private static <T> T convertMvcResultToObject(final MvcResult result, final Class<T> responseType) throws Exception {
        final ObjectMapper objectMapper = new ObjectMapper();
        final JsonNode rootNode = objectMapper.readTree(result.getResponse().getContentAsString());
        final JsonNode responseObjectNode = rootNode.path("responseObject");
        return objectMapper.treeToValue(responseObjectNode, responseType);
    }

}
