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
import com.jayway.jsonpath.JsonPath;
import com.wultra.core.audit.base.database.DatabaseAudit;
import com.wultra.security.powerauth.client.model.entity.CallbackUrl;
import com.wultra.security.powerauth.client.model.enumeration.CallbackUrlType;
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.response.CreateCallbackUrlResponse;
import com.wultra.security.powerauth.client.model.response.GetCallbackUrlListResponse;
import com.wultra.security.powerauth.client.model.response.OperationDetailResponse;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationHistoryEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.OperationEntity;
import io.getlime.security.powerauth.app.server.database.model.enumeration.OperationStatusDo;
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

import java.util.*;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
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
