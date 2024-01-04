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

import com.jayway.jsonpath.JsonPath;
import com.wultra.core.audit.base.database.DatabaseAudit;
import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import com.wultra.security.powerauth.client.model.request.OperationApproveRequest;
import com.wultra.security.powerauth.client.model.request.OperationCreateRequest;
import com.wultra.security.powerauth.client.model.request.OperationDetailRequest;
import com.wultra.security.powerauth.client.model.response.OperationDetailResponse;
import com.wultra.security.powerauth.client.model.response.OperationUserActionResponse;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationHistoryEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.OperationEntity;
import io.getlime.security.powerauth.app.server.database.model.enumeration.OperationStatusDo;
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

import java.util.List;

import static com.wultra.security.powerauth.client.model.enumeration.UserActionResult.APPROVED;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private EntityManager entityManager;

    @Autowired
    private DatabaseAudit databaseAudit;

    @Autowired
    OperationServiceBehavior operationServiceBehavior;

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
        final String operationId = createOperation(false).getId();

        mockMvc.perform(post("/rest/v3/operation/approve")
                        .content("""
                                {
                                  "requestObject": {
                                    "operationId": "%s",
                                    "userId": "%s",
                                    "applicationId": "%s",
                                    "data": "%s",
                                    "signatureType": "POSSESSION_KNOWLEDGE"
                                  }
                                }
                                """.formatted(operationId, USER_ID, APPLICATION_ID, DATA))
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
        MvcResult result = mockMvc.perform(post("/rest/v3/operation/create")
                        .content("""
                                {
                                  "requestObject": {
                                    "applications": ["PA_Tests"],
                                    "templateName": "test-template"
                                  }
                                }
                                """)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))

                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("OK"))
                .andExpect(jsonPath("$.responseObject.status").value("PENDING")).andReturn();


        final String operationId = JsonPath.read(result.getResponse().getContentAsString(), "$.responseObject.id");

        final OperationEntity operation = entityManager.find(OperationEntity.class, operationId);
        assertEquals("test-template", operation.getTemplateName());
    }

    @Test
    void testGetOperationDetail() throws Exception {
        final OperationDetailResponse operation = createOperation(false);

        final OperationDetailRequest detailRequest = new OperationDetailRequest();
        final String operationId = operation.getId();
        detailRequest.setOperationId(operationId);

        MvcResult result = mockMvc.perform(post("/rest/v3/operation/detail")
                        .content("""
                                {
                                  "requestObject": {
                                    "operationId": "%s",
                                    "userId": "%s"
                                  }
                                }
                                """.formatted(operation.getId(), USER_ID))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.responseObject.status").value("PENDING"))
                .andExpect(jsonPath("$.responseObject.data").value(DATA))
                .andExpect(jsonPath("$.responseObject.templateName").value(TEMPLATE_NAME))
                .andExpect(jsonPath("$.responseObject.id").value(operationId)).andReturn();
    }

    private OperationDetailResponse createOperation(final boolean proximityOtp) throws Exception {
        final OperationCreateRequest operationCreateRequest = new OperationCreateRequest();
        operationCreateRequest.setApplications(List.of(APPLICATION_ID));
        operationCreateRequest.setTemplateName(TEMPLATE_NAME);
        operationCreateRequest.setUserId(USER_ID);
        operationCreateRequest.setProximityCheckEnabled(proximityOtp);
        return operationServiceBehavior.createOperation(operationCreateRequest);
    }

    private static OperationApproveRequest createOperationApproveRequest(final String operationId) {
        final OperationApproveRequest approveRequest = new OperationApproveRequest();
        approveRequest.setOperationId(operationId);
        approveRequest.setUserId(USER_ID);
        approveRequest.setApplicationId(APPLICATION_ID);
        approveRequest.setData(DATA);
        approveRequest.setSignatureType(SignatureType.POSSESSION_KNOWLEDGE);
        return approveRequest;
    }
}
