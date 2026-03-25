/*
 * PowerAuth Server and related software components
 * Copyright (C) 2026 Wultra s.r.o.
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

package com.wultra.powerauth.fido2.rest.controller;

import com.wultra.powerauth.fido2.service.AssertionService;
import com.wultra.security.powerauth.fido2.model.entity.AuthenticatorAssertionResponse;
import com.wultra.security.powerauth.fido2.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.fido2.model.request.AssertionChallengeRequest;
import com.wultra.security.powerauth.fido2.model.request.AssertionVerificationRequest;
import com.wultra.security.powerauth.fido2.model.response.AssertionChallengeResponse;
import com.wultra.security.powerauth.fido2.model.response.AssertionVerificationResponse;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests of {@link AssertionController}.
 *
 * @author Pavel Sindelar, pavel.sindelar@wultra.com
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes = com.wultra.security.powerauth.app.server.Application.class)
@ActiveProfiles("test")
class AssertionControllerTest {

    @Autowired
    private WebTestClient webTestClient;

    @MockitoBean
    private AssertionService assertionService;

    @Test
    void testRequestAssertionChallenge() throws Exception {
        final String requestBody = """
                {
                  "requestObject": {
                    "applicationIds": ["app-id"],
                    "templateName": "login",
                    "userId": "user-id"
                  }
                }
                """;

        final AssertionChallengeRequest request = new AssertionChallengeRequest();
        request.setApplicationIds(List.of("app-id"));
        request.setTemplateName("login");
        request.setUserId("user-id");

        final AssertionChallengeResponse response = new AssertionChallengeResponse();
        response.setOperationId("op-id");
        response.setChallenge("challenge-value");
        response.setUserId("user-id");
        response.setApplicationIds(List.of("app-id"));
        response.setFailedAttempts(0L);
        response.setMaxFailedAttempts(5L);

        when(assertionService.requestAssertionChallenge(request)).thenReturn(response);

        webTestClient.post()
                .uri("/fido2/assertions/challenge")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(requestBody)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.status").isEqualTo("OK")
                .jsonPath("$.responseObject.operationId").isEqualTo("op-id")
                .jsonPath("$.responseObject.challenge").isEqualTo("challenge-value")
                .jsonPath("$.responseObject.userId").isEqualTo("user-id")
                .jsonPath("$.responseObject.failedAttempts").isEqualTo(0)
                .jsonPath("$.responseObject.maxFailedAttempts").isEqualTo(5);

        verify(assertionService).requestAssertionChallenge(request);
    }

    @Test
    void testAuthenticate() throws Exception {
        final String requestBody = """
                {
                  "requestObject": {
                    "credentialId": "credentialId",
                    "type": "public-key",
                    "response": {
                      "clientDataJSON": "dGVzdAo=",
                      "authenticatorData": "dGVzdAo=",
                      "signature": "dGVzdAo="
                    },
                    "relyingPartyId": "example.com"
                  }
                }
                """;

        final AuthenticatorAssertionResponse assertionResponse = new AuthenticatorAssertionResponse();
        assertionResponse.setClientDataJSON("dGVzdAo=");
        assertionResponse.setAuthenticatorData("dGVzdAo=");
        assertionResponse.setSignature(Base64.getDecoder().decode("dGVzdAo="));

        final AssertionVerificationRequest request = new AssertionVerificationRequest();
        request.setCredentialId("credentialId");
        request.setType("public-key");
        request.setResponse(assertionResponse);
        request.setRelyingPartyId("example.com");

        final AssertionVerificationResponse response = new AssertionVerificationResponse();
        response.setAssertionValid(true);
        response.setUserId("user-id");
        response.setActivationId("activation-id");
        response.setActivationStatus(ActivationStatus.ACTIVE);

        when(assertionService.authenticate(request)).thenReturn(response);

        webTestClient.post()
                .uri("/fido2/assertions")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(requestBody)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.status").isEqualTo("OK")
                .jsonPath("$.responseObject.assertionValid").isEqualTo(true)
                .jsonPath("$.responseObject.userId").isEqualTo("user-id")
                .jsonPath("$.responseObject.activationId").isEqualTo("activation-id")
                .jsonPath("$.responseObject.activationStatus").isEqualTo("ACTIVE");

        verify(assertionService).authenticate(request);
    }

    @Test
    void testAuthenticate_base64UrlCredentialId_normalizedToBase64() throws Exception {
        final String requestBody = """
                {
                  "requestObject": {
                    "credentialId": "-_-",
                    "type": "public-key",
                    "response": {
                      "clientDataJSON": "dGVzdAo=",
                      "authenticatorData": "dGVzdAo=",
                      "signature": "dGVzdAo="
                    },
                    "relyingPartyId": "example.com"
                  }
                }
                """;

        webTestClient.post()
                .uri("/fido2/assertions")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(requestBody)
                .exchange()
                .expectStatus().isOk();

        final ArgumentCaptor<AssertionVerificationRequest> captor = ArgumentCaptor.forClass(AssertionVerificationRequest.class);
        verify(assertionService).authenticate(captor.capture());
        assertEquals("+/+=", captor.getValue().getCredentialId());
    }

    @Test
    void testAuthenticate_invalidBase64CredentialId_returnsBadRequest() {
        final String requestBody = """
                {
                  "requestObject": {
                    "credentialId": "A",
                    "type": "public-key",
                    "response": {
                      "clientDataJSON": "dGVzdAo=",
                      "authenticatorData": "dGVzdAo=",
                      "signature": "dGVzdAo="
                    },
                    "relyingPartyId": "example.com"
                  }
                }
                """;

        webTestClient.post()
                .uri("/fido2/assertions")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(requestBody)
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.responseObject.code").isEqualTo("INVALID_REQUEST")
                .jsonPath("$.responseObject.message")
                .isEqualTo("JSON parse error: Invalid value for path '/requestObject/credentialId': length mod 4 == 1 is not a valid Base64 remainder");
    }
}
