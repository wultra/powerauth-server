/*
 * PowerAuth Server and related software components
 * Copyright (C) 2025 Wultra s.r.o.
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

package com.wultra.security.powerauth.app.server.controller.api.v4;

import com.wultra.security.powerauth.app.server.service.behavior.tasks.v4.TokenServiceBehavior;
import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.client.model.enumeration.v3.SignatureType;
import com.wultra.security.powerauth.client.model.enumeration.v4.AuthenticationCodeType;
import com.wultra.security.powerauth.client.model.request.ValidateTokenRequest;
import com.wultra.security.powerauth.client.model.response.v4.ValidateTokenResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.util.Collections;
import java.util.List;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Test of {@link TokenController}.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@AutoConfigureWebTestClient
class TokenControllerTest {

    @Autowired
    private WebTestClient webTestClient;

    @MockitoBean
    private TokenServiceBehavior tokenService;

    @MockitoBean
    private com.wultra.security.powerauth.app.server.service.behavior.tasks.v3.TokenServiceBehavior legacyTokenService;

    /**
     * Test of calling the validate token endpoint with V4 token.
     */
    @Test
    void validateToken() throws Exception {
        final String validateTokenRequestBody = """
                {
                  "requestObject": {
                    "tokenId": "e4615c8f-1e44-4859-8dcd-05229ba22218",
                    "tokenDigest": "dG9rZW5EaWdlc3Q=",
                    "nonce": "bm9uY2U=",
                    "protocolVersion": "4.0",
                    "timestamp": 1765457829991
                  }
                }
                """;

        final ValidateTokenRequest validateTokenRequest = new ValidateTokenRequest();
        validateTokenRequest.setTokenId("e4615c8f-1e44-4859-8dcd-05229ba22218");
        validateTokenRequest.setTokenDigest("dG9rZW5EaWdlc3Q=");
        validateTokenRequest.setNonce("bm9uY2U=");
        validateTokenRequest.setProtocolVersion("4.0");
        validateTokenRequest.setTimestamp(1765457829991L);

        final ValidateTokenResponse validateTokenResponse = new ValidateTokenResponse();
        validateTokenResponse.setTokenValid(true);
        validateTokenResponse.setActivationId("e107ba7f-f602-4f95-a390-18a29013070f");
        validateTokenResponse.setActivationStatus(ActivationStatus.ACTIVE);
        validateTokenResponse.setBlockedReason(null);
        validateTokenResponse.setUserId("user");
        validateTokenResponse.setApplicationId("app");
        validateTokenResponse.setAuthenticationCodeType(AuthenticationCodeType.POSSESSION_KNOWLEDGE);
        validateTokenResponse.setApplicationRoles(List.of("ROLE"));
        validateTokenResponse.setActivationFlags(Collections.emptyList());

        when(tokenService.validateToken(validateTokenRequest))
                .thenReturn(validateTokenResponse);

        webTestClient.post()
                .uri("/rest/v4/token/validate")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(validateTokenRequestBody)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.status").isEqualTo("OK")
                .jsonPath("$.responseObject").isNotEmpty()
                .jsonPath("$.responseObject.tokenValid").isEqualTo(true)
                .jsonPath("$.responseObject.activationId").isEqualTo("e107ba7f-f602-4f95-a390-18a29013070f")
                .jsonPath("$.responseObject.activationStatus").isEqualTo("ACTIVE")
                .jsonPath("$.responseObject.blockedReason").isEmpty()
                .jsonPath("$.responseObject.userId").isEqualTo("user")
                .jsonPath("$.responseObject.applicationId").isEqualTo("app")
                .jsonPath("$.responseObject.authenticationCodeType").isEqualTo("POSSESSION_KNOWLEDGE")
                .jsonPath("$.responseObject.applicationRoles").isEqualTo(List.of("ROLE"))
                .jsonPath("$.responseObject.activationFlags").isEmpty();

        verify(tokenService).validateToken(validateTokenRequest);
    }

    /**
     * Test of calling the validate token endpoint with V3.3 token.
     * This verifies the legacy token validation is applied on v4 endpoint
     * if required by the specified `protocolVersion` in the request body.
     */
    @Test
    void validateToken_legacy() throws Exception {
        final String validateTokenRequestBody = """
                {
                  "requestObject": {
                    "tokenId": "69521414-b965-44f7-9d2a-a56b0512825c",
                    "tokenDigest": "bGVnYWN5VG9rZW5EaWdlc3Q=",
                    "nonce": "bm9uY2U=",
                    "protocolVersion": "3.3",
                    "timestamp": 1765457829991
                  }
                }
                """;

        final ValidateTokenRequest validateTokenRequest = new ValidateTokenRequest();
        validateTokenRequest.setTokenId("69521414-b965-44f7-9d2a-a56b0512825c");
        validateTokenRequest.setTokenDigest("bGVnYWN5VG9rZW5EaWdlc3Q=");
        validateTokenRequest.setNonce("bm9uY2U=");
        validateTokenRequest.setProtocolVersion("3.3");
        validateTokenRequest.setTimestamp(1765457829991L);

        final com.wultra.security.powerauth.client.model.response.v3.ValidateTokenResponse validateTokenResponse = new com.wultra.security.powerauth.client.model.response.v3.ValidateTokenResponse();
        validateTokenResponse.setTokenValid(true);
        validateTokenResponse.setActivationId("e107ba7f-f602-4f95-a390-18a29013070f");
        validateTokenResponse.setActivationStatus(ActivationStatus.ACTIVE);
        validateTokenResponse.setBlockedReason(null);
        validateTokenResponse.setUserId("user");
        validateTokenResponse.setApplicationId("app");
        validateTokenResponse.setSignatureType(SignatureType.POSSESSION_KNOWLEDGE);
        validateTokenResponse.setApplicationRoles(List.of("ROLE"));
        validateTokenResponse.setActivationFlags(Collections.emptyList());

        when(legacyTokenService.validateToken(validateTokenRequest))
                .thenReturn(validateTokenResponse);

        webTestClient.post()
                .uri("/rest/v4/token/validate")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(validateTokenRequestBody)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.status").isEqualTo("OK")
                .jsonPath("$.responseObject").isNotEmpty()
                .jsonPath("$.responseObject.tokenValid").isEqualTo(true)
                .jsonPath("$.responseObject.activationId").isEqualTo("e107ba7f-f602-4f95-a390-18a29013070f")
                .jsonPath("$.responseObject.activationStatus").isEqualTo("ACTIVE")
                .jsonPath("$.responseObject.blockedReason").isEmpty()
                .jsonPath("$.responseObject.userId").isEqualTo("user")
                .jsonPath("$.responseObject.applicationId").isEqualTo("app")
                .jsonPath("$.responseObject.authenticationCodeType").isEqualTo("POSSESSION_KNOWLEDGE")
                .jsonPath("$.responseObject.applicationRoles").isEqualTo(List.of("ROLE"))
                .jsonPath("$.responseObject.activationFlags").isEmpty();

        verify(legacyTokenService).validateToken(validateTokenRequest);
    }

}
