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

import com.wultra.security.powerauth.app.server.service.behavior.tasks.v3.OnlineSignatureServiceBehavior;
import com.wultra.security.powerauth.app.server.service.behavior.tasks.v4.OnlineAuthenticationServiceBehavior;
import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.client.model.enumeration.v3.SignatureType;
import com.wultra.security.powerauth.client.model.enumeration.v4.AuthenticationCodeType;
import com.wultra.security.powerauth.client.model.request.v3.VerifySignatureRequest;
import com.wultra.security.powerauth.client.model.request.v4.VerifyAuthenticationRequest;
import com.wultra.security.powerauth.client.model.response.v3.VerifySignatureResponse;
import com.wultra.security.powerauth.client.model.response.v4.VerifyAuthenticationResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Test of {@link AuthenticationController}.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class AuthenticationControllerTest {

    @Autowired
    private WebTestClient webTestClient;

    @MockitoBean
    private OnlineSignatureServiceBehavior legacyOnlineSignatureService;

    @MockitoBean
    private OnlineAuthenticationServiceBehavior onlineAuthenticationService;

    /**
     * Test of calling the verify authentication endpoint with V4 authentication code.
     */
    @Test
    void testVerifyAuthentication() throws Exception {
        final String verifyAuthenticationRequestBody = """
                {
                  "requestObject": {
                    "activationId": "e107ba7f-f602-4f95-a390-18a29013070f",
                    "applicationKey": "YXBwbGljYXRpb25LZXk=",
                    "data": "ZGF0YQ==",
                    "authenticationCode": "YXV0aGVudGljYXRpb25Db2Rl",
                    "authenticationCodeType": "POSSESSION_KNOWLEDGE",
                    "authenticationVersion": "4.0",
                    "allowedStates": ["ACTIVE"]
                  }
                }
                """;

        final VerifyAuthenticationRequest request = new VerifyAuthenticationRequest();
        request.setActivationId("e107ba7f-f602-4f95-a390-18a29013070f");
        request.setApplicationKey("YXBwbGljYXRpb25LZXk=");
        request.setData("ZGF0YQ==");
        request.setAuthenticationCode("YXV0aGVudGljYXRpb25Db2Rl");
        request.setAuthenticationCodeType(AuthenticationCodeType.POSSESSION_KNOWLEDGE);
        request.setAuthenticationVersion("4.0");
        request.setAllowedStates(List.of(ActivationStatus.ACTIVE));

        final VerifyAuthenticationResponse response = new VerifyAuthenticationResponse();
        response.setAuthenticationValid(true);
        response.setActivationStatus(ActivationStatus.ACTIVE);
        response.setBlockedReason(null);
        response.setActivationId("e107ba7f-f602-4f95-a390-18a29013070f");
        response.setUserId("user");
        response.setApplicationId("app");
        response.setAuthenticationCodeType(AuthenticationCodeType.POSSESSION_KNOWLEDGE);
        response.setRemainingAttempts(new BigInteger("5"));
        response.setApplicationRoles(List.of("ROLE"));
        response.setActivationFlags(Collections.emptyList());

        when(onlineAuthenticationService.verifyAuthentication(request, new ArrayList<>()))
                .thenReturn(response);

        webTestClient.post()
                .uri("/rest/v4/auth/verify")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(verifyAuthenticationRequestBody)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.status").isEqualTo("OK")
                .jsonPath("$.responseObject").isNotEmpty()
                .jsonPath("$.responseObject.authenticationValid").isEqualTo(true)
                .jsonPath("$.responseObject.activationStatus").isEqualTo("ACTIVE")
                .jsonPath("$.responseObject.blockedReason").isEmpty()
                .jsonPath("$.responseObject.activationId").isEqualTo("e107ba7f-f602-4f95-a390-18a29013070f")
                .jsonPath("$.responseObject.userId").isEqualTo("user")
                .jsonPath("$.responseObject.applicationId").isEqualTo("app")
                .jsonPath("$.responseObject.authenticationCodeType").isEqualTo("POSSESSION_KNOWLEDGE")
                .jsonPath("$.responseObject.remainingAttempts").isEqualTo(5)
                .jsonPath("$.responseObject.applicationRoles").isEqualTo(List.of("ROLE"))
                .jsonPath("$.responseObject.activationFlags").isEmpty();

        verify(onlineAuthenticationService).verifyAuthentication(request, new ArrayList<>());
    }

    /**
     * Test of calling the verify authentication endpoint with V3.3 signature.
     * This verifies the legacy signature verification is applied on v4 endpoint
     * if required by the specified `authenticationVersion` in the request body.
     */
    @Test
    void testVerifyAuthentication_legacy() throws Exception {
        final String verifyAuthenticationRequestBody = """
                {
                  "requestObject": {
                    "activationId": "e107ba7f-f602-4f95-a390-18a29013070f",
                    "applicationKey": "YXBwbGljYXRpb25LZXk=",
                    "data": "ZGF0YQ==",
                    "authenticationCode": "bGVnYWN5U2lnbmF0dXJl",
                    "authenticationCodeType": "POSSESSION_KNOWLEDGE",
                    "authenticationVersion": "3.3"
                  }
                }
                """;

        final VerifySignatureRequest request = new VerifySignatureRequest();
        request.setActivationId("e107ba7f-f602-4f95-a390-18a29013070f");
        request.setApplicationKey("YXBwbGljYXRpb25LZXk=");
        request.setData("ZGF0YQ==");
        request.setSignature("bGVnYWN5U2lnbmF0dXJl");
        request.setSignatureType(SignatureType.POSSESSION_KNOWLEDGE);
        request.setSignatureVersion("3.3");

        final VerifySignatureResponse response = new VerifySignatureResponse();
        response.setSignatureValid(true);
        response.setActivationStatus(ActivationStatus.ACTIVE);
        response.setBlockedReason(null);
        response.setActivationId("e107ba7f-f602-4f95-a390-18a29013070f");
        response.setUserId("user");
        response.setApplicationId("app");
        response.setSignatureType(SignatureType.POSSESSION_KNOWLEDGE);
        response.setRemainingAttempts(new BigInteger("5"));
        response.setApplicationRoles(List.of("ROLE"));
        response.setActivationFlags(Collections.emptyList());

        when(legacyOnlineSignatureService.verifySignature(request, new ArrayList<>()))
                .thenReturn(response);

        webTestClient.post()
                .uri("/rest/v4/auth/verify")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(verifyAuthenticationRequestBody)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.status").isEqualTo("OK")
                .jsonPath("$.responseObject").isNotEmpty()
                .jsonPath("$.responseObject.authenticationValid").isEqualTo(true)
                .jsonPath("$.responseObject.activationStatus").isEqualTo("ACTIVE")
                .jsonPath("$.responseObject.blockedReason").isEmpty()
                .jsonPath("$.responseObject.activationId").isEqualTo("e107ba7f-f602-4f95-a390-18a29013070f")
                .jsonPath("$.responseObject.userId").isEqualTo("user")
                .jsonPath("$.responseObject.applicationId").isEqualTo("app")
                .jsonPath("$.responseObject.authenticationCodeType").isEqualTo("POSSESSION_KNOWLEDGE")
                .jsonPath("$.responseObject.remainingAttempts").isEqualTo(5)
                .jsonPath("$.responseObject.applicationRoles").isEqualTo(List.of("ROLE"))
                .jsonPath("$.responseObject.activationFlags").isEmpty();

        verify(legacyOnlineSignatureService).verifySignature(request, new ArrayList<>());
    }

}
