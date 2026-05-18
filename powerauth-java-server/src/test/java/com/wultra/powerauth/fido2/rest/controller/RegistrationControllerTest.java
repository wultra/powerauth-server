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

import com.wultra.powerauth.fido2.service.RegistrationService;
import com.wultra.security.powerauth.fido2.model.request.RegistrationRequest;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;

/**
 * Tests of {@link RegistrationController}.
 *
 * @author Pavel Sindelar, pavel.sindelar@wultra.com
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes = com.wultra.security.powerauth.app.server.Application.class)
@ActiveProfiles("test")
@AutoConfigureWebTestClient
class RegistrationControllerTest {

    @Autowired
    private WebTestClient webTestClient;

    @MockitoBean
    private RegistrationService registrationService;

    @Test
    void testRegister_base64UrlCredentialId_normalizedToBase64() throws Exception {
        final String requestBody = """
                {
                  "requestObject": {
                    "applicationId": "app-id",
                    "activationName": "My Device",
                    "authenticatorParameters": {
                      "credentialId": "-_-",
                      "type": "public-key",
                      "response": {
                        "clientDataJSON": "dGVzdAo=",
                        "attestationObject": "dGVzdAo="
                      },
                      "relyingPartyId": "example.com"
                    }
                  }
                }
                """;

        webTestClient.post()
                .uri("/fido2/registrations")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(requestBody)
                .exchange()
                .expectStatus().isOk();

        final ArgumentCaptor<RegistrationRequest> captor = ArgumentCaptor.forClass(RegistrationRequest.class);
        verify(registrationService).register(captor.capture());
        assertEquals("+/+=", captor.getValue().getAuthenticatorParameters().getCredentialId());
    }

    @Test
    void testRegister_invalidBase64CredentialId_returnsBadRequest() {
        final String requestBody = """
                {
                  "requestObject": {
                    "applicationId": "app-id",
                    "activationName": "My Device",
                    "authenticatorParameters": {
                      "credentialId": "A",
                      "type": "public-key",
                      "response": {
                        "clientDataJSON": "dGVzdAo=",
                        "attestationObject": "dGVzdAo="
                      },
                      "relyingPartyId": "example.com"
                    }
                  }
                }
                """;

        webTestClient.post()
                .uri("/fido2/registrations")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(requestBody)
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.responseObject.code").isEqualTo("INVALID_REQUEST")
                .jsonPath("$.responseObject.message")
                .isEqualTo("JSON parse error: Invalid value for path '/requestObject/authenticatorParameters/credentialId': length mod 4 == 1 is not a valid Base64 remainder");
    }
}
