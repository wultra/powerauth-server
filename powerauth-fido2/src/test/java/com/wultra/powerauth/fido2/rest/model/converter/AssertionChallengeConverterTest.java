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

package com.wultra.powerauth.fido2.rest.model.converter;

import com.wultra.powerauth.fido2.rest.model.entity.AssertionChallenge;
import com.wultra.powerauth.fido2.rest.model.entity.AuthenticatorDetail;
import com.wultra.security.powerauth.client.model.request.OperationCreateRequest;
import com.wultra.security.powerauth.client.model.response.OperationDetailResponse;
import com.wultra.security.powerauth.fido2.model.entity.AllowCredentials;
import com.wultra.security.powerauth.fido2.model.request.AssertionChallengeRequest;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test of {@link AssertionChallengeConverter}.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
class AssertionChallengeConverterTest {

    @Test
    void testConvertAssertionRequestToOperationRequest() {
        final AssertionChallengeRequest challengeRequest = new AssertionChallengeRequest();
        challengeRequest.setUserId("user");
        challengeRequest.setApplicationIds(List.of("application"));
        challengeRequest.setTemplateName("payment");
        challengeRequest.setParameters(Map.of("amount", "10"));

        final AuthenticatorDetail authenticatorDetail = new AuthenticatorDetail();
        authenticatorDetail.setCredentialId("credential-1");
        final List<AuthenticatorDetail> authenticatorDetails = List.of(authenticatorDetail);

        final OperationCreateRequest createRequest = AssertionChallengeConverter
                .convertAssertionRequestToOperationRequest(challengeRequest, authenticatorDetails);
        assertEquals("user", createRequest.getUserId());
        assertEquals("application", createRequest.getApplications().get(0));
        assertEquals("payment", createRequest.getTemplateName());
        assertEquals("10", createRequest.getParameters().get("amount"));
        assertEquals(Set.of("credential-1"), createRequest.getAdditionalData().get("allowCredentials"));
    }

    @Test
    void testConvertAssertionRequestToOperationRequest_emptyAuthenticatorDetails() {
        final AssertionChallengeRequest challengeRequest = new AssertionChallengeRequest();
        challengeRequest.setUserId("user");
        challengeRequest.setApplicationIds(List.of("application"));
        challengeRequest.setTemplateName("payment");
        challengeRequest.setParameters(Map.of("amount", "10"));

        final OperationCreateRequest createRequest = AssertionChallengeConverter
                .convertAssertionRequestToOperationRequest(challengeRequest, Collections.emptyList());
        assertEquals("user", createRequest.getUserId());
        assertEquals("application", createRequest.getApplications().get(0));
        assertEquals("payment", createRequest.getTemplateName());
        assertEquals("10", createRequest.getParameters().get("amount"));
        assertNull(createRequest.getAdditionalData());
    }

    @Test
    void testConvertAssertionChallengeFromOperationDetail_emptyAuthenticatorDetails() {
        final OperationDetailResponse operationDetailResponse = new OperationDetailResponse();
        operationDetailResponse.setUserId("user");
        operationDetailResponse.setApplications(List.of("app"));
        operationDetailResponse.setId("operationID");
        operationDetailResponse.setData("A1*A100CZK");
        operationDetailResponse.setFailureCount(0L);
        operationDetailResponse.setMaxFailureCount(5L);

        final AssertionChallenge assertionChallenge = AssertionChallengeConverter
                .convertAssertionChallengeFromOperationDetail(operationDetailResponse, Collections.emptyList());
        assertEquals("user", assertionChallenge.getUserId());
        assertEquals("app", assertionChallenge.getApplicationIds().get(0));
        assertEquals("operationID&A1*A100CZK", assertionChallenge.getChallenge());
        assertEquals(0L, assertionChallenge.getFailedAttempts());
        assertEquals(5L, assertionChallenge.getMaxFailedAttempts());
        assertNull(assertionChallenge.getAllowCredentials());
    }

    @Test
    void testConvertAssertionChallengeFromOperationDetail_nonWultraAuthenticatorDetail() {
        final OperationDetailResponse operationDetailResponse = new OperationDetailResponse();
        operationDetailResponse.setUserId("user");
        operationDetailResponse.setApplications(List.of("app"));
        operationDetailResponse.setId("operationID");
        operationDetailResponse.setData("A1*A100CZK");
        operationDetailResponse.setFailureCount(0L);
        operationDetailResponse.setMaxFailureCount(5L);

        final AuthenticatorDetail authenticatorDetail = new AuthenticatorDetail();
        authenticatorDetail.setCredentialId(Base64.getEncoder().encodeToString("credential-1".getBytes()));
        authenticatorDetail.setExtras(Map.of(
                "transports", List.of("hybrid"),
                "aaguid", "00000000-0000-0000-0000-000000000000"));
        final List<AuthenticatorDetail> authenticatorDetails = List.of(authenticatorDetail);

        final AssertionChallenge assertionChallenge = AssertionChallengeConverter
                .convertAssertionChallengeFromOperationDetail(operationDetailResponse, authenticatorDetails);
        assertEquals("user", assertionChallenge.getUserId());
        assertEquals("app", assertionChallenge.getApplicationIds().get(0));
        assertEquals("operationID&A1*A100CZK", assertionChallenge.getChallenge());
        assertEquals(0L, assertionChallenge.getFailedAttempts());
        assertEquals(5L, assertionChallenge.getMaxFailedAttempts());

        assertNotNull(assertionChallenge.getAllowCredentials());
        final AllowCredentials allowCredential = assertionChallenge.getAllowCredentials().get(0);
        assertArrayEquals("credential-1".getBytes(), allowCredential.getCredentialId());
        assertEquals("hybrid", allowCredential.getTransports().get(0));
        assertEquals("public-key", allowCredential.getType());
    }

    @Test
    void testConvertAssertionChallengeFromOperationDetail_withWultraAuthenticatorDetail() {
        final OperationDetailResponse operationDetailResponse = new OperationDetailResponse();
        operationDetailResponse.setUserId("user");
        operationDetailResponse.setApplications(List.of("app"));
        operationDetailResponse.setId("operationID");
        operationDetailResponse.setData("A1*A100CZK");
        operationDetailResponse.setFailureCount(0L);
        operationDetailResponse.setMaxFailureCount(5L);

        final AuthenticatorDetail authenticatorDetail = new AuthenticatorDetail();
        authenticatorDetail.setCredentialId(Base64.getEncoder().encodeToString("credential-1".getBytes()));
        authenticatorDetail.setExtras(Map.of(
                "transports", List.of("usb"),
                "aaguid", "dca09ba7-4992-4be8-9283-ee98cd6fb529"));
        final List<AuthenticatorDetail> authenticatorDetails = List.of(authenticatorDetail);

        final AssertionChallenge assertionChallenge = AssertionChallengeConverter
                .convertAssertionChallengeFromOperationDetail(operationDetailResponse, authenticatorDetails);
        assertEquals("user", assertionChallenge.getUserId());
        assertEquals("app", assertionChallenge.getApplicationIds().get(0));
        assertEquals("operationID&A1*A100CZK", assertionChallenge.getChallenge());
        assertEquals(0L, assertionChallenge.getFailedAttempts());
        assertEquals(5L, assertionChallenge.getMaxFailedAttempts());

        assertNotNull(assertionChallenge.getAllowCredentials());
        assertEquals(2, assertionChallenge.getAllowCredentials().size());
        final AllowCredentials allowCredential = assertionChallenge.getAllowCredentials().get(0);
        assertArrayEquals("credential-1".getBytes(), allowCredential.getCredentialId());
        assertEquals("usb", allowCredential.getTransports().get(0));
        assertEquals("public-key", allowCredential.getType());

        final AllowCredentials operationDataCredential = assertionChallenge.getAllowCredentials().get(1);
        assertArrayEquals("A1*A100CZK".getBytes(), operationDataCredential.getCredentialId());
        assertTrue(operationDataCredential.getTransports().isEmpty());
        assertEquals("public-key", operationDataCredential.getType());
    }

    @Test
    void testConvertAssertionChallengeFromOperationDetail_multipleWultraAuthenticatorDetails() {
        final OperationDetailResponse operationDetailResponse = new OperationDetailResponse();
        operationDetailResponse.setUserId("user");
        operationDetailResponse.setApplications(List.of("app"));
        operationDetailResponse.setId("operationID");
        operationDetailResponse.setData("A1*A100CZK");
        operationDetailResponse.setFailureCount(0L);
        operationDetailResponse.setMaxFailureCount(5L);

        final AuthenticatorDetail authenticatorDetail1 = new AuthenticatorDetail();
        authenticatorDetail1.setCredentialId(Base64.getEncoder().encodeToString("credential-1".getBytes()));
        authenticatorDetail1.setExtras(Map.of(
                "transports", List.of("usb"),
                "aaguid", "dca09ba7-4992-4be8-9283-ee98cd6fb529"));

        final AuthenticatorDetail authenticatorDetail2 = new AuthenticatorDetail();
        authenticatorDetail2.setCredentialId(Base64.getEncoder().encodeToString("credential-2".getBytes()));
        authenticatorDetail2.setExtras(Map.of(
                "transports", List.of("usb"),
                "aaguid", "dca09ba7-4992-4be8-9283-ee98cd6fb529"));

        final List<AuthenticatorDetail> authenticatorDetails = List.of(authenticatorDetail1, authenticatorDetail2);

        final AssertionChallenge assertionChallenge = AssertionChallengeConverter
                .convertAssertionChallengeFromOperationDetail(operationDetailResponse, authenticatorDetails);
        assertEquals("user", assertionChallenge.getUserId());
        assertEquals("app", assertionChallenge.getApplicationIds().get(0));
        assertEquals("operationID&A1*A100CZK", assertionChallenge.getChallenge());
        assertEquals(0L, assertionChallenge.getFailedAttempts());
        assertEquals(5L, assertionChallenge.getMaxFailedAttempts());

        assertNotNull(assertionChallenge.getAllowCredentials());
        assertEquals(3, assertionChallenge.getAllowCredentials().size());
        final AllowCredentials allowCredential1 = assertionChallenge.getAllowCredentials().get(0);
        assertArrayEquals("credential-1".getBytes(), allowCredential1.getCredentialId());
        assertEquals("usb", allowCredential1.getTransports().get(0));
        assertEquals("public-key", allowCredential1.getType());

        final AllowCredentials allowCredential2 = assertionChallenge.getAllowCredentials().get(1);
        assertArrayEquals("credential-2".getBytes(), allowCredential2.getCredentialId());
        assertEquals("usb", allowCredential2.getTransports().get(0));
        assertEquals("public-key", allowCredential2.getType());

        final AllowCredentials operationDataCredential = assertionChallenge.getAllowCredentials().get(2);
        assertArrayEquals("A1*A100CZK".getBytes(), operationDataCredential.getCredentialId());
        assertTrue(operationDataCredential.getTransports().isEmpty());
        assertEquals("public-key", operationDataCredential.getType());
    }

}
