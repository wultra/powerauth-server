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

package com.wultra.powerauth.fido2.rest.model.converter;

import com.wultra.powerauth.fido2.rest.model.entity.AllowCredentials;
import com.wultra.powerauth.fido2.rest.model.entity.AssertionChallenge;
import com.wultra.powerauth.fido2.rest.model.entity.AuthenticatorDetail;
import com.wultra.powerauth.fido2.rest.model.entity.Fido2DefaultAuthenticators;
import com.wultra.powerauth.fido2.rest.model.request.AssertionChallengeRequest;
import com.wultra.powerauth.fido2.rest.model.response.AssertionChallengeResponse;
import com.wultra.security.powerauth.client.model.request.OperationCreateRequest;
import com.wultra.security.powerauth.client.model.response.OperationDetailResponse;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Converter for assertion challenge values.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Slf4j
public class AssertionChallengeConverter {

    private static final String ATTR_ALLOW_CREDENTIALS = "allowCredentials";

    private AssertionChallengeConverter() {
        throw new IllegalStateException("Should not be instantiated");
    }

    /**
     * Convert a new assertion challenge response from a provided challenge.
     *
     * @param source Challenge.
     * @return Assertion challenge response.
     */
    public static AssertionChallengeResponse fromChallenge(AssertionChallenge source) {
        if (source == null) {
            return null;
        }
        final AssertionChallengeResponse destination = new AssertionChallengeResponse();
        destination.setUserId(source.getUserId());
        destination.setApplicationIds(source.getApplicationIds());
        destination.setChallenge(source.getChallenge());
        destination.setFailedAttempts(source.getFailedAttempts());
        destination.setMaxFailedAttempts(source.getMaxFailedAttempts());
        destination.setAllowCredentials(source.getAllowCredentials());
        return destination;
    }

    /**
     * Convert the assertion challenge request to a new operation create request. Optionally, store allowed
     * authenticators with the operation.
     *
     * @param source Assertion challenge.
     * @param authenticatorDetails Allowed authenticators. If null or empty, all are allowed.
     * @return Request for creating a new operation.
     */
    public static OperationCreateRequest convertAssertionRequestToOperationRequest(AssertionChallengeRequest source, List<AuthenticatorDetail> authenticatorDetails) {
        final OperationCreateRequest destination = new OperationCreateRequest();
        destination.setUserId(source.getUserId());
        destination.setApplications(source.getApplicationIds());
        destination.setTemplateName(source.getTemplateName());
        destination.getParameters().putAll(source.getParameters());

        //TODO: Use relation to activation ID instead of additional data
        if (authenticatorDetails != null && !authenticatorDetails.isEmpty()) {
            final Set<String> allowCredentials = new LinkedHashSet<>();
            for (AuthenticatorDetail ad : authenticatorDetails) {
                allowCredentials.add(ad.getCredentialId());
            }
            destination.setAdditionalData(Map.of(ATTR_ALLOW_CREDENTIALS, allowCredentials));
        }
        return destination;
    }

    /**
     * Convert assertion challenge request from operation detail response.
     *
     * @param source Operation detail.
     * @param authenticatorDetails Add authenticator details to be assigned with the challenge. If null or empty, all are allowed.
     * @return Assertion challenge
     */
    public static AssertionChallenge convertAssertionChallengeFromOperationDetail(OperationDetailResponse source, List<AuthenticatorDetail> authenticatorDetails) {
        final AssertionChallenge destination = new AssertionChallenge();
        destination.setUserId(source.getUserId());
        destination.setApplicationIds(source.getApplications());
        destination.setChallenge(source.getId() + "&" + source.getData());
        destination.setFailedAttempts(source.getFailureCount());
        destination.setMaxFailedAttempts(source.getMaxFailureCount());

        if (authenticatorDetails != null && !authenticatorDetails.isEmpty()) {
            final List<AllowCredentials> allowCredentials = new ArrayList<>();
            boolean hasWultraModel = false;
            for (AuthenticatorDetail ad: authenticatorDetails) {

                @SuppressWarnings("unchecked")
                final List<String> transports = (List<String>) ad.getExtras().get("transports");
                final String aaguid = (String) ad.getExtras().get("aaguid");

                byte[] credentialId = Base64.getDecoder().decode(ad.getCredentialId());
                if (aaguid != null && Fido2DefaultAuthenticators.isWultraModel(aaguid)) {
                    hasWultraModel = true;
                }

                final AllowCredentials ac = AllowCredentials.builder()
                        .credentialId(credentialId)
                        .transports(transports)
                        .build();
                allowCredentials.add(ac);
            }
            if (hasWultraModel) {
                final byte[] credentialId = source.getData().getBytes(StandardCharsets.UTF_8);
                final AllowCredentials ac = AllowCredentials.builder()
                        .credentialId(credentialId)
                        .build();
                allowCredentials.add(ac);
            }
            destination.setAllowCredentials(allowCredentials);
        }
        return destination;
    }

}
