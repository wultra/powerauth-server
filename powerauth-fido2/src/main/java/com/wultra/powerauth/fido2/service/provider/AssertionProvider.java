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

package com.wultra.powerauth.fido2.service.provider;

import com.wultra.powerauth.fido2.errorhandling.Fido2AuthenticationFailedException;
import com.wultra.powerauth.fido2.rest.model.entity.AssertionChallenge;
import com.wultra.powerauth.fido2.rest.model.entity.AuthenticatorData;
import com.wultra.powerauth.fido2.rest.model.entity.AuthenticatorDetail;
import com.wultra.powerauth.fido2.rest.model.entity.CollectedClientData;

import java.util.List;
import java.util.Map;

/**
 * Interface with methods responsible for assertion verification.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public interface AssertionProvider {

    /**
     * Obtain challenge for authentication.
     *
     * @param applicationIds List of application ID.
     * @param operationType Type of the operation this challenge is for.
     * @param parameters Operation parameters.
     * @param externalAuthenticationId External ID of operation, i.e., transaction in transaction system.
     * @return Assertion challenge.
     * @throws Exception In case any issue occur during processing.
     */
    AssertionChallenge provideChallengeForAssertion(List<String> applicationIds, String operationType, Map<String, String> parameters, String externalAuthenticationId) throws Exception;

    /**
     * Approve assertion.
     *
     * @param challengeValue      Challenge value.
     * @param authenticatorDetail Authenticator information.
     * @param authenticatorData   Authenticator data.
     * @param clientDataJSON      Client data.
     * @return Assertion challenge.
     * @throws Fido2AuthenticationFailedException In case assertion approval fails.
     */
    AssertionChallenge approveAssertion(String challengeValue, AuthenticatorDetail authenticatorDetail, AuthenticatorData authenticatorData, CollectedClientData clientDataJSON) throws Fido2AuthenticationFailedException;

    /**
     * Fail assertion approval.
     *
     * @param challenge           Challenge for assertion.
     * @param authenticatorDetail Authenticator detail.
     * @param authenticatorData   Authenticator data.
     * @param clientDataJSON      Client data.
     * @return Info about the assertion.
     * @throws Fido2AuthenticationFailedException In case assertion approval fails.
     */
    AssertionChallenge failAssertion(String challenge, AuthenticatorDetail authenticatorDetail, AuthenticatorData authenticatorData, CollectedClientData clientDataJSON) throws Fido2AuthenticationFailedException;

}
