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

package com.wultra.powerauth.fido2.service;

import com.wultra.powerauth.fido2.errorhandling.Fido2AuthenticationFailedException;
import com.wultra.powerauth.fido2.rest.model.entity.AssertionChallenge;
import com.wultra.powerauth.fido2.rest.model.entity.RegistrationChallenge;

import java.util.List;
import java.util.Map;

/**
 * Interface for challenge providers.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public interface ChallengeProvider {

    /**
     * Obtain challenge information based on challenge value for registration.
     *
     * @param applicationId Application key.
     * @param challenge Challenge value.
     * @return Challenge Information.
     * @throws Exception In case any issue occur during processing.
     */
    RegistrationChallenge provideChallengeForRegistrationChallengeValue(String applicationId, String challenge) throws Exception;

    /**
     * Obtain challenge for registration.
     *
     * @param userId User ID.
     * @param applicationId Application ID.
     * @return Registration challenge.
     * @throws Exception In case any issue occur during processing.
     */
    RegistrationChallenge provideChallengeForRegistration(String userId, String applicationId) throws Exception;

    /**
     * Obtain challenge for authentication.
     *
     * @param userId User ID.
     * @param applicationIds List of application ID.
     * @param operationType Type of the operation this challenge is for.
     * @param parameters Operation parameters.
     * @return Assertion challenge.
     * @throws Exception In case any issue occur during processing.
     */
    default AssertionChallenge provideChallengeForAuthentication(String userId, List<String> applicationIds, String operationType, Map<String, String> parameters) throws Exception {
        return provideChallengeForAuthentication(userId, applicationIds, operationType, parameters, null);
    };

    /**
     * Obtain challenge for authentication.
     *
     * @param userId User ID.
     * @param applicationIds List of application ID.
     * @param operationType Type of the operation this challenge is for.
     * @param parameters Operation parameters.
     * @param externalAuthenticationId External ID of operation, i.e., transaction in transaction system.
     * @return Assertion challenge.
     * @throws Exception In case any issue occur during processing.
     */
    AssertionChallenge provideChallengeForAuthentication(String userId, List<String> applicationIds, String operationType, Map<String, String> parameters, String externalAuthenticationId) throws Exception;

    /**
     * Revoke challenge based on the challenge value.
     *
     * @param applicationId Application ID.
     * @param challengeValue Challenge value.
     * @throws Exception In case any issue occur during processing.
     */
    void revokeChallengeForRegistrationChallengeValue(String applicationId, String challengeValue) throws Exception;
}
