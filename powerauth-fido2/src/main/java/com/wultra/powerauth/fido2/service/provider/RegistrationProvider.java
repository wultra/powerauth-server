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

import com.wultra.security.powerauth.fido2.model.entity.RegistrationChallenge;

/**
 * Interface for registration use-cases.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public interface RegistrationProvider {

    /**
     * Obtain a new challenge for registration.
     *
     * @param userId User ID.
     * @param applicationId Application ID.
     * @return Registration challenge.
     * @throws Exception In case any issue occur during processing.
     */
    RegistrationChallenge provideChallengeForRegistration(String userId, String applicationId) throws Exception;

    /**
     * Obtain an existing challenge information based on challenge value for registration.
     *
     * @param applicationId Application key.
     * @param challenge Challenge value.
     * @return Challenge Information.
     * @throws Exception In case any issue occur during processing.
     */
    RegistrationChallenge findRegistrationChallengeByValue(String applicationId, String challenge) throws Exception;

    /**
     * Revoke existing challenge based on the challenge value.
     *
     * @param applicationId Application ID.
     * @param challengeValue Challenge value.
     * @throws Exception In case any issue occur during processing.
     */
    void revokeRegistrationByChallengeValue(String applicationId, String challengeValue) throws Exception;

    /**
     * Verify registration parameters and determine whether registration is allowed.
     * @param applicationId Application ID.
     * @param credentialId Credential ID.
     * @param attestationFormat FIDO2 registration attestation format.
     * @param aaguid FIDO2 registration AAGUID value.
     * @return Whether registration is allowed.
     * @throws Exception In case any issue occur during processing.
     */
    boolean registrationAllowed(String applicationId, String credentialId, String attestationFormat, byte[] aaguid) throws Exception;

}
