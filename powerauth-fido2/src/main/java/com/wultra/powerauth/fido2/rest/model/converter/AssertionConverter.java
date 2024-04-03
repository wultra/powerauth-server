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

import com.wultra.powerauth.fido2.rest.model.response.AssertionVerificationResponse;
import com.wultra.security.powerauth.fido2.model.entity.AuthenticatorDetail;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Converter between assertion verification result to signature verification.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Component
@Slf4j
public class AssertionConverter {

    /**
     * Convert authenticator detail to assertion verification response.
     * @param source Authenticator detail.
     * @param assertionValid Whether assertion is valid.
     * @return Converted assertion verification response.
     */
    public AssertionVerificationResponse fromAuthenticatorDetail(AuthenticatorDetail source, boolean assertionValid) {
        if (source == null) {
            return null;
        }

        if (!assertionValid) { // return empty object for invalid assertions
            final AssertionVerificationResponse destination = new AssertionVerificationResponse();
            destination.setAssertionValid(false);
            return destination;
        } else {
            final AssertionVerificationResponse destination = new AssertionVerificationResponse();
            destination.setAssertionValid(assertionValid);
            destination.setUserId(source.getUserId());
            destination.setActivationId(source.getActivationId());
            destination.setApplicationId(source.getApplicationId());
            destination.setActivationStatus(source.getActivationStatus());
            destination.setBlockedReason(source.getBlockedReason());
            destination.setRemainingAttempts(source.getMaxFailedAttempts() - source.getFailedAttempts());
            destination.setApplicationRoles(source.getApplicationRoles());
            destination.setActivationFlags(source.getActivationFlags());
            return destination;
        }
    }

}
