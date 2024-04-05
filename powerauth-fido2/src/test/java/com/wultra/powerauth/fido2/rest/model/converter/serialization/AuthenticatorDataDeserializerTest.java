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
package com.wultra.powerauth.fido2.rest.model.converter.serialization;

import com.wultra.powerauth.fido2.rest.model.entity.AttestedCredentialData;
import com.wultra.powerauth.fido2.rest.model.entity.AuthenticatorData;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link AuthenticatorDataDeserializer}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
class AuthenticatorDataDeserializerTest {

    @Test
    void testDeserialize() throws Exception{
        final AuthenticatorData result = AuthenticatorDataDeserializer.deserialize("ANexYfkh9tDjBkTaAF/dyyouYB0YesVvYolcxTs9fxAFAAAAAg==");

        assertTrue(result.getFlags().isUserPresent());
        assertFalse(result.getFlags().isReservedBit2());
        assertTrue(result.getFlags().isUserVerified());
        assertFalse(result.getFlags().isBackupEligible());
        assertFalse(result.getFlags().isBackupState());
        assertFalse(result.getFlags().isReservedBit6());
        assertFalse(result.getFlags().isAttestedCredentialsIncluded());
        assertFalse(result.getFlags().isExtensionDataIncluded());
        assertEquals(2, result.getSignCount());

        final AttestedCredentialData attestedCredentialData = result.getAttestedCredentialData();
        assertNull(attestedCredentialData.getCredentialId());
        assertNull(attestedCredentialData.getAaguid());
        assertNull(attestedCredentialData.getPublicKeyObject());
    }

}
