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
import com.wultra.powerauth.fido2.rest.model.entity.PublicKeyObject;
import com.wultra.powerauth.fido2.rest.model.enumeration.CurveType;
import com.wultra.powerauth.fido2.rest.model.enumeration.ECKeyType;
import com.wultra.powerauth.fido2.rest.model.enumeration.SignatureAlgorithm;
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

    @Test
    void testDeserialize_credentials() throws Exception{
        final AuthenticatorData result = AuthenticatorDataDeserializer.deserialize("SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NdAAAAALraVWanqkAfvZZFYZpVEg0AENntBM0k3kUGHZJgXctZB2mlAQIDJiABIVggUnRRgaXiOSdKFnu6u04mUQNMDyuHWDODUdIcrt4Ca9wiWCBEq2quWbx976dPV7Ajt8yR5+4h1tnfT8X5ey7PT0utKA==");

        assertTrue(result.getFlags().isUserPresent());
        assertFalse(result.getFlags().isReservedBit2());
        assertTrue(result.getFlags().isUserVerified());
        assertTrue(result.getFlags().isBackupEligible());
        assertTrue(result.getFlags().isBackupState());
        assertFalse(result.getFlags().isReservedBit6());
        assertTrue(result.getFlags().isAttestedCredentialsIncluded());
        assertFalse(result.getFlags().isExtensionDataIncluded());
        assertEquals(0, result.getSignCount());

        final AttestedCredentialData attestedCredentialData = result.getAttestedCredentialData();
        assertNotNull(attestedCredentialData.getCredentialId());
        assertNotNull(attestedCredentialData.getAaguid());

        final PublicKeyObject publicKeyObject = attestedCredentialData.getPublicKeyObject();
        assertNotNull(publicKeyObject);
        assertEquals(SignatureAlgorithm.ES256, publicKeyObject.getAlgorithm());
        assertEquals(CurveType.P256, publicKeyObject.getCurveType());
        assertEquals(ECKeyType.UNCOMPRESSED, publicKeyObject.getKeyType());
        assertNotNull(publicKeyObject.getPoint().getX());
        assertNotNull(publicKeyObject.getPoint().getY());
    }

}
