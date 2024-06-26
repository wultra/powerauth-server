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

package com.wultra.powerauth.fido2.service;

import com.wultra.powerauth.fido2.database.entity.Fido2AuthenticatorEntity;
import com.wultra.powerauth.fido2.database.repository.Fido2AuthenticatorRepository;
import com.wultra.powerauth.fido2.service.model.Fido2Authenticator;
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.when;

/**
 * Test of {@link Fido2AuthenticatorService}
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@ExtendWith(MockitoExtension.class)
class Fido2AuthenticatorServiceTest {

    private final static String WA1_AAGUID = "dca09ba7-4992-4be8-9283-ee98cd6fb529";

    @Mock
    private Fido2AuthenticatorRepository fido2AuthenticatorRepository;

    @InjectMocks
    private Fido2AuthenticatorService tested;

    @Test
    void testFindByAaguid_fromDatabase() {
        final UUID aaguid = UUID.fromString("00000000-0000-0000-0000-000000000000");
        final Fido2AuthenticatorEntity entity = new Fido2AuthenticatorEntity();
        entity.setAaguid(aaguid.toString());
        entity.setDescription("My FIDO2 Authenticator");
        entity.setSignatureType(SignatureType.POSSESSION);

        when(fido2AuthenticatorRepository.findById(aaguid.toString()))
                .thenReturn(Optional.of(entity));

        final Fido2Authenticator authenticator = tested.findByAaguid(aaguid);
        assertEquals(aaguid, authenticator.aaguid());
        assertEquals("My FIDO2 Authenticator", authenticator.description());
        assertEquals(SignatureType.POSSESSION, authenticator.signatureType());
    }

    @Test
    void testFindByAaguid_fromDefaultSet() {
        final UUID aaguid = UUID.fromString(WA1_AAGUID);
        when(fido2AuthenticatorRepository.findById(aaguid.toString()))
                .thenReturn(Optional.empty());

        final Fido2Authenticator authenticator = tested.findByAaguid(aaguid);
        assertEquals(aaguid, authenticator.aaguid());
        assertEquals("Wultra Authenticator 1", authenticator.description());
        assertEquals(SignatureType.POSSESSION_KNOWLEDGE, authenticator.signatureType());
        assertEquals(List.of("usb"), authenticator.transports());
    }

    @Test
    void testFindByAaguid_unknown() {
        final UUID aaguid = UUID.fromString("00000000-0000-0000-0000-000000000000");
        when(fido2AuthenticatorRepository.findById(aaguid.toString()))
                .thenReturn(Optional.empty());

        final Fido2Authenticator authenticator = tested.findByAaguid(aaguid);
        assertEquals(aaguid, authenticator.aaguid());
        assertEquals("Unknown FIDO2 Authenticator", authenticator.description());
        assertEquals(SignatureType.POSSESSION, authenticator.signatureType());
        assertEquals(Collections.emptyList(), authenticator.transports());
    }

    @Test
    void testFindByAaguid_missingAaguid() {
        final Fido2Authenticator authenticator = tested.findByAaguid(null);
        assertNull(authenticator.aaguid());
        assertEquals("Unknown FIDO2 Authenticator", authenticator.description());
        assertEquals(SignatureType.POSSESSION, authenticator.signatureType());
        assertEquals(Collections.emptyList(), authenticator.transports());
    }

}
