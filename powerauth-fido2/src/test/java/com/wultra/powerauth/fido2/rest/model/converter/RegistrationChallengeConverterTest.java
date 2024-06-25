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

import com.wultra.powerauth.fido2.service.Fido2AuthenticatorService;
import com.wultra.powerauth.fido2.service.model.Fido2Authenticator;
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import com.wultra.security.powerauth.fido2.model.entity.AuthenticatorDetail;
import com.wultra.security.powerauth.fido2.model.entity.Credential;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.*;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

/**
 * Test of {@link RegistrationChallengeConverter}.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@ExtendWith(MockitoExtension.class)
class RegistrationChallengeConverterTest {

    @Mock
    private Fido2AuthenticatorService fido2AuthenticatorService;

    @InjectMocks
    private RegistrationChallengeConverter tested;

    @Test
    void testToCredentialDescriptor() {
        final AuthenticatorDetail authenticatorDetail = new AuthenticatorDetail();
        authenticatorDetail.setCredentialId(Base64.getEncoder().encodeToString("credential-1".getBytes()));
        authenticatorDetail.setExtras(Map.of(
                "transports", List.of("hybrid"),
                "aaguid", "10000000-0000-0000-0000-000000000000"));

        final Credential excludeCredential = tested.toCredentialDescriptor(authenticatorDetail);
        assertArrayEquals("credential-1".getBytes(), excludeCredential.getCredentialId());
        assertEquals(1, excludeCredential.getTransports().size());
        assertEquals("hybrid", excludeCredential.getTransports().get(0));
        assertEquals("public-key", excludeCredential.getType());
    }

    @Test
    void testToCredentialDescriptor_emptyTransports() {
        final AuthenticatorDetail authenticatorDetail = new AuthenticatorDetail();
        authenticatorDetail.setCredentialId(Base64.getEncoder().encodeToString("credential-1".getBytes()));
        authenticatorDetail.setExtras(Map.of(
                "transports", Collections.emptyList(),
                "aaguid", "10000000-0000-0000-0000-000000000000"));

        when(fido2AuthenticatorService.findByAaguid(UUID.fromString("10000000-0000-0000-0000-000000000000")))
                .thenReturn(Fido2Authenticator.create("10000000-0000-0000-0000-000000000000", "Any", SignatureType.POSSESSION, List.of("usb")));

        final Credential excludeCredential = tested.toCredentialDescriptor(authenticatorDetail);
        assertArrayEquals("credential-1".getBytes(), excludeCredential.getCredentialId());
        assertEquals(1, excludeCredential.getTransports().size());
        assertEquals("usb", excludeCredential.getTransports().get(0));
        assertEquals("public-key", excludeCredential.getType());
    }

    @Test
    void testToCredentialDescriptor_nullTransports() {
        final AuthenticatorDetail authenticatorDetail = new AuthenticatorDetail();
        authenticatorDetail.setCredentialId(Base64.getEncoder().encodeToString("credential-1".getBytes()));
        authenticatorDetail.setExtras(Map.of(
                "aaguid", "10000000-0000-0000-0000-000000000000"));

        when(fido2AuthenticatorService.findByAaguid(UUID.fromString("10000000-0000-0000-0000-000000000000")))
                .thenReturn(Fido2Authenticator.create("10000000-0000-0000-0000-000000000000", "Any", SignatureType.POSSESSION, List.of("usb")));

        final Credential excludeCredential = tested.toCredentialDescriptor(authenticatorDetail);
        assertArrayEquals("credential-1".getBytes(), excludeCredential.getCredentialId());
        assertEquals(1, excludeCredential.getTransports().size());
        assertEquals("usb", excludeCredential.getTransports().get(0));
        assertEquals("public-key", excludeCredential.getType());
    }

    @Test
    void testToCredentialDescriptor_bothTransportsEmpty() {
        final AuthenticatorDetail authenticatorDetail = new AuthenticatorDetail();
        authenticatorDetail.setCredentialId(Base64.getEncoder().encodeToString("credential-1".getBytes()));
        authenticatorDetail.setExtras(Map.of(
                "aaguid", "10000000-0000-0000-0000-000000000000"));

        when(fido2AuthenticatorService.findByAaguid(UUID.fromString("10000000-0000-0000-0000-000000000000")))
                .thenReturn(Fido2Authenticator.create("10000000-0000-0000-0000-000000000000", "Any", SignatureType.POSSESSION, null));

        final Credential excludeCredential = tested.toCredentialDescriptor(authenticatorDetail);
        assertArrayEquals("credential-1".getBytes(), excludeCredential.getCredentialId());
        assertEquals(0, excludeCredential.getTransports().size());
    }

}
