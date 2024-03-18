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
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import java.nio.ByteBuffer;
import java.util.UUID;

/**
 * Service related to manage FIDO2 Authenticator details.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@Service
@AllArgsConstructor
@Slf4j
public class Fido2AuthenticatorService {

    private static final String UNKNOWN_AUTHENTICATOR_DESCRIPTION = "Unknown FIDO2 Authenticator";
    private static final SignatureType UNKNOWN_AUTHENTICATOR_SIGNATURE_TYPE = SignatureType.POSSESSION;

    private final Fido2AuthenticatorRepository fido2AuthenticatorRepository;

    /**
     * Retrieve FIDO2 Authenticator details from database by its aaguid.
     * If it does not exist, return unknown Fido2Authenticator.
     * @param aaguid Authenticator identifier.
     * @return Fido2Authenticator with registered details.
     */
    @Cacheable("fido2-authenticators-cache")
    public Fido2Authenticator findByAaguid(final byte[] aaguid) {
        final UUID uuid = uuidFromBytes(aaguid);
        if (uuid == null) {
            return unknownAuthenticator();
        }
        return fido2AuthenticatorRepository.findById(uuid.toString())
                .map(Fido2AuthenticatorService::convert)
                .orElseGet(() -> unknownAuthenticator(uuid));
    }

    private static Fido2Authenticator convert(final Fido2AuthenticatorEntity entity) {
        return new Fido2Authenticator(UUID.fromString(entity.getAaguid()), entity.getDescription(), entity.getSignatureType());
    }

    private static Fido2Authenticator unknownAuthenticator() {
        return new Fido2Authenticator(null, UNKNOWN_AUTHENTICATOR_DESCRIPTION, UNKNOWN_AUTHENTICATOR_SIGNATURE_TYPE);
    }

    private static Fido2Authenticator unknownAuthenticator(final UUID aaguid) {
        return new Fido2Authenticator(aaguid, UNKNOWN_AUTHENTICATOR_DESCRIPTION, UNKNOWN_AUTHENTICATOR_SIGNATURE_TYPE);
    }

    private static UUID uuidFromBytes(final byte[] bytes) {
        if (bytes == null || bytes.length != 16) { // strange byte array length, UUID requires 16 bytes
            logger.debug("Invalid byte length provided for UUID: {}", bytes);
            return null;
        }
        final ByteBuffer bb = ByteBuffer.wrap(bytes);
        return new UUID(bb.getLong(), bb.getLong());
    }

}
