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

package com.wultra.powerauth.fido2.service.model;

import com.wultra.security.powerauth.client.model.enumeration.SignatureType;

import java.util.Objects;
import java.util.UUID;

/**
 * FIDO2 Authenticator details model. It associates the AAGUID value to a descriptive name
 * and expected authentication factors available with a given authenticator.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
public record Fido2Authenticator(
        UUID aaguid,
        String description,
        SignatureType signatureType
) {

    public static Fido2Authenticator create(String aaguid, String description) {
        return new Fido2Authenticator(UUID.fromString(aaguid), description, SignatureType.POSSESSION);
    }

    public static Fido2Authenticator create(String aaguid, String description, SignatureType signatureType) {
        return new Fido2Authenticator(UUID.fromString(aaguid), description, signatureType);
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        final Fido2Authenticator that = (Fido2Authenticator) o;
        return Objects.equals(aaguid, that.aaguid);
    }

    @Override
    public int hashCode() {
        return Objects.hash(aaguid);
    }

}
