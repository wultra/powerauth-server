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

package com.wultra.powerauth.fido2.database.entity;

import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;

/**
 * Entity representing a FIDO2 Authenticator details.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@Entity
@Table(name = "pa_fido2_authenticator")
@Getter @Setter @ToString
public class Fido2AuthenticatorEntity implements Serializable {

    @Serial
    private static final long serialVersionUID = -8651010447132056907L;

    @Id
    @Column(name = "aaguid")
    private String aaguid;

    @Column(name = "description", nullable = false)
    private String description;

    @Enumerated(EnumType.STRING)
    @Column(name = "signature_type", nullable = false)
    private SignatureType signatureType;

    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        final Fido2AuthenticatorEntity entity = (Fido2AuthenticatorEntity) o;
        return Objects.equals(aaguid, entity.aaguid);
    }

    @Override
    public int hashCode() {
        return Objects.hash(aaguid);
    }

}
