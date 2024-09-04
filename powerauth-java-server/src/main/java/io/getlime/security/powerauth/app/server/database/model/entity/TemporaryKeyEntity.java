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

package io.getlime.security.powerauth.app.server.database.model.entity;

import io.getlime.security.powerauth.app.server.database.model.enumeration.EncryptionMode;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.io.Serial;
import java.io.Serializable;
import java.util.Date;
import java.util.Objects;

/**
 * Entity representing a temporary key pair.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Entity
@Table(name = "pa_temporary_key")
@Getter
@Setter
public class TemporaryKeyEntity implements Serializable {

    @Serial
    private static final long serialVersionUID = 1295434927785255417L;

    /**
     * Key identifier.
     */
    @Id
    @Column(name = "id", nullable = false, updatable = false, length = 37)
    private String id;

    /**
     * App key identifier.
     */
    @Column(name = "application_key", nullable = false, updatable = false)
    private String appKey;

    /**
     * Activation identifier.
     */
    @Column(name = "activation_id", updatable = false)
    private String activationId;

    /**
     * Key encryption.
     */
    @Column(name = "private_key_encryption", nullable = false)
    @Enumerated
    private EncryptionMode privateKeyEncryption;

    /**
     * Temporary private key.
     */
    @Column(name = "private_key_base64", nullable = false)
    private String privateKeyBase64;

    /**
     * Temporary public key.
     */
    @Column(name = "public_key_base64", nullable = false)
    private String publicKeyBase64;

    /**
     * Timestamp when operation expired.
     */
    @Column(name = "timestamp_expires", nullable = false)
    private Date timestampExpires;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TemporaryKeyEntity that = (TemporaryKeyEntity) o;
        return Objects.equals(id, that.id)
                && Objects.equals(appKey, that.appKey)
                && Objects.equals(activationId, that.activationId)
                && Objects.equals(publicKeyBase64, that.publicKeyBase64);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, appKey, activationId, publicKeyBase64);
    }
}
