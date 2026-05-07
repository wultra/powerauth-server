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

package com.wultra.security.powerauth.app.server.database.model.entity;

import com.wultra.security.powerauth.app.server.database.model.enumeration.EncryptionAlgorithm;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.util.ProxyUtils;

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
    private EncryptionAlgorithm privateKeyEncryption;

    /**
     * Temporary private key.
     */
    @Column(name = "private_key_base64")
    private String privateKeyBase64;

    /**
     * Temporary public key.
     */
    @Column(name = "public_key_base64")
    private String publicKeyBase64;

    /**
     * Secret key stored in Base-64 encoding.
     */
    @Column(name = "secret_key_base64")
    private String secretKeyBase64;

    /**
     * Mode of secret key encryption {@code (0 = NO_ENCRYPTION, 1 = AES_HMAC)}.
     */
    @Column(name = "secret_key_encryption", nullable = false)
    @Enumerated
    private EncryptionAlgorithm secretKeyEncryption;

    /**
     * Timestamp when operation expired.
     */
    @Column(name = "timestamp_expires", nullable = false)
    private Date timestampExpires;

    @Override
    public boolean equals(Object o) {
        if (null == o) {
            return false;
        } else if (this == o) {
            return true;
        } else if (!this.getClass().equals(ProxyUtils.getUserClass(o))) {
            return false;
        } else {
            final TemporaryKeyEntity other = (TemporaryKeyEntity) o;
            return Objects.equals(id, other.id)
                    && Objects.equals(appKey, other.appKey)
                    && Objects.equals(activationId, other.activationId)
                    && Objects.equals(publicKeyBase64, other.publicKeyBase64);
        }
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, appKey, activationId, publicKeyBase64);
    }
}
