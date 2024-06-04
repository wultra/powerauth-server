/*
 * PowerAuth Server and related software components
 * Copyright (C) 2018 Wultra s.r.o.
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

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.io.Serial;
import java.io.Serializable;
import java.util.Date;
import java.util.Objects;

/**
 * Database entity for the tokens used during token-based authentication.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Entity
@Table(name = "pa_token")
@Getter @Setter
public class TokenEntity implements Serializable {

    @Serial
    private static final long serialVersionUID = 4283363212931780053L;

    /**
     * Token ID.
     */
    @Id
    @Column(name = "token_id", length = 37)
    private String tokenId;

    /**
     * Token secret.
     */
    @Column(name = "token_secret", nullable = false, updatable = false)
    private String tokenSecret;

    /**
     * Associated activation entity.
     */
    @ManyToOne
    @JoinColumn(name = "activation_id", referencedColumnName = "activation_id", updatable = false)
    private ActivationRecordEntity activation;

    /**
     * The information about the type of the signature that was used to issue this token.
     */
    @Column(name = "signature_type", nullable = false, updatable = false)
    private String signatureTypeCreated;

    /**
     * The timestamp when the token was issued.
     */
    @Column(name = "timestamp_created", nullable = false, updatable = false)
    private Date timestampCreated;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TokenEntity that = (TokenEntity) o;
        return Objects.equals(tokenId, that.tokenId) &&
                tokenSecret.equals(that.tokenSecret) &&
                Objects.equals(activation, that.activation) &&
                signatureTypeCreated.equals(that.signatureTypeCreated) &&
                timestampCreated.equals(that.timestampCreated);
    }

    @Override
    public int hashCode() {
        return Objects.hash(tokenId, tokenSecret, activation, signatureTypeCreated, timestampCreated);
    }
}
