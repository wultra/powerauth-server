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

import javax.persistence.*;
import java.util.Date;
import java.util.Objects;

/**
 * Database entity for the tokens used during token-based authentication.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Entity(name = "pa_token")
public class TokenEntity {

    @Id
    @Column(name = "token_id", length = 37)
    private String tokenId;

    @Column(name = "token_secret", nullable = false, updatable = false)
    private String tokenSecret;

    @ManyToOne
    @JoinColumn(name = "activation_id", referencedColumnName = "activation_id", updatable = false)
    private ActivationRecordEntity activation;

    @Column(name = "signature_type", nullable = false, updatable = false)
    private String signatureTypeCreated;

    @Column(name = "timestamp_created", nullable = false, updatable = false)
    private Date timestampCreated;

    /**
     * Get token ID.
     * @return Token ID.
     */
    public String getTokenId() {
        return tokenId;
    }

    /**
     * Set token ID.
     * @param tokenId Token ID.
     */
    public void setTokenId(String tokenId) {
        this.tokenId = tokenId;
    }

    /**
     * Get token secret.
     * @return Token secret.
     */
    public String getTokenSecret() {
        return tokenSecret;
    }

    /**
     * Set token secret.
     * @param tokenSecret Token secret.
     */
    public void setTokenSecret(String tokenSecret) {
        this.tokenSecret = tokenSecret;
    }

    /**
     * Get associated activation entity.
     * @return Associated activation.
     */
    public ActivationRecordEntity getActivation() {
        return activation;
    }

    /**
     * Set associated activation entity.
     * @param activation Associated activation entity.
     */
    public void setActivation(ActivationRecordEntity activation) {
        this.activation = activation;
    }

    /**
     * Get the information about the type of the signature that was used to issue this token.
     * @return Signature type of the signature used to issue the token.
     */
    public String getSignatureTypeCreated() {
        return signatureTypeCreated;
    }

    /**
     * Set the information about the type of the signature that was used to issue this token.
     * @param signatureTypeCreated Signature type of the signature used to issue the token.
     */
    public void setSignatureTypeCreated(String signatureTypeCreated) {
        this.signatureTypeCreated = signatureTypeCreated;
    }

    /**
     * Get the timestamp when the token was issued.
     * @return Timestamp created.
     */
    public Date getTimestampCreated() {
        return timestampCreated;
    }

    /**
     * Set the timestamp when the token was issued.
     * @param timestampCreated Timestamp created.
     */
    public void setTimestampCreated(Date timestampCreated) {
        this.timestampCreated = timestampCreated;
    }

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
