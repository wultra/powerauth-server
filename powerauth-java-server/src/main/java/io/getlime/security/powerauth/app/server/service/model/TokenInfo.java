/*
 * PowerAuth Server and related software components
 * Copyright (C) 2017 Lime - HighTech Solutions s.r.o.
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

package io.getlime.security.powerauth.app.server.service.model;

/**
 * Simple class to encapsulate token info send inside the encrypted package.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class TokenInfo {

    private String tokenId;
    private String tokenSecret;
    private Long expires;

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
     * Get expiration timestamp as Unix timestamp in milliseconds.
     * @return Expiration timestamp.
     */
    public Long getExpires() {
        return expires;
    }

    /**
     * Set expiration timestamp as Unix timestamp in milliseconds.
     * @param expires Expiration timestamp.
     */
    public void setExpires(Long expires) {
        this.expires = expires;
    }

}
