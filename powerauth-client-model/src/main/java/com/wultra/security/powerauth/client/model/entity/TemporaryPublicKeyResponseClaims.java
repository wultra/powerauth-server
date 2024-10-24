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

package com.wultra.security.powerauth.client.model.entity;

import lombok.Data;
import lombok.ToString;

import java.util.Date;

/**
 * Class for holding the temporary key response claims.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
public class TemporaryPublicKeyResponseClaims {

    private String applicationKey;
    private String activationId;
    @ToString.Exclude
    private String challenge;
    private String keyId;
    private String publicKey;
    private Date expiration;

}
