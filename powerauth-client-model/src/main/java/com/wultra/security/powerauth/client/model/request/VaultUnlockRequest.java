/*
 * PowerAuth Server and related software components
 * Copyright (C) 2021 Wultra s.r.o.
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

package com.wultra.security.powerauth.client.model.request;

import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import lombok.Data;
import lombok.ToString;

/**
 * Model class representing request for unlocking secure vault.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
public class VaultUnlockRequest {

    private String activationId;
    private String applicationKey;
    private String signedData;
    @ToString.Exclude
    private String signature;
    private SignatureType signatureType;
    private String signatureVersion;
    private String temporaryKeyId;
    private String ephemeralPublicKey;
    private String encryptedData;
    private String mac;
    @ToString.Exclude
    private String nonce;
    private Long timestamp;

}
