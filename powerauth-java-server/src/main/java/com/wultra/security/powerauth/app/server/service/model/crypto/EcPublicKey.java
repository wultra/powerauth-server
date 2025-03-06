/*
 * PowerAuth Server and related software components
 * Copyright (C) 2025 Wultra s.r.o.
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
 *
 */

package com.wultra.security.powerauth.app.server.service.model.crypto;

import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import lombok.*;
import lombok.extern.slf4j.Slf4j;

import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

/**
 * EC public key wrapper.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@NoArgsConstructor
@Slf4j
public class EcPublicKey extends BasePublicKey {

    private final KeyConvertor KEY_CONVERTOR = new KeyConvertor();

    public EcPublicKey(byte[] publicKeyBytes) {
        try {
            // TODO - v4 support
            this.ecPublicKey = KEY_CONVERTOR.convertBytesToPublicKey(EcCurve.P256, publicKeyBytes);
        } catch (InvalidKeySpecException | CryptoProviderException | GenericCryptoException e) {
            logger.warn("Invalid public key", e);
        }
    }

    @ToString.Exclude
    @Getter
    private PublicKey ecPublicKey;

}
