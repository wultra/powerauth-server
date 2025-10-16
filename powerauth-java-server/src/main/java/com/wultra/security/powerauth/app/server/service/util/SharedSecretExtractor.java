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

package com.wultra.security.powerauth.app.server.service.util;

import com.wultra.security.powerauth.app.server.converter.ActivationSharedSecretConverter;
import com.wultra.security.powerauth.app.server.database.model.SharedSecret;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Base64;

/**
 * Utility class for shared secret key derivation.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@AllArgsConstructor
@Service
public class SharedSecretExtractor {

    private final ActivationSharedSecretConverter activationSharedSecretConverter;

    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();

    /**
     * Extract the activation secret key from activation entity.
     *
     * @param activation Activation entity.
     * @return Activation shared secret key.
     * @throws GenericServiceException Thrown in case key conversion fails.
     */
    public SecretKey extractActivationSecretKey(ActivationRecordEntity activation) throws GenericServiceException {
        final SharedSecret activationSharedSecret = new SharedSecret(activation.getSharedSecretEncryption(), activation.getSharedSecret());
        final String activationSecretBase64 = activationSharedSecretConverter.fromDBValue(activationSharedSecret, activation.getUserId(), activation.getActivationId());
        final byte[] activationSecretBytes = Base64.getDecoder().decode(activationSecretBase64);
        return KEY_CONVERTOR.convertBytesToSharedSecretKey(activationSecretBytes);
    }

}
