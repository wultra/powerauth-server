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

package com.wultra.security.powerauth.app.server.service.crypto;

import com.wultra.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Service for validating supported cryptography protocol versions.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
@AllArgsConstructor
public class ProtocolVersionValidationService {

    private final PowerAuthServiceConfiguration configuration;
    private final LocalizationProvider localizationProvider;

    /**
     * Check whether a given protocol version is supported.
     * @param protocolVersionMajor Protocol version major number.
     * @throws GenericServiceException Thrown in case protocol version is not supported.
     */
    public void checkProtocolVersionSupported(int protocolVersionMajor) throws GenericServiceException {
        if (configuration.getMinSupportedProtocolVersion() > protocolVersionMajor) {
            logger.warn("Cryptography protocol version is not supported: {}, minimum supported version: {}", protocolVersionMajor, configuration.getMinSupportedProtocolVersion());
            throw localizationProvider.buildExceptionForCode(ServiceError.CRYPTOGRAPHY_PROTOCOL_VERSION_NOT_SUPPORTED);
        }
    }

}
