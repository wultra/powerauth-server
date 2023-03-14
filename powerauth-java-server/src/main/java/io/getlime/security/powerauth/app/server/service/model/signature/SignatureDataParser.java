/*
 * PowerAuth Server and related software components
 * Copyright (C) 2023 Wultra s.r.o.
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

package io.getlime.security.powerauth.app.server.service.model.signature;

import com.google.common.io.BaseEncoding;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;

/**
 * Signature data parser.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Slf4j
public class SignatureDataParser {

    /**
     * Parse signature request data from raw data byte array.
     * @param data Raw signature request data byte array.
     */
    public static SignatureRequestData parseRequestData(final byte[] data) {
        if (data == null) {
            // Null data has no request data
            return null;
        }
        final String dataString = new String(data, StandardCharsets.UTF_8);

        // Parse standardized request data based on standard PowerAuth signature data specification:
        // REQUEST_DATA = ${REQUEST_METHOD}&${REQUEST_URI_IDENTIFIER}&${NONCE}&${REQUEST_BODY}
        // DATA = ${REQUEST_DATA}&${APPLICATION_SECRET}

        final String[] parts = dataString.split("&");
        if (parts.length != 5) {
            // Non-standard request data, do not parse such data
            return null;
        }
        final String method = parts[0];
        try {
            final String uriIdentifier = new String(BaseEncoding.base64().decode(parts[1]), StandardCharsets.UTF_8);
            final String body = new String(BaseEncoding.base64().decode(parts[3]), StandardCharsets.UTF_8);
            return new SignatureRequestData(method, uriIdentifier, body);
        } catch (IllegalArgumentException ex) {
            logger.warn("Invalid request data, error: {}", ex.getMessage(), ex);
            return null;
        }
    }
}
