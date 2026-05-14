/*
 * PowerAuth Server and related software components
 * Copyright (C) 2026 Wultra s.r.o.
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

package com.wultra.security.powerauth.fido2.model.converter.serialization;

import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.deser.std.StdDeserializer;
import tools.jackson.databind.exc.InvalidFormatException;

import java.util.Base64;

/**
 * Jackson deserializer that transparently normalizes Base64URL-encoded strings
 * to standard Base64 encoding (RFC 4648 §4). The deserializer accepts both encodings
 * and always produces a standard Base64 string.
 *
 * @author Pavel Sindelar, pavel.sindelar@wultra.com
 */
public class Base64UrlToBase64Deserializer extends StdDeserializer<String> {

    public Base64UrlToBase64Deserializer() {
        this(String.class);
    }

    public Base64UrlToBase64Deserializer(final Class<?> valueClass) {
        super(valueClass);
    }

    @Override
    public String deserialize(final JsonParser parser, final DeserializationContext context) {
        final String value = parser.getString();
        if (value == null) {
            return null;
        }

        if (value.length() % 4 == 1) {
            throw InvalidFormatException.from(
                    parser,
                    "Invalid value for path '%s': length mod 4 == 1 is not a valid Base64 remainder".formatted(parser.streamReadContext().pathAsPointer()),
                    value,
                    String.class
            );
        }

        if (value.length() % 4 == 0 && !value.contains("-") && !value.contains("_")) {
            // already standard Base64 string
            return validate(value, parser);
        }

        final String normalized = value.replace('-', '+').replace('_', '/');

        final int remainder = normalized.length() % 4;
        if (remainder == 0) {
            // no padding needed
            return validate(normalized, parser);
        }

        // add padding
        final String normalizedPadded = normalized + "=".repeat(4 - remainder);

        return validate(normalizedPadded, parser);
    }

    private String validate(final String value, final JsonParser parser) throws InvalidFormatException {
        try {
            Base64.getDecoder().decode(value);
        } catch (final Exception e) {
            throw InvalidFormatException.from(
                    parser,
                    "Invalid value for path '%s': %s".formatted(parser.streamReadContext().pathAsPointer(), e.getMessage()),
                    value,
                    String.class
            );
        }

        return value;
    }
}
