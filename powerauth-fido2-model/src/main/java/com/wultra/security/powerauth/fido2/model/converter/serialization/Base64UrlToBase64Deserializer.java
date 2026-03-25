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

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;

import java.io.IOException;
import java.io.Serial;

/**
 * Jackson deserializer that transparently normalizes Base64URL-encoded strings
 * to standard Base64 encoding (RFC 4648 §4). The deserializer accepts both encodings
 * and always produces a standard Base64 string.
 *
 * @author Pavel Sindelar, pavel.sindelar@wultra.com
 */
public class Base64UrlToBase64Deserializer extends StdDeserializer<String> {

    @Serial
    private static final long serialVersionUID = 4871203406847302591L;

    public Base64UrlToBase64Deserializer() {
        this(null);
    }

    public Base64UrlToBase64Deserializer(final Class<?> valueClass) {
        super(valueClass);
    }

    @Override
    public String deserialize(final JsonParser parser, final DeserializationContext context) throws IOException {
        final String value = parser.getText();
        if (value == null) {
            return null;
        }

        if (value.length() % 4 == 1) {
            throw InvalidFormatException.from(
                    parser,
                    "Invalid value for path '%s': length mod 4 == 1 is not a valid Base64 remainder".formatted(parser.getParsingContext().pathAsPointer()),
                    value,
                    String.class
            );
        }

        if (value.length() % 4 == 0 && !value.contains("-") && !value.contains("_")) {
            // already standard Base64 string
            return value;
        }

        final String normalized = value.replace('-', '+').replace('_', '/');

        final int remainder = normalized.length() % 4;
        if (remainder == 0) {
            // no padding needed
            return normalized;
        }

        // add padding
        return normalized + "=".repeat(4 - remainder);
    }
}
