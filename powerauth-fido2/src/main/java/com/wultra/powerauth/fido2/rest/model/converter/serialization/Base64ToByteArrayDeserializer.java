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
 */

package com.wultra.powerauth.fido2.rest.model.converter.serialization;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

import java.io.IOException;
import java.io.Serial;
import java.util.Base64;

/**
 * @author Petr Dvorak, petr@wultra.com
 */
public class Base64ToByteArrayDeserializer extends StdDeserializer<byte[]> {

    @Serial
    private static final long serialVersionUID = 4519714786533202920L;

    public Base64ToByteArrayDeserializer() {
        this(null);
    }

    public Base64ToByteArrayDeserializer(Class<?> vc) {
        super(vc);
    }

    @Override
    public byte[] deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException {
        return Base64.getDecoder().decode(jsonParser.getText());
    }
}
