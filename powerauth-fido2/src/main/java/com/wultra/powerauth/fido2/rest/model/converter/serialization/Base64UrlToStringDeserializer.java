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

import tools.jackson.core.JsonParser;
import lombok.extern.slf4j.Slf4j;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.deser.std.StdDeserializer;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Deserializer from Base64 to string.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Slf4j
public class Base64UrlToStringDeserializer extends StdDeserializer<String> {

    /**
     * No-arg deserializer constructor.
     */
    public Base64UrlToStringDeserializer() {
        this(String.class);
    }

    /**
     * Deserializer constructor with value class parameter.
     * @param vc Value class.
     */
    public Base64UrlToStringDeserializer(Class<?> vc) {
        super(vc);
    }

    /**
     * Deserialize data from Base64Url to string.
     * @param jsonParser JSON parser.
     * @param deserializationContext Deserialization context.
     * @return Deserialized string.
     */
    @Override
    public String deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) {
        return new String(Base64.getUrlDecoder().decode(jsonParser.getString()), StandardCharsets.UTF_8);
    }

}
