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
package com.wultra.powerauth.fido2.rest.model.converter.serialization;

import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.wultra.security.powerauth.fido2.model.converter.serialization.Base64UrlToBase64Deserializer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Test for {@link Base64UrlToBase64Deserializer}.
 *
 * @author Pavel Sindelar, pavel.sindelar@wultra.com
 */
class Base64UrlToBase64DeserializerTest {

    private static ObjectMapper objectMapper;

    @BeforeAll
    static void setUp() {
        final SimpleModule module = new SimpleModule();
        module.addDeserializer(String.class, new Base64UrlToBase64Deserializer());
        objectMapper = new ObjectMapper();
        objectMapper.registerModule(module);
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(
            value = {
                    "base64UrlWithoutPadding_convertedToBase64,              -_--,     +/++",
                    "base64UrlMissingPadding_paddingAdded,                   SGVsbG8,  SGVsbG8=",
                    "alreadyStandardBase64_returnedUnchanged,                SGVsbG8=, SGVsbG8=",
                    "alreadyStandardBase64NoPaddingNeeded_returnedUnchanged, ABCDEFGH, ABCDEFGH",
                    "null_returnsNull,                                       null,     null",
                    "dashOnly_convertedToPlus,                               AA-A,     AA+A",
                    "underscoreOnly_convertedToSlash,                        AA_A,     AA/A"
            },
            nullValues = "null"
    )
    void testDeserialize_validInput(final String name, final String input, final String expected) throws Exception {
        assertEquals(expected, objectMapper.readValue(
                input != null ? "\"%s\"".formatted(input) : "null",
                String.class
        ));
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource({
            "invalidLength,                             A",
            "invalidCharInStandardBase64,               A!B=",
            "invalidCharInBase64UrlRequiringPadding,    A!-",
            "invalidCharInBase64UrlNotRequiringPadding, -_!-"
    })
    void testDeserialize_invalidInput_throwsException(final String name, final String input) {
        assertThrows(JsonMappingException.class, () -> objectMapper.readValue("\"%s\"".formatted(input), String.class));
    }
}
