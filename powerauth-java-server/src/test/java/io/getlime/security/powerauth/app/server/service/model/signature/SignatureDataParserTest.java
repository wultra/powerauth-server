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

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Signature data parser test.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
class SignatureDataParserTest {

   @Test
   void testSignatureDataParserValid() {
        final byte[] rawData = "POST&L3BhL3Rva2VuL2NyZWF0ZQ==&YD375huieypEKAr16VhgZg==&eyJlbmNyeXB0ZWREYXRhIjoiU3poXC9MNU9HUkRpdStIb2NtQ0ZXT1E9PSIsIm5vbmNlIjoiSmtnM3F3bEN1cG5UTXJVbWFYaU5adz09IiwibWFjIjoiQnd1Q2V4eVN1aWh3ckNRXC9ETFJNc0pEVXBMMW5GM2RKMHpZdVFrcXNjTjA9IiwiZXBoZW1lcmFsUHVibGljS2V5IjoiQWp6ODBmdzZtRDZYbVBDMUxYdEtUZWN2MHhFNUJ1R3FBVEtmaHNtTHhuVkEifQ==&Pgd67vpBT6/Y+2fNBt7Sxg==".getBytes(StandardCharsets.UTF_8);
        final SignatureRequestData parsedData = SignatureDataParser.parseRequestData(rawData);
        assertEquals("POST", parsedData.getMethod());
        assertEquals("/pa/token/create", parsedData.getUriIdentifier());
        assertEquals("{\"encryptedData\":\"Szh\\/L5OGRDiu+HocmCFWOQ==\",\"nonce\":\"Jkg3qwlCupnTMrUmaXiNZw==\",\"mac\":\"BwuCexySuihwrCQ\\/DLRMsJDUpL1nF3dJ0zYuQkqscN0=\",\"ephemeralPublicKey\":\"Ajz80fw6mD6XmPC1LXtKTecv0xE5BuGqATKfhsmLxnVA\"}", parsedData.getBody());
    }

   @Test
   void testSignatureDataParserValidInvalid() {
        final byte[] rawData = "POSTL3BhL3Rva2VuL2NyZWF0ZQ==&YD375huieypEKAr16VhgZg==&eyJlbmNyeXB0ZWREYXRhIjoiU3poXC9MNU9HUkRpdStIb2NtQ0ZXT1E9PSIsIm5vbmNlIjoiSmtnM3F3bEN1cG5UTXJVbWFYaU5adz09IiwibWFjIjoiQnd1Q2V4eVN1aWh3ckNRXC9ETFJNc0pEVXBMMW5GM2RKMHpZdVFrcXNjTjA9IiwiZXBoZW1lcmFsUHVibGljS2V5IjoiQWp6ODBmdzZtRDZYbVBDMUxYdEtUZWN2MHhFNUJ1R3FBVEtmaHNtTHhuVkEifQ==&Pgd67vpBT6/Y+2fNBt7Sxg==".getBytes(StandardCharsets.UTF_8);
        final SignatureRequestData parsedData = SignatureDataParser.parseRequestData(rawData);
        assertNull(parsedData);
    }

}
