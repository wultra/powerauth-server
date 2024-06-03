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

package io.getlime.security.powerauth.app.server.service.util;

import io.getlime.security.powerauth.app.server.service.model.SdkConfiguration;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Test for SDK data writer.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class SdkConfigurationSerializerTest {

    @Test
    public void testSerializeAndDeserialize() {
        final String appKey = "w4+hAeogFLTZjcSjPwbG2g==";
        final String appSecret = "Szls/7JWbKN+FAOijHcsPA==";
        final String masterPublicKey = "BEEOwljSgItBIAnzr3f7K36s+KKoUzC8LE+K+7Dy0X6iAkcPXAjLP1KKPxdqyM/iihHAcW5x/WzJPCbtytcJo2w=";
        final String expectedValue = "ARDDj6EB6iAUtNmNxKM/BsbaEEs5bP+yVmyjfhQDoox3LDwBAUEEQQ7CWNKAi0EgCfOvd/srfqz4oqhTMLwsT4r7sPLRfqICRw9cCMs/Uoo/F2rIz+KKEcBxbnH9bMk8Ju3K1wmjbA==";
        final String serialized = SdkConfigurationSerializer.serialize(new SdkConfiguration(appKey, appSecret, masterPublicKey));
        assertEquals(expectedValue, serialized);
        final SdkConfiguration config = SdkConfigurationSerializer.deserialize(serialized);
        assertNotNull(config);
        assertEquals(appKey, config.appKeyBase64());
        assertEquals(appSecret, config.appSecretBase64());
        assertEquals(masterPublicKey, config.masterPublicKeyBase64());
    }
}