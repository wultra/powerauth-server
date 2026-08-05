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
 *
 */
package com.wultra.security.powerauth.app.server.configuration;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Tests for {@link PowerAuthServiceConfiguration}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
class PowerAuthServiceConfigurationTest {

    @Test
    void shouldSerializeDatesAsText() {
        final JsonMapper.Builder builder = JsonMapper.builder();
        new PowerAuthServiceConfiguration().jsonMapperBuilderCustomizer().customize(builder);
        final ObjectMapper objectMapper = builder.build();

        assertEquals("\"2024-01-01T00:00:00.123+00:00\"", objectMapper.writeValueAsString(new Date(1704067200123L)));
    }
}
