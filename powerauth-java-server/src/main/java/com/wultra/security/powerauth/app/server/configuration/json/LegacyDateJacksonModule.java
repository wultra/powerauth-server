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

package com.wultra.security.powerauth.app.server.configuration.json;

import tools.jackson.databind.module.SimpleModule;

import java.util.Date;

/**
 * Jackson module registering the {@link LegacyDateSerializer} for {@link Date}. It is applied both to
 * the application {@code ObjectMapper} (main REST API responses) and to the callback
 * {@code DefaultRestClient} so that the legacy {@code +00:00} date-time wire format can be restored on
 * every serialization path via a single configuration flag.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class LegacyDateJacksonModule extends SimpleModule {

    public LegacyDateJacksonModule() {
        super("PowerAuthLegacyDateModule");
        addSerializer(Date.class, new LegacyDateSerializer());
    }

}
