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

import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ValueSerializer;

import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Date;

/**
 * Serialize-only {@link Date} serializer that reproduces the legacy (pre-Jackson 3) wire format
 * of PowerAuth REST contracts, i.e. an ISO-8601 date-time in UTC with a numeric {@code +00:00}
 * offset instead of the Jackson 3 default {@code Z} designator.
 * <p>
 * The lower-case {@code xxx} pattern token forces the numeric {@code +00:00} form; the upper-case
 * {@code XXX} token and {@link java.text.SimpleDateFormat} emit {@code Z} for UTC and must not be used
 * here. This serializer intentionally does not touch deserialization, which stays on the Jackson
 * lenient reader and continues to accept both {@code +00:00} and {@code Z}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class LegacyDateSerializer extends ValueSerializer<Date> {

    private static final DateTimeFormatter LEGACY_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSxxx").withZone(ZoneOffset.UTC);

    @Override
    public void serialize(final Date value, final JsonGenerator gen, final SerializationContext ctxt) {
        gen.writeString(LEGACY_FORMATTER.format(value.toInstant()));
    }

}
