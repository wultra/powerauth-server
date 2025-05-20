/*
 * PowerAuth Server and related software components
 * Copyright (C) 2024 Wultra s.r.o.
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

package io.getlime.security.powerauth.app.server.database.model.converter;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeParseException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for {@link DurationConverter}
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
class DurationConverterTest {

    private DurationConverter tested = new DurationConverter();

    @Test
    void testConvertToDatabaseColumn() {
        assertEquals("PT4M", tested.convertToDatabaseColumn(Duration.ofMinutes(4)));
        assertEquals("PT168H", tested.convertToDatabaseColumn(Duration.ofDays(7)));
        assertEquals("PT0S", tested.convertToDatabaseColumn(Duration.ZERO));
        assertNull(tested.convertToDatabaseColumn(null));

        final LocalDateTime date1 = LocalDateTime.parse("2020-01-01T06:30:30");
        final LocalDateTime date2 = LocalDateTime.parse("2025-10-05T16:45:00");
        assertEquals("PT50506H14M30S", tested.convertToDatabaseColumn(Duration.between(date1, date2)));
    }

    @Test
    void testConvertToEntityAttribute() {
        assertEquals(Duration.ofMinutes(4), tested.convertToEntityAttribute("PT4M"));
        assertEquals(Duration.ofDays(7), tested.convertToEntityAttribute("PT168H"));
        assertEquals(Duration.ZERO, tested.convertToEntityAttribute("PT0S"));
        assertNull(tested.convertToEntityAttribute(null));
        assertThrows(DateTimeParseException.class, () -> tested.convertToEntityAttribute("invalid"));

        final LocalDateTime date1 = LocalDateTime.parse("2020-01-01T06:30:30");
        final LocalDateTime date2 = LocalDateTime.parse("2025-10-05T16:45:00");
        assertEquals(Duration.between(date1, date2), tested.convertToEntityAttribute("PT50506H14M30S"));
    }

}
