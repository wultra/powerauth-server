/*
 * PowerAuth Server and related software components
 * Copyright (C) 2017 Lime - HighTech Solutions s.r.o.
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
package io.getlime.powerauth.soap.adapter;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.temporal.TemporalAccessor;
import java.time.temporal.TemporalQueries;

import javax.xml.bind.annotation.adapters.XmlAdapter;

/**
 * Implementation of XmlAdapter for jaxb binding. Converts String(xsd:dateTime) to LocalDateTime and vice versa.
 */
public class DateTimeToLocalDateTime extends XmlAdapter<String, LocalDateTime> {

    private static final DateTimeFormatter DATE_TIME_FORMATTER = new DateTimeFormatterBuilder().parseCaseInsensitive()
            .append(DateTimeFormatter.ISO_LOCAL_DATE)
            .appendLiteral('T')
            .append(DateTimeFormatter.ISO_LOCAL_TIME)
            .optionalStart() // zone and offset made optional
            .appendOffsetId()
            .optionalStart()
            .appendLiteral('[')
            .parseCaseSensitive()
            .appendZoneRegionId()
            .appendLiteral(']')
            .optionalEnd()
            .optionalEnd()
            .toFormatter();

    @Override
    public LocalDateTime unmarshal(String value) {
        if (value == null) {
            return null;
        }

        final TemporalAccessor parse = DATE_TIME_FORMATTER.parse(value);
        if (parse.query(TemporalQueries.zone()) == null) {
            return LocalDateTime.from(parse);
        }
        return ZonedDateTime.from(parse).withZoneSameInstant(ZoneId.systemDefault()).toLocalDateTime();
    }

    @Override
    public String marshal(LocalDateTime value) {
        return value != null ? ZonedDateTime.of(value, ZoneId.systemDefault()).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME) : null;
    }
}