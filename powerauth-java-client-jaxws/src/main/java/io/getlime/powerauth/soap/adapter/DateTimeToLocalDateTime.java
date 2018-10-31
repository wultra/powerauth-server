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