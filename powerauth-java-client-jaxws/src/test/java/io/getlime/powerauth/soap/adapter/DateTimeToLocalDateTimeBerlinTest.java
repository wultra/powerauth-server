package io.getlime.powerauth.soap.adapter;

import java.time.LocalDateTime;
import java.time.ZoneId;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;

/**
 * Test of {@link DateTimeToLocalDateTime}.
 */
public class DateTimeToLocalDateTimeBerlinTest {

    @Rule
    public final ZoneRule zoneRule = new ZoneRule(ZoneId.of("Europe/Berlin"));

    private final DateTimeToLocalDateTime marshaller = new DateTimeToLocalDateTime();

    @Test
    public void testUnmarshal() {
        Assert.assertEquals(LocalDateTime.of(2018, 12, 11, 10, 9, 8, 555000000), marshaller.unmarshal("2018-12-11T10:09:08.555"));
        Assert.assertEquals(LocalDateTime.of(2018, 12, 11, 10, 9, 8, 555000000), marshaller.unmarshal("2018-12-11T10:09:08.555+01:00"));
        Assert.assertEquals(LocalDateTime.of(2018, 12, 11, 11, 9, 8, 555000000), marshaller.unmarshal("2018-12-11T10:09:08.555Z"));
        Assert.assertEquals(LocalDateTime.of(2018, 12, 11, 9, 9, 8, 555000000), marshaller.unmarshal("2018-12-11T10:09:08.555+02:00"));
    }

    @Test
    public void testMarshal() {
        Assert.assertEquals("2018-12-11T10:09:08.555+01:00", marshaller.marshal(LocalDateTime.of(2018, 12, 11, 10, 9, 8, 555000000)));
    }

    @Test
    public void testMarshalDateTime() {
        Assert.assertNotNull(marshaller.marshal(LocalDateTime.now()));
    }

    @Test
    public void testMarshalDateTimeNull() {
        Assert.assertNull(marshaller.marshal(null));
    }
}