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

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;

/**
 * Test of {@link DateTimeToLocalDateTime}.
 */
public class DateTimeToLocalDateTimeUtcTest {

    @Rule
    public final ZoneRule zoneRule = new ZoneRule(ZoneId.of("UTC"));

    private final DateTimeToLocalDateTime marshaller = new DateTimeToLocalDateTime();

    @Test
    public void testUnmarshalString() {
        LocalDateTime value = LocalDateTime.now();
        String marshal = marshaller.marshal(value);
        LocalDateTime unmarshal = marshaller.unmarshal(marshal);
        String marshal2 = marshaller.marshal(unmarshal);
        Assert.assertEquals(marshal, marshal2);
    }

    @Test
    public void testUnmarshal() {
        Assert.assertEquals(LocalDateTime.of(2018, 12, 11, 10, 9, 8, 555000000), marshaller.unmarshal("2018-12-11T10:09:08.555"));
        Assert.assertEquals(LocalDateTime.of(2018, 12, 11, 10, 9, 8, 555000000), marshaller.unmarshal("2018-12-11T10:09:08.555Z"));
        Assert.assertEquals(LocalDateTime.of(2018, 12, 11, 8, 9, 8, 555000000), marshaller.unmarshal("2018-12-11T10:09:08.555+02:00"));
        Assert.assertEquals(LocalDateTime.of(2018, 12, 11, 9, 9, 8, 555000000), marshaller.unmarshal("2018-12-11T10:09:08.555+01:00"));
    }

    @Test
    public void testMarshal() {
        Assert.assertEquals("2018-12-11T10:09:08.555Z", marshaller.marshal(LocalDateTime.of(2018, 12, 11, 10, 9, 8, 555000000)));
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