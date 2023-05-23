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

import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for SDK data writer.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class SdkDataWriterTest {

    @Test
    public void testCountWrite() {
        final String countsGeneratedBySdk = "AAF/gICA/4EAgQG//8AAQADAAP//wAEAAMD////BAAAAwQIDBNAgMED/////";
        final SdkDataReader readerSdk = new SdkDataReader(Base64.decode(countsGeneratedBySdk));
        final List<Long> expectedCounts = new ArrayList<>();
        expectedCounts.add(0L);
        expectedCounts.add(1L);
        expectedCounts.add(0x7FL);
        expectedCounts.add(0x80L);
        expectedCounts.add(0xFFL);
        expectedCounts.add(0x100L);
        expectedCounts.add(0x101L);
        expectedCounts.add(0x3FFFL);
        expectedCounts.add(0x4000L);
        expectedCounts.add(0xFFFFL);
        expectedCounts.add(0x10000L);
        expectedCounts.add(0xFFFFFFL);
        expectedCounts.add(0x1000000L);
        expectedCounts.add(0x1020304L);
        expectedCounts.add(0x10203040L);
        expectedCounts.add(0x3FFFFFFFL);
        expectedCounts.forEach(countExpected -> {
            final int countExpectedFromSdk = readerSdk.readCount();
            // Attempt to write value into serialized data, compare with expected hex value
            final SdkDataWriter sdkDataWriter = new SdkDataWriter();
            sdkDataWriter.writeCount(Math.toIntExact(countExpected));
            final byte[] serialized = sdkDataWriter.getSerializedData();
            // Attempt to read value from serialized data, it should match the expected count from SDK
            final SdkDataReader sdkDataReader = new SdkDataReader(serialized);
            final int countDeserialized = sdkDataReader.readCount();
            assertEquals(countExpected, countDeserialized);
            assertEquals(countExpectedFromSdk, countDeserialized);
        });
    }

    @Test
    public void testCountWriteInvalid() {
        final SdkDataWriter sdkDataWriter = new SdkDataWriter();
        assertFalse(sdkDataWriter.writeCount(1073741824));
        assertEquals(0, sdkDataWriter.getSerializedData().length);
    }

    @Test
    public void testCountWriteInvalidMaxInt() {
        final SdkDataWriter sdkDataWriter = new SdkDataWriter();
        assertFalse(sdkDataWriter.writeCount(Integer.MAX_VALUE));
        assertEquals(0, sdkDataWriter.getSerializedData().length);
    }

    @Test
    public void testCountWriteInvalidNegative() {
        final SdkDataWriter sdkDataWriter = new SdkDataWriter();
        assertFalse(sdkDataWriter.writeCount(-1));
        assertEquals(0, sdkDataWriter.getSerializedData().length);
    }

    @Test
    public void testCountWriteInvalidMinInt() {
        final SdkDataWriter sdkDataWriter = new SdkDataWriter();
        assertFalse(sdkDataWriter.writeCount(Integer.MIN_VALUE));
        assertEquals(0, sdkDataWriter.getSerializedData().length);
    }

}