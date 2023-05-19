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

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for SDK data writer.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class SdkDataWriterTest {

    @Test
    public void testCountWrite() {
        final Map<Integer, String> values = new LinkedHashMap<>();
        values.put(0, "00");
        values.put(1, "01");
        values.put(127, "7F");
        values.put(128, "8080");
        values.put(16383, "BFFF");
        values.put(16384, "C0004000");
        values.put(1073741823, "FFFFFFFF");
        values.forEach((key, value) -> {
            // Attempt to write value into serialized data, compare with expected hex value
            final SdkDataWriter sdkDataWriter = new SdkDataWriter();
            sdkDataWriter.writeCount(key);
            byte[] serialized = sdkDataWriter.getSerializedData();
            StringBuilder result = new StringBuilder();
            for (byte b : serialized) {
                result.append(String.format("%02X", b));
            }
            assertEquals(value, result.toString());
            // Attempt to read value from serialized data, it should match the key
            final SdkDataReader sdkDataReader = new SdkDataReader(serialized);
            int count = sdkDataReader.readCount();
            assertEquals(key, count);
        });
    }

    @Test
    public void testCountWriteInvalid() {
        final SdkDataWriter sdkDataWriter = new SdkDataWriter();
        assertFalse(sdkDataWriter.writeCount(1073741824));
        assertEquals(0, sdkDataWriter.getSerializedData().length);
    }
}