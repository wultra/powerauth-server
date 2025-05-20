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

import lombok.extern.slf4j.Slf4j;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Data writer implementation for PowerAuth mobile SDK, see:
 * https://github.com/wultra/powerauth-mobile-sdk/blob/develop/src/PowerAuth/utils/DataWriter.cpp
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Slf4j
public class SdkDataWriter implements DataWriter {

    private final ByteArrayOutputStream os = new ByteArrayOutputStream();

    @Override
    public void reset() {
        os.reset();
    }

    @Override
    public void writeByte(byte b) {
        os.write(b);
    }

    @Override
    public void writeData(byte[] bytes) {
        if (!writeCount(bytes.length)) {
            return;
        }
        writeRaw(bytes);
    }

    @Override
    public void writeString(String str) {
        writeData(str.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public void writeRaw(byte[] bytes) {
        try {
            os.write(bytes);
        } catch (IOException e) {
            logger.warn(e.getMessage(), e);
        }
    }

    @Override
    public boolean writeCount(int count) {
        // The SDK expects unsigned values, convert int to unsigned long for the byte operations
        if (count < 0) {
            logger.warn("Count is invalid: {}", count);
        }
        long n = Integer.toUnsignedLong(count);
        if (n <= 0x7F) {
            writeByte((byte) n);
        } else if (n <= 0x3FFF) {
            writeByte((byte) (((n >> 8 ) & 0x3F) | 0x80));
            writeByte((byte) (n        & 0xFF));
        } else if (n <= 0x3FFFFFFF) {
            writeByte((byte) (((n >> 24) & 0x3F) | 0xC0));
            writeByte((byte) ((n >> 16) & 0xFF));
            writeByte((byte) ((n >> 8 ) & 0xFF));
            writeByte((byte) (n        & 0xFF));
        } else {
            logger.warn("Count is too large: {}", n);
            return false;
        }
        return true;
    }

    @Override
    public byte[] getSerializedData() {
        return os.toByteArray();
    }

    @Override
    public int getMaxCount() {
        return 0x3FFFFFFF;
    }

}