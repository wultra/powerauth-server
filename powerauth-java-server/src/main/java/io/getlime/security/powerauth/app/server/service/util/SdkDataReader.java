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

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Data reader implementation for PowerAuth mobile SDK, see:
 * https://github.com/wultra/powerauth-mobile-sdk/blob/develop/src/PowerAuth/utils/DataReader.cpp
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Slf4j
public class SdkDataReader implements DataReader {

    private final byte[] data;
    private int offset = 0;

    /**
     * SDK reader constructor.
     * @param data Binary data to read.
     */
    public SdkDataReader(byte[] data) {
        this.data = data;
    }

    @Override
    public void reset() {
        this.offset = 0;
    }

    @Override
    public int remainingSize() {
        return data.length - offset;
    }

    @Override
    public int currentOffset() {
        return offset;
    }

    @Override
    public boolean canReadSize(int size) {
        return remainingSize() >= size;
    }

    @Override
    public boolean skipBytes(int size) {
        if (!canReadSize(size)) {
            return false;
        }
        offset += size;
        return true;
    }

    @Override
    public byte[] readData(int expectedSize) {
        final Integer size = readCount();
        if (size == null) {
            return null;
        }
        if (!canReadSize(size)) {
            return null;
        }
        if (expectedSize > 0 && expectedSize != size) {
            return null;
        }
        byte[] result = Arrays.copyOfRange(data, offset, offset + size);
        offset += size;
        return result;
    }

    @Override
    public String readString() {
        final Integer size = readCount();
        if (size == null) {
            return null;
        }
        if (!canReadSize(size)) {
            return null;
        }
        final byte[] strData = Arrays.copyOfRange(data, offset, offset + size);
        offset += size;
        return new String(strData, StandardCharsets.UTF_8);
    }

    @Override
    public byte[] readRaw(int size) {
        if (!canReadSize(size)) {
            return null;
        }
        final byte[] result = Arrays.copyOfRange(data, offset, offset + size);
        offset += size;
        return result;
    }

    @Override
    public Byte readByte() {
        if (!canReadSize(1)) {
            return null;
        }
        byte result = data[offset];
        offset++;
        return result;
    }

    @Override
    public Integer readCount() {
        final Byte firstByte = readByte();
        if (firstByte == null) {
            return null;
        }
        final int byte1u = Byte.toUnsignedInt(firstByte);
        final int marker = byte1u & 0xC0;
        if (marker == 0x00 || marker == 0x40) {
            return byte1u;
        }
        // marker is 2 or 3, that means that we need 1 or 3 more bytes
        final int additionalByteCount = marker == 0xC0 ? 3 : 1;
        final byte[] remainingBytes = readRaw(additionalByteCount);
        if (remainingBytes == null) {
            return null;
        }
        final int byte2u = Byte.toUnsignedInt(remainingBytes[0]);
        if (marker == 0xC0) {
            // 4 bytes
            int byte3u = Byte.toUnsignedInt(remainingBytes[1]);
            int byte4u = Byte.toUnsignedInt(remainingBytes[2]);
            return (byte1u & 0x3F) << 24 |
                    byte2u << 16 |
                    byte3u << 8 |
                    byte4u;
        } else {
            // 2 bytes
            return (byte1u & 0x3F) << 8 |
                    byte2u;
        }
    }
}
