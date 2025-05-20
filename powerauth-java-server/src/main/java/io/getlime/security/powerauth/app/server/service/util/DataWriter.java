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

/**
 * Data writer interface for PowerAuth mobile SDK, see:
 * https://github.com/wultra/powerauth-mobile-sdk/blob/develop/src/PowerAuth/utils/DataWriter.h
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public interface DataWriter {

    /**
     * Resets data writer object to its initial state.
     */
    void reset();

    /**
     * Writes one byte to the stream.
     * @param b Byte to write.
     */
    void writeByte(byte b);

    /**
     * Writes number of bytes in byte range and actual
     * data to the stream. The size of range must not exceed
     * value returned from {@link #getMaxCount()} method.
     * @param bytes Bytes to write.
     */
    void writeData(byte[] bytes);

    /**
     * Writes number of characters in string and actual content
     * of string to the data stream. The length of string must
     * not exceed value returned from {@link #getMaxCount()} method.
     * @param str String to write.
     */
    void writeString(String str);

    /**
     * Writes only the content of byte range to the data stream.
     * Unlike the {@link #writeData(byte[])}, this method doesn't store number of bytes
     * as a size marker. It's up to you, how you determine the size
     * of sequence during the data reading.
     * @param bytes Data bytes.
     */
    void writeRaw(byte[] bytes);

    /**
     * Writes a count to the stream in optimized binary format. The count
     * parameter must be less or equal than value returned from
     * {@link #getMaxCount()} method.
     *
     * You should prefer this method for counter-type values over the writing
     * 32-bit or 64-bit values to the stream, because it usually produces a shorter byte
     * streams. For example, if count value is lesser than 128, then just
     * one byte is serialized.
     * @param count Count value to write.
     */
    boolean writeCount(int count);

    /**
     * Returns serialized data.
     * @return Serialized data.
     */
    byte[] getSerializedData();

    /**
     * Returns maximum supported value which can be serialized as
     * a counter. The returned value is the same for all supported
     * platforms and CPU architectures.
     * @return Maximum count value.
     */
    int getMaxCount();

}
