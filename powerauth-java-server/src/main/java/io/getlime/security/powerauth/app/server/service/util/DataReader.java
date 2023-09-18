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
 * Data reader interface for PowerAuth mobile SDK, see:
 * https://github.com/wultra/powerauth-mobile-sdk/blob/develop/src/PowerAuth/utils/DataReader.h
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public interface DataReader {

    /**
     * Resets data reader to its initial state.
     */
    void reset();

    /**
     * Returns remaining size available in the stream.
     * @return Remaining size.
     */
    int remainingSize();

    /**
     * Returns current reading offset.
     * @return Current reading offset.
     */
    int currentOffset();

    /**
     *  Returns true if it's possible to read at least |size| of bytes from stream.
     * @param size Byte size.
     * @return True if reader can read next bytes.
     */
    boolean canReadSize(int size);

    /**
     * Skips required number of bytes in the stream. Returns false, if there's not enough bytes left.
     * @param size Byte size.
     * @return True if skip was successful.
     */
    boolean skipBytes(int size);

    /**
     * Reads a data object into output byte array.
     * @param expectedSize Expected byte array size or 0 for any size.
     * @return Read data.
     */
    byte[] readData(int expectedSize);

    /**
     * Reads a string object into output byte array.
     * @return Read string.
     */
    String readString();

    /**
     * Reads an exact number of bytes into output byte array. Unlike the {@link #readData(int)} method, this method
     * reads just exact number of bytes from the stream, without any size marker.
     * @param size Byte size.
     * @return Read bytes.
     */
    byte[] readRaw(int size);

    /**
     * Reads one byte into output byte array.
     * @return Read byte.
     */
    Byte readByte();

    /**
     * Returns count from data stream.
     * @return Count.
     */
    Integer readCount();

}
