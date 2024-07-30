/*
 * PowerAuth Server and related software components
 * Copyright (C) 2024 Wultra s.r.o.
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
package io.getlime.security.powerauth.app.server.service.encryption;

import io.getlime.security.powerauth.app.server.database.model.enumeration.EncryptionMode;

/**
 * A generic wrapper for encryption, keeping both the mode and the data.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
public interface Encryptable {

    /**
     * Return encryption mode.
     * <p>
     * Determine format of {@link #getEncryptedData()}.
     *
     * @return encryption mode
     */
    EncryptionMode getEncryptionMode();

    /**
     * Return the data.
     * <p>
     * May be plain or encrypted. Depends on {@link #getEncryptionMode()}.
     *
     * @return encrypted or plain data
     */
    byte[] getEncryptedData();
}
