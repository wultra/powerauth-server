/*
 * PowerAuth Server and related software components
 * Copyright (C) 2018 Wultra s.r.o.
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
package io.getlime.security.powerauth.app.server.database.model;

import io.getlime.security.powerauth.app.server.database.model.enumeration.EncryptionMode;

/**
 * Compound value of server private key. Key can be stored encrypted or decrypted based on key encryption mode.
 *
 * @param encryptionMode         Key encryption mode.
 * @param serverPrivateKeyBase64 Base64-encoded server private key.
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public record ServerPrivateKey(EncryptionMode encryptionMode, String serverPrivateKeyBase64) {

}
