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

import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesScope;
import io.getlime.security.powerauth.crypto.lib.util.ByteUtils;

/**
 * ECIES data utility class.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class EciesDataUtils {

    /**
     * Private constructor.
     */
    private EciesDataUtils() {
    }

    public static byte[] deriveAssociatedData(EciesScope eciesScope, String version, String applicationKey, String activationId) {
        if ("3.2".equals(version)) {
            if (eciesScope == EciesScope.ACTIVATION_SCOPE) {
                return ByteUtils.concatStrings(version, applicationKey, activationId);
            } else {
                return ByteUtils.concatStrings(version, applicationKey);
            }
        } else {
            return null;
        }
    }
}