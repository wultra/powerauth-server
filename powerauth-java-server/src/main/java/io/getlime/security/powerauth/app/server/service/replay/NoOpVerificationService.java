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

package io.getlime.security.powerauth.app.server.service.replay;

import io.getlime.security.powerauth.app.server.database.model.enumeration.UniqueValueType;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.util.Date;

/**
 * Service for checking unique cryptography values to prevent replay attacks.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@ConditionalOnProperty(prefix = "powerauth.service.crypto", name = "replayVerificationService", havingValue = "none")
public class NoOpVerificationService implements ReplayVerificationService {

    @Override
    public void checkAndPersistUniqueValue(UniqueValueType type, Date requestTimestamp, String ephemeralPublicKey, String nonce, String identifier) {
        // No-op implementation is empty
    }

}