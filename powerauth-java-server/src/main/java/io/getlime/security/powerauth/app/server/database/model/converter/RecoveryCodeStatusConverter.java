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
 */
package io.getlime.security.powerauth.app.server.database.model.converter;

import io.getlime.security.powerauth.app.server.database.model.enumeration.RecoveryCodeStatus;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.springframework.stereotype.Component;

/**
 * Converter between {@link RecoveryCodeStatus} and integer values.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Converter
@Component
public class RecoveryCodeStatusConverter implements AttributeConverter<RecoveryCodeStatus, Integer> {

    @Override
    public Integer convertToDatabaseColumn(RecoveryCodeStatus status) {
        return switch (status) {
            case CREATED -> 1;
            case ACTIVE -> 2;
            case BLOCKED -> 3;
            default -> 4;
        };
    }

    @Override
    public RecoveryCodeStatus convertToEntityAttribute(Integer b) {
        return switch (b) {
            case 1 -> RecoveryCodeStatus.CREATED;
            case 2 -> RecoveryCodeStatus.ACTIVE;
            case 3 -> RecoveryCodeStatus.BLOCKED;
            default -> RecoveryCodeStatus.REVOKED;
        };
    }

}
