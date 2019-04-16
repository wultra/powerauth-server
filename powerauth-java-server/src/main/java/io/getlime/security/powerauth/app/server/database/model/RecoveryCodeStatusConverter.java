/*
 * PowerAuth Server and related software components
 * Copyright (C) 2019 Wultra s.r.o.
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

import org.springframework.stereotype.Component;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

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
        switch (status) {
            case CREATED:
                return 1;
            case ACTIVE:
                return 2;
            case BLOCKED:
                return 3;
            case REVOKED:
                return 4;
            default:
                return 4;
        }
    }

    @Override
    public RecoveryCodeStatus convertToEntityAttribute(Integer b) {
        switch (b) {
            case 1:
                return RecoveryCodeStatus.CREATED;
            case 2:
                return RecoveryCodeStatus.ACTIVE;
            case 3:
                return RecoveryCodeStatus.BLOCKED;
            case 4:
                return RecoveryCodeStatus.REVOKED;
            default:
                return RecoveryCodeStatus.REVOKED;
        }
    }

}
