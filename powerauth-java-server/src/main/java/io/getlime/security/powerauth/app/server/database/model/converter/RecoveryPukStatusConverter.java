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

import io.getlime.security.powerauth.app.server.database.model.enumeration.RecoveryPukStatus;
import org.springframework.stereotype.Component;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

/**
 * Converter between {@link RecoveryPukStatus} and integer values.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Converter
@Component
public class RecoveryPukStatusConverter implements AttributeConverter<RecoveryPukStatus, Integer> {

    @Override
    public Integer convertToDatabaseColumn(RecoveryPukStatus status) {
        switch (status) {
            case VALID:
                return 1;
            case USED:
                return 2;
            case INVALID:
            default:
                return 3;
        }
    }

    @Override
    public RecoveryPukStatus convertToEntityAttribute(Integer b) {
        switch (b) {
            case 1:
                return RecoveryPukStatus.VALID;
            case 2:
                return RecoveryPukStatus.USED;
            case 3:
            default:
                return RecoveryPukStatus.INVALID;
        }
    }

}
