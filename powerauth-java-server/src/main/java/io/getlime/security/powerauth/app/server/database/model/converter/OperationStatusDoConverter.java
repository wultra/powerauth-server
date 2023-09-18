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

import io.getlime.security.powerauth.app.server.database.model.enumeration.OperationStatusDo;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.springframework.stereotype.Component;

/**
 * Converter between {@link OperationStatusDo} and integer values.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Converter
@Component
public class OperationStatusDoConverter implements AttributeConverter<OperationStatusDo, Integer> {

    @Override
    public Integer convertToDatabaseColumn(OperationStatusDo status) {
        return switch (status) {
            case PENDING -> 1;
            case CANCELED -> 2;
            case EXPIRED -> 3;
            case APPROVED -> 4;
            case REJECTED -> 5;
            // FAILED
            default -> 6;
        };
    }

    @Override
    public OperationStatusDo convertToEntityAttribute(Integer b) {
        return switch (b) {
            case 1 -> OperationStatusDo.PENDING;
            case 2 -> OperationStatusDo.CANCELED;
            case 3 -> OperationStatusDo.EXPIRED;
            case 4 -> OperationStatusDo.APPROVED;
            case 5 -> OperationStatusDo.REJECTED;
            // 6
            default -> OperationStatusDo.FAILED;
        };
    }

}
