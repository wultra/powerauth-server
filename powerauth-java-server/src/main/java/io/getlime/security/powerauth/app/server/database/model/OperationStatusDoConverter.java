/*
 * PowerAuth Server and related software components
 * Copyright (C) 2020 Wultra s.r.o.
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
 * Converter between {@link OperationStatusDo} and integer values.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Converter
@Component
public class OperationStatusDoConverter implements AttributeConverter<OperationStatusDo, Integer> {

    @Override
    public Integer convertToDatabaseColumn(OperationStatusDo status) {
        switch (status) {
            case PENDING:
                return 1;
            case CANCELED:
                return 2;
            case EXPIRED:
                return 3;
            case APPROVED:
                return 4;
            case REJECTED:
                return 5;
            default: // FAILED
                return 6;
        }
    }

    @Override
    public OperationStatusDo convertToEntityAttribute(Integer b) {
        switch (b) {
            case 1:
                return OperationStatusDo.PENDING;
            case 2:
                return OperationStatusDo.CANCELED;
            case 3:
                return OperationStatusDo.EXPIRED;
            case 4:
                return OperationStatusDo.APPROVED;
            case 5:
                return OperationStatusDo.REJECTED;
            default: // 6
                return OperationStatusDo.FAILED;
        }
    }

}
