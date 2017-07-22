/*
 * PowerAuth Server and related software components
 * Copyright (C) 2017 Lime - HighTech Solutions s.r.o.
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
package io.getlime.security.powerauth.app.server.repository.model;

import org.springframework.stereotype.Component;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

/**
 * Converter between {@link ActivationStatus} and integer values.
 *
 * @author Petr Dvorak
 */
@Converter
@Component
public class ActivationStatusConverter implements AttributeConverter<ActivationStatus, Integer> {

    @Override
    public Integer convertToDatabaseColumn(ActivationStatus status) {
        return new Integer(status.getByte());
    }

    @Override
    public ActivationStatus convertToEntityAttribute(Integer b) {
        switch (b) {
            case 1:
                return ActivationStatus.CREATED;
            case 2:
                return ActivationStatus.OTP_USED;
            case 3:
                return ActivationStatus.ACTIVE;
            case 4:
                return ActivationStatus.BLOCKED;
            default:
                return ActivationStatus.REMOVED;
        }
    }

}
