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

import io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationOtpValidation;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.springframework.stereotype.Component;

/**
 * Converter between {@link ActivationOtpValidation} enumeration and integer values.
 */
@Converter
@Component
public class ActivationOtpValidationConverter implements AttributeConverter<ActivationOtpValidation, Integer> {

    /**
     * Convert {@link ActivationOtpValidation} enum into integer value
     * @param validation Enumeration to convert.
     * @return Integer representation of {@link ActivationOtpValidation} enumeration.
     */
    @Override
    public Integer convertToDatabaseColumn(ActivationOtpValidation validation) {
        return (int) validation.getByte();
    }

    /**
     * Convert integer value into {@link ActivationOtpValidation} enumeration.
     * @param value Integer value to convert.
     * @return {@link ActivationOtpValidation} enumeration.
     */
    @Override
    public ActivationOtpValidation convertToEntityAttribute(Integer value) {
        return switch (value) {
            case 1 -> ActivationOtpValidation.ON_KEY_EXCHANGE;
            case 2 -> ActivationOtpValidation.ON_COMMIT;
            default -> ActivationOtpValidation.NONE;
        };
    }
}
