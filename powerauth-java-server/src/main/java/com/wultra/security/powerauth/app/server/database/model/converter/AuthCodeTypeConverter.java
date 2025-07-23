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

package com.wultra.security.powerauth.app.server.database.model.converter;

import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author Petr Dvorak, petr@wultra.com
 */
@Converter
@Component
public class AuthCodeTypeConverter implements AttributeConverter<PowerAuthCodeType[], String> {

    @Override
    public String convertToDatabaseColumn(PowerAuthCodeType[] authCodeTypes) {
        if (authCodeTypes == null) {
            return null;
        }
        return Arrays.stream(authCodeTypes)
                .map(PowerAuthCodeType::toString)
                .collect(Collectors.joining(","));
    }

    @Override
    public PowerAuthCodeType[] convertToEntityAttribute(String authCodeTypes) {
        if (authCodeTypes == null) {
            return null;
        }
        final String[] factorStrings = authCodeTypes.split(",");
        List<PowerAuthCodeType> result = new ArrayList<>();
        for (String factorString : factorStrings) {
            final PowerAuthCodeType authCodeType = PowerAuthCodeType.getEnumFromString(factorString);
            if (authCodeType != null) {
                result.add(authCodeType);
            }
        }
        return result.toArray(new PowerAuthCodeType[0]);
    }

}
