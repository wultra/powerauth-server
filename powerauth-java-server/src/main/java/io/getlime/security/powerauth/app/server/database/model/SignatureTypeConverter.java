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

import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import org.springframework.stereotype.Component;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author Petr Dvorak, petr@wultra.com
 */
@Converter
@Component
public class SignatureTypeConverter implements AttributeConverter<PowerAuthSignatureTypes[], String> {

    @Override
    public String convertToDatabaseColumn(PowerAuthSignatureTypes[] powerAuthSignatureTypes) {
        if (powerAuthSignatureTypes == null) {
            return null;
        }
        return Arrays.stream(powerAuthSignatureTypes)
                .map(PowerAuthSignatureTypes::toString)
                .collect(Collectors.joining(","));
    }

    @Override
    public PowerAuthSignatureTypes[] convertToEntityAttribute(String signatures) {
        if (signatures == null) {
            return null;
        }
        final String[] factorStrings = signatures.split(",");
        List<PowerAuthSignatureTypes> result = new ArrayList<>();
        for (String factorString : factorStrings) {
            final PowerAuthSignatureTypes signatureType = PowerAuthSignatureTypes.getEnumFromString(factorString);
            if (signatureType != null) {
                result.add(signatureType);
            }
        }
        return result.toArray(new PowerAuthSignatureTypes[0]);
    }

}
