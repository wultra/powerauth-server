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

import io.getlime.security.powerauth.app.server.database.model.enumeration.CallbackUrlType;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.springframework.stereotype.Component;


/**
 * Converter for callback URL types.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Converter
@Component
public class CallbackUrlTypeConverter implements AttributeConverter<CallbackUrlType, String> {

    @Override
    public String convertToDatabaseColumn(CallbackUrlType callbackUrlType) {
        if (callbackUrlType == null) {
            return null;
        }
        return callbackUrlType.toString();
    }

    @Override
    public CallbackUrlType convertToEntityAttribute(String s) {
        if (s == null) {
            return null;
        }
        return CallbackUrlType.valueOf(s);
    }
}
