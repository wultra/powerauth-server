/*
 * PowerAuth Server and related software components
 * Copyright (C) 2024 Wultra s.r.o.
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
package io.getlime.security.powerauth.app.server.converter;

import io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationProtocol;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.springframework.util.StringUtils;

/**
 * Specialization of {@link AttributeConverter} converting {@link ActivationProtocol} and {@link String}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@Converter
public class ActivationProtocolConverter implements AttributeConverter<ActivationProtocol, String>  {

    @Override
    public String convertToDatabaseColumn(final ActivationProtocol attribute) {
        if (attribute == null) {
            return null;
        }
        return attribute.name().toLowerCase();
    }

    @Override
    public ActivationProtocol convertToEntityAttribute(final String dbData) {
        if (!StringUtils.hasText(dbData)) {
            return null;
        }
        return ActivationProtocol.valueOf(dbData.toUpperCase());
    }
}
