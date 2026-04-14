/*
 * PowerAuth Server and related software components
 * Copyright (C) 2025 Wultra s.r.o.
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
 *
 */

package com.wultra.security.powerauth.app.server.converter.v4;

import com.wultra.security.powerauth.app.server.converter.AuthenticationCodeTypeConverter;
import com.wultra.security.powerauth.app.server.database.model.entity.OperationTemplateEntity;
import com.wultra.security.powerauth.client.model.enumeration.v4.AuthenticationCodeType;
import com.wultra.security.powerauth.client.model.request.v4.OperationTemplateCreateRequest;
import com.wultra.security.powerauth.client.model.request.v4.OperationTemplateUpdateRequest;
import com.wultra.security.powerauth.client.model.response.v4.OperationTemplateDetailResponse;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.util.Arrays;
import java.util.List;

/**
 * Converter for operation template related use-cases.
 *
 * @author Petr Dvorak, petr@wultra.com
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class OperationTemplateConverter {

    public static OperationTemplateEntity convertToDB(final OperationTemplateCreateRequest source) {
        if (source == null) {
            return null;
        }
        final OperationTemplateEntity destination = new OperationTemplateEntity();
        destination.setTemplateName(source.getTemplateName());
        destination.setOperationType(source.getOperationType());
        destination.setDataTemplate(source.getDataTemplate());
        destination.setMaxFailureCount(source.getMaxFailureCount());
        destination.setExpiration(source.getExpiration());
        destination.setRiskFlags(source.getRiskFlags());
        destination.setProximityCheckEnabled(source.isProximityCheckEnabled());

        final PowerAuthCodeType[] typesArray = source.getAuthenticationCodeType().stream()
                .map(AuthenticationCodeTypeConverter::convert)
                .distinct()
                .toArray(PowerAuthCodeType[]::new);
        destination.setSignatureType(typesArray);

        return destination;
    }

    public static OperationTemplateEntity convertToDB(final OperationTemplateEntity original, final OperationTemplateUpdateRequest source) {
        if (original == null || source == null) {
            return original;
        }
        original.setId(source.getId());
        original.setOperationType(source.getOperationType());
        original.setDataTemplate(source.getDataTemplate());
        original.setMaxFailureCount(source.getMaxFailureCount());
        original.setExpiration(source.getExpiration());
        original.setRiskFlags(source.getRiskFlags());
        original.setProximityCheckEnabled(source.isProximityCheckEnabled());

        final PowerAuthCodeType[] typesArray = source.getAuthenticationCodeType().stream()
                .map(AuthenticationCodeTypeConverter::convert)
                .distinct()
                .toArray(PowerAuthCodeType[]::new);
        original.setSignatureType(typesArray);

        return original;
    }

    public static OperationTemplateDetailResponse convertFromDB(final OperationTemplateEntity source) {
        final OperationTemplateDetailResponse destination = new OperationTemplateDetailResponse();
        destination.setId(source.getId());
        destination.setTemplateName(source.getTemplateName());
        destination.setOperationType(source.getOperationType());
        destination.setDataTemplate(source.getDataTemplate());
        destination.setExpiration(source.getExpiration());
        destination.setMaxFailureCount(source.getMaxFailureCount());
        destination.setRiskFlags(source.getRiskFlags());
        destination.setProximityCheckEnabled(source.isProximityCheckEnabled());

        final List<AuthenticationCodeType> authenticationCodeTypesResponse = Arrays.stream(source.getSignatureType())
                .map(AuthenticationCodeTypeConverter::convert)
                .distinct()
                .toList();
        destination.setAuthenticationCodeTypes(authenticationCodeTypesResponse);
        return destination;
    }

}
