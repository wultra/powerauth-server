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

package com.wultra.security.powerauth.app.server.converter.v3;

import com.wultra.security.powerauth.client.model.enumeration.v3.SignatureType;
import com.wultra.security.powerauth.client.model.request.v3.OperationTemplateCreateRequest;
import com.wultra.security.powerauth.client.model.request.v3.OperationTemplateUpdateRequest;
import com.wultra.security.powerauth.client.model.response.v3.OperationTemplateDetailResponse;
import com.wultra.security.powerauth.app.server.database.model.entity.OperationTemplateEntity;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Converter for operation template related use-cases.
 *
 * @author Petr Dvorak, petr@wultra.com
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component("operationTemplateConverterV3")
public class OperationTemplateConverter {

    public OperationTemplateEntity convertToDB(OperationTemplateCreateRequest source) {
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

        final List<PowerAuthCodeType> authCodeTypes = new ArrayList<>();
        for (final SignatureType type : source.getSignatureType()) {
            final PowerAuthCodeType powerAuthCodeType = PowerAuthCodeType.getEnumFromString(type.toString());
            if (!authCodeTypes.contains(powerAuthCodeType)) {
                authCodeTypes.add(powerAuthCodeType);
            }
        }
        final PowerAuthCodeType[] typesArray = authCodeTypes.toArray(new PowerAuthCodeType[0]);
        destination.setSignatureType(typesArray);

        return destination;
    }

    public OperationTemplateEntity convertToDB(OperationTemplateEntity original, OperationTemplateUpdateRequest source) {
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

        final List<PowerAuthCodeType> authCodeTypes = new ArrayList<>();
        for (final SignatureType type : source.getSignatureType()) {
            final PowerAuthCodeType powerAuthCodeType = PowerAuthCodeType.getEnumFromString(type.toString());
            if (!authCodeTypes.contains(powerAuthCodeType)) {
                authCodeTypes.add(powerAuthCodeType);
            }
        }
        final PowerAuthCodeType[] typesArray = authCodeTypes.toArray(new PowerAuthCodeType[0]);
        original.setSignatureType(typesArray);

        return original;
    }

    public OperationTemplateDetailResponse convertFromDB(OperationTemplateEntity source) {
        final OperationTemplateDetailResponse destination = new OperationTemplateDetailResponse();
        destination.setId(source.getId());
        destination.setTemplateName(source.getTemplateName());
        destination.setOperationType(source.getOperationType());
        destination.setDataTemplate(source.getDataTemplate());
        destination.setExpiration(source.getExpiration());
        destination.setMaxFailureCount(source.getMaxFailureCount());
        destination.setRiskFlags(source.getRiskFlags());
        destination.setProximityCheckEnabled(source.isProximityCheckEnabled());
        final List<SignatureType> signatureTypesResponse = new ArrayList<>();
        for (final PowerAuthCodeType type : source.getSignatureType()) {
            final SignatureType signatureType = SignatureType.enumFromString(type.toString());
            if (!signatureTypesResponse.contains(signatureType)) {
                signatureTypesResponse.add(signatureType);
            }
        }
        destination.setSignatureType(signatureTypesResponse);
        return destination;
    }

}
