/*
 * PowerAuth Server and related software components
 * Copyright (C) 2021 Wultra s.r.o.
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

package com.wultra.security.powerauth.client.model.request;

import com.wultra.security.powerauth.client.model.enumeration.SignatureType;

import java.util.ArrayList;
import java.util.List;

/**
 * Request to create a new operation template.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class OperationTemplateCreateRequest {

    private String templateName;
    private String operationType;
    private String dataTemplate;
    private final List<SignatureType> signatureType = new ArrayList<>();
    private Long maxFailureCount;
    private Long expiration;

    public String getTemplateName() {
        return templateName;
    }

    public void setTemplateName(String templateName) {
        this.templateName = templateName;
    }

    public String getOperationType() {
        return operationType;
    }

    public void setOperationType(String operationType) {
        this.operationType = operationType;
    }

    public String getDataTemplate() {
        return dataTemplate;
    }

    public void setDataTemplate(String dataTemplate) {
        this.dataTemplate = dataTemplate;
    }

    public List<SignatureType> getSignatureType() {
        return signatureType;
    }

    public Long getMaxFailureCount() {
        return maxFailureCount;
    }

    public void setMaxFailureCount(Long maxFailureCount) {
        this.maxFailureCount = maxFailureCount;
    }

    public Long getExpiration() {
        return expiration;
    }

    public void setExpiration(Long expiration) {
        this.expiration = expiration;
    }

    @Override
    public String toString() {
        return "OperationTemplateCreateRequest{" +
                "templateName='" + templateName + '\'' +
                ", operationType='" + operationType + '\'' +
                ", dataTemplate='" + dataTemplate + '\'' +
                ", signatureType=" + signatureType +
                ", maxFailureCount=" + maxFailureCount +
                ", expiration=" + expiration +
                '}';
    }
}
