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

package com.wultra.security.powerauth.client.model.response;

import com.wultra.security.powerauth.client.model.enumeration.SignatureType;

import java.util.List;

/**
 * Model object representing operation template.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class OperationTemplateDetailResponse {

    private Long id;
    private String templateName;
    private String operationType;
    private String dataTemplate;
    private List<SignatureType> signatureType;
    private Long maxFailureCount;
    private Long expiration;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

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

    public void setSignatureType(List<SignatureType> signatureType) {
        this.signatureType = signatureType;
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
}
