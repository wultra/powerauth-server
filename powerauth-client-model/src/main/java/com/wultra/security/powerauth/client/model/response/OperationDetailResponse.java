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

package com.wultra.security.powerauth.client.model.response;

import com.wultra.security.powerauth.client.model.enumeration.OperationStatus;

import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Response object for creating the operation.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class OperationDetailResponse {

    private String id;
    private String userId;
    private Long applicationId;
    private String templateName;
    private String externalId;
    private String operationType;
    private String data;
    private Map<String, String> parameters;
    private OperationStatus status;
    private List<String> signatureType;
    private long failureCount;
    private Long maxFailureCount;
    private Date timestampCreated;
    private Date timestampExpires;
    private Date timestampFinalized;

    public void setId(String id) {
        this.id = id;
    }

    public String getId() {
        return id;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getUserId() {
        return userId;
    }

    public void setApplicationId(Long applicationId) {
        this.applicationId = applicationId;
    }

    public Long getApplicationId() {
        return applicationId;
    }

    public String getTemplateName() {
        return templateName;
    }

    public void setTemplateName(String templateName) {
        this.templateName = templateName;
    }

    public void setExternalId(String externalId) {
        this.externalId = externalId;
    }

    public String getExternalId() {
        return externalId;
    }

    public void setOperationType(String operationType) {
        this.operationType = operationType;
    }

    public String getOperationType() {
        return operationType;
    }

    public void setData(String data) {
        this.data = data;
    }

    public String getData() {
        return data;
    }

    public void setParameters(Map<String, String> parameters) {
        this.parameters = parameters;
    }

    public Map<String, String> getParameters() {
        return parameters;
    }

    public void setStatus(OperationStatus status) {
        this.status = status;
    }

    public OperationStatus getStatus() {
        return status;
    }

    public void setSignatureType(List<String> signatureType) {
        this.signatureType = signatureType;
    }

    public List<String> getSignatureType() {
        return signatureType;
    }

    public void setFailureCount(long failureCount) {
        this.failureCount = failureCount;
    }

    public long getFailureCount() {
        return failureCount;
    }

    public void setMaxFailureCount(Long maxFailureCount) {
        this.maxFailureCount = maxFailureCount;
    }

    public Long getMaxFailureCount() {
        return maxFailureCount;
    }

    public void setTimestampCreated(Date timestampCreated) {
        this.timestampCreated = timestampCreated;
    }

    public Date getTimestampCreated() {
        return timestampCreated;
    }

    public void setTimestampExpires(Date timestampExpires) {
        this.timestampExpires = timestampExpires;
    }

    public Date getTimestampExpires() {
        return timestampExpires;
    }

    public void setTimestampFinalized(Date timestampFinalized) {
        this.timestampFinalized = timestampFinalized;
    }

    public Date getTimestampFinalized() {
        return timestampFinalized;
    }
}
