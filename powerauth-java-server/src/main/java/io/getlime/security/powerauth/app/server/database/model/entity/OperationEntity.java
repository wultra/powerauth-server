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

package io.getlime.security.powerauth.app.server.database.model.entity;

import io.getlime.security.powerauth.app.server.database.model.OperationStatusDo;
import io.getlime.security.powerauth.app.server.database.model.OperationStatusDoConverter;
import io.getlime.security.powerauth.app.server.database.model.SignatureTypeConverter;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Arrays;
import java.util.Date;
import java.util.Objects;

/**
 * Entity representing an operation for approval.
 *
 * @author Petr Dvorak, petr@wutra.com
 */
@Entity
@Table(name = "pa_operation")
public class OperationEntity implements Serializable {

    private static final long serialVersionUID = -5284589668386509303L;

    @Id
    @Column(name = "id", updatable = false, length = 37)
    private String id;

    @Column(name = "user_id")
    private String userId;

    @Column(name = "application_id")
    private Long applicationId;

    @ManyToOne
    @JoinColumn(name = "template_id", referencedColumnName = "id", nullable = false)
    private OperationTemplateEntity template;

    @Column(name = "external_id")
    private String externalId;

    @Column(name = "operation_type")
    private String operationType;

    @Column(name = "data")
    private String data;

    @Column(name = "parameters")
    private String parameters;

    @Column(name = "status")
    @Convert(converter = OperationStatusDoConverter.class)
    private OperationStatusDo status;

    @Column(name = "signature_type")
    @Convert(converter = SignatureTypeConverter.class)
    private PowerAuthSignatureTypes[] signatureType;

    @Column(name = "failure_count")
    private Long failureCount;

    @Column(name = "max_failure_count")
    private Long maxFailureCount;

    @Column(name = "timestamp_created")
    private Date timestampCreated;

    @Column(name = "timestamp_expires")
    private Date timestampExpires;

    @Column(name = "timestamp_finalized")
    private Date timestampFinalized;

    /**
     * Get operation ID.
     * @return Operation ID.
     */
    public String getId() {
        return id;
    }

    /**
     * Set operation ID.
     * @param id Operation ID.
     */
    public void setId(String id) {
        this.id = id;
    }

    /**
     * Get user ID.
     * @return User ID.
     */
    public String getUserId() {
        return userId;
    }

    /**
     * Set user ID.
     * @param userId User ID.
     */
    public void setUserId(String userId) {
        this.userId = userId;
    }

    /**
     * Get application ID.
     * @return Application ID.
     */
    public Long getApplicationId() {
        return applicationId;
    }

    /**
     * Set application ID.
     * @param applicationId Application ID.
     */
    public void setApplicationId(Long applicationId) {
        this.applicationId = applicationId;
    }

    /**
     * Get template.
     * @return Template.
     */
    public OperationTemplateEntity getTemplate() {
        return template;
    }

    /**
     * Set template.
     * @param template Template.
     */
    public void setTemplate(OperationTemplateEntity template) {
        this.template = template;
    }

    /**
     * Get external ID.
     * @return External ID.
     */
    public String getExternalId() {
        return externalId;
    }

    /**
     * Set external ID.
     * @param externalId External ID.
     */
    public void setExternalId(String externalId) {
        this.externalId = externalId;
    }

    /**
     * Get operation type.
     * @return Operation type.
     */
    public String getOperationType() {
        return operationType;
    }

    /**
     * Set operation type.
     * @param operationType Operation type.
     */
    public void setOperationType(String operationType) {
        this.operationType = operationType;
    }

    /**
     * Get operation data.
     * @return Operation data.
     */
    public String getData() {
        return data;
    }

    /**
     * Set operation data.
     * @param data Operation data.
     */
    public void setData(String data) {
        this.data = data;
    }

    /**
     * Get operation parameters.
     * @return Operation parameters.
     */
    public String getParameters() {
        return parameters;
    }

    /**
     * Set operation parameters.
     * @param parameters Operation parameters.
     */
    public void setParameters(String parameters) {
        this.parameters = parameters;
    }

    /**
     * Get operation status.
     * @return Operation status.
     */
    public OperationStatusDo getStatus() {
        return status;
    }

    /**
     * Set operation status.
     * @param status Operation status.
     */
    public void setStatus(OperationStatusDo status) {
        this.status = status;
    }

    /**
     * Get signature type.
     * @return Signature type.
     */
    public PowerAuthSignatureTypes[] getSignatureType() {
        return signatureType;
    }

    /**
     * Set signature type.
     * @param signatureType Signature type.
     */
    public void setSignatureType(PowerAuthSignatureTypes[] signatureType) {
        this.signatureType = signatureType;
    }

    /**
     * Get failure count.
     * @return Failure count.
     */
    public Long getFailureCount() {
        return failureCount;
    }

    /**
     * Set failure count.
     * @param failureCount Failure count.
     */
    public void setFailureCount(Long failureCount) {
        this.failureCount = failureCount;
    }

    /**
     * Get maximum allowed failure count.
     * @return Maximum allowed failure count.
     */
    public Long getMaxFailureCount() {
        return maxFailureCount;
    }

    /**
     * Set maximum allowed failure count.
     * @param maxFailureCount Maximum allowed failure count.
     */
    public void setMaxFailureCount(Long maxFailureCount) {
        this.maxFailureCount = maxFailureCount;
    }

    /**
     * Get timestamp created.
     * @return Timestamp created.
     */
    public Date getTimestampCreated() {
        return timestampCreated;
    }

    /**
     * Set timestamp created.
     * @param timestampCreated Timestamp created.
     */
    public void setTimestampCreated(Date timestampCreated) {
        this.timestampCreated = timestampCreated;
    }

    /**
     * Get timestamp when operation expired.
     * @return Timestamp when operation expires.
     */
    public Date getTimestampExpires() {
        return timestampExpires;
    }

    /**
     * Get timestamp when operation expired.
     * @param timestampExpires Timestamp when operation expires.
     */
    public void setTimestampExpires(Date timestampExpires) {
        this.timestampExpires = timestampExpires;
    }

    /**
     * Get timestamp in which the operation was finalized (moved from PENDING state).
     * @return Timestamp when operation was finalized.
     */
    public Date getTimestampFinalized() {
        return timestampFinalized;
    }

    /**
     * Set timestamp in which the operation was finalized (moved from PENDING state).
     * @param timestampFinalized Timestamp when operation was finalized.
     */
    public void setTimestampFinalized(Date timestampFinalized) {
        this.timestampFinalized = timestampFinalized;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof OperationEntity)) return false;
        OperationEntity that = (OperationEntity) o;
        return Objects.equals(id, that.id)
                && Objects.equals(userId, that.userId)
                && Objects.equals(template, that.template)
                && Objects.equals(externalId, that.externalId)
                && Objects.equals(operationType, that.operationType)
                && Objects.equals(data, that.data)
                && Objects.equals(parameters, that.parameters)
                && status == that.status
                && Arrays.equals(signatureType, that.signatureType)
                && Objects.equals(failureCount, that.failureCount)
                && Objects.equals(maxFailureCount, that.maxFailureCount)
                && Objects.equals(timestampCreated, that.timestampCreated)
                && Objects.equals(timestampExpires, that.timestampExpires)
                && Objects.equals(timestampFinalized, that.timestampFinalized);
    }

    @Override
    public int hashCode() {
        return Objects.hash(
                id,
                userId,
                template,
                externalId,
                operationType,
                data,
                parameters,
                status,
                signatureType,
                failureCount,
                maxFailureCount,
                timestampCreated,
                timestampExpires,
                timestampFinalized
        );
    }

    @Override public String toString() {
        return "OperationEntity{" +
                "id='" + id + '\'' +
                ", userId='" + userId + '\'' +
                ", template=" + template.toString() +
                ", externalId='" + externalId + '\'' +
                ", operationType='" + operationType + '\'' +
                ", data='" + data + '\'' +
                ", parameters='" + parameters + '\'' +
                ", status=" + status +
                ", signatureType='" + Arrays.toString(signatureType) + '\'' +
                ", failureCount=" + failureCount +
                ", maxFailureCount=" + maxFailureCount +
                ", timestampCreated=" + timestampCreated +
                ", timestampExpires=" + timestampExpires +
                ", timestampFinalized=" + timestampFinalized +
                '}';
    }
}
