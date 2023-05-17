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

import io.getlime.security.powerauth.app.server.database.model.converter.*;
import io.getlime.security.powerauth.app.server.database.model.enumeration.OperationStatusDo;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import jakarta.persistence.*;
import org.hibernate.annotations.Mutability;

import java.io.Serial;
import java.io.Serializable;
import java.util.*;

/**
 * Entity representing an operation for approval.
 *
 * @author Petr Dvorak, petr@wutra.com
 */
@Entity
@Table(name = "pa_operation")
public class OperationEntity implements Serializable {

    @Serial
    private static final long serialVersionUID = -5284589668386509303L;

    @Id
    @Column(name = "id", updatable = false, length = 37)
    private String id;

    @Column(name = "user_id")
    private String userId;

    @ManyToMany
    @JoinTable(
            name = "pa_operation_application",
            joinColumns = @JoinColumn(name = "operation_id", referencedColumnName = "id", nullable = false),
            inverseJoinColumns = @JoinColumn(name = "application_id")
    )
    private List<ApplicationEntity> applications;

    @Column(name = "external_id")
    private String externalId;

    @Column(name = "activation_flag")
    private String activationFlag;

    @Column(name = "operation_type", nullable = false)
    private String operationType;

    @Column(name = "template_name", nullable = false)
    private String templateName;

    @Column(name = "data", nullable = false)
    private String data;

    @Column(name = "parameters")
    @Convert(converter = MapToJsonConverter.class)
    @Mutability(MapConverterMutabilityPlan.class)
    private Map<String, String> parameters = new HashMap<>();

    @Column(name = "additional_data")
    @Convert(converter = MapToJsonConverter.class)
    @Mutability(MapConverterMutabilityPlan.class)
    private Map<String, String> additionalData = new HashMap<>();

    @Column(name = "status", nullable = false)
    @Convert(converter = OperationStatusDoConverter.class)
    private OperationStatusDo status;

    @Column(name = "signature_type", nullable = false)
    @Convert(converter = SignatureTypeConverter.class)
    @Mutability(PowerAuthSignatureArrayConverterMutabilityPlan.class)
    private PowerAuthSignatureTypes[] signatureType;

    @Column(name = "failure_count", nullable = false)
    private Long failureCount;

    @Column(name = "max_failure_count", nullable = false)
    private Long maxFailureCount;

    @Column(name = "timestamp_created", nullable = false)
    private Date timestampCreated;

    @Column(name = "timestamp_expires", nullable = false)
    private Date timestampExpires;

    @Column(name = "timestamp_finalized")
    private Date timestampFinalized;

    @Column(name = "risk_flags")
    private String riskFlags;

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
     * Get application.
     * @return Application.
     */
    public List<ApplicationEntity> getApplications() {
        return applications;
    }

    /**
     * Set application ID.
     * @param applications Applications.
     */
    public void setApplications(List<ApplicationEntity> applications) {
        this.applications = applications;
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
     * Get activation flag required to be present.
     * @return Activation flag.
     */
    public String getActivationFlag() {
        return activationFlag;
    }

    /**
     * Set activation flag required to be present.
     * @param activationFlag Activation flag.
     */
    public void setActivationFlag(String activationFlag) {
        this.activationFlag = activationFlag;
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
     * Get template name used when creating this operation.
     * @return Template name.
     */
    public String getTemplateName() {
        return templateName;
    }

    /**
     * Set template name used when creating this operation.
     * @param templateName Template name.
     */
    public void setTemplateName(String templateName) {
        this.templateName = templateName;
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
    public Map<String, String> getParameters() {
        return parameters;
    }

    /**
     * Set operation parameters.
     * @param parameters Operation parameters.
     */
    public void setParameters(Map<String, String> parameters) {
        this.parameters = parameters;
    }

    /**
     * Get operation additional data set on operation approval or reject.
     * @return Additional data.
     */
    public Map<String, String> getAdditionalData() {
        return additionalData;
    }

    /**
     * Set operation additional data set on operation approval or reject.
     * @param additionalData Additional data.
     */
    public void setAdditionalData(Map<String, String> additionalData) {
        this.additionalData = additionalData;
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

    /**
     * Get risk flags.
     *
     * @return Risk flags.
     */
    public String getRiskFlags() {
        return riskFlags;
    }

    /**
     * Set risk flags.
     *
     * @param riskFlags Risk flags.
     */
    public void setRiskFlags(String riskFlags) {
        this.riskFlags = riskFlags;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof final OperationEntity that)) return false;
        return id.equals(that.id) // ID is generated on application level
                && userId.equals(that.userId)
                && applications.equals(that.applications)
                && activationFlag.equals(that.activationFlag)
                && operationType.equals(that.operationType)
                && templateName.equals(that.templateName)
                && data.equals(that.data)
                && Objects.equals(parameters, that.parameters)
                && Objects.equals(additionalData, that.additionalData)
                && Objects.equals(riskFlags, that.riskFlags);
    }

    @Override
    public int hashCode() {
        return Objects.hash(
                id, userId, applications, activationFlag, operationType, templateName, data, parameters, additionalData, riskFlags
        );
    }

    @Override
    public String toString() {
        return "OperationEntity{" +
                "id='" + id + '\'' +
                ", userId='" + userId + '\'' +
                ", applications=" + applications +
                ", externalId='" + externalId + '\'' +
                ", activationFlag='" + activationFlag + '\'' +
                ", operationType='" + operationType + '\'' +
                ", templateName='" + templateName + '\'' +
                ", data='" + data + '\'' +
                ", parameters=" + parameters +
                ", additionalData=" + additionalData +
                ", status=" + status +
                ", signatureType=" + Arrays.toString(signatureType) +
                ", failureCount=" + failureCount +
                ", maxFailureCount=" + maxFailureCount +
                ", timestampCreated=" + timestampCreated +
                ", timestampExpires=" + timestampExpires +
                ", timestampFinalized=" + timestampFinalized +
                ", riskFlags=" + riskFlags +
                '}';
    }
}
