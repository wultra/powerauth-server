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

import io.getlime.security.powerauth.app.server.database.model.converter.MapToJsonConverter;
import io.getlime.security.powerauth.app.server.database.model.converter.OperationStatusDoConverter;
import io.getlime.security.powerauth.app.server.database.model.converter.SignatureTypeConverter;
import io.getlime.security.powerauth.app.server.database.model.enumeration.OperationStatusDo;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

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
@Getter @Setter
public class OperationEntity implements Serializable {

    @Serial
    private static final long serialVersionUID = -5284589668386509303L;

    /**
     * Operation ID.
     */
    @Id
    @Column(name = "id", updatable = false, length = 37)
    private String id;

    /**
     * User ID.
     */
    @Column(name = "user_id")
    private String userId;

    /**
     * Applications.
     */
    @ManyToMany
    @JoinTable(
            name = "pa_operation_application",
            joinColumns = @JoinColumn(name = "operation_id", referencedColumnName = "id", nullable = false),
            inverseJoinColumns = @JoinColumn(name = "application_id")
    )
    private List<ApplicationEntity> applications;

    /**
     * External ID.
     */
    @Column(name = "external_id")
    private String externalId;

    /**
     * Activation flag required to be present.
     */
    @Column(name = "activation_flag")
    private String activationFlag;

    /**
     * Operation type.
     */
    @Column(name = "operation_type", nullable = false)
    private String operationType;

    /**
     * Template name used when creating this operation.
     */
    @Column(name = "template_name", nullable = false)
    private String templateName;

    /**
     * Operation data.
     */
    @Column(name = "data", nullable = false)
    private String data;

    /**
     * Operation parameters.
     */
    @Column(name = "parameters")
    @Convert(converter = MapToJsonConverter.class)
    private Map<String, String> parameters = new HashMap<>();

    /**
     * Operation additional data set on operation approval or reject.
     */
    @Column(name = "additional_data")
    @Convert(converter = MapToJsonConverter.class)
    private Map<String, Object> additionalData = new HashMap<>();

    /**
     * Operation status.
     */
    @Column(name = "status", nullable = false)
    @Convert(converter = OperationStatusDoConverter.class)
    private OperationStatusDo status;

    /**
     * Optional details why the status has changed.
     * The value should be sent in the form of a computer-readable code, not a free-form text.
     */
    @Column(name = "status_reason", length = 32)
    private String statusReason;

    /**
     * Signature types.
     */
    @Column(name = "signature_type", nullable = false)
    @Convert(converter = SignatureTypeConverter.class)
    private PowerAuthSignatureTypes[] signatureType;

    /**
     * Failure count.
     */
    @Column(name = "failure_count", nullable = false)
    private Long failureCount;

    /**
     * Maximum allowed failure count.
     */
    @Column(name = "max_failure_count", nullable = false)
    private Long maxFailureCount;

    /**
     * Timestamp created.
     */
    @Column(name = "timestamp_created", nullable = false)
    private Date timestampCreated;

    /**
     * Timestamp when operation expired.
     */
    @Column(name = "timestamp_expires", nullable = false)
    private Date timestampExpires;

    /**
     * Timestamp in which the operation was finalized (moved from PENDING state).
     */
    @Column(name = "timestamp_finalized")
    private Date timestampFinalized;

    /**
     * The risk flags.
     */
    @Column(name = "risk_flags")
    private String riskFlags;

    /**
     * Optional TOTP seed used for proximity check, base64 encoded.
     */
    @Column(name = "totp_seed")
    private String totpSeed;

    /**
     * Optional activationId of a device.
     */
    @Column(name = "activation_id")
    private String activationId;

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
                && Objects.equals(riskFlags, that.riskFlags)
                && Objects.equals(totpSeed, that.totpSeed);
    }

    @Override
    public int hashCode() {
        return Objects.hash(
                id, userId, applications, activationFlag, operationType, templateName, data, parameters, additionalData, riskFlags, totpSeed
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
                ", status_reason=" + statusReason +
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
