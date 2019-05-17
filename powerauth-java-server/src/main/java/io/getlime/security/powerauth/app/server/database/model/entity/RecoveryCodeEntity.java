/*
 * PowerAuth Server and related software components
 * Copyright (C) 2019 Wultra s.r.o.
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

import io.getlime.security.powerauth.app.server.database.model.RecoveryCodeStatus;
import io.getlime.security.powerauth.app.server.database.model.RecoveryCodeStatusConverter;

import javax.persistence.*;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * Database entity for recovery codes.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Entity
@Table(name = "pa_recovery_code")
public class RecoveryCodeEntity implements Serializable {

    private static final long serialVersionUID = 3356659945010116930L;

    @Id
    @SequenceGenerator(name = "pa_recovery_code", sequenceName = "pa_recovery_code_seq")
    @GeneratedValue(strategy = GenerationType.AUTO, generator = "pa_recovery_code")
    @Column(name = "id")
    private Long id;

    @Column(name = "recovery_code", nullable = false, updatable = false)
    private String recoveryCode;

    @Column(name = "application_id", nullable = false, updatable = false)
    private Long applicationId;

    @Column(name = "user_id", nullable = false, updatable = false)
    private String userId;

    @Column(name = "activation_id", nullable = true)
    private String activationId;

    @Column(name = "status", nullable = false)
    @Convert(converter = RecoveryCodeStatusConverter.class)
    private RecoveryCodeStatus status;

    @Column(name = "failed_attempts", nullable = false)
    private Long failedAttempts;

    @Column(name = "max_failed_attempts", nullable = false)
    private Long maxFailedAttempts;

    @Column(name = "timestamp_created", nullable = false)
    private Date timestampCreated;

    @Column(name = "timestamp_last_used", nullable = false)
    private Date timestampLastUsed;

    @Column(name = "timestamp_last_change", nullable = true)
    private Date timestampLastChange;

    @OneToMany(mappedBy = "recoveryCode", cascade = CascadeType.ALL)
    @OrderBy("puk_index")
    private List<RecoveryPukEntity> recoveryPuks = new ArrayList<>();

    /**
     * Default constructor.
     */
    public RecoveryCodeEntity() {
    }

    /**
     * Constructor with all parameters.
     *
     * @param id Recovery code ID.
     * @param recoveryCode Recovery code.
     * @param applicationId Application ID.
     * @param userId User ID.
     * @param activationId Activation ID.
     * @param status Recovery code status.
     * @param failedAttempts Failed attempts.
     * @param maxFailedAttempts Maximum failed attempts.
     * @param timestampCreated Created timestamp.
     * @param timestampLastUsed Last usage timestamp.
     * @param timestampLastChange Last change timestamp.
     */
    public RecoveryCodeEntity(Long id,
                              String recoveryCode,
                              Long applicationId,
                              String userId,
                              String activationId,
                              RecoveryCodeStatus status,
                              Long failedAttempts,
                              Long maxFailedAttempts,
                              Date timestampCreated,
                              Date timestampLastUsed,
                              Date timestampLastChange) {
        this.id = id;
        this.recoveryCode = recoveryCode;
        this.applicationId = applicationId;
        this.userId = userId;
        this.activationId = activationId;
        this.status = status;
        this.failedAttempts = failedAttempts;
        this.maxFailedAttempts = maxFailedAttempts;
        this.timestampCreated = timestampCreated;
        this.timestampLastUsed = timestampLastUsed;
        this.timestampLastChange = timestampLastChange;
    }

    /**
     * Get recovery code entity ID.
     * @return Recovery code entity ID.
     */
    public Long getId() {
        return id;
    }

    /**
     * Set recovery code entity ID.
     * @param id Recovery code entity ID.
     */
    public void setId(Long id) {
        this.id = id;
    }

    /**
     * Get recovery code.
     * @return Recovery code.
     */
    public String getRecoveryCode() {
        return recoveryCode;
    }

    /**
     * Get masked recovery code.
     * @return Masked recovery code.
     */
    public String getRecoveryCodeMasked() {
        if (recoveryCode == null || recoveryCode.length() != 23) {
            return "";
        }
        return "XXXXX-XXXXX-XXXXX-" + recoveryCode.substring(18);
    }

    /**
     * Set recovery code.
     * @param recoveryCode Recovery code.
     */
    public void setRecoveryCode(String recoveryCode) {
        this.recoveryCode = recoveryCode;
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
     * Get activation ID.
     * @return Activation ID.
     */
    public String getActivationId() {
        return activationId;
    }

    /**
     * Set activation ID.
     * @param activationId Activation ID.
     */
    public void setActivationId(String activationId) {
        this.activationId = activationId;
    }

    /**
     * Get recovery code status.
     * @return Recovery code status.
     */
    public RecoveryCodeStatus getStatus() {
        return status;
    }

    /**
     * Set recovery code status.
     * @param status Recovery code status.
     */
    public void setStatus(RecoveryCodeStatus status) {
        this.status = status;
    }

    /**
     * Get failed attempts.
     * @return Failed attempts.
     */
    public Long getFailedAttempts() {
        return failedAttempts;
    }

    /**
     * Set failed attempts.
     * @param failedAttempts Failed attempts.
     */
    public void setFailedAttempts(Long failedAttempts) {
        this.failedAttempts = failedAttempts;
    }

    /**
     * Get maximum failed attempts.
     * @return Maximum failed attempts.
     */
    public Long getMaxFailedAttempts() {
        return maxFailedAttempts;
    }

    /**
     * Set maximum failed attempts.
     * @param maxFailedAttempts Maximum failed attempts.
     */
    public void setMaxFailedAttempts(Long maxFailedAttempts) {
        this.maxFailedAttempts = maxFailedAttempts;
    }

    /**
     * Get timestamp when recovery code was created.
     * @return Timestamp when recovery code was created.
     */
    public Date getTimestampCreated() {
        return timestampCreated;
    }

    /**
     * Set timestamp when recovery code was created.
     * @param timestampCreated Timestamp when recovery code was created.
     */
    public void setTimestampCreated(Date timestampCreated) {
        this.timestampCreated = timestampCreated;
    }

    /**
     * Get timestamp when recovery code was used last time.
     * @return Timestamp when recovery code was used last time.
     */
    public Date getTimestampLastUsed() {
        return timestampLastUsed;
    }

    /**
     * Set timestamp when recovery code was used last time.
     * @param timestampLastUsed Timestamp when recovery code was used last time.
     */
    public void setTimestampLastUsed(Date timestampLastUsed) {
        this.timestampLastUsed = timestampLastUsed;
    }

    /**
     * Get timestamp when recovery code status changed last time.
     * @return Timestamp when recovery code status changed last time.
     */
    public Date getTimestampLastChange() {
        return timestampLastChange;
    }

    /**
     * Set timestamp when recovery code status changed last time.
     * @param timestampLastChange Timestamp when recovery code status changed last time.
     */
    public void setTimestampLastChange(Date timestampLastChange) {
        this.timestampLastChange = timestampLastChange;
    }

    /**
     * Get recovery PUKs.
     * @return Recovery PUKs.
     */
    public List<RecoveryPukEntity> getRecoveryPuks() {
        return recoveryPuks;
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 71 * hash + Objects.hashCode(this.recoveryCode);
        hash = 71 * hash + Objects.hashCode(this.applicationId);
        hash = 71 * hash + Objects.hashCode(this.userId);
        hash = 71 * hash + Objects.hashCode(this.activationId);
        hash = 71 * hash + Objects.hashCode(this.status);
        hash = 71 * hash + Objects.hashCode(this.failedAttempts);
        hash = 71 * hash + Objects.hashCode(this.maxFailedAttempts);
        hash = 71 * hash + Objects.hashCode(this.timestampCreated);
        hash = 71 * hash + Objects.hashCode(this.timestampLastUsed);
        hash = 71 * hash + Objects.hashCode(this.timestampLastChange);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final RecoveryCodeEntity other = (RecoveryCodeEntity) obj;
        if (!Objects.equals(this.recoveryCode, other.recoveryCode)) {
            return false;
        }
        if (!Objects.equals(this.applicationId, other.applicationId)) {
            return false;
        }
        if (!Objects.equals(this.userId, other.userId)) {
            return false;
        }
        if (!Objects.equals(this.activationId, other.activationId)) {
            return false;
        }
        if (!Objects.equals(this.status, other.status)) {
            return false;
        }
        if (!Objects.equals(this.failedAttempts, other.failedAttempts)) {
            return false;
        }
        if (!Objects.equals(this.maxFailedAttempts, other.maxFailedAttempts)) {
            return false;
        }
        if (!Objects.equals(this.timestampCreated, other.timestampCreated)) {
            return false;
        }
        if (!Objects.equals(this.timestampLastUsed, other.timestampLastUsed)) {
            return false;
        }
        return Objects.equals(this.timestampLastChange, other.timestampLastChange);
    }

    @Override
    public String toString() {
        return "RecoveryCodeEntity{"
                + "id=" + id
                + ", applicationId=" + applicationId
                + ", userId=" + userId
                + ", activationId=" + activationId
                + ", status=" + status
                + ", failedAttempts=" + failedAttempts
                + ", maxFailedAttempts=" + maxFailedAttempts
                + ", timestampCreated=" + timestampCreated
                + ", timestampLastUsed=" + timestampLastUsed
                + ", timestampLastChange=" + timestampLastChange
                + '}';
    }

}
