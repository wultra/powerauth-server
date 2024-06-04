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

import io.getlime.security.powerauth.app.server.database.model.converter.RecoveryCodeStatusConverter;
import io.getlime.security.powerauth.app.server.database.model.enumeration.RecoveryCodeStatus;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.io.Serial;
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
@Getter @Setter
public class RecoveryCodeEntity implements Serializable {

    @Serial
    private static final long serialVersionUID = 3356659945010116930L;

    /**
     * Recovery code entity ID.
     */
    @Id
    @SequenceGenerator(name = "pa_recovery_code", sequenceName = "pa_recovery_code_seq", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.AUTO, generator = "pa_recovery_code")
    @Column(name = "id")
    private Long id;

    /**
     * Recovery code.
     */
    @Column(name = "recovery_code", nullable = false, updatable = false)
    private String recoveryCode;

    /**
     * Application.
     */
    @ManyToOne
    @JoinColumn(name = "application_id", referencedColumnName = "id", nullable = false, updatable = false)
    private ApplicationEntity application;

    /**
     * User ID.
     */
    @Column(name = "user_id", nullable = false, updatable = false)
    private String userId;

    /**
     * Activation ID.
     */
    @Column(name = "activation_id")
    private String activationId;

    /**
     * Recovery code status.
     */
    @Column(name = "status", nullable = false)
    @Convert(converter = RecoveryCodeStatusConverter.class)
    private RecoveryCodeStatus status;

    /**
     * Failed attempts.
     */
    @Column(name = "failed_attempts", nullable = false)
    private Long failedAttempts;

    /**
     * Maximum failed attempts.
     */
    @Column(name = "max_failed_attempts", nullable = false)
    private Long maxFailedAttempts;

    /**
     * Timestamp when recovery code was created.
     */
    @Column(name = "timestamp_created", nullable = false)
    private Date timestampCreated;

    /**
     * Timestamp when recovery code was used last time.
     */
    @Column(name = "timestamp_last_used")
    private Date timestampLastUsed;

    /**
     * Timestamp when recovery code status changed last time.
     */
    @Column(name = "timestamp_last_change")
    private Date timestampLastChange;

    /**
     * Recovery PUKs.
     */
    @OneToMany(mappedBy = "recoveryCode", cascade = CascadeType.ALL)
    @OrderBy("pukIndex")
    private final List<RecoveryPukEntity> recoveryPuks = new ArrayList<>();

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

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 71 * hash + Objects.hashCode(this.recoveryCode);
        hash = 71 * hash + Objects.hashCode(this.application);
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
        if (!Objects.equals(this.application, other.application)) {
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
                + ", application=" + application.toString()
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
