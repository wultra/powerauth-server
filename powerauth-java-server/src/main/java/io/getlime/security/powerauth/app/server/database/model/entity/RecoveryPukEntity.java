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

import io.getlime.security.powerauth.app.server.database.model.RecoveryPukStatus;
import io.getlime.security.powerauth.app.server.database.model.RecoveryPukStatusConverter;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Date;
import java.util.Objects;

/**
 * Database entity for recovery PUKs.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Entity
@Table(name = "pa_recovery_puk")
public class RecoveryPukEntity implements Serializable {

    private static final long serialVersionUID = 1836238476585497799L;

    @Id
    @SequenceGenerator(name = "pa_recovery_puk", sequenceName = "pa_recovery_puk_seq")
    @GeneratedValue(strategy = GenerationType.AUTO, generator = "pa_recovery_puk")
    @Column(name = "id")
    private Long id;

    @ManyToOne
    @JoinColumn(name = "recovery_code_id", referencedColumnName = "id", nullable = false, updatable = false)
    private RecoveryCodeEntity recoveryCode;

    @Column(name = "puk", nullable = false)
    private String puk;

    @Column(name = "puk_index", nullable = false, updatable = false)
    private Long pukIndex;

    @Column(name = "status", nullable = false)
    @Convert(converter = RecoveryPukStatusConverter.class)
    private RecoveryPukStatus status;

    @Column(name = "timestamp_last_change", nullable = true)
    private Date timestampLastChange;

    /**
     * Default constructor.
     */
    public RecoveryPukEntity() {
    }

    /**
     * Constructor with all parameters.
     *
     * @param id Recovery PUK ID.
     * @param recoveryCode Recovery code.
     * @param puk PUK value.
     * @param pukIndex PUK index.
     * @param status PUK status.
     * @param timestampLastChange Last change timestamp.
     */
    public RecoveryPukEntity(Long id,
                             RecoveryCodeEntity recoveryCode,
                             String puk,
                             Long pukIndex,
                             RecoveryPukStatus status,
                             Date timestampLastChange) {
        this.id = id;
        this.recoveryCode = recoveryCode;
        this.puk = puk;
        this.pukIndex = pukIndex;
        this.status = status;
        this.timestampLastChange = timestampLastChange;
    }

    /**
     * Get recovery PUK entity ID.
     * @return Recovery PUK entity ID.
     */
    public Long getId() {
        return id;
    }

    /**
     * Set recovery PUK entity ID.
     * @param id Recoverz PUK entity ID.
     */
    public void setId(Long id) {
        this.id = id;
    }

    /**
     * Get recovery code for which this PUK is defined.
     * @return Recovery code.
     */
    public RecoveryCodeEntity getRecoveryCode() {
        return recoveryCode;
    }

    /**
     * Set recovery code for which this PUK is defined.
     * @param recoveryCode Recovery code.
     */
    public void setRecoveryCode(RecoveryCodeEntity recoveryCode) {
        this.recoveryCode = recoveryCode;
    }

    /**
     * Get PUK value.
     * @return PUK value.
     */
    public String getPuk() {
        return puk;
    }

    /**
     * Set PUK value.
     * @param puk PUK value.
     */
    public void setPuk(String puk) {
        this.puk = puk;
    }

    /**
     * Get PUK index.
     * @return PUK index.
     */
    public Long getPukIndex() {
        return pukIndex;
    }

    /**
     * Set PUK index.
     * @param pukIndex PUK index.
     */
    public void setPukIndex(Long pukIndex) {
        this.pukIndex = pukIndex;
    }

    /**
     * Get PUK status.
     * @return PUK status.
     */
    public RecoveryPukStatus getStatus() {
        return status;
    }

    /**
     * Set PUK status.
     * @param status PUK status.
     */
    public void setStatus(RecoveryPukStatus status) {
        this.status = status;
    }

    /**
     * Get timestamp of last status change.
     * @return Timestamp of last status change.
     */
    public Date getTimestampLastChange() {
        return timestampLastChange;
    }

    /**
     * Set timestamp of last status change.
     * @param timestampLastChange Timestamp of last status change.
     */
    public void setTimestampLastChange(Date timestampLastChange) {
        this.timestampLastChange = timestampLastChange;
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 71 * hash + Objects.hashCode(this.id);
        hash = 71 * hash + Objects.hashCode(this.recoveryCode);
        hash = 71 * hash + Objects.hashCode(this.puk);
        hash = 71 * hash + Objects.hashCode(this.pukIndex);
        hash = 71 * hash + Objects.hashCode(this.status);
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
        final RecoveryPukEntity other = (RecoveryPukEntity) obj;
        if (!Objects.equals(this.id, other.id)) {
            return false;
        }
        if (!Objects.equals(this.recoveryCode, other.recoveryCode)) {
            return false;
        }
        if (!Objects.equals(this.puk, other.puk)) {
            return false;
        }
        if (!Objects.equals(this.pukIndex, other.pukIndex)) {
            return false;
        }
        if (!Objects.equals(this.status, other.status)) {
            return false;
        }
        return Objects.equals(this.timestampLastChange, other.timestampLastChange);
    }

    @Override
    public String toString() {
        return "RecoveryPukEntity{"
                + "id=" + id
                + ", recoveryCode=" + recoveryCode.getRecoveryCode()
                + ", pukIndex=" + pukIndex
                + ", status=" + status
                + ", timestampLastChange=" + timestampLastChange
                + '}';
    }

}
