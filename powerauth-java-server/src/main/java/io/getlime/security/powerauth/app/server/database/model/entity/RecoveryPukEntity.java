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

import io.getlime.security.powerauth.app.server.database.model.converter.RecoveryPukStatusConverter;
import io.getlime.security.powerauth.app.server.database.model.enumeration.EncryptionMode;
import io.getlime.security.powerauth.app.server.database.model.enumeration.RecoveryPukStatus;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.io.Serial;
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
@Getter @Setter
public class RecoveryPukEntity implements Serializable {

    @Serial
    private static final long serialVersionUID = 1836238476585497799L;

    /**
     * Recovery PUK entity ID.
     */
    @Id
    @SequenceGenerator(name = "pa_recovery_puk", sequenceName = "pa_recovery_puk_seq", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.AUTO, generator = "pa_recovery_puk")
    @Column(name = "id")
    private Long id;

    /**
     * Recovery code for which this PUK is defined.
     */
    @ManyToOne
    @JoinColumn(name = "recovery_code_id", referencedColumnName = "id", nullable = false, updatable = false)
    private RecoveryCodeEntity recoveryCode;

    /**
     * PUK value.
     */
    @Column(name = "puk", nullable = false)
    private String puk;

    /**
     * PUK encryption mode.
     */
    @Column(name = "puk_encryption", nullable = false)
    @Enumerated
    private EncryptionMode pukEncryption;

    /**
     * PUK index.
     */
    @Column(name = "puk_index", nullable = false, updatable = false)
    private Long pukIndex;

    /**
     * PUK status.
     */
    @Column(name = "status", nullable = false)
    @Convert(converter = RecoveryPukStatusConverter.class)
    private RecoveryPukStatus status;

    /**
     * Timestamp of last status change.
     */
    @Column(name = "timestamp_last_change")
    private Date timestampLastChange;

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 71 * hash + Objects.hashCode(this.recoveryCode);
        hash = 71 * hash + Objects.hashCode(this.puk);
        hash = 71 * hash + Objects.hashCode(this.pukEncryption);
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
        if (!Objects.equals(this.recoveryCode, other.recoveryCode)) {
            return false;
        }
        if (!Objects.equals(this.puk, other.puk)) {
            return false;
        }
        if (!Objects.equals(this.pukEncryption, other.pukEncryption)) {
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
                + ", pukEncryption=" + pukEncryption
                + ", pukIndex=" + pukIndex
                + ", status=" + status
                + ", timestampLastChange=" + timestampLastChange
                + '}';
    }

}
