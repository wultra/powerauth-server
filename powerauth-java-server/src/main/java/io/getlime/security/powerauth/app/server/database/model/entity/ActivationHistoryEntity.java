/*
 * PowerAuth Server and related software components
 * Copyright (C) 2018 Wultra s.r.o.
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

import io.getlime.security.powerauth.app.server.database.model.ActivationStatus;
import io.getlime.security.powerauth.app.server.database.model.ActivationStatusConverter;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Date;
import java.util.Objects;

/**
 * Entity representing activation history used for storing activation status changes.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Entity
@Table(name = "pa_activation_history")
public class ActivationHistoryEntity implements Serializable {

    private static final long serialVersionUID = -8232192926562045920L;

    @Id
    @SequenceGenerator(name = "pa_activation_history", sequenceName = "pa_activation_history_seq")
    @GeneratedValue(strategy = GenerationType.AUTO, generator = "pa_activation_history")
    @Column(name = "id")
    private Long id;

    @ManyToOne
    @JoinColumn(name = "activation_id", referencedColumnName = "activation_id", updatable = false)
    private ActivationRecordEntity activation;

    @Column(name = "activation_status")
    @Convert(converter = ActivationStatusConverter.class)
    private ActivationStatus activationStatus;

    @Column(name = "event_reason")
    private String eventReason;

    @Column(name = "external_user_id")
    private String externalUserId;

    @Column(name = "timestamp_created", nullable = false)
    private Date timestampCreated;

    /**
     * Default constructor.
     */
    public ActivationHistoryEntity() {
    }

    /**
     * Constructor with all properties.
     *
     * @param id                Signature audit item record ID.
     * @param activation        Associated activation, or null of no related activation was found.
     * @param activationStatus  Activation status at the time of signature computation attempt.
     * @param timestampCreated  Created timestapm.
     */
    public ActivationHistoryEntity(Long id, ActivationRecordEntity activation, ActivationStatus activationStatus, Date timestampCreated) {
        super();
        this.id = id;
        this.activation = activation;
        this.activationStatus = activationStatus;
        this.timestampCreated = timestampCreated;
    }

    /**
     * Get record ID.
     *
     * @return Record ID.
     */
    public Long getId() {
        return id;
    }

    /**
     * Set record ID.
     *
     * @param id Record ID.
     */
    public void setId(Long id) {
        this.id = id;
    }

    /**
     * Get related activation.
     *
     * @return Related activation.
     */
    public ActivationRecordEntity getActivation() {
        return activation;
    }

    /**
     * Set related activation.
     *
     * @param activation Related activation.
     */
    public void setActivation(ActivationRecordEntity activation) {
        this.activation = activation;
    }

    /**
     * Get activation status.
     *
     * @return Activation status.
     */
    public ActivationStatus getActivationStatus() {
        return activationStatus;
    }

    /**
     * Set activation status.
     *
     * @param activationStatus Activation status.
     */
    public void setActivationStatus(ActivationStatus activationStatus) {
        this.activationStatus = activationStatus;
    }

    /**
     * Get reason why activation history record was created.
     * @return Reason why activation history record was created.
     */
    public String getEventReason() {
        return eventReason;
    }

    /**
     * Set reason why activation history record was created.
     * @param eventReason Reason why activation history record was created.
     */
    public void setEventReason(String eventReason) {
        this.eventReason = eventReason;
    }

    /**
     * Get user ID of user who caused last activation change. Null value is returned if activation owner caused the change.
     * @return User ID of user who caused last activation change.
     */
    public String getExternalUserId() {
        return externalUserId;
    }

    /**
     * Set user ID of user who caused last activation change. Null value is returned if activation owner caused the change.
     * @param externalUserId User ID of user who caused last activation change.
     */
    public void setExternalUserId(String externalUserId) {
        this.externalUserId = externalUserId;
    }

    /**
     * Get created timestamp.
     *
     * @return Created timestamp.
     */
    public Date getTimestampCreated() {
        return timestampCreated;
    }

    /**
     * Set created timestamp.
     *
     * @param timestampCreated Created timestamp.
     */
    public void setTimestampCreated(Date timestampCreated) {
        this.timestampCreated = timestampCreated;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 23 * hash + Objects.hashCode(this.activation);
        hash = 23 * hash + Objects.hashCode(this.activationStatus);
        hash = 23 * hash + Objects.hashCode(this.eventReason);
        hash = 23 * hash + Objects.hashCode(this.externalUserId);
        hash = 23 * hash + Objects.hashCode(this.timestampCreated);
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
        final ActivationHistoryEntity other = (ActivationHistoryEntity) obj;
        if (!Objects.equals(this.activation, other.activation)) {
            return false;
        }
        if (!Objects.equals(this.activationStatus, other.activationStatus)) {
            return false;
        }
        if (!Objects.equals(this.eventReason, other.eventReason)) {
            return false;
        }
        if (!Objects.equals(this.externalUserId, other.externalUserId)) {
            return false;
        }
        return Objects.equals(this.timestampCreated, other.timestampCreated);
    }

    @Override
    public String toString() {
        return "ActivationHistoryEntity{" +
                "id=" + id + ", activation=" + activation + ", activationStatus=" + activationStatus +
                ", eventReason=" + eventReason + ", externalUserId=" + externalUserId + ", timestampCreated=" + timestampCreated + '}';
    }

}
