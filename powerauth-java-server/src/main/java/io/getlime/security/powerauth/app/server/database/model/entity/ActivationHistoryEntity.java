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

import io.getlime.security.powerauth.app.server.database.model.converter.ActivationStatusConverter;
import io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.data.util.ProxyUtils;

import java.io.Serial;
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
@Getter @Setter @ToString
public class ActivationHistoryEntity implements Serializable {

    @Serial
    private static final long serialVersionUID = -8232192926562045920L;

    /**
     * Record ID.
     */
    @Id
    @SequenceGenerator(name = "pa_activation_history", sequenceName = "pa_activation_history_seq", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.AUTO, generator = "pa_activation_history")
    @Column(name = "id")
    private Long id;

    /**
     * Related activation.
     */
    @ManyToOne
    @JoinColumn(name = "activation_id", referencedColumnName = "activation_id", updatable = false)
    private ActivationRecordEntity activation;

    /**
     * Activation status.
     */
    @Column(name = "activation_status")
    @Convert(converter = ActivationStatusConverter.class)
    private ActivationStatus activationStatus;

    /**
     * Reason why activation history record was created.
     */
    @Column(name = "event_reason")
    private String eventReason;

    /**
     * User ID of user who caused last activation change. {@code null} value is returned if activation owner caused the change.
     */
    @Column(name = "external_user_id")
    private String externalUserId;

    /**
     * Created timestamp.
     */
    @Column(name = "timestamp_created", nullable = false)
    private Date timestampCreated;

    /**
     * Current {@link ActivationRecordEntity#version} specified whenever an activation history event is audited.
     * PowerAuth protocol major version for activation.
     */
    @Column(name = "activation_version")
    private Integer activationVersion;

    @Column(name = "activation_name")
    private String activationName;

    @Override
    public boolean equals(final Object o) {
        if (null == o) {
            return false;
        } else if (this == o) {
            return true;
        } else if (!this.getClass().equals(ProxyUtils.getUserClass(o))) {
            return false;
        } else {
            final ActivationHistoryEntity that = (ActivationHistoryEntity) o;
            return Objects.equals(getActivationId(), that.getActivationId()) && Objects.equals(getTimestampCreated(), that.getTimestampCreated());
        }
    }

    @Override
    public int hashCode() {
        return Objects.hash(getActivationId(), timestampCreated);
    }

    // TODO (racansky, 2023-11-08) remove when activation equals and hashCode implemented correctly
    private String getActivationId() {
        return getActivation() == null ? null : getActivation().getActivationId();
    }

}
