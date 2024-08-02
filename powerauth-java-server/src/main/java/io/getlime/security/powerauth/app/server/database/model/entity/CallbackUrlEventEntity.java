/*
 * PowerAuth Server and related software components
 * Copyright (C) 2024 Wultra s.r.o.
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
import io.getlime.security.powerauth.app.server.database.model.enumeration.CallbackUrlEventStatus;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.util.ProxyUtils;

import java.io.Serial;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Objects;

/**
 * Entity representing callback URL event.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@Entity
@Table(name = "pa_application_callback_event")
@Getter @Setter
public class CallbackUrlEventEntity implements Serializable {

    @Serial
    private static final long serialVersionUID = 3438887028420848470L;

    @Id
    @Column(name = "id", length = 36)
    private String id;

    @ManyToOne
    @JoinColumn(name = "application_callback_id", referencedColumnName = "id", nullable = false, updatable = false)
    private CallbackUrlEntity callbackUrlEntity;

    @Column(name = "callback_data", nullable = false)
    @Convert(converter = MapToJsonConverter.class)
    private Map<String, Object> callbackData;

    @Column(name = "status", nullable = false)
    @Enumerated(EnumType.STRING)
    private CallbackUrlEventStatus status;

    @Column(name = "timestamp_created", nullable = false)
    private LocalDateTime timestampCreated;

    @Column(name = "timestamp_last_call")
    private LocalDateTime timestampLastCall;

    @Column(name = "timestamp_next_call")
    private LocalDateTime timestampNextCall;

    @Column(name = "timestamp_delete_after")
    private LocalDateTime timestampDeleteAfter;

    @Column(name = "attempts", nullable = false)
    private int attempts;

    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;
        if (o == null || !this.getClass().equals(ProxyUtils.getUserClass(o))) return false;

        final CallbackUrlEventEntity that = (CallbackUrlEventEntity) o;
        return id.equals(that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
    
}
