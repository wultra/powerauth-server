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

import io.getlime.security.powerauth.app.server.converter.CallbackAttributeConverter;
import io.getlime.security.powerauth.app.server.database.model.converter.CallbackUrlTypeConverter;
import io.getlime.security.powerauth.app.server.database.model.converter.DurationConverter;
import io.getlime.security.powerauth.app.server.database.model.enumeration.CallbackUrlType;
import io.getlime.security.powerauth.app.server.database.model.enumeration.EncryptionMode;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.SQLRestriction;

import java.io.Serial;
import java.io.Serializable;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Objects;

/**
 * Class representing a callback URL associated with given application.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Entity
@Table(name = "pa_application_callback")
@Getter @Setter
@SQLRestriction("enabled = true")
public class CallbackUrlEntity implements Serializable {

    @Serial
    private static final long serialVersionUID = 3372029113954119581L;

    /**
     * ID of the callback.
     */
    @Id
    @Column(name = "id", updatable = false, length = 37)
    private String id;

    /**
     * Application.
     */
    @ManyToOne
    @JoinColumn(name = "application_id", referencedColumnName = "id", nullable = false, updatable = false)
    private ApplicationEntity application;

    /**
     * Type of the callback URL.
     */
    @Column(name = "type", nullable = false)
    @Convert(converter = CallbackUrlTypeConverter.class)
    private CallbackUrlType type;

    /**
     * The name of the callback.
     */
    @Column(name = "name", nullable = false)
    private String name;

    /**
     * Callback URL string.
     */
    @Column(name = "callback_url", nullable = false)
    private String callbackUrl;

    /**
     * Callback attribute settings.
     */
    @Column(name = "attributes")
    @Convert(converter = CallbackAttributeConverter.class)
    private List<String> attributes;

    /**
     * Callback request authentication. May be encrypted, configured by {@link #encryptionMode}.
     */
    @Column(name = "authentication", columnDefinition = "CLOB")
    private String authentication = "{}";

    /**
     * Encryption mode of {@link #authentication}.
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "encryption_mode", nullable = false, columnDefinition = "varchar(255) default 'NO_ENCRYPTION'")
    private EncryptionMode encryptionMode;

    /**
     * Maximum number of attempts to send the callback.
     */
    @Column(name = "max_attempts")
    private Integer maxAttempts;

    /**
     * Initial backoff before the next send attempt.
     */
    @Column(name = "initial_backoff")
    @Convert(converter = DurationConverter.class)
    private Duration initialBackoff;

    /**
     * Duration for which is the callback event stored.
     */
    @Column(name = "retention_period")
    @Convert(converter = DurationConverter.class)
    private Duration retentionPeriod;

    /**
     * Timestamp of last callback failure.
     */
    @Column(name = "timestamp_last_failure")
    private LocalDateTime timestampLastFailure;

    /**
     * Number of failed callbacks in a row.
     */
    @Column(name = "failure_count", nullable = false)
    private Integer failureCount;

    /**
     * Whether the callback is enabled and can be used.
     */
    @Column(name = "enabled", nullable = false)
    private boolean enabled = true;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof final CallbackUrlEntity that)) return false;
        return application.equals(that.application) && name.equals(that.getName()) && type == that.type && callbackUrl.equals(that.callbackUrl);
    }

    @Override
    public int hashCode() {
        return Objects.hash(application, name, type, callbackUrl);
    }
}
