/*
 * PowerAuth Server and related software components
 * Copyright (C) 2026 Wultra s.r.o.
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
 *
 */
package com.wultra.security.powerauth.app.server.database.model.entity;

import com.wultra.security.powerauth.app.server.database.model.enumeration.ConfigScope;
import com.wultra.security.powerauth.app.server.database.model.enumeration.EncryptionAlgorithm;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.util.ProxyUtils;

import java.io.Serial;
import java.io.Serializable;
import java.util.Date;
import java.util.Objects;

/**
 * Entity class representing a configuration store record. The configuration is stored as a JSON document
 * to optimize the dominant bulk-read path.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Entity
@Getter
@Setter
@Table(name = "pa_config_store")
public class ConfigStoreEntity implements Serializable {

    @Serial
    private static final long serialVersionUID = 8312842631321330043L;

    @Id
    @SequenceGenerator(name = "pa_config_store", sequenceName = "pa_config_store_seq", allocationSize = 50)
    @GeneratedValue(strategy = GenerationType.AUTO, generator = "pa_config_store")
    @Column(name = "id")
    private Long id;

    @ManyToOne
    @JoinColumn(name = "application_id", referencedColumnName = "id", nullable = false, updatable = false)
    private ApplicationEntity application;

    @ManyToOne
    @JoinColumn(name = "activation_id", referencedColumnName = "activation_id", updatable = false)
    private ActivationRecordEntity activation;

    @Enumerated(EnumType.STRING)
    @Column(name = "config_scope", nullable = false)
    private ConfigScope scope;

    @Column(name = "config_data", columnDefinition = "CLOB")
    private String configData = "{}";

    @Enumerated(EnumType.STRING)
    @Column(name = "encryption_mode", nullable = false, columnDefinition = "varchar(255) default 'NO_ENCRYPTION'")
    private EncryptionAlgorithm encryptionAlgorithm;

    @Column(name = "timestamp_created", nullable = false)
    private Date timestampCreated = new Date();

    @Column(name = "timestamp_last_updated")
    private Date timestampLastUpdated;

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (null == o) {
            return false;
        }
        if (!ProxyUtils.getUserClass(this).equals(ProxyUtils.getUserClass(o))) {
            return false;
        }
        final ConfigStoreEntity other = (ConfigStoreEntity) o;
        return Objects.equals(application, other.application) &&
                Objects.equals(activation, other.activation) &&
                scope == other.scope;
    }

    @Override
    public int hashCode() {
        return Objects.hash(application, activation, scope);
    }

    @Override
    public String toString() {
        return "ConfigStoreEntity{" +
                "id=" + id +
                ", appId='" + application.getId() + "'" +
                ", activationId='" + (activation != null ? activation.getActivationId() : null) + "'" +
                ", scope=" + scope +
                ", encryptionMode=" + encryptionAlgorithm +
                '}';
    }
}
