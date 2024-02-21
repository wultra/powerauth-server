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

import io.getlime.security.powerauth.app.server.database.model.converter.ListToJsonConverter;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.util.ProxyUtils;

import java.io.Serial;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Entity class representing an application configuration.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Entity
@Getter
@Setter
@Table(name = "pa_application_config")
public class ApplicationConfigEntity implements Serializable {

    @Serial
    private static final long serialVersionUID = -7670843254389928550L;

    @Id
    @SequenceGenerator(name = "pa_application_config", sequenceName = "pa_app_conf_seq", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.AUTO, generator = "pa_application_config")
    @Column(name = "id")
    private Long rid;

    @OneToOne
    @JoinColumn(name = "application_id", referencedColumnName = "id", nullable = false, updatable = false)
    private ApplicationEntity application;

    @Column(name = "config_key", nullable = false)
    private String key;

    @Column(name = "config_values")
    @Convert(converter = ListToJsonConverter.class)
    private List<String> values = new ArrayList<>();

    /**
     * No-arg constructor.
     */
    public ApplicationConfigEntity() {
    }

    /**
     * Constructor for a new application configuration.
     *
     * @param application Application entity.
     * @param key         Configuration key.
     * @param values       Configuration values.
     */
    public ApplicationConfigEntity(ApplicationEntity application, String key, List<String> values) {
        this.application = application;
        this.key = key;
        this.values = values;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!this.getClass().equals(ProxyUtils.getUserClass(o))) return false;
        ApplicationConfigEntity that = (ApplicationConfigEntity) o;
        return Objects.equals(application, that.application) &&
                Objects.equals(key, that.key) &&
                Objects.equals(values, that.values);
    }

    @Override
    public int hashCode() {
        return Objects.hash(application, key, values);
    }

    @Override
    public String toString() {
        return "ApplicationConfigEntity{" +
                "rid=" + rid +
                ", appId='" + application.getId() + '\'' +
                ", key=" + key +
                ", values=" + values +
                '}';
    }
}
