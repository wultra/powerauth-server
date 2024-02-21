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

import io.getlime.security.powerauth.app.server.database.model.converter.ApplicationRoleConverter;
import jakarta.persistence.*;

import java.io.Serial;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Entity class representing an application.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Entity
@Table(name = "pa_application")
public class ApplicationEntity implements Serializable {

    @Serial
    private static final long serialVersionUID = 1295434927785255417L;

    @Id
    @SequenceGenerator(name = "pa_application", sequenceName = "pa_application_seq", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.AUTO, generator = "pa_application")
    @Column(name = "id")
    private Long rid;

    @Column(name = "name", unique = true)
    private String id;

    @Column(name = "roles")
    @Convert(converter = ApplicationRoleConverter.class)
    private final List<String> roles = new ArrayList<>();

    @OneToMany(mappedBy = "application")
    private final List<ApplicationVersionEntity> versions = new ArrayList<>();

    @OneToMany(mappedBy = "application")
    private final List<CallbackUrlEntity> callbacks = new ArrayList<>();

    @OneToMany(mappedBy = "application")
    private final List<RecoveryCodeEntity> recoveryCodes = new ArrayList<>();

    /**
     * No-arg constructor.
     */
    public ApplicationEntity() {
    }

    /**
     * Constructor for a new application.
     *
     * @param rid       Application RID.
     * @param id     Application ID.
     * @param roles    Application roles.
     * @param versions Collection of versions.
     */
    public ApplicationEntity(Long rid, String id, List<String> roles, List<ApplicationVersionEntity> versions) {
        this.rid = rid;
        this.id = id;
        this.roles.addAll(roles);
        this.versions.addAll(versions);
    }

    /**
     * Get application RID.
     *
     * @return Application RID.
     */
    public Long getRid() {
        return rid;
    }

    /**
     * Set application RID.
     *
     * @param id Application RID.
     */
    public void setRid(Long id) {
        this.rid = id;
    }

    /**
     * Get application ID.
     *
     * @return Application ID.
     */
    public String getId() {
        return id;
    }

    /**
     * Set application ID.
     *
     * @param id Application ID.
     */
    public void setId(String id) {
        this.id = id;
    }

    /**
     * Get application roles.
     * @return Application roles.
     */
    public List<String> getRoles() {
        return roles;
    }

    /**
     * Get list of versions associated with given application.
     * @return Application versions.
     */
    public List<ApplicationVersionEntity> getVersions() {
        return versions;
    }

    /**
     * Get the list of callbacks for given application.
     * @return List of callbacks.
     */
    public List<CallbackUrlEntity> getCallbacks() {
        return callbacks;
    }

    /**
     * Get the list of recovery codes.
     * @return List of recovery codes.
     */
    public List<RecoveryCodeEntity> getRecoveryCodes() {
        return recoveryCodes;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ApplicationEntity that = (ApplicationEntity) o;
        return Objects.equals(id, that.id) &&
                Objects.equals(roles, that.roles) &&
                Objects.equals(versions, that.versions);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, roles, versions);
    }

    @Override
    public String toString() {
        return "ApplicationEntity{" +
                "rid=" + rid +
                ", id='" + id + '\'' +
                ", roles=" + roles +
                ", versions=" + versions +
                ", callbacks=" + callbacks +
                ", recoveryCodes=" + recoveryCodes +
                '}';
    }
}
