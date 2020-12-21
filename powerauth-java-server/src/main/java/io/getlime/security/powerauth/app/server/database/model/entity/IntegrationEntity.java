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

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import java.io.Serializable;

/**
 * Class representing an integration - essentially an application that is allowed to communicate
 * with this PowerAuth Server instance.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Entity
@Table(name = "pa_integration")
public class IntegrationEntity implements Serializable {

    private static final long serialVersionUID = 3372029113954119581L;

    @Id
    @Column(name = "id", updatable = false, length = 37)
    private String id;

    @Column(name = "name", nullable = false, updatable = false)
    private String name;

    @Column(name = "client_token", nullable = false, updatable = false, length = 37)
    private String clientToken;

    @Column(name = "client_secret", nullable = false, updatable = false, length = 37)
    private String clientSecret;

    /**
     * Get the ID of an integration.
     * @return ID of an integration.
     */
    public String getId() {
        return id;
    }

    /**
     * Set the ID of an integration.
     * @param id ID of an integration.
     */
    public void setId(String id) {
        this.id = id;
    }

    /**
     * Get the name of an integration.
     * @return Name of an integration.
     */
    public String getName() {
        return name;
    }

    /**
     * Set the name of an integration.
     * @param name Name of an integration.
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Get the client token value. Basically, this value serves as integration's "username".
     * @return Client token.
     */
    public String getClientToken() {
        return clientToken;
    }

    /**
     * Set the client token value.
     * @param clientToken Client token.
     */
    public void setClientToken(String clientToken) {
        this.clientToken = clientToken;
    }

    /**
     * Get the client secret value. Basically, this value serves as integration's "password".
     * @return Client secret.
     */
    public String getClientSecret() {
        return clientSecret;
    }

    /**
     * Set the client secret value.
     * @param clientSecret Client secret.
     */
    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

}
