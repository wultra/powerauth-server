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

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

import java.io.Serial;
import java.io.Serializable;

/**
 * Class representing an integration - essentially an application that is allowed to communicate
 * with this PowerAuth Server instance.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Entity
@Table(name = "pa_integration")
@Getter @Setter
public class IntegrationEntity implements Serializable {

    @Serial
    private static final long serialVersionUID = 3372029113954119581L;

    /**
     * ID of an integration.
     */
    @Id
    @Column(name = "id", updatable = false, length = 37)
    private String id;

    /**
     * The name of an integration.
     */
    @Column(name = "name", nullable = false, updatable = false)
    private String name;

    /**
     *  The client token value. Basically, this value serves as integration's {@code username}.
     */
    @Column(name = "client_token", nullable = false, updatable = false, length = 37)
    private String clientToken;

    /**
     *  The client secret value. Basically, this value serves as integration's {@code password}.
     */
    @Column(name = "client_secret", nullable = false, updatable = false, length = 37)
    private String clientSecret;

}
