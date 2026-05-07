/*
 * PowerAuth Server and related software components
 * Copyright (C) 2025 Wultra s.r.o.
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

package com.wultra.security.powerauth.app.server.database.model.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.util.ProxyUtils;

import java.util.Objects;

/**
 * Database entity representing server public key.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@Entity
@Table(name = "pa_server_public_key")
@Getter @Setter
public class ServerPublicKeyEntity {

    @Id
    @SequenceGenerator(name = "pa_server_public_key", sequenceName = "pa_server_public_key_seq", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.AUTO, generator = "pa_server_public_key")
    @Column(name = "id")
    private Long id;

    /**
     * Server public keys for V4 cryptography algorithms serialized into JSON.
     */
    @Column(name = "key_data", columnDefinition = "CLOB")
    private String keyData;

    @Override
    public int hashCode() {
        return Objects.hash(keyData);
    }

    @Override
    public boolean equals(Object o) {
        if (null == o) {
            return false;
        } else if (this == o) {
            return true;
        } else if (!ProxyUtils.getUserClass(this).equals(ProxyUtils.getUserClass(o))) {
            return false;
        } else {
            final ServerPublicKeyEntity other = (ServerPublicKeyEntity) o;
            return Objects.equals(this.keyData, other.keyData);
        }
    }

}
