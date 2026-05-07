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
package com.wultra.security.powerauth.app.server.database.model.entity;

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
 * Entity class representing Master Key Pair in the database.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Entity
@Table(name = "pa_master_keypair")
@Getter @Setter
public class MasterKeyPairEntity implements Serializable {

    @Serial
    private static final long serialVersionUID = 1507932260603647825L;

    /**
     * Master key pair ID.
     */
    @Id
    @SequenceGenerator(name = "pa_master_keypair", sequenceName = "pa_master_keypair_seq", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.AUTO, generator = "pa_master_keypair")
    @Column(name = "id")
    private Long id;

    /**
     * Master key pair name.
     */
    @Column(name = "name")
    private String name;

    /**
     * Master key pair private part encoded as Base64.
     */
    @Column(name = "master_key_private_base64", nullable = false)
    private String masterKeyPrivateBase64;

    /**
     * Master key pair public part encoded as Base64.
     */
    @Column(name = "master_key_public_base64", nullable = false)
    private String masterKeyPublicBase64;

    /**
     * Master private keys for newer cryptography algorithms serialized to JSON.
     */
    @Column(name = "master_private_keys", columnDefinition = "CLOB")
    private String masterPrivateKeys;

    /**
     * Mode of master private keys encryption {@code (0 = NO_ENCRYPTION, 1 = AES_HMAC)}.
     */
    @Column(name = "master_private_keys_encryption", nullable = false)
    @Enumerated
    private EncryptionAlgorithm masterPrivateKeysEncryption;

    /**
     * Master public keys for newer cryptography algorithms serialized to JSON.
     */
    @Column(name = "master_public_keys", columnDefinition = "CLOB")
    private String masterPublicKeys;

    /**
     * Master key pair created timestamp.
     */
    @Column(name = "timestamp_created", nullable = false)
    private Date timestampCreated;

    /**
     * Master key pair associated application.
     */
    @ManyToOne
    @JoinColumn(name = "application_id", referencedColumnName = "id", nullable = false, updatable = false)
    private ApplicationEntity application;

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 37 * hash + Objects.hashCode(this.masterKeyPrivateBase64);
        hash = 37 * hash + Objects.hashCode(this.masterPrivateKeys);
        hash = 37 * hash + Objects.hashCode(this.timestampCreated);
        hash = 37 * hash + Objects.hashCode(this.application);
        return hash;
    }

    @Override
    public boolean equals(Object o) {
        if (null == o) {
            return false;
        }
        if (this == o) {
            return true;
        }
        if (!ProxyUtils.getUserClass(this).equals(ProxyUtils.getUserClass(o))) {
            return false;
        }
        final MasterKeyPairEntity other = (MasterKeyPairEntity) o;
        return Objects.equals(this.masterKeyPrivateBase64, other.masterKeyPrivateBase64)
                && Objects.equals(this.masterPrivateKeys, other.masterPrivateKeys)
                && Objects.equals(this.timestampCreated, other.timestampCreated)
                && Objects.equals(this.application, other.application);
    }

    @Override
    public String toString() {
        return "MasterKeyPairEntity{"
                + "id=" + id
                + ", name=" + name
                + ", timestampCreated=" + timestampCreated
                + ", application=" + application.getRid()
                + '}';
    }

}
