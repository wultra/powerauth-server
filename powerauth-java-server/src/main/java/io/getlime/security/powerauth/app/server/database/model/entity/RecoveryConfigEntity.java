/*
 * PowerAuth Server and related software components
 * Copyright (C) 2019 Wultra s.r.o.
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

import io.getlime.security.powerauth.app.server.database.model.enumeration.EncryptionMode;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;

/**
 * Entity class representing recovery configuration in the database.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Entity
@Table(name = "pa_recovery_config")
@Getter @Setter
public class RecoveryConfigEntity implements Serializable {

    @Serial
    private static final long serialVersionUID = -6333795855186594869L;

    /**
     * Master key pair ID
     */
    @Id
    @SequenceGenerator(name = "pa_recovery_config", sequenceName = "pa_recovery_config_seq", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.AUTO, generator = "pa_recovery_config")
    @Column(name = "id")
    private Long id;

    /**
     * Whether activation recovery is enabled.
     */
    @Column(name = "activation_recovery_enabled", nullable = false)
    private boolean activationRecoveryEnabled;

    /**
     * Whether recovery postcard is enabled.
     */
    @Column(name = "recovery_postcard_enabled", nullable = false)
    private Boolean recoveryPostcardEnabled;

    /**
     * Whether multiple recovery codes per user are allowed.
     */
    @Column(name = "allow_multiple_recovery_codes", nullable = false)
    private Boolean allowMultipleRecoveryCodes;

    /**
     * Base64 encoded local recovery postcard private key.
     */
    @Column(name = "postcard_private_key_base64")
    private String recoveryPostcardPrivateKeyBase64;

    /**
     * Base64 encoded local recovery postcard public key.
     */
    @Column(name = "postcard_public_key_base64")
    private String recoveryPostcardPublicKeyBase64;

    /**
     * Base64 encoded remote recovery postcard public key.
     */
    @Column(name = "remote_public_key_base64")
    private String remotePostcardPublicKeyBase64;

    /**
     * Recovery postcard private key encryption mode.
     */
    @Column(name = "postcard_priv_key_encryption", nullable = false)
    @Enumerated
    private EncryptionMode privateKeyEncryption;

    /**
     * Associated application.
     */
    @ManyToOne
    @JoinColumn(name = "application_id", referencedColumnName = "id", nullable = false, updatable = false)
    private ApplicationEntity application;

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 37 * hash + Objects.hashCode(this.activationRecoveryEnabled);
        hash = 37 * hash + Objects.hashCode(this.recoveryPostcardEnabled);
        hash = 37 * hash + Objects.hashCode(this.allowMultipleRecoveryCodes);
        hash = 37 * hash + Objects.hashCode(this.recoveryPostcardPrivateKeyBase64);
        hash = 37 * hash + Objects.hashCode(this.recoveryPostcardPublicKeyBase64);
        hash = 37 * hash + Objects.hashCode(this.remotePostcardPublicKeyBase64);
        hash = 37 * hash + Objects.hashCode(this.privateKeyEncryption);
        hash = 37 * hash + Objects.hashCode(this.application);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final RecoveryConfigEntity other = (RecoveryConfigEntity) obj;
        if (!Objects.equals(this.activationRecoveryEnabled, other.activationRecoveryEnabled)) {
            return false;
        }
        if (!Objects.equals(this.recoveryPostcardEnabled, other.recoveryPostcardEnabled)) {
            return false;
        }
        if (!Objects.equals(this.allowMultipleRecoveryCodes, other.allowMultipleRecoveryCodes)) {
            return false;
        }
        if (!Objects.equals(this.recoveryPostcardPrivateKeyBase64, other.recoveryPostcardPrivateKeyBase64)) {
            return false;
        }
        if (!Objects.equals(this.recoveryPostcardPublicKeyBase64, other.recoveryPostcardPublicKeyBase64)) {
            return false;
        }
        if (!Objects.equals(this.remotePostcardPublicKeyBase64, other.remotePostcardPublicKeyBase64)) {
            return false;
        }
        if (!Objects.equals(this.privateKeyEncryption, other.privateKeyEncryption)) {
            return false;
        }
        return Objects.equals(this.application, other.application);
    }

    @Override
    public String toString() {
        return "RecoveryConfigEntity{"
                + "id=" + id
                + ", activationRecoveryEnabled=" + activationRecoveryEnabled
                + ", recoveryPostcardEnabled=" + recoveryPostcardEnabled
                + ", allowMultipleRecoveryCodes=" + allowMultipleRecoveryCodes
                + ", recoveryPostcardPublicKeyBase64=" + recoveryPostcardPublicKeyBase64
                + ", remotePostcardPublicKeyBase64=" + remotePostcardPublicKeyBase64
                + ", privateKeyEncryption=" + privateKeyEncryption
                + ", application=" + application.getRid()
                + '}';
    }

}
