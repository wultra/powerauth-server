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

import com.wultra.security.powerauth.app.server.database.model.AuthenticationCodeMetadata;
import com.wultra.security.powerauth.app.server.database.model.converter.ActivationStatusConverter;
import com.wultra.security.powerauth.app.server.database.model.converter.AuthenticationCodeMetadataConverter;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.util.ProxyUtils;

import java.io.Serial;
import java.io.Serializable;
import java.util.Date;
import java.util.Objects;

/**
 * Entity representing a single signature audit log.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Entity
@Table(name = "pa_signature_audit")
@Getter @Setter
public class SignatureEntity implements Serializable {

    @Serial
    private static final long serialVersionUID = 1930424474990335368L;

    /**
     * Record ID.
     */
    @Id
    @SequenceGenerator(name = "pa_signature_audit", sequenceName = "pa_signature_audit_seq", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.AUTO, generator = "pa_signature_audit")
    @Column(name = "id")
    private Long id;

    /**
     * Related activation.
     */
    @ManyToOne
    @JoinColumn(name = "activation_id", referencedColumnName = "activation_id", updatable = false)
    private ActivationRecordEntity activation;

    /**
     * Activation counter value.
     */
    @Column(name = "activation_counter", nullable = false)
    private Long activationCounter;

    /**
     * Base64 encoded activation counter data.
     */
    @Column(name = "activation_ctr_data")
    private String activationCtrDataBase64;

    /**
     * Activation status.
     */
    @Column(name = "activation_status")
    @Convert(converter = ActivationStatusConverter.class)
    private ActivationStatus activationStatus;

    /**
     * Additional information related to this signature.
     */
    @Column(name = "additional_info")
    private String additionalInfo;

    /**
     * Base64 encoded data that entered the signature.
     */
    @Column(name = "data_base64", updatable = false, columnDefinition = "CLOB")
    private String dataBase64;

    /**
     * Requested signature version.
     */
    @Column(name = "signature_version", updatable = false)
    private String signatureVersion;

    /**
     * Signature type.
     */
    @Column(name = "signature_type", nullable = false, updatable = false)
    private String signatureType;

    /**
     * Signature.
     */
    @Column(name = "signature", nullable = false, updatable = false)
    private String signature;

    /**
     * Signature metadata associated with this signature.
     */
    @Column(name = "signature_metadata")
    @Convert(converter = AuthenticationCodeMetadataConverter.class)
    private AuthenticationCodeMetadata signatureMetadata;

    /**
     * Signature data body.
     */
    @Column(name = "signature_data_body", updatable = false, columnDefinition = "CLOB")
    private String signatureDataBody;

    /**
     * Signature audit record note.
     */
    @Column(name = "note", updatable = false)
    private String note;

    /**
     * Whether the signature was valid or not.
     */
    @Column(name = "valid", nullable = false, updatable = false)
    private Boolean valid;

    /**
     * Signature version.
     */
    @Column(name = "version", nullable = false)
    private Integer version;

    /**
     * Created timestamp.
     */
    @Column(name = "timestamp_created", nullable = false)
    private Date timestampCreated;

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 23 * hash + Objects.hashCode(this.activation);
        hash = 23 * hash + Objects.hashCode(this.activationCounter);
        hash = 23 * hash + Objects.hashCode(this.activationCtrDataBase64);
        hash = 23 * hash + Objects.hashCode(this.activationStatus);
        hash = 23 * hash + Objects.hashCode(this.dataBase64);
        hash = 23 * hash + Objects.hashCode(this.signatureType);
        hash = 23 * hash + Objects.hashCode(this.signature);
        hash = 23 * hash + Objects.hashCode(this.signatureMetadata);
        hash = 23 * hash + Objects.hashCode(this.signatureDataBody);
        hash = 23 * hash + Objects.hashCode(this.additionalInfo);
        hash = 23 * hash + Objects.hashCode(this.note);
        hash = 23 * hash + Objects.hashCode(this.valid);
        hash = 23 * hash + Objects.hashCode(this.version);
        hash = 23 * hash + Objects.hashCode(this.timestampCreated);
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
        final SignatureEntity other = (SignatureEntity) o;
        return Objects.equals(this.dataBase64, other.dataBase64)
                && Objects.equals(this.signatureType, other.signatureType)
                && Objects.equals(this.signature, other.signature)
                && Objects.equals(this.signatureMetadata, other.signatureMetadata)
                && Objects.equals(this.signatureDataBody, other.signatureDataBody)
                && Objects.equals(this.additionalInfo, other.additionalInfo)
                && Objects.equals(this.activation, other.activation)
                && Objects.equals(this.activationCounter, other.activationCounter)
                && Objects.equals(this.activationCtrDataBase64, other.activationCtrDataBase64)
                && Objects.equals(this.activationStatus, other.activationStatus)
                && Objects.equals(this.valid, other.valid)
                && Objects.equals(this.version, other.version)
                && Objects.equals(this.timestampCreated, other.timestampCreated)
                && Objects.equals(this.note, other.note);
    }

    @Override
    public String toString() {
        return "SignatureEntity{" + "id=" + id + ", activation=" + activation + ", activationCounter=" + activationCounter + ", activationCtrDataBase64=" + activationCtrDataBase64 + ", activationStatus=" + activationStatus + ", dataBase64=" + dataBase64 + ", authenticationCodeType=" + signatureType + ", signature=" + signature + ", additionalInfo= " + additionalInfo + ", valid=" + valid + ", version=" + version + ", note=" + note + ", timestampCreated=" + timestampCreated + "}";
    }

}
