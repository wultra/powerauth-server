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

import io.getlime.security.powerauth.app.server.converter.ActivationProtocolConverter;
import io.getlime.security.powerauth.app.server.database.model.converter.ActivationFlagConverter;
import io.getlime.security.powerauth.app.server.database.model.converter.ActivationOtpValidationConverter;
import io.getlime.security.powerauth.app.server.database.model.converter.ActivationStatusConverter;
import io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationOtpValidation;
import io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationProtocol;
import io.getlime.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import io.getlime.security.powerauth.app.server.database.model.enumeration.EncryptionMode;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.io.Serial;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * Database entity for an "activation" objects.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Entity
@Table(name = "pa_activation")
@Getter @Setter
public class ActivationRecordEntity implements Serializable {

    @Serial
    private static final long serialVersionUID = 7512286634644851705L;

    /**
     * Activation ID.
     */
    @Id
    @Column(name = "activation_id", length = 37)
    private String activationId;

    /**
     * Activation code.
     */
    @Column(name = "activation_code", nullable = false, updatable = false)
    private String activationCode;

    /**
     * Activation OTP validation.
     */
    @Column(name = "activation_otp_validation", nullable = false)
    @Convert(converter = ActivationOtpValidationConverter.class)
    private ActivationOtpValidation activationOtpValidation;

    /**
     * Activation OTP.
     */
    @Column(name = "activation_otp")
    private String activationOtp;

    /**
     * External ID.
     */
    @Column(name = "external_id")
    private String externalId;

    /**
     * User ID.
     */
    @Column(name = "user_id", nullable = false, updatable = false)
    private String userId;

    /**
     * Activation name.
     */
    @Column(name = "activation_name")
    private String activationName;

    /**
     * Extra parameter.
     */
    @Column(name = "extras", columnDefinition = "CLOB")
    private String extras;

    /**
     * Protocol.
     */
    @Convert(converter = ActivationProtocolConverter.class)
    @Column(name = "protocol", nullable = false, columnDefinition = "varchar(32) default 'powerauth'")
    private ActivationProtocol protocol;

    /**
     * User device platform.
     */
    @Column(name = "platform")
    private String platform;

    /**
     * User device information.
     */
    @Column(name = "device_info")
    private String deviceInfo;

    /**
     * Activation flags.
     */
    @Column(name = "flags")
    @Convert(converter = ActivationFlagConverter.class)
    private final List<String> flags = new ArrayList<>();

    /**
     * Base64 encoded server private key.
     */
    @Column(name = "server_private_key_base64", nullable = false)
    private String serverPrivateKeyBase64;

    /**
     * Base64 encoded server public key
     */
    @Column(name = "server_public_key_base64", nullable = false)
    private String serverPublicKeyBase64;

    /**
     * Base64 encoded device public key
     */
    @Column(name = "device_public_key_base64")
    private String devicePublicKeyBase64;

    /**
     * Counter value.
     */
    @Column(name = "counter", nullable = false)
    private Long counter;

    /**
     * Base64 encoded counter data.
     */
    @Column(name = "ctr_data")
    private String ctrDataBase64;

    /**
     * Current number of failed attempts.
     */
    @Column(name = "failed_attempts", nullable = false)
    private Long failedAttempts;

    /**
     * Maximum allowed number of failed attempts.
     */
    @Column(name = "max_failed_attempts", nullable = false)
    private Long maxFailedAttempts;

    /**
     * Created timestamp.
     */
    @Column(name = "timestamp_created", nullable = false)
    private Date timestampCreated;

    /**
     * Timestamp of activation completion expiration - application must turn
     *  from CREATED to ACTIVE state before this moment, or else it will turn REMOVED
     *  on next access.
     */
    @Column(name = "timestamp_activation_expire", nullable = false)
    private Date timestampActivationExpire;

    /**
     * Timestamp of the last signature calculation.
     */
    @Column(name = "timestamp_last_used", nullable = false)
    private Date timestampLastUsed;

    /**
     * Timestamp of the last activation status change.
     */
    @Column(name = "timestamp_last_change")
    private Date timestampLastChange;

    /**
     * Activation status.
     */
    @Column(name = "activation_status", nullable = false)
    @Convert(converter = ActivationStatusConverter.class)
    private ActivationStatus activationStatus;

    /**
     * Reason why activation is blocked.
     */
    @Column(name = "blocked_reason")
    private String blockedReason;

    /**
     * Mode of server private key encryption {@code (0 = NO_ENCRYPTION, 1 = AES_HMAC)}.
     */
    @Column(name = "server_private_key_encryption", nullable = false)
    @Enumerated
    private EncryptionMode serverPrivateKeyEncryption;

    /**
     * PowerAuth protocol major version for activation.
     */
    // Version must be nullable, it is not known yet during init activation step
    @Column(name = "version")
    private Integer version;

    /**
     * Associated application instance. Each activation is strongly associated with a single application.
     */
    @ManyToOne
    @JoinColumn(name = "application_id", referencedColumnName = "id", nullable = false)
    private ApplicationEntity application;

    /**
     * Associated master key pair.
     * While master key pair is associated with an application by default, it must also be associated with an activation when a new activation is
     * created so that it is strongly bound with the activation.
     */
    @ManyToOne
    @JoinColumn(name = "master_keypair_id", referencedColumnName = "id", nullable = false)
    private MasterKeyPairEntity masterKeyPair;

    /**
     * Activation history.
     */
    @OneToMany(mappedBy = "activation", cascade = CascadeType.ALL)
    @OrderBy("timestampCreated")
    private final List<ActivationHistoryEntity> activationHistory = new ArrayList<>();

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 71 * hash + Objects.hashCode(this.activationId);
        hash = 71 * hash + Objects.hashCode(this.activationCode);
        hash = 71 * hash + Objects.hashCode(this.activationOtpValidation);
        hash = 71 * hash + Objects.hashCode(this.activationOtp);
        hash = 71 * hash + Objects.hashCode(this.userId);
        hash = 71 * hash + Objects.hashCode(this.activationName);
        hash = 71 * hash + Objects.hashCode(this.extras);
        hash = 71 * hash + Objects.hashCode(this.platform);
        hash = 71 * hash + Objects.hashCode(this.deviceInfo);
        hash = 71 * hash + Objects.hashCode(this.flags);
        hash = 71 * hash + Objects.hashCode(this.serverPrivateKeyBase64);
        hash = 71 * hash + Objects.hashCode(this.serverPublicKeyBase64);
        hash = 71 * hash + Objects.hashCode(this.devicePublicKeyBase64);
        hash = 71 * hash + Objects.hashCode(this.counter);
        hash = 71 * hash + Objects.hashCode(this.ctrDataBase64);
        hash = 71 * hash + Objects.hashCode(this.failedAttempts);
        hash = 71 * hash + Objects.hashCode(this.maxFailedAttempts);
        hash = 71 * hash + Objects.hashCode(this.timestampCreated);
        hash = 71 * hash + Objects.hashCode(this.timestampActivationExpire);
        hash = 71 * hash + Objects.hashCode(this.timestampLastUsed);
        hash = 71 * hash + Objects.hashCode(this.timestampLastChange);
        hash = 71 * hash + Objects.hashCode(this.activationStatus);
        hash = 71 * hash + Objects.hashCode(this.blockedReason);
        hash = 71 * hash + Objects.hashCode(this.serverPrivateKeyEncryption);
        hash = 71 * hash + Objects.hashCode(this.application);
        hash = 71 * hash + Objects.hashCode(this.masterKeyPair);
        hash = 71 * hash + Objects.hashCode(this.version);
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
        final ActivationRecordEntity other = (ActivationRecordEntity) obj;
        if (!Objects.equals(this.activationCode, other.activationCode)) {
            return false;
        }
        if (this.activationOtpValidation != other.activationOtpValidation) {
            return false;
        }
        if (!Objects.equals(this.activationOtp, other.activationOtp)) {
            return false;
        }
        if (!Objects.equals(this.userId, other.userId)) {
            return false;
        }
        if (!Objects.equals(this.activationName, other.activationName)) {
            return false;
        }
        if (!Objects.equals(this.extras, other.extras)) {
            return false;
        }
        if (!Objects.equals(this.platform, other.platform)) {
            return false;
        }
        if (!Objects.equals(this.deviceInfo, other.deviceInfo)) {
            return false;
        }
        if (!Objects.equals(this.flags, other.flags)) {
            return false;
        }
        if (!Objects.equals(this.activationId, other.activationId)) {
            return false;
        }
        if (!Objects.equals(this.serverPrivateKeyBase64, other.serverPrivateKeyBase64)) {
            return false;
        }
        if (!Objects.equals(this.serverPublicKeyBase64, other.serverPublicKeyBase64)) {
            return false;
        }
        if (!Objects.equals(this.devicePublicKeyBase64, other.devicePublicKeyBase64)) {
            return false;
        }
        if (!Objects.equals(this.counter, other.counter)) {
            return false;
        }
        if (!Objects.equals(this.ctrDataBase64, other.ctrDataBase64)) {
            return false;
        }
        if (!Objects.equals(this.failedAttempts, other.failedAttempts)) {
            return false;
        }
        if (!Objects.equals(this.maxFailedAttempts, other.maxFailedAttempts)) {
            return false;
        }
        if (!Objects.equals(this.timestampCreated, other.timestampCreated)) {
            return false;
        }
        if (!Objects.equals(this.timestampActivationExpire, other.timestampActivationExpire)) {
            return false;
        }
        if (!Objects.equals(this.timestampLastUsed, other.timestampLastUsed)) {
            return false;
        }
        if (!Objects.equals(this.timestampLastChange, other.timestampLastChange)) {
            return false;
        }
        if (this.activationStatus != other.activationStatus) {
            return false;
        }
        if (!Objects.equals(this.blockedReason, other.blockedReason)) {
            return false;
        }
        if (!Objects.equals(this.serverPrivateKeyEncryption, other.serverPrivateKeyEncryption)) {
            return false;
        }
        if (!Objects.equals(this.application, other.application)) {
            return false;
        }
        if (!Objects.equals(this.masterKeyPair, other.masterKeyPair)) {
            return false;
        }
        return Objects.equals(this.version, other.version);
    }

    @Override
    public String toString() {
        return "ActivationRecordEntity{"
                + "activationId=" + activationId
                + ", activationCode=" + activationCode
                + ", activationOtpValidation=" + activationOtpValidation
                + ", activationOtp=" + activationOtp
                + ", userId=" + userId
                + ", activationName=" + activationName
                + ", extras=" + extras
                + ", platform=" + platform
                + ", deviceInfo=" + deviceInfo
                + ", flags=" + flags
                + ", serverPublicKeyBase64=" + serverPublicKeyBase64
                + ", devicePublicKeyBase64=" + devicePublicKeyBase64
                + ", counter=" + counter
                + ", ctrDataBase64=" + ctrDataBase64
                + ", failedAttempts=" + failedAttempts
                + ", maxFailedAttempts=" + maxFailedAttempts
                + ", timestampCreated=" + timestampCreated
                + ", timestampActivationExpire=" + timestampActivationExpire
                + ", timestampLastUsed=" + timestampLastUsed
                + ", timestampLastChange=" + timestampLastChange
                + ", status=" + activationStatus
                + ", blockedReason=" + blockedReason
                + ", masterKeyPair=" + masterKeyPair
                + ", version=" + version
                + ", application=" + application
                + '}';
    }
}
