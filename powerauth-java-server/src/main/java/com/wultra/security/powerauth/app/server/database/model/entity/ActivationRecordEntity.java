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

import com.wultra.security.powerauth.app.server.converter.ActivationProtocolConverter;
import com.wultra.security.powerauth.app.server.database.model.converter.ActivationCommitPhaseConverter;
import com.wultra.security.powerauth.app.server.database.model.converter.ActivationFlagConverter;
import com.wultra.security.powerauth.app.server.database.model.converter.ActivationOtpValidationConverter;
import com.wultra.security.powerauth.app.server.database.model.converter.ActivationStatusConverter;
import com.wultra.security.powerauth.app.server.database.model.enumeration.*;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.util.ProxyUtils;

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
    @Deprecated
    private ActivationOtpValidation activationOtpValidation;

    /**
     * Commit phase.
     */
    @Column(name = "commit_phase")
    @Convert(converter = ActivationCommitPhaseConverter.class)
    private CommitPhase commitPhase;

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
     * Authenticator extra parameter.
     */
    @Column(name = "extras", columnDefinition = "CLOB")
    private String extras;

    /**
     * Optional additional data, structure is customer-specific JSON. Could be set during creation or initialization.
     */
    @Column(name = "additional_data", columnDefinition = "CLOB")
    private String additionalData;

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
    @Column(name = "server_private_key_base64")
    private String serverPrivateKeyBase64;

    /**
     * Base64 encoded server public key
     */
    @Column(name = "server_public_key_base64")
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
     * Base64 encoded counter data (V4).
     */
    @Column(name = "ctr_data_v4")
    private String ctrDataV4Base64;

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
     * Timestamp of the last authentication calculation.
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
    private EncryptionAlgorithm serverPrivateKeyEncryption;

    /**
     * Cryptography algorithm used for shared secret computation.
     */
    @Column(name = "crypto_algorithm")
    @Enumerated(EnumType.STRING)
    private SharedSecretAlgorithm cryptoAlgorithm;

    /**
     * Device public keys for V4 cryptography algorithms.
     */
    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "device_public_key_id")
    private DevicePublicKeyEntity devicePublicKey;

    /**
     * Server private keys for V4 cryptography algorithms.
     */
    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "server_private_key_id")
    private ServerPrivateKeyEntity serverPrivateKey;

    /**
     * Server public keys for V4 cryptography algorithms.
     */
    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "server_public_key_id")
    private ServerPublicKeyEntity serverPublicKey;

    /**
     * Activation fingerprint derived from device public key and server public key.
     */
    @Column(name = "activation_fingerprint")
    private String activationFingerprint;

    /**
     * Pre-computed shared secret.
     */
    @Column(name = "shared_secret")
    private String sharedSecret;

    /**
     * Mode of shared secret encryption {@code (0 = NO_ENCRYPTION, 1 = AES_HMAC)}.
     */
    @Column(name = "shared_secret_encryption", nullable = false)
    @Enumerated
    private EncryptionAlgorithm sharedSecretEncryption;

    /**
     * Whether biometric factor is enabled.
     */
    @Column(name = "biometric_factor_enabled")
    private boolean biometricFactorEnabled;

    /**
     * Current biometry factor key.
     */
    @Column(name = "biometric_factor_key")
    private String biometricFactorKey;

    /**
     * Next biometry factor key.
     */
    @Column(name = "biometric_factor_key_next")
    private String biometricFactorKeyNext;

    /**
     * Current knowledge factor key.
     */
    @Column(name = "knowledge_factor_key")
    private String knowledgeFactorKey;

    /**
     * Next knowledge factor key.
     */
    @Column(name = "knowledge_factor_key_next")
    private String knowledgeFactorKeyNext;

    /**
     * Whether confirmation is pending.
     */
    @Column(name = "confirmation_pending")
    private boolean confirmationPending;

    /**
     * Whether upgrade confirmation is pending.
     */
    @Column(name = "upgrade_confirmation_pending")
    private boolean upgradeConfirmationPending;

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

    /**
     * The parent activation. Mandatory when {@link #getTransferType()} is present.
     */
    @ManyToOne
    @JoinColumn(name = "parent_activation_id", referencedColumnName = "activation_id")
    private ActivationRecordEntity parentActivation;

    /**
     * The activation transfer type. Mandatory when {@link #getParentActivation()} is present.
     */
    @Enumerated(EnumType.STRING)
    private ActivationTransferType transferType;

    @Override
    public int hashCode() {
        return Objects.hash(activationCode);
    }

    @Override
    public boolean equals(Object o) {
        if (null == o) {
            return false;
        } else if (this == o) {
            return true;
        } else if (!this.getClass().equals(ProxyUtils.getUserClass(o))) {
            return false;
        } else {
            final ActivationRecordEntity other = (ActivationRecordEntity) o;
            return Objects.equals(this.activationCode, other.activationCode);
        }
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
                + ", counter=" + counter
                + ", ctrDataBase64=" + ctrDataBase64
                + ", ctrDataV4Base64=" + ctrDataV4Base64
                + ", failedAttempts=" + failedAttempts
                + ", maxFailedAttempts=" + maxFailedAttempts
                + ", timestampCreated=" + timestampCreated
                + ", timestampActivationExpire=" + timestampActivationExpire
                + ", timestampLastUsed=" + timestampLastUsed
                + ", timestampLastChange=" + timestampLastChange
                + ", status=" + activationStatus
                + ", confirmationPending=" + confirmationPending
                + ", upgradeConfirmationPending=" + upgradeConfirmationPending
                + ", blockedReason=" + blockedReason
                + ", version=" + version
                + ", application=" + application
                + '}';
    }
}
