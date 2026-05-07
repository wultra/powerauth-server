/*
 * PowerAuth Server and related software components
 * Copyright (C) 2020 Wultra s.r.o.
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

import com.wultra.security.powerauth.app.server.database.model.converter.AuthCodeTypeConverter;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.util.ProxyUtils;

import java.io.Serial;
import java.io.Serializable;
import java.util.Arrays;
import java.util.Objects;

/**
 * Entity representing an operation template.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Entity
@Table(name = "pa_operation_template")
@Getter @Setter
public class OperationTemplateEntity implements Serializable {

    @Serial
    private static final long serialVersionUID = -1534031615106111156L;

    /**
     * Template ID.
     */
    @Id
    @SequenceGenerator(name = "pa_operation_template", sequenceName = "pa_operation_template_seq", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.AUTO, generator = "pa_operation_template")
    @Column(name = "id")
    private Long id;

    /**
     * Template name.
     */
    @Column(name = "template_name", nullable=false, unique = true)
    private String templateName;

    /**
     * Operation type.
     */
    @Column(name = "operation_type", nullable=false)
    private String operationType;

    /**
     * Data template. Template of the data used for signing. The value may contain {@code ${xyz}} placeholders.
     */
    @Column(name = "data_template", nullable=false)
    private String dataTemplate;

    /**
     * Authentication code types. Value representing which factors are allowed. One of: {@code 1FA}, {@code 2FA}, {@code 2FA_NO_BIOMETRY}.
     */
    @Column(name = "signature_type", nullable=false)
    @Convert(converter = AuthCodeTypeConverter.class)
    private PowerAuthCodeType[] signatureType;

    /**
     * Maximum failure count.
     */
    @Column(name = "max_failure_count", nullable=false)
    private Long maxFailureCount;

    /**
     * Expiration in seconds (since now).
     */
    @Column(name = "expiration", nullable=false)
    private Long expiration;

    /**
     * Risk flags.
     */
    @Column(name = "risk_flags")
    private String riskFlags;

    /**
     * Whether proximity check enabled.
     */
    @Column(name = "proximity_check_enabled")
    private boolean proximityCheckEnabled;

    @Override public boolean equals(Object o) {
        if (null == o) {
            return false;
        }
        if (this == o) {
            return true;
        }
        if (!ProxyUtils.getUserClass(this).equals(ProxyUtils.getUserClass(o))) {
            return false;
        }
        final OperationTemplateEntity other = (OperationTemplateEntity) o;
        return templateName.equals(other.templateName)
                && operationType.equals(other.operationType)
                && Objects.equals(dataTemplate, other.dataTemplate)
                && Arrays.equals(signatureType, other.signatureType)
                && Objects.equals(maxFailureCount, other.maxFailureCount)
                && Objects.equals(expiration, other.expiration)
                && Objects.equals(riskFlags, other.riskFlags)
                && Objects.equals(proximityCheckEnabled, other.proximityCheckEnabled);
    }

    @Override public int hashCode() {
        int result = Objects.hash(
                templateName, operationType, dataTemplate, maxFailureCount, expiration, riskFlags, proximityCheckEnabled
        );
        result = 31 * result + Arrays.hashCode(signatureType);
        return result;
    }

    @Override public String toString() {
        return "OperationTemplateEntity{" +
                "id=" + id +
                ", templateName='" + templateName + '\'' +
                ", operationType='" + operationType + '\'' +
                ", dataTemplate='" + dataTemplate + '\'' +
                ", signatureType=" + Arrays.toString(signatureType) +
                ", maxFailureCount=" + maxFailureCount +
                ", expiration=" + expiration +
                ", riskFlags=" + riskFlags +
                ", proximityCheckEnabled=" + proximityCheckEnabled +
                '}';
    }
}
