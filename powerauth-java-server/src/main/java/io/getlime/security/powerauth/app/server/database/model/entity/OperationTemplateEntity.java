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

package io.getlime.security.powerauth.app.server.database.model.entity;

import io.getlime.security.powerauth.app.server.database.model.SignatureTypeConverter;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;

import javax.persistence.*;
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
public class OperationTemplateEntity implements Serializable {

    private static final long serialVersionUID = -1534031615106111156L;

    @Id
    @SequenceGenerator(name = "pa_operation_template", sequenceName = "pa_operation_template_seq")
    @GeneratedValue(strategy = GenerationType.AUTO, generator = "pa_operation_template")
    @Column(name = "id")
    private Long id;

    @Column(name = "template_name")
    private String templateName;

    @Column(name = "operation_type")
    private String operationType;

    @Column(name = "data_template")
    private String dataTemplate;

    @Column(name = "signature_type")
    @Convert(converter = SignatureTypeConverter.class)
    private PowerAuthSignatureTypes[] signatureType;

    @Column(name = "max_failure_count")
    private Long maxFailureCount;

    @Column(name = "expiration")
    private Long expiration;

    /**
     * Default constructor.
     */
    public OperationTemplateEntity() {
    }

    /**
     * All param constructor
     *
     * @param id Operation template ID.
     * @param templateName Name of the template.
     * @param operationType Type of the operation.
     * @param dataTemplate Template of the data used for signing. The value may contain `${xyz}` placeholders.
     * @param signatureType Value representing which factors are allowed. One of: `1FA`, `2FA`, `2FA_NO_BIOMETRY`.
     * @param maxFailureCount Maximum allowed number of failures for authentication.
     * @param expiration Expiration in seconds (since "now").
     */
    public OperationTemplateEntity(Long id, String templateName, String operationType, String dataTemplate, PowerAuthSignatureTypes[] signatureType, Long maxFailureCount, Long expiration) {
        this.id = id;
        this.templateName = templateName;
        this.operationType = operationType;
        this.dataTemplate = dataTemplate;
        this.signatureType = signatureType;
        this.maxFailureCount = maxFailureCount;
        this.expiration = expiration;
    }

    /**
     * Get template ID.
     * @return Template ID.
     */
    public Long getId() {
        return id;
    }

    /**
     * Set template ID.
     * @param id Template ID.
     */
    public void setId(Long id) {
        this.id = id;
    }

    /**
     * Get template name.
     * @return Template name.
     */
    public String getTemplateName() {
        return templateName;
    }

    /**
     * Set template name.
     * @param templateName Template name.
     */
    public void setTemplateName(String templateName) {
        this.templateName = templateName;
    }

    /**
     * Get operation type.
     * @return Operation type.
     */
    public String getOperationType() {
        return operationType;
    }

    /**
     * Set operation type.
     * @param operationType Operation type.
     */
    public void setOperationType(String operationType) {
        this.operationType = operationType;
    }

    /**
     * Get data template. Template of the data used for signing. The value may contain `${xyz}` placeholders.
     * @return Data template.
     */
    public String getDataTemplate() {
        return dataTemplate;
    }

    /**
     * Set data template. Template of the data used for signing. The value may contain `${xyz}` placeholders.
     * @param dataTemplate Data template.
     */
    public void setDataTemplate(String dataTemplate) {
        this.dataTemplate = dataTemplate;
    }

    /**
     * Get signature type. Value representing which factors are allowed. One of: `1FA`, `2FA`, `2FA_NO_BIOMETRY`.
     * @return Signature types.
     */
    public PowerAuthSignatureTypes[] getSignatureType() {
        return signatureType;
    }

    /**
     * Set signature type. Value representing which factors are allowed. One of: `1FA`, `2FA`, `2FA_NO_BIOMETRY`.
     * @param signatureType Signature types.
     */
    public void setSignatureType(PowerAuthSignatureTypes[] signatureType) {
        this.signatureType = signatureType;
    }

    /**
     * Get maximum failure count.
     * @return Maximum failure count.
     */
    public Long getMaxFailureCount() {
        return maxFailureCount;
    }

    /**
     * Set maximum failure count.
     * @param maxFailureCount Maximum failure count.
     */
    public void setMaxFailureCount(Long maxFailureCount) {
        this.maxFailureCount = maxFailureCount;
    }

    /**
     * Get expiration in seconds (since "now").
     * @return Expiration.
     */
    public Long getExpiration() {
        return expiration;
    }

    /**
     * Set expiration in seconds (since "now").
     * @param expiration Expiration.
     */
    public void setExpiration(Long expiration) {
        this.expiration = expiration;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof OperationTemplateEntity)) return false;
        OperationTemplateEntity that = (OperationTemplateEntity) o;
        return Objects.equals(id, that.id)
                && Objects.equals(templateName, that.templateName)
                && Objects.equals(operationType, that.operationType)
                && Objects.equals(dataTemplate, that.dataTemplate)
                && Arrays.equals(signatureType, that.signatureType)
                && Objects.equals(maxFailureCount, that.maxFailureCount)
                && Objects.equals(expiration, that.expiration);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(id, templateName, operationType, dataTemplate, maxFailureCount, expiration);
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
                '}';
    }
}
