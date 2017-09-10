/*
 * PowerAuth Server and related software components
 * Copyright (C) 2017 Lime - HighTech Solutions s.r.o.
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

package io.getlime.security.powerauth.app.server.service.behavior;

import io.getlime.security.powerauth.app.server.service.behavior.tasks.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Collection of all behaviors used by the PowerAuth 2.0 Server service.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Component
public class ServiceBehaviorCatalogue {

    private ActivationServiceBehavior activationServiceBehavior;

    private ApplicationServiceBehavior applicationServiceBehavior;

    private AuditingServiceBehavior auditingServiceBehavior;

    private SignatureServiceBehavior signatureServiceBehavior;

    private VaultUnlockServiceBehavior vaultUnlockServiceBehavior;

    private EncryptionServiceBehavior encryptionServiceBehavior;

    private IntegrationBehavior integrationBehavior;

    private CallbackUrlBehavior callbackUrlBehavior;

    private AsymmetricSignatureServiceBehavior asymmetricSignatureServiceBehavior;

    public ActivationServiceBehavior getActivationServiceBehavior() {
        return activationServiceBehavior;
    }

    @Autowired
    public void setActivationServiceBehavior(ActivationServiceBehavior activationServiceBehavior) {
        this.activationServiceBehavior = activationServiceBehavior;
    }

    @Autowired
    public void setApplicationServiceBehavior(ApplicationServiceBehavior applicationServiceBehavior) {
        this.applicationServiceBehavior = applicationServiceBehavior;
    }

    @Autowired
    public void setAuditingServiceBehavior(AuditingServiceBehavior auditingServiceBehavior) {
        this.auditingServiceBehavior = auditingServiceBehavior;
    }

    @Autowired
    public void setSignatureServiceBehavior(SignatureServiceBehavior signatureServiceBehavior) {
        this.signatureServiceBehavior = signatureServiceBehavior;
    }

    @Autowired
    public void setVaultUnlockServiceBehavior(VaultUnlockServiceBehavior vaultUnlockServiceBehavior) {
        this.vaultUnlockServiceBehavior = vaultUnlockServiceBehavior;
    }

    @Autowired
    public void setEncryptionServiceBehavior(EncryptionServiceBehavior encryptionServiceBehavior) {
        this.encryptionServiceBehavior = encryptionServiceBehavior;
    }
    @Autowired
    public void setIntegrationBehavior(IntegrationBehavior integrationBehavior) {
        this.integrationBehavior = integrationBehavior;
    }

    @Autowired
    public void setCallbackUrlBehavior(CallbackUrlBehavior callbackUrlBehavior) {
        this.callbackUrlBehavior = callbackUrlBehavior;
    }

    @Autowired
    public void setAsymmetricSignatureServiceBehavior(AsymmetricSignatureServiceBehavior asymmetricSignatureServiceBehavior) {
        this.asymmetricSignatureServiceBehavior = asymmetricSignatureServiceBehavior;
    }

    public ApplicationServiceBehavior getApplicationServiceBehavior() {
        return applicationServiceBehavior;
    }

    public AuditingServiceBehavior getAuditingServiceBehavior() {
        return auditingServiceBehavior;
    }

    public SignatureServiceBehavior getSignatureServiceBehavior() {
        return signatureServiceBehavior;
    }

    public VaultUnlockServiceBehavior getVaultUnlockServiceBehavior() {
        return vaultUnlockServiceBehavior;
    }

    public EncryptionServiceBehavior getEncryptionServiceBehavior() {
        return encryptionServiceBehavior;
    }

    public IntegrationBehavior getIntegrationBehavior() {
        return integrationBehavior;
    }

    public CallbackUrlBehavior getCallbackUrlBehavior() {
        return callbackUrlBehavior;
    }

    public AsymmetricSignatureServiceBehavior getAsymmetricSignatureServiceBehavior() {
        return asymmetricSignatureServiceBehavior;
    }

}
