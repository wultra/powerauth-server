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
package io.getlime.security.powerauth.app.server.service.behavior;

import io.getlime.security.powerauth.app.server.service.behavior.tasks.v3.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;

/**
 * Collection of all behaviors used by the PowerAuth Server service.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Component
public class ServiceBehaviorCatalogue {

    private ActivationServiceBehavior activationServiceBehavior;

    private ActivationFlagsServiceBehavior activationFlagsServiceBehavior;

    private ActivationHistoryServiceBehavior activationHistoryServiceBehavior;

    private ApplicationServiceBehavior applicationServiceBehavior;

    private ApplicationRolesServiceBehavior applicationRolesServiceBehavior;

    private AuditingServiceBehavior auditingServiceBehavior;

    private OnlineSignatureServiceBehavior onlineSignatureServiceBehavior;

    private OfflineSignatureServiceBehavior offlineSignatureServiceBehavior;

    private VaultUnlockServiceBehavior vaultUnlockServiceBehavior;

    private IntegrationBehavior integrationBehavior;

    private CallbackUrlBehavior callbackUrlBehavior;

    private AsymmetricSignatureServiceBehavior asymmetricSignatureServiceBehavior;

    private TokenBehavior tokenBehavior;

    private EciesEncryptionBehavior eciesEncryptionBehavior;

    private UpgradeServiceBehavior upgradeServiceBehavior;

    private RecoveryServiceBehavior recoveryServiceBehavior;

    private OperationServiceBehavior operationServiceBehavior;

    private OperationTemplateServiceBehavior operationTemplateServiceBehavior;

    @Autowired
    public void setActivationServiceBehavior(@Lazy ActivationServiceBehavior activationServiceBehavior) {
        this.activationServiceBehavior = activationServiceBehavior;
    }

    @Autowired
    public void setActivationFlagsServiceBehavior(@Lazy ActivationFlagsServiceBehavior activationFlagsServiceBehavior) {
        this.activationFlagsServiceBehavior = activationFlagsServiceBehavior;
    }

    @Autowired
    public void setActivationHistoryServiceBehavior(@Lazy ActivationHistoryServiceBehavior activationHistoryServiceBehavior) {
        this.activationHistoryServiceBehavior = activationHistoryServiceBehavior;
    }

    @Autowired
    public void setApplicationServiceBehavior(@Lazy ApplicationServiceBehavior applicationServiceBehavior) {
        this.applicationServiceBehavior = applicationServiceBehavior;
    }

    @Autowired
    public void setApplicationRolesServiceBehavior(@Lazy ApplicationRolesServiceBehavior applicationRolesServiceBehavior) {
        this.applicationRolesServiceBehavior = applicationRolesServiceBehavior;
    }

    @Autowired
    public void setAuditingServiceBehavior(@Lazy AuditingServiceBehavior auditingServiceBehavior) {
        this.auditingServiceBehavior = auditingServiceBehavior;
    }

    @Autowired
    public void setOnlineSignatureServiceBehavior(@Lazy OnlineSignatureServiceBehavior onlineSignatureServiceBehavior) {
        this.onlineSignatureServiceBehavior = onlineSignatureServiceBehavior;
    }

    @Autowired
    public void setOfflineSignatureServiceBehavior(@Lazy OfflineSignatureServiceBehavior offlineSignatureServiceBehavior) {
        this.offlineSignatureServiceBehavior = offlineSignatureServiceBehavior;
    }

    @Autowired
    public void setVaultUnlockServiceBehavior(@Lazy VaultUnlockServiceBehavior vaultUnlockServiceBehavior) {
        this.vaultUnlockServiceBehavior = vaultUnlockServiceBehavior;
    }

    @Autowired
    public void setIntegrationBehavior(@Lazy IntegrationBehavior integrationBehavior) {
        this.integrationBehavior = integrationBehavior;
    }

    @Autowired
    public void setCallbackUrlBehavior(@Lazy CallbackUrlBehavior callbackUrlBehavior) {
        this.callbackUrlBehavior = callbackUrlBehavior;
    }

    @Autowired
    public void setAsymmetricSignatureServiceBehavior(@Lazy AsymmetricSignatureServiceBehavior asymmetricSignatureServiceBehavior) {
        this.asymmetricSignatureServiceBehavior = asymmetricSignatureServiceBehavior;
    }

    @Autowired
    public void setTokenBehavior(@Lazy TokenBehavior tokenBehavior) {
        this.tokenBehavior = tokenBehavior;
    }

    @Autowired
    public void setEciesEncryptionBehavior(@Lazy EciesEncryptionBehavior eciesEncryptionBehavior) {
        this.eciesEncryptionBehavior = eciesEncryptionBehavior;
    }

    @Autowired
    public void setUpgradeServiceBehavior(@Lazy UpgradeServiceBehavior upgradeServiceBehavior) {
        this.upgradeServiceBehavior = upgradeServiceBehavior;
    }

    @Autowired
    public void setRecoveryServiceBehavior(@Lazy RecoveryServiceBehavior recoveryServiceBehavior) {
        this.recoveryServiceBehavior = recoveryServiceBehavior;
    }

    @Autowired
    public void setRecoveryServiceBehavior(@Lazy OperationServiceBehavior operationServiceBehavior) {
        this.operationServiceBehavior = operationServiceBehavior;
    }

    @Autowired
    public void setOperationBehavior(@Lazy OperationServiceBehavior operationServiceBehavior) {
        this.operationServiceBehavior = operationServiceBehavior;
    }

    @Autowired
    public void setOperationTemplateBehavior(@Lazy OperationTemplateServiceBehavior operationTemplateServiceBehavior) {
        this.operationTemplateServiceBehavior = operationTemplateServiceBehavior;
    }

    public ActivationServiceBehavior getActivationServiceBehavior() {
        return activationServiceBehavior;
    }

    public ActivationFlagsServiceBehavior getActivationFlagsServiceBehavior() {
        return activationFlagsServiceBehavior;
    }

    public ApplicationServiceBehavior getApplicationServiceBehavior() {
        return applicationServiceBehavior;
    }

    public ApplicationRolesServiceBehavior getApplicationRolesServiceBehavior() {
        return applicationRolesServiceBehavior;
    }

    public ActivationHistoryServiceBehavior getActivationHistoryServiceBehavior() {
        return activationHistoryServiceBehavior;
    }

    public AuditingServiceBehavior getAuditingServiceBehavior() {
        return auditingServiceBehavior;
    }

    public OnlineSignatureServiceBehavior getOnlineSignatureServiceBehavior() {
        return onlineSignatureServiceBehavior;
    }

    public OfflineSignatureServiceBehavior getOfflineSignatureServiceBehavior() {
        return offlineSignatureServiceBehavior;
    }

    public VaultUnlockServiceBehavior getVaultUnlockServiceBehavior() {
        return vaultUnlockServiceBehavior;
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

    public TokenBehavior getTokenBehavior() {
        return tokenBehavior;
    }

    public EciesEncryptionBehavior getEciesEncryptionBehavior() {
        return eciesEncryptionBehavior;
    }

    public UpgradeServiceBehavior getUpgradeServiceBehavior() {
        return upgradeServiceBehavior;
    }

    public RecoveryServiceBehavior getRecoveryServiceBehavior() {
        return recoveryServiceBehavior;
    }

    public OperationServiceBehavior getOperationBehavior() {
        return operationServiceBehavior;
    }

    public OperationTemplateServiceBehavior getOperationTemplateBehavior() {
        return operationTemplateServiceBehavior;
    }

}
