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
package io.getlime.security.powerauth.app.server.database;

import io.getlime.security.powerauth.app.server.database.repository.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Catalogue with all repositories.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Component
public class RepositoryCatalogue {

    private final ActivationRepository activationRepository;

    private final ActivationHistoryRepository activationHistoryRepository;

    private final ApplicationRepository applicationRepository;

    private final ApplicationVersionRepository applicationVersionRepository;

    private final ApplicationConfigRepository applicationConfigRepository;

    private final CallbackUrlRepository callbackUrlRepository;

    private final IntegrationRepository integrationRepository;

    private final MasterKeyPairRepository masterKeyPairRepository;

    private final SignatureAuditRepository signatureAuditRepository;

    private final TokenRepository tokenRepository;

    private final RecoveryCodeRepository recoveryCodeRepository;

    private final RecoveryConfigRepository recoveryConfigRepository;

    @Autowired
    public RepositoryCatalogue(
            ActivationRepository activationRepository,
            ActivationHistoryRepository activationHistoryRepository,
            ApplicationRepository applicationRepository,
            ApplicationVersionRepository applicationVersionRepository,
            ApplicationConfigRepository applicationConfigRepository, CallbackUrlRepository callbackUrlRepository,
            IntegrationRepository integrationRepository,
            MasterKeyPairRepository masterKeyPairRepository,
            SignatureAuditRepository signatureAuditRepository,
            TokenRepository tokenRepository,
            RecoveryCodeRepository recoveryCodeRepository,
            RecoveryConfigRepository recoveryConfigRepository) {

        this.activationRepository = activationRepository;
        this.activationHistoryRepository = activationHistoryRepository;
        this.applicationRepository = applicationRepository;
        this.applicationVersionRepository = applicationVersionRepository;
        this.applicationConfigRepository = applicationConfigRepository;
        this.callbackUrlRepository = callbackUrlRepository;
        this.integrationRepository = integrationRepository;
        this.masterKeyPairRepository = masterKeyPairRepository;
        this.signatureAuditRepository = signatureAuditRepository;
        this.tokenRepository = tokenRepository;
        this.recoveryCodeRepository = recoveryCodeRepository;
        this.recoveryConfigRepository = recoveryConfigRepository;
    }

    // Getters

    public ActivationRepository getActivationRepository() {
        return activationRepository;
    }

    public ActivationHistoryRepository getActivationHistoryRepository() {
        return activationHistoryRepository;
    }

    public ApplicationRepository getApplicationRepository() {
        return applicationRepository;
    }

    public ApplicationVersionRepository getApplicationVersionRepository() {
        return applicationVersionRepository;
    }

    public ApplicationConfigRepository getApplicationConfigRepository() {
        return applicationConfigRepository;
    }

    public CallbackUrlRepository getCallbackUrlRepository() {
        return callbackUrlRepository;
    }

    public IntegrationRepository getIntegrationRepository() {
        return integrationRepository;
    }

    public MasterKeyPairRepository getMasterKeyPairRepository() {
        return masterKeyPairRepository;
    }

    public SignatureAuditRepository getSignatureAuditRepository() {
        return signatureAuditRepository;
    }

    public TokenRepository getTokenRepository() {
        return tokenRepository;
    }

    public RecoveryCodeRepository getRecoveryCodeRepository() {
        return recoveryCodeRepository;
    }

    public RecoveryConfigRepository getRecoveryConfigRepository() {
        return recoveryConfigRepository;
    }
}
