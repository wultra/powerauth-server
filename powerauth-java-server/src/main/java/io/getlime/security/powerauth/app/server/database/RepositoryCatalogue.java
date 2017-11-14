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

package io.getlime.security.powerauth.app.server.database;

import io.getlime.security.powerauth.app.server.database.repository.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Catalogue with all repositories.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Component
public class RepositoryCatalogue {

    private final ActivationRepository activationRepository;

    private final ApplicationRepository applicationRepository;

    private final ApplicationVersionRepository applicationVersionRepository;

    private final CallbackUrlRepository callbackUrlRepository;

    private final IntegrationRepository integrationRepository;

    private final MasterKeyPairRepository masterKeyPairRepository;

    private final SignatureAuditRepository signatureAuditRepository;

    private final TokenRepository tokenRepository;

    @Autowired
    public RepositoryCatalogue(
            ActivationRepository activationRepository,
            ApplicationRepository applicationRepository,
            ApplicationVersionRepository applicationVersionRepository,
            CallbackUrlRepository callbackUrlRepository,
            IntegrationRepository integrationRepository,
            MasterKeyPairRepository masterKeyPairRepository,
            SignatureAuditRepository signatureAuditRepository,
            TokenRepository tokenRepository) {

        this.activationRepository = activationRepository;
        this.applicationRepository = applicationRepository;
        this.applicationVersionRepository = applicationVersionRepository;
        this.callbackUrlRepository = callbackUrlRepository;
        this.integrationRepository = integrationRepository;
        this.masterKeyPairRepository = masterKeyPairRepository;
        this.signatureAuditRepository = signatureAuditRepository;
        this.tokenRepository = tokenRepository;
    }

    // Getters

    public ActivationRepository getActivationRepository() {
        return activationRepository;
    }

    public ApplicationRepository getApplicationRepository() {
        return applicationRepository;
    }

    public ApplicationVersionRepository getApplicationVersionRepository() {
        return applicationVersionRepository;
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
}
