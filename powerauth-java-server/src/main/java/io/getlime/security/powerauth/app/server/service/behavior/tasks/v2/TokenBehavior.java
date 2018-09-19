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

package io.getlime.security.powerauth.app.server.service.behavior.tasks.v2;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import io.getlime.security.powerauth.app.server.converter.v3.SignatureTypeConverter;
import io.getlime.security.powerauth.app.server.database.RepositoryCatalogue;
import io.getlime.security.powerauth.app.server.database.model.ActivationStatus;
import io.getlime.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.MasterKeyPairEntity;
import io.getlime.security.powerauth.app.server.database.model.entity.TokenEntity;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import io.getlime.security.powerauth.app.server.service.i18n.LocalizationProvider;
import io.getlime.security.powerauth.app.server.service.model.ServiceError;
import io.getlime.security.powerauth.app.server.service.model.TokenInfo;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.BasicEciesDecryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.exception.EciesException;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesPayload;
import io.getlime.security.powerauth.crypto.server.token.ServerTokenGenerator;
import io.getlime.security.powerauth.crypto.server.token.ServerTokenVerifier;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.v2.CreateTokenRequest;
import io.getlime.security.powerauth.v2.CreateTokenResponse;
import io.getlime.security.powerauth.v2.SignatureType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Calendar;
import java.util.Optional;

/**
 * Behavior that contains methods related to simple token-based authentication.
 *
 * <h5>PowerAuth protocol versions:</h5>
 * <ul>
 *     <li>2.0</li>
 *     <li>2.1</li>
 * </ul>
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Component("TokenBehaviorV2")
public class TokenBehavior {

    private RepositoryCatalogue repositoryCatalogue;
    private LocalizationProvider localizationProvider;
    private PowerAuthServiceConfiguration powerAuthServiceConfiguration;

    // Business logic implementation classes
    private final ServerTokenGenerator tokenGenerator = new ServerTokenGenerator();
    private final ServerTokenVerifier tokenVerifier = new ServerTokenVerifier();

    // Helper classes
    private final SignatureTypeConverter signatureTypeConverter = new SignatureTypeConverter();

    @Autowired
    public TokenBehavior(RepositoryCatalogue repositoryCatalogue, LocalizationProvider localizationProvider, PowerAuthServiceConfiguration powerAuthServiceConfiguration) {
        this.repositoryCatalogue = repositoryCatalogue;
        this.localizationProvider = localizationProvider;
        this.powerAuthServiceConfiguration = powerAuthServiceConfiguration;
    }

    /**
     * Method that creates a new token provided activation.
     *
     * <h5>PowerAuth protocol versions:</h5>
     * <ul>
     *     <li>2.0</li>
     *     <li>2.1</li>
     * </ul>
     *
     * @param request Request with the activation ID, signature type and ephemeral public key.
     * @param keyConversion Key conversion utility class.
     * @return Response with a newly created token information (ECIES encrypted).
     * @throws GenericServiceException In case a business error occurs.
     */
    public CreateTokenResponse createToken(CreateTokenRequest request, CryptoProviderUtil keyConversion) throws GenericServiceException {
        final String activationId = request.getActivationId();
        final String ephemeralPublicKeyBase64 = request.getEphemeralPublicKey();
        final SignatureType signatureType = request.getSignatureType();

        EciesPayload encryptedPayload = createToken(activationId, ephemeralPublicKeyBase64, signatureType.value(), keyConversion);

        final CreateTokenResponse response = new CreateTokenResponse();
        response.setMac(BaseEncoding.base64().encode(encryptedPayload.getMac()));
        response.setEncryptedData(BaseEncoding.base64().encode(encryptedPayload.getEncryptedData()));
        return response;
    }

    /**
     * Create a new token implementation.
     *
     * @param activationId Activation ID.
     * @param ephemeralPublicKeyBase64 Base-64 encoded ephemeral public key.
     * @param signatureType Signature type.
     * @param keyConversion Key conversion utility class.
     * @return Response with a newly created token information (ECIES encrypted).
     * @throws GenericServiceException In case a business error occurs.
     */
    private EciesPayload createToken(String activationId, String ephemeralPublicKeyBase64, String signatureType, CryptoProviderUtil keyConversion) throws GenericServiceException {
        try {
            // Lookup the activation
            final ActivationRecordEntity activation = repositoryCatalogue.getActivationRepository().findActivation(activationId);
            if (activation == null) {
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
            }

            // Check if the activation is in correct state
            if (!ActivationStatus.ACTIVE.equals(activation.getActivationStatus())) {
                throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
            }

            final Long applicationId = activation.getApplication().getId();
            final MasterKeyPairEntity masterKeyPairEntity = repositoryCatalogue.getMasterKeyPairRepository().findFirstByApplicationIdOrderByTimestampCreatedDesc(applicationId);
            final String masterPrivateKeyBase64 = masterKeyPairEntity.getMasterKeyPrivateBase64();

            final PrivateKey privateKey = keyConversion.convertBytesToPrivateKey(BaseEncoding.base64().decode(masterPrivateKeyBase64));
            final byte[] ephemeralPublicKeyBytes = BaseEncoding.base64().decode(ephemeralPublicKeyBase64);
            final PublicKey ephemeralPublicKey = keyConversion.convertBytesToPublicKey(ephemeralPublicKeyBytes);

            // Generate unique token ID.
            String tokenId = null;
            for (int i = 0; i < powerAuthServiceConfiguration.getGenerateTokenIdIterations(); i++) {
                String tmpTokenId = tokenGenerator.generateTokenId();
                final Optional<TokenEntity> tmpTokenOptional = repositoryCatalogue.getTokenRepository().findById(tmpTokenId);
                if (!tmpTokenOptional.isPresent()) {
                    tokenId = tmpTokenId;
                    break;
                } // ... else this token ID has a collision, reset it and try to find another one
            }
            if (tokenId == null) {
                throw localizationProvider.buildExceptionForCode(ServiceError.UNABLE_TO_GENERATE_TOKEN);
            }

            // Create a new token
            TokenEntity token = new TokenEntity();
            token.setTokenId(tokenId);
            token.setTokenSecret(BaseEncoding.base64().encode(tokenGenerator.generateTokenSecret()));
            token.setActivation(activation);
            token.setTimestampCreated(Calendar.getInstance().getTime());
            token.setSignatureTypeCreated(signatureType);
            token = repositoryCatalogue.getTokenRepository().save(token);

            final TokenInfo tokenInfo = new TokenInfo();
            tokenInfo.setTokenId(token.getTokenId());
            tokenInfo.setTokenSecret(token.getTokenSecret());

            final ObjectMapper mapper = new ObjectMapper();
            final byte[] tokenBytes = mapper.writeValueAsBytes(tokenInfo);

            final BasicEciesDecryptor decryptor = new BasicEciesDecryptor((ECPrivateKey) privateKey);
            return decryptor.encrypt(tokenBytes, (ECPublicKey) ephemeralPublicKey, ephemeralPublicKeyBytes);
        } catch (InvalidKeySpecException e) {
            throw localizationProvider.buildExceptionForCode(ServiceError.INCORRECT_MASTER_SERVER_KEYPAIR_PRIVATE);
        } catch (EciesException e) {
            throw localizationProvider.buildExceptionForCode(ServiceError.ENCRYPTION_FAILED);
        } catch (JsonProcessingException e) {
            throw localizationProvider.buildExceptionForCode(ServiceError.UNKNOWN_ERROR);
        }
    }
}
