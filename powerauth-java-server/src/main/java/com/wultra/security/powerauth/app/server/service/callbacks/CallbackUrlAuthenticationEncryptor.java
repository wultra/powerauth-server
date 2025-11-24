package com.wultra.security.powerauth.app.server.service.callbacks;

import com.wultra.security.powerauth.app.server.service.encryption.*;
import com.wultra.security.powerauth.client.model.entity.HttpAuthenticationPrivate;
import com.wultra.security.powerauth.client.model.entity.HttpAuthenticationPublic;
import com.wultra.security.powerauth.app.server.converter.CallbackAuthenticationConverter;
import com.wultra.security.powerauth.app.server.converter.CallbackAuthenticationPublicConverter;
import com.wultra.security.powerauth.app.server.database.model.entity.CallbackUrlAuthentication;
import com.wultra.security.powerauth.app.server.database.model.entity.CallbackUrlEntity;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Helper class handling encryption and decryption of the CallbackUrlAuthentication.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@Component
@Slf4j
@AllArgsConstructor
public final class CallbackUrlAuthenticationEncryptor {

    private final CallbackAuthenticationConverter callbackAuthenticationConverter;
    private final DatabaseEncryptionService encryptionService;

    private final CallbackAuthenticationPublicConverter authenticationPublicConverter = new CallbackAuthenticationPublicConverter();

    /**
     * Encrypt Callback URL authentication settings.
     * @param source Callback URL authentication settings.
     * @param applicationId ID of associated application.
     * @return Encrypted Callback URL authentication settings.
     * @throws GenericServiceException In case of an encryption error.
     */
    public EncryptableString encrypt(final HttpAuthenticationPrivate source, final String applicationId) throws GenericServiceException {
        final CallbackUrlAuthentication callbackAuthentication = authenticationPublicConverter.fromNetworkObject(source);
        final String callbackAuthenticationString = callbackAuthenticationConverter.convertToDatabaseColumn(callbackAuthentication);
        final EncryptionKeySupplier keySupplier = encryptionKeySupplier(applicationId);
        return encryptionService.encrypt(callbackAuthenticationString, keySupplier, encryptionService.getDefaultEncryptionAlgorithm());
    }

    /**
     * Decrypt Callback URL authentication settings.
     * @param entity Callback URL Entity which authentication settings to decrypt.
     * @return Callback URL authentication settings.
     * @throws GenericServiceException In case of a decryption error.
     */
    public CallbackUrlAuthentication decrypt(final CallbackUrlEntity entity) throws GenericServiceException {
        final String encryptedAuthentication = entity.getAuthentication();
        if (encryptedAuthentication == null) {
            return new CallbackUrlAuthentication();
        }
        final EncryptionKeySupplier keySupplier = encryptionKeySupplier(entity.getApplication().getId());
        final String decrypted = encryptionService.decrypt(encryptedAuthentication, keySupplier, entity.getEncryptionAlgorithm());
        return callbackAuthenticationConverter.convertToEntityAttribute(decrypted);
    }

    /**
     * Decrypt Callback URL authentication settings and return structure with hidden secrets.
     * @param entity Callback URL Entity which authentication settings to decrypt.
     * @return Callback URL authentication settings with hidden secrets.
     * @throws GenericServiceException In case of a decryption error.
     */
    public HttpAuthenticationPublic decryptToPublic(final CallbackUrlEntity entity) throws GenericServiceException {
        final CallbackUrlAuthentication authentication = decrypt(entity);
        return authenticationPublicConverter.toPublic(authentication);
    }

    private static EncryptionKeySupplier encryptionKeySupplier(final String applicationId) {
        return new DefaultEncryptionKeySupplier(
                List.of(applicationId),
                List.of("pa_application_callback", "authentication", applicationId)
        );
    }

}