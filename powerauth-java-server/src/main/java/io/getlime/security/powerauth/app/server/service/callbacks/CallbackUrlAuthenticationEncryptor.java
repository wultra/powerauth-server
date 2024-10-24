package io.getlime.security.powerauth.app.server.service.callbacks;

import com.wultra.security.powerauth.client.model.entity.HttpAuthenticationPrivate;
import com.wultra.security.powerauth.client.model.entity.HttpAuthenticationPublic;
import io.getlime.security.powerauth.app.server.converter.CallbackAuthenticationConverter;
import io.getlime.security.powerauth.app.server.converter.CallbackAuthenticationPublicConverter;
import io.getlime.security.powerauth.app.server.database.model.entity.CallbackUrlAuthentication;
import io.getlime.security.powerauth.app.server.database.model.entity.CallbackUrlEntity;
import io.getlime.security.powerauth.app.server.service.encryption.EncryptableString;
import io.getlime.security.powerauth.app.server.service.encryption.EncryptionService;
import io.getlime.security.powerauth.app.server.service.exceptions.GenericServiceException;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.function.Supplier;

/**
 * Helper class handling encryption and decryption of the CallbackUrlAuthentication.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@Component
@AllArgsConstructor
public final class CallbackUrlAuthenticationEncryptor {

    private CallbackAuthenticationConverter callbackAuthenticationConverter;
    private EncryptionService encryptionService;

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
        return encryptionService.encrypt(callbackAuthenticationString, createEncryptionKeyProvider(applicationId));
    }

    /**
     * Decrypt Callback URL authentication settings.
     * @param entity Callback URL Entity which authentication settings to decrypt.
     * @return Callback URL authentication settings.
     * @throws GenericServiceException In case of a decryption error.
     */
    public CallbackUrlAuthentication decrypt(final CallbackUrlEntity entity) throws GenericServiceException {
        final String authentication = entity.getAuthentication();
        if (authentication == null) {
            return new CallbackUrlAuthentication();
        }
        final String existingCallbackAuthenticationString = encryptionService.decrypt(authentication, entity.getEncryptionMode(), createEncryptionKeyProvider(entity.getApplication().getId()));
        return callbackAuthenticationConverter.convertToEntityAttribute(existingCallbackAuthenticationString);
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

    private static Supplier<List<String>> createEncryptionKeyProvider(final String applicationId) {
        return () -> List.of(applicationId);
    }

}
