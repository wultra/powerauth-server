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
public final class CallbackUrlAuthenticationCryptor {

    private CallbackAuthenticationConverter callbackAuthenticationConverter;
    private EncryptionService encryptionService;

    private final CallbackAuthenticationPublicConverter authenticationPublicConverter = new CallbackAuthenticationPublicConverter();

    public EncryptableString encrypt(final HttpAuthenticationPrivate source, final String applicationId) throws GenericServiceException {
        final CallbackUrlAuthentication callbackAuthentication = authenticationPublicConverter.fromNetworkObject(source);
        final String callbackAuthenticationString = callbackAuthenticationConverter.convertToDatabaseColumn(callbackAuthentication);
        return encryptionService.encrypt(callbackAuthenticationString, createEncryptionKeyProvider(applicationId));
    }

    public CallbackUrlAuthentication decrypt(final CallbackUrlEntity entity) throws GenericServiceException {
        final String authentication = entity.getAuthentication();
        if (authentication == null) {
            return new CallbackUrlAuthentication();
        }
        final String existingCallbackAuthenticationString = encryptionService.decrypt(authentication, entity.getEncryptionMode(), createEncryptionKeyProvider(entity.getApplication().getId()));
        return callbackAuthenticationConverter.convertToEntityAttribute(existingCallbackAuthenticationString);
    }

    public HttpAuthenticationPublic decryptToPublic(final CallbackUrlEntity entity) throws GenericServiceException {
        final CallbackUrlAuthentication authentication = decrypt(entity);
        return authenticationPublicConverter.toPublic(authentication);
    }

    public static Supplier<List<String>> createEncryptionKeyProvider(final String applicationId) {
        return () -> List.of(applicationId);
    }

}
