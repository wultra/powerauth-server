/*
 * PowerAuth Server and related software components
 * Copyright (C) 2025 Wultra s.r.o.
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

package com.wultra.security.powerauth.app.server.service.crypto;

import com.wultra.security.powerauth.app.server.converter.PublicKeysConverter;
import com.wultra.security.powerauth.app.server.converter.ServerPrivateKeysConverter;
import com.wultra.security.powerauth.app.server.database.model.KeyType;
import com.wultra.security.powerauth.app.server.database.model.PrivateKeyRegistry;
import com.wultra.security.powerauth.app.server.database.model.PrivateKeysRecord;
import com.wultra.security.powerauth.app.server.database.model.PublicKeyRegistry;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.DevicePublicKeyEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ServerPrivateKeyEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ServerPublicKeyEntity;
import com.wultra.security.powerauth.app.server.database.repository.DevicePublicKeyRepository;
import com.wultra.security.powerauth.app.server.database.repository.ServerPrivateKeyRepository;
import com.wultra.security.powerauth.app.server.database.repository.ServerPublicKeyRepository;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Optional;

/**
 * Component responsible for loading and storing server and device keys
 * associated with an activation.
 *
 * @author Jan Pesek, jan.pesek@wultra.com
 */
@AllArgsConstructor
@Component
public class KeyProvider {

    private final ServerPublicKeyRepository serverPublicKeyRepository;
    private final PublicKeysConverter publicKeysConverter;

    private final ServerPrivateKeyRepository serverPrivateKeyRepository;
    private final ServerPrivateKeysConverter serverPrivateKeysConverter;

    private final DevicePublicKeyRepository devicePublicKeyRepository;

    /**
     * Retrieve server private keys associated with the given activation.
     *
     * @param activation The activation which server private keys to retrieve.
     * @return An {@link Optional} containing the server private key registry, or empty if none exists.
     * @throws GenericServiceException If the conversion from database representation fails.
     */
    public Optional<PrivateKeyRegistry> getServerPrivateKeys(final ActivationRecordEntity activation) throws GenericServiceException {
        final ServerPrivateKeyEntity entity = activation.getServerPrivateKey();
        if (entity == null) {
            return Optional.empty();
        }

        final PrivateKeysRecord privateKeys = new PrivateKeysRecord(
                entity.getEncryptionAlgorithm(),
                entity.getKeyData()
        );

        return Optional.of(
                serverPrivateKeysConverter.fromDBValue(
                        privateKeys,
                        activation.getUserId(),
                        activation.getActivationId()
                )
        );
    }

    /**
     * Retrieve a specific server private key of the given type.
     *
     * @param activation The activation which server private key to retrieve.
     * @param keyType The type of the private key to retrieve.
     * @return An {@link Optional} containing the server private key, or empty if it does not exist.
     * @throws GenericServiceException If the conversion from database representation fails.
     */
    public Optional<PrivateKey> getServerPrivateKey(final ActivationRecordEntity activation, final KeyType keyType) throws GenericServiceException {
        return getServerPrivateKeys(activation)
                .flatMap(registry -> registry.getPrivateKey(keyType));
    }

    /**
     * Stores server private keys for the given activation.
     *
     * @param activation The activation to which the server private keys should be attached.
     * @param registry Registry containing server private keys.
     * @throws GenericServiceException If the conversion to database representation fails.
     */
    public void storeServerPrivateKeys(final ActivationRecordEntity activation, final PrivateKeyRegistry registry) throws GenericServiceException {
        ServerPrivateKeyEntity entity = activation.getServerPrivateKey();
        if (entity == null) {
            entity = new ServerPrivateKeyEntity();
            activation.setServerPrivateKey(entity);
        }

        final PrivateKeysRecord record = serverPrivateKeysConverter.toDBValue(registry, activation.getUserId(), activation.getActivationId());
        entity.setEncryptionAlgorithm(record.encryptionAlgorithm());
        entity.setKeyData(record.privateKeysBase64());
        serverPrivateKeyRepository.save(entity);
    }

    /**
     * Retrieve server public keys associated with the given activation.
     *
     * @param activation The activation which server public keys to retrieve.
     * @return An {@link Optional} containing the server public key registry, or empty if none exists.
     * @throws GenericServiceException If the conversion from database representation fails.
     */
    public Optional<PublicKeyRegistry> getServerPublicKeys(final ActivationRecordEntity activation) throws GenericServiceException {
        final ServerPublicKeyEntity entity = activation.getServerPublicKey();
        if (entity == null) {
            return Optional.empty();
        }

        return Optional.of(publicKeysConverter.fromDBValue(entity.getKeyData()));
    }

    /**
     * Retrieve a specific server public key of the given type.
     *
     * @param activation The activation which server public key to retrieve.
     * @param keyType The type of the public key to retrieve.
     * @return An {@link Optional} containing the server public key, or empty if it does not exist.
     * @throws GenericServiceException If the conversion from database representation fails.
     */
    public Optional<PublicKey> getServerPublicKey(final ActivationRecordEntity activation, final KeyType keyType) throws GenericServiceException {
        return getServerPublicKeys(activation)
                .flatMap(registry -> registry.getPublicKey(keyType));
    }

    /**
     * Stores server public keys for the given activation.
     *
     * @param activation The activation to which the server public keys should be attached.
     * @param registry Registry containing server public keys.
     * @throws GenericServiceException If the conversion to database representation fails.
     */
    public void storeServerPublicKeys(final ActivationRecordEntity activation, final PublicKeyRegistry registry) throws GenericServiceException {
        ServerPublicKeyEntity entity = activation.getServerPublicKey();
        if (entity == null) {
            entity = new ServerPublicKeyEntity();
            activation.setServerPublicKey(entity);
        }

        entity.setKeyData(publicKeysConverter.toDBValue(registry));
        serverPublicKeyRepository.save(entity);
    }

    /**
     * Retrieve device public keys associated with the given activation.
     *
     * @param activation The activation which device public keys to retrieve.
     * @return An {@link Optional} containing the device public key registry, or empty if none exists.
     * @throws GenericServiceException If the conversion from database representation fails.
     */
    public Optional<PublicKeyRegistry> getDevicePublicKeys(final ActivationRecordEntity activation) throws GenericServiceException {
        final DevicePublicKeyEntity entity = activation.getDevicePublicKey();
        if (entity == null) {
            return Optional.empty();
        }

        return Optional.of(publicKeysConverter.fromDBValue(entity.getKeyData()));
    }

    /**
     * Retrieve a specific device public key of the given type.
     *
     * @param activation The activation which device public key to retrieve.
     * @param keyType The type of the public key to retrieve.
     * @return An {@link Optional} containing the device public key, or empty if it does not exist.
     * @throws GenericServiceException If the conversion from database representation fails.
     */
    public Optional<PublicKey> getDevicePublicKey(final ActivationRecordEntity activation, final KeyType keyType) throws GenericServiceException {
        return getDevicePublicKeys(activation)
                .flatMap(registry -> registry.getPublicKey(keyType));
    }

    /**
     * Stores a device public key for the given activation.
     *
     * @param activation The activation to which the device public key should be attached.
     * @param keyType The type of the public key to store.
     * @param publicKey The public key to store.
     * @throws GenericServiceException If the conversion to database representation fails.
     */
    public void storeDevicePublicKey(final ActivationRecordEntity activation, final KeyType keyType, final PublicKey publicKey) throws GenericServiceException {
        DevicePublicKeyEntity entity = activation.getDevicePublicKey();
        if (entity == null) {
            entity = new DevicePublicKeyEntity();
            activation.setDevicePublicKey(entity);
        }

        final PublicKeyRegistry registry = entity.getKeyData() == null
                ? new PublicKeyRegistry()
                : publicKeysConverter.fromDBValue(entity.getKeyData());

        registry.storePublicKey(keyType, publicKey);
        entity.setKeyData(publicKeysConverter.toDBValue(registry));
        devicePublicKeyRepository.save(entity);
    }

}
