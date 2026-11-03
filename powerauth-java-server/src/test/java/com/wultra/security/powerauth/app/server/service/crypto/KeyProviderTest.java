/*
 * PowerAuth Server and related software components
 * Copyright (C) 2026 Wultra s.r.o.
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
 *
 */
package com.wultra.security.powerauth.app.server.service.crypto;

import com.wultra.security.powerauth.app.server.converter.PublicKeysConverter;
import com.wultra.security.powerauth.app.server.converter.ServerPrivateKeysConverter;
import com.wultra.security.powerauth.app.server.database.repository.DevicePublicKeyRepository;
import com.wultra.security.powerauth.app.server.database.repository.ServerPrivateKeyRepository;
import com.wultra.security.powerauth.app.server.database.repository.ServerPublicKeyRepository;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.DevicePublicKeyEntity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.LongStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Test for {@link KeyProvider} device public key pre-fetch.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@ExtendWith(MockitoExtension.class)
class KeyProviderTest {

    @Mock
    private ServerPublicKeyRepository serverPublicKeyRepository;

    @Mock
    private PublicKeysConverter publicKeysConverter;

    @Mock
    private ServerPrivateKeyRepository serverPrivateKeyRepository;

    @Mock
    private ServerPrivateKeysConverter serverPrivateKeysConverter;

    @Mock
    private DevicePublicKeyRepository devicePublicKeyRepository;

    private KeyProvider tested;

    @BeforeEach
    void setUp() {
        tested = new KeyProvider(serverPublicKeyRepository, publicKeysConverter, serverPrivateKeyRepository, serverPrivateKeysConverter, devicePublicKeyRepository);
    }

    @Test
    void prefetchDoesNotQueryForNoActivations() {
        tested.prefetchDevicePublicKeys(List.of());

        verifyNoInteractions(devicePublicKeyRepository);
    }

    @Test
    void prefetchDoesNotQueryWhenNoActivationHasDeviceKey() {
        tested.prefetchDevicePublicKeys(List.of(activation(null), activation(null)));

        verifyNoInteractions(devicePublicKeyRepository);
    }

    @Test
    void prefetchUsesSingleQueryForUpToChunkSize() {
        tested.prefetchDevicePublicKeys(activations(1000));

        final List<List<Long>> chunks = capturedChunks(1);
        assertThat(chunks.get(0)).hasSize(1000);
    }

    @Test
    void prefetchSplitsIntoChunksOfAtMostThousandIds() {
        tested.prefetchDevicePublicKeys(activations(2500));

        final List<List<Long>> chunks = capturedChunks(3);
        assertThat(chunks).extracting(List::size).containsExactly(1000, 1000, 500);
        assertThat(chunks.stream().flatMap(List::stream).collect(Collectors.toSet())).hasSize(2500);
    }

    @Test
    void prefetchAddsQueryWhenChunkSizeIsExceededByOne() {
        tested.prefetchDevicePublicKeys(activations(1001));

        final List<List<Long>> chunks = capturedChunks(2);
        assertThat(chunks).extracting(List::size).containsExactly(1000, 1);
    }

    @Test
    void prefetchSkipsActivationsWithoutDeviceKeyAndDeduplicatesIds() {
        final DevicePublicKeyEntity shared = key(7L);
        final List<ActivationRecordEntity> activations = List.of(activation(shared), activation(null), activation(shared), activation(key(8L)));

        tested.prefetchDevicePublicKeys(activations);

        final List<List<Long>> chunks = capturedChunks(1);
        assertThat(chunks.get(0)).containsExactly(7L, 8L);
    }

    private List<List<Long>> capturedChunks(final int expectedQueries) {
        @SuppressWarnings("unchecked")
        final ArgumentCaptor<Iterable<Long>> captor = ArgumentCaptor.forClass(Iterable.class);
        verify(devicePublicKeyRepository, times(expectedQueries)).findAllById(captor.capture());
        final List<List<Long>> chunks = new ArrayList<>();
        for (final Iterable<Long> chunk : captor.getAllValues()) {
            final List<Long> ids = new ArrayList<>();
            chunk.forEach(ids::add);
            chunks.add(ids);
        }
        return chunks;
    }

    private static List<ActivationRecordEntity> activations(final int count) {
        return LongStream.rangeClosed(1, count)
                .mapToObj(id -> activation(key(id)))
                .toList();
    }

    private static ActivationRecordEntity activation(final DevicePublicKeyEntity key) {
        final ActivationRecordEntity activation = new ActivationRecordEntity();
        activation.setDevicePublicKey(key);
        return activation;
    }

    private static DevicePublicKeyEntity key(final long id) {
        final DevicePublicKeyEntity key = new DevicePublicKeyEntity();
        key.setId(id);
        return key;
    }

}
