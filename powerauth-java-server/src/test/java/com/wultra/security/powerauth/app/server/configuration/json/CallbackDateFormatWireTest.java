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
 */

package com.wultra.security.powerauth.app.server.configuration.json;

import com.wultra.core.rest.client.base.DefaultRestClient;
import com.wultra.core.rest.client.base.RestClient;
import com.wultra.security.powerauth.app.server.configuration.PowerAuthServiceConfiguration;
import com.wultra.security.powerauth.app.server.database.model.entity.CallbackUrlAuthentication;
import com.wultra.security.powerauth.app.server.database.model.entity.CallbackUrlEntity;
import com.wultra.security.powerauth.app.server.database.repository.CallbackUrlRepository;
import com.wultra.security.powerauth.app.server.service.callbacks.CallbackUrlAuthenticationEncryptor;
import com.wultra.security.powerauth.app.server.service.callbacks.CallbackUrlRestClientCacheLoader;
import com.wultra.security.powerauth.app.server.service.callbacks.model.CachedRestClient;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.ParameterizedTypeReference;
import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.http.server.HttpServer;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * End-to-end wire test proving the actual callback serialization mechanism described in the issue #2436
 * analysis.
 * <p>
 * PowerAuth callbacks do not go through the application {@code ObjectMapper}. The callback body is an
 * in-memory {@code Map<String, Object>} holding raw {@link Date} values, POSTed by a wultra-core
 * {@link DefaultRestClient}. When that client is built without an explicit Jackson configuration or
 * modules (as the callback client is by default), it uses the Spring WebClient default JSON codec, whose
 * fresh Jackson 3 mapper emits the {@code Z} designator. Registering the {@link LegacyDateJacksonModule}
 * on the client restores the legacy {@code +00:00} form.
 * <p>
 * This test captures the raw HTTP body on a local reactor-netty server to assert the true wire format.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
class CallbackDateFormatWireTest {

    private static final Date FIXED_DATE = new Date(1785926829449L);

    private static final Pattern Z_PATTERN =
            Pattern.compile(".*\"timestampExpires\"\\s*:\\s*\"\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z\".*", Pattern.DOTALL);

    private static final Pattern OFFSET_PATTERN =
            Pattern.compile(".*\"timestampExpires\"\\s*:\\s*\"\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}\\+00:00\".*", Pattern.DOTALL);

    private DisposableServer server;
    private AtomicReference<String> captured;
    private CountDownLatch latch;

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.disposeNow();
        }
    }

    /**
     * The default callback {@link DefaultRestClient} (no modules) serializes the raw {@link Date} map with
     * the Jackson 3 default {@code Z} designator. This reproduces the reported regression.
     */
    @Test
    void testDefaultCallbackClientEmitsZ() throws Exception {
        final String body = captureCallbackBody(DefaultRestClient.builder());

        assertTrue(Z_PATTERN.matcher(body).matches(),
                "Default callback wire body must use the Z designator, was: " + body);
    }

    /**
     * With the {@link LegacyDateJacksonModule} registered on the callback client, the same map is
     * serialized with the legacy {@code +00:00} offset.
     */
    @Test
    void testLegacyCallbackClientEmitsNumericOffset() throws Exception {
        final DefaultRestClient.Builder builder = DefaultRestClient.builder();
        builder.modules(List.of(new LegacyDateJacksonModule()));

        final String body = captureCallbackBody(builder);

        assertTrue(OFFSET_PATTERN.matcher(body).matches(),
                "Legacy callback wire body must use the +00:00 offset, was: " + body);
    }

    /**
     * Regression guard for the real production wiring. Drives the actual
     * {@link CallbackUrlRestClientCacheLoader} with the legacy flag <em>disabled</em> and asserts that the
     * {@link RestClient} it builds emits the Jackson 3 default {@code Z} designator. This exercises
     * {@code CallbackUrlRestClientCacheLoader#initializeRestClient}, not a hand-rolled replica.
     */
    @Test
    void testLoaderWithFlagDisabledEmitsZ() throws Exception {
        final String body = captureCallbackBodyViaLoader(false);

        assertTrue(Z_PATTERN.matcher(body).matches(),
                "Loader-built callback body with flag disabled must use the Z designator, was: " + body);
    }

    /**
     * Regression guard for the real production wiring. Drives the actual
     * {@link CallbackUrlRestClientCacheLoader} with the legacy flag <em>enabled</em> and asserts that the
     * {@link RestClient} it builds emits the legacy {@code +00:00} offset. Removing the flag-guarded module
     * registration in {@code CallbackUrlRestClientCacheLoader} makes this test fail.
     */
    @Test
    void testLoaderWithFlagEnabledEmitsNumericOffset() throws Exception {
        final String body = captureCallbackBodyViaLoader(true);

        assertTrue(OFFSET_PATTERN.matcher(body).matches(),
                "Loader-built callback body with flag enabled must use the +00:00 offset, was: " + body);
    }

    /**
     * Reload / retry sub-path. When a callback event is dispatched after being reloaded from the DB, its
     * timestamps are already {@code String} values (materialized by {@code MapToJsonConverter}, which uses
     * the application {@code ObjectMapper}). {@code DefaultRestClient} sends those strings <em>verbatim</em>,
     * so this path's wire format is fixed at store time and is independent of any module on the callback
     * client. This is why the application {@code ObjectMapper} — not the callback client — governs the
     * reload/retry format, and why the fix also registers the module on the application mapper.
     */
    @Test
    void testReloadedStringTimestampIsSentVerbatim() throws Exception {
        final Map<String, Object> reloadedMap = new LinkedHashMap<>();
        reloadedMap.put("operationId", "edef9d7e-1500-4cf9-8366-ecb68240c06d");
        reloadedMap.put("timestampExpires", "2026-08-05T10:47:09.449+00:00");

        final String body = captureCallbackBody(DefaultRestClient.builder(), reloadedMap);

        assertTrue(OFFSET_PATTERN.matcher(body).matches(),
                "A reloaded String timestamp must be sent verbatim by DefaultRestClient, was: " + body);
    }

    private String captureCallbackBody(final DefaultRestClient.Builder clientBuilder) throws Exception {
        return captureCallbackBody(clientBuilder, callbackShapedMap());
    }

    private String captureCallbackBody(final DefaultRestClient.Builder clientBuilder, final Map<String, Object> payload) throws Exception {
        final String baseUrl = startCapturingServer();

        final RestClient restClient = clientBuilder
                .baseUrl(baseUrl)
                .build();

        restClient.postNonBlocking("/",
                payload,
                new ParameterizedTypeReference<String>() {},
                responseEntity -> {},
                throwable -> {});

        return awaitCapturedBody();
    }

    /**
     * Builds a callback {@link RestClient} through the real {@link CallbackUrlRestClientCacheLoader}, with
     * the legacy flag toggled on the shared {@link PowerAuthServiceConfiguration}, and captures the wire
     * body it produces. All authentication variants are disabled so the client is built through the same
     * default path used in production for an unauthenticated callback.
     */
    private String captureCallbackBodyViaLoader(final boolean legacyEnabled) throws Exception {
        final String baseUrl = startCapturingServer();

        final PowerAuthServiceConfiguration configuration = new PowerAuthServiceConfiguration();
        configuration.setHttpConnectionTimeout(Duration.ofSeconds(5));
        configuration.setHttpResponseTimeout(Duration.ofSeconds(10));
        configuration.setHttpMaxIdleTime(Duration.ofSeconds(5));
        configuration.setRestDateLegacyFormatEnabled(legacyEnabled);

        final CallbackUrlEntity entity = new CallbackUrlEntity();
        entity.setId("test-callback");

        final CallbackUrlAuthenticationEncryptor encryptor = mock(CallbackUrlAuthenticationEncryptor.class);
        when(encryptor.decrypt(entity)).thenReturn(new CallbackUrlAuthentication());

        final CallbackUrlRepository repository = mock(CallbackUrlRepository.class);
        when(repository.findById("test-callback")).thenReturn(Optional.of(entity));

        final CallbackUrlRestClientCacheLoader loader =
                new CallbackUrlRestClientCacheLoader(configuration, encryptor, repository);

        final CachedRestClient cached = loader.load("test-callback");
        assertNotNull(cached, "Loader must return a cached client");
        final RestClient restClient = cached.restClient();

        restClient.postNonBlocking(baseUrl + "/",
                callbackShapedMap(),
                new ParameterizedTypeReference<String>() {},
                responseEntity -> {},
                throwable -> {});

        return awaitCapturedBody();
    }

    private String startCapturingServer() {
        captured = new AtomicReference<>();
        latch = new CountDownLatch(1);

        server = HttpServer.create()
                .host("127.0.0.1")
                .port(0)
                .handle((request, response) -> request.receive()
                        .aggregate()
                        .asString(StandardCharsets.UTF_8)
                        .defaultIfEmpty("")
                        .flatMap(requestBody -> {
                            captured.set(requestBody);
                            latch.countDown();
                            return response.status(200)
                                    .sendString(Mono.just("{}"))
                                    .then();
                        }))
                .bindNow();

        return "http://127.0.0.1:" + server.port();
    }

    private String awaitCapturedBody() throws Exception {
        assertTrue(latch.await(10, TimeUnit.SECONDS), "Callback request was not received in time");
        final String body = captured.get();
        assertNotNull(body);
        return body;
    }

    private static Map<String, Object> callbackShapedMap() {
        final Map<String, Object> map = new LinkedHashMap<>();
        map.put("operationId", "edef9d7e-1500-4cf9-8366-ecb68240c06d");
        map.put("timestampExpires", FIXED_DATE);
        return map;
    }

}
