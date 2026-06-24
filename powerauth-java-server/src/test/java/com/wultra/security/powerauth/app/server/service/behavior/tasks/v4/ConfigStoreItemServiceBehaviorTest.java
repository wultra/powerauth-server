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
package com.wultra.security.powerauth.app.server.service.behavior.tasks.v4;

import com.wultra.core.audit.base.model.AuditDetail;
import com.wultra.core.audit.base.model.AuditLevel;
import com.wultra.security.powerauth.app.server.database.model.entity.ActivationRecordEntity;
import com.wultra.security.powerauth.app.server.database.model.entity.ApplicationEntity;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.app.server.database.model.enumeration.ConfigScope;
import com.wultra.security.powerauth.app.server.database.repository.ApplicationRepository;
import com.wultra.security.powerauth.app.server.service.exceptions.GenericServiceException;
import com.wultra.security.powerauth.app.server.service.i18n.LocalizationProvider;
import com.wultra.security.powerauth.app.server.service.model.ServiceError;
import com.wultra.security.powerauth.app.server.service.persistence.ActivationQueryService;
import com.wultra.security.powerauth.app.server.service.persistence.ConfigStoreService;
import com.wultra.security.powerauth.app.server.service.persistence.ConfigStoreService.ConfigStoreItem;
import com.wultra.security.powerauth.client.model.request.v4.CreateConfigItemRequest;
import com.wultra.security.powerauth.client.model.request.v4.FetchConfigRequest;
import com.wultra.security.powerauth.client.model.request.v4.GetConfigItemsRequest;
import com.wultra.security.powerauth.client.model.request.v4.RemoveConfigItemRequest;
import com.wultra.security.powerauth.client.model.response.v4.CreateConfigItemResponse;
import com.wultra.security.powerauth.client.model.response.v4.FetchConfigResponse;
import com.wultra.security.powerauth.client.model.response.v4.GetConfigItemsResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Test for {@link ConfigStoreServiceBehavior}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@ExtendWith(MockitoExtension.class)
class ConfigStoreItemServiceBehaviorTest {

    private static final String APP_ID = "app-1";
    private static final String ACTIVATION_ID = "e43a5dec-afea-4a10-a80b-b2183399f16b";

    private static final com.wultra.security.powerauth.client.model.enumeration.ConfigScope CLIENT_APPLICATION =
            com.wultra.security.powerauth.client.model.enumeration.ConfigScope.APPLICATION;
    private static final com.wultra.security.powerauth.client.model.enumeration.ConfigScope CLIENT_ACTIVATION =
            com.wultra.security.powerauth.client.model.enumeration.ConfigScope.ACTIVATION;

    @Mock
    private LocalizationProvider localizationProvider;

    @Mock
    private ConfigStoreService configStoreService;

    @Mock
    private ApplicationRepository applicationRepository;

    @Mock
    private ActivationQueryService activationQueryService;

    @Mock
    private AuditingServiceBehavior audit;

    @Captor
    private ArgumentCaptor<ConfigStoreItem> configStoreCaptor;

    private final ObjectMapper objectMapper = JsonMapper.builder().build();

    private ConfigStoreServiceBehavior tested;

    @BeforeEach
    void setUp() {
        tested = new ConfigStoreServiceBehavior(localizationProvider, configStoreService, applicationRepository,
                activationQueryService, objectMapper, audit);
    }

    @Test
    void testCreate_applicationLevel_mergesKeyAndAudits() throws Exception {
        final ApplicationEntity application = application(APP_ID);
        when(applicationRepository.findById(APP_ID)).thenReturn(Optional.of(application));
        when(configStoreService.findApplicationLevel(APP_ID, ConfigScope.APPLICATION)).thenReturn(Optional.empty());

        final CreateConfigItemRequest request = new CreateConfigItemRequest();
        request.setApplicationId(APP_ID);
        request.setScope(com.wultra.security.powerauth.client.model.enumeration.ConfigScope.APPLICATION);
        request.setKey("base_url");
        request.setValue("https://example.com");

        final CreateConfigItemResponse response = tested.createConfigItem(request);

        verify(configStoreService).createOrUpdate(configStoreCaptor.capture());
        final ConfigStoreItem saved = configStoreCaptor.getValue();
        assertEquals(ConfigScope.APPLICATION, saved.scope());
        assertNull(saved.activation());
        assertEquals("{\"base_url\":\"https://example.com\"}", saved.configData());
        assertEquals(CLIENT_APPLICATION, response.getScope());
        assertEquals("base_url", response.getKey());
        verify(audit).log(any(AuditLevel.class), anyString(), any(AuditDetail.class), any());
    }

    @Test
    void testCreate_invalidKey_throws() {
        when(localizationProvider.buildExceptionForCode(anyString()))
                .thenReturn(new GenericServiceException(ServiceError.INVALID_INPUT_FORMAT, "Invalid input format"));

        final CreateConfigItemRequest request = new CreateConfigItemRequest();
        request.setApplicationId(APP_ID);
        request.setScope(com.wultra.security.powerauth.client.model.enumeration.ConfigScope.APPLICATION);
        request.setKey("bad key!");
        request.setValue("x");

        assertThrows(GenericServiceException.class, () -> tested.createConfigItem(request));
        verifyNoInteractions(configStoreService);
    }

    @Test
    void testCreate_perDevice_conflictingScope_throws() throws Exception {
        final ActivationRecordEntity activation = new ActivationRecordEntity();
        activation.setActivationId(ACTIVATION_ID);
        activation.setApplication(application(APP_ID));
        when(localizationProvider.buildExceptionForCode(anyString()))
                .thenReturn(new GenericServiceException(ServiceError.INVALID_REQUEST, "Invalid request"));

        final CreateConfigItemRequest request = new CreateConfigItemRequest();
        request.setApplicationId(APP_ID);
        request.setActivationId(ACTIVATION_ID);
        request.setScope(com.wultra.security.powerauth.client.model.enumeration.ConfigScope.APPLICATION); // conflicting; a per-device write must be ACTIVATION scope
        request.setKey("token");
        request.setValue("v");

        assertThrows(GenericServiceException.class, () -> tested.createConfigItem(request));
        verify(configStoreService, never()).createOrUpdate(any());
    }

    @Test
    void testRemove_existingKey_savesDocumentWithoutKey() throws Exception {
        final ApplicationEntity application = application(APP_ID);
        when(applicationRepository.findById(APP_ID)).thenReturn(Optional.of(application));
        when(configStoreService.findApplicationLevel(APP_ID, ConfigScope.APPLICATION)).thenReturn(
                Optional.of(new ConfigStoreItem(1L, application, null, ConfigScope.APPLICATION, "{\"a\":1,\"b\":2}", null, null)));

        final RemoveConfigItemRequest request = new RemoveConfigItemRequest();
        request.setApplicationId(APP_ID);
        request.setScope(com.wultra.security.powerauth.client.model.enumeration.ConfigScope.APPLICATION);
        request.setKey("a");

        tested.removeConfigItem(request);

        verify(configStoreService).createOrUpdate(configStoreCaptor.capture());
        assertEquals("{\"b\":2}", configStoreCaptor.getValue().configData());
    }

    @Test
    void testGet_applicationLevel_returnsItemsTaggedWithScope() throws Exception {
        final ApplicationEntity application = application(APP_ID);
        when(applicationRepository.findById(APP_ID)).thenReturn(Optional.of(application));
        when(configStoreService.findAllForApplication(APP_ID)).thenReturn(java.util.List.of(
                new ConfigStoreItem(1L, application, null, ConfigScope.APPLICATION, "{\"base_url\":\"https://example.com\"}", null, null)));

        final GetConfigItemsRequest request = new GetConfigItemsRequest();
        request.setApplicationId(APP_ID);

        final GetConfigItemsResponse response = tested.getConfigItems(request);

        assertEquals(1, response.getConfigs().size());
        assertEquals("base_url", response.getConfigs().get(0).getKey());
        assertEquals("https://example.com", response.getConfigs().get(0).getValue());
        assertEquals(com.wultra.security.powerauth.client.model.enumeration.ConfigScope.APPLICATION, response.getConfigs().get(0).getScope());
    }

    @Test
    void testCreate_perDevice_mergesKeyWithActivationScope() throws Exception {
        final ActivationRecordEntity activation = activation(ACTIVATION_ID, APP_ID);
        when(activationQueryService.findActivationWithoutLock(ACTIVATION_ID)).thenReturn(Optional.of(activation));
        when(configStoreService.findByActivationId(ACTIVATION_ID)).thenReturn(Optional.empty());

        final CreateConfigItemRequest request = new CreateConfigItemRequest();
        request.setApplicationId(APP_ID);
        request.setActivationId(ACTIVATION_ID);
        request.setScope(CLIENT_ACTIVATION);
        request.setKey("token");
        request.setValue("secret");

        final CreateConfigItemResponse response = tested.createConfigItem(request);

        verify(configStoreService).createOrUpdate(configStoreCaptor.capture());
        final ConfigStoreItem saved = configStoreCaptor.getValue();
        assertEquals(ConfigScope.ACTIVATION, saved.scope());
        assertEquals(activation, saved.activation());
        assertEquals("{\"token\":\"secret\"}", saved.configData());
        assertEquals(ACTIVATION_ID, response.getActivationId());
        assertEquals(CLIENT_ACTIVATION, response.getScope());
    }

    @Test
    void testCreate_perDevice_nullScope_throws() throws Exception {
        when(localizationProvider.buildExceptionForCode(anyString()))
                .thenReturn(new GenericServiceException(ServiceError.INVALID_REQUEST, "Invalid request"));

        final CreateConfigItemRequest request = new CreateConfigItemRequest();
        request.setApplicationId(APP_ID);
        request.setActivationId(ACTIVATION_ID);
        // no scope set; the scope is required and must be ACTIVATION for a per-device write
        request.setKey("token");
        request.setValue("v");

        assertThrows(GenericServiceException.class, () -> tested.createConfigItem(request));
        verify(configStoreService, never()).createOrUpdate(any());
    }

    @Test
    void testCreate_applicationLevel_upsertPreservesOtherKeys() throws Exception {
        final ApplicationEntity application = application(APP_ID);
        when(applicationRepository.findById(APP_ID)).thenReturn(Optional.of(application));
        when(configStoreService.findApplicationLevel(APP_ID, ConfigScope.APPLICATION)).thenReturn(
                Optional.of(new ConfigStoreItem(1L, application, null, ConfigScope.APPLICATION, "{\"a\":1}", null, null)));

        final CreateConfigItemRequest request = new CreateConfigItemRequest();
        request.setApplicationId(APP_ID);
        request.setScope(CLIENT_APPLICATION);
        request.setKey("b");
        request.setValue(2);

        tested.createConfigItem(request);

        verify(configStoreService).createOrUpdate(configStoreCaptor.capture());
        assertEquals("{\"a\":1,\"b\":2}", configStoreCaptor.getValue().configData());
    }

    @Test
    void testCreate_applicationLevel_nestedObjectValueIsStored() throws Exception {
        final ApplicationEntity application = application(APP_ID);
        when(applicationRepository.findById(APP_ID)).thenReturn(Optional.of(application));
        when(configStoreService.findApplicationLevel(APP_ID, ConfigScope.APPLICATION)).thenReturn(Optional.empty());

        final CreateConfigItemRequest request = new CreateConfigItemRequest();
        request.setApplicationId(APP_ID);
        request.setScope(CLIENT_APPLICATION);
        request.setKey("endpoint");
        request.setValue(Map.of("url", "https://example.com"));

        tested.createConfigItem(request);

        verify(configStoreService).createOrUpdate(configStoreCaptor.capture());
        assertEquals("{\"endpoint\":{\"url\":\"https://example.com\"}}", configStoreCaptor.getValue().configData());
    }

    @Test
    void testCreate_applicationLevel_missingScope_throws() throws Exception {
        when(localizationProvider.buildExceptionForCode(anyString()))
                .thenReturn(new GenericServiceException(ServiceError.INVALID_REQUEST, "Invalid request"));

        final CreateConfigItemRequest request = new CreateConfigItemRequest();
        request.setApplicationId(APP_ID);
        // no scope on an application-level write
        request.setKey("base_url");
        request.setValue("x");

        assertThrows(GenericServiceException.class, () -> tested.createConfigItem(request));
        verify(configStoreService, never()).createOrUpdate(any());
    }

    @Test
    void testCreate_applicationLevel_unknownApplication_throws() throws Exception {
        when(applicationRepository.findById(APP_ID)).thenReturn(Optional.empty());
        when(localizationProvider.buildExceptionForCode(anyString()))
                .thenReturn(new GenericServiceException(ServiceError.INVALID_APPLICATION, "Invalid application"));

        final CreateConfigItemRequest request = new CreateConfigItemRequest();
        request.setApplicationId(APP_ID);
        request.setScope(CLIENT_APPLICATION);
        request.setKey("base_url");
        request.setValue("x");

        assertThrows(GenericServiceException.class, () -> tested.createConfigItem(request));
        verify(configStoreService, never()).createOrUpdate(any());
    }

    @Test
    void testCreate_perDevice_unknownActivation_throws() throws Exception {
        when(activationQueryService.findActivationWithoutLock(ACTIVATION_ID)).thenReturn(Optional.empty());
        when(localizationProvider.buildExceptionForCode(anyString()))
                .thenReturn(new GenericServiceException(ServiceError.ACTIVATION_NOT_FOUND, "Activation not found"));

        final CreateConfigItemRequest request = new CreateConfigItemRequest();
        request.setApplicationId(APP_ID);
        request.setActivationId(ACTIVATION_ID);
        request.setScope(CLIENT_ACTIVATION);
        request.setKey("token");
        request.setValue("v");

        assertThrows(GenericServiceException.class, () -> tested.createConfigItem(request));
        verify(configStoreService, never()).createOrUpdate(any());
    }

    @Test
    void testCreate_perDevice_activationFromOtherApplication_throws() throws Exception {
        final ActivationRecordEntity activation = activation(ACTIVATION_ID, "other-app");
        when(activationQueryService.findActivationWithoutLock(ACTIVATION_ID)).thenReturn(Optional.of(activation));
        when(localizationProvider.buildExceptionForCode(anyString()))
                .thenReturn(new GenericServiceException(ServiceError.INVALID_REQUEST, "Invalid request"));

        final CreateConfigItemRequest request = new CreateConfigItemRequest();
        request.setApplicationId(APP_ID);
        request.setActivationId(ACTIVATION_ID);
        request.setScope(CLIENT_ACTIVATION);
        request.setKey("token");
        request.setValue("v");

        assertThrows(GenericServiceException.class, () -> tested.createConfigItem(request));
        verify(configStoreService, never()).createOrUpdate(any());
    }

    @Test
    void testCreate_largeDocument_isAccepted() throws Exception {
        final ApplicationEntity application = application(APP_ID);
        when(applicationRepository.findById(APP_ID)).thenReturn(Optional.of(application));
        when(configStoreService.findApplicationLevel(APP_ID, ConfigScope.APPLICATION)).thenReturn(Optional.empty());

        final CreateConfigItemRequest request = new CreateConfigItemRequest();
        request.setApplicationId(APP_ID);
        request.setScope(CLIENT_APPLICATION);
        request.setKey("big");
        request.setValue("x".repeat(200_000)); // no server-side size limit; storage column is CLOB

        tested.createConfigItem(request);

        verify(configStoreService).createOrUpdate(any());
    }

    @Test
    void testRemove_invalidKey_throws() {
        when(localizationProvider.buildExceptionForCode(anyString()))
                .thenReturn(new GenericServiceException(ServiceError.INVALID_INPUT_FORMAT, "Invalid input format"));

        final RemoveConfigItemRequest request = new RemoveConfigItemRequest();
        request.setApplicationId(APP_ID);
        request.setScope(CLIENT_APPLICATION);
        request.setKey("bad key!");

        assertThrows(GenericServiceException.class, () -> tested.removeConfigItem(request));
        verifyNoInteractions(configStoreService);
    }

    @Test
    void testRemove_noDocument_isNoOp() throws Exception {
        when(applicationRepository.findById(APP_ID)).thenReturn(Optional.of(application(APP_ID)));
        when(configStoreService.findApplicationLevel(APP_ID, ConfigScope.APPLICATION)).thenReturn(Optional.empty());

        final RemoveConfigItemRequest request = new RemoveConfigItemRequest();
        request.setApplicationId(APP_ID);
        request.setScope(CLIENT_APPLICATION);
        request.setKey("a");

        tested.removeConfigItem(request);

        verify(configStoreService, never()).createOrUpdate(any());
    }

    @Test
    void testRemove_keyNotPresent_isNoOp() throws Exception {
        final ApplicationEntity application = application(APP_ID);
        when(applicationRepository.findById(APP_ID)).thenReturn(Optional.of(application));
        when(configStoreService.findApplicationLevel(APP_ID, ConfigScope.APPLICATION)).thenReturn(
                Optional.of(new ConfigStoreItem(1L, application, null, ConfigScope.APPLICATION, "{\"a\":1}", null, null)));

        final RemoveConfigItemRequest request = new RemoveConfigItemRequest();
        request.setApplicationId(APP_ID);
        request.setScope(CLIENT_APPLICATION);
        request.setKey("missing");

        tested.removeConfigItem(request);

        verify(configStoreService, never()).createOrUpdate(any());
    }

    @Test
    void testRemove_perDevice_conflictingScope_throws() throws Exception {
        when(localizationProvider.buildExceptionForCode(anyString()))
                .thenReturn(new GenericServiceException(ServiceError.INVALID_REQUEST, "Invalid request"));

        final RemoveConfigItemRequest request = new RemoveConfigItemRequest();
        request.setApplicationId(APP_ID);
        request.setActivationId(ACTIVATION_ID);
        request.setScope(CLIENT_APPLICATION); // conflicting; a per-device removal must be ACTIVATION scope
        request.setKey("token");

        assertThrows(GenericServiceException.class, () -> tested.removeConfigItem(request));
        verify(configStoreService, never()).createOrUpdate(any());
    }

    @Test
    void testRemove_perDevice_nullScope_throws() throws Exception {
        when(localizationProvider.buildExceptionForCode(anyString()))
                .thenReturn(new GenericServiceException(ServiceError.INVALID_REQUEST, "Invalid request"));

        final RemoveConfigItemRequest request = new RemoveConfigItemRequest();
        request.setApplicationId(APP_ID);
        request.setActivationId(ACTIVATION_ID);
        // no scope set; the scope is required and must be ACTIVATION for a per-device removal
        request.setKey("token");

        assertThrows(GenericServiceException.class, () -> tested.removeConfigItem(request));
        verify(configStoreService, never()).createOrUpdate(any());
    }

    @Test
    void testGet_perDevice_listsActivationItemsTaggedWithScope() throws Exception {
        final ActivationRecordEntity activation = activation(ACTIVATION_ID, APP_ID);
        when(activationQueryService.findActivationWithoutLock(ACTIVATION_ID)).thenReturn(Optional.of(activation));
        when(configStoreService.findByActivationId(ACTIVATION_ID)).thenReturn(
                Optional.of(new ConfigStoreItem(1L, activation.getApplication(), activation, ConfigScope.ACTIVATION, "{\"token\":\"v\"}", null, null)));

        final GetConfigItemsRequest request = new GetConfigItemsRequest();
        request.setApplicationId(APP_ID);
        request.setActivationId(ACTIVATION_ID);

        final GetConfigItemsResponse response = tested.getConfigItems(request);

        assertEquals(1, response.getConfigs().size());
        assertEquals("token", response.getConfigs().get(0).getKey());
        assertEquals(CLIENT_ACTIVATION, response.getConfigs().get(0).getScope());
    }

    @Test
    void testGet_perDevice_activationFromOtherApplication_throws() {
        final ActivationRecordEntity activation = activation(ACTIVATION_ID, "other-app");
        when(activationQueryService.findActivationWithoutLock(ACTIVATION_ID)).thenReturn(Optional.of(activation));
        when(localizationProvider.buildExceptionForCode(anyString()))
                .thenReturn(new GenericServiceException(ServiceError.INVALID_REQUEST, "Invalid request"));

        final GetConfigItemsRequest request = new GetConfigItemsRequest();
        request.setApplicationId(APP_ID);
        request.setActivationId(ACTIVATION_ID);

        assertThrows(GenericServiceException.class, () -> tested.getConfigItems(request));
    }

    @Test
    void testGet_applicationLevel_withScopeFilter_usesScopedLookup() throws Exception {
        final ApplicationEntity application = application(APP_ID);
        when(applicationRepository.findById(APP_ID)).thenReturn(Optional.of(application));
        when(configStoreService.findApplicationLevel(APP_ID, ConfigScope.ACTIVATION)).thenReturn(
                Optional.of(new ConfigStoreItem(1L, application, null, ConfigScope.ACTIVATION, "{\"k\":\"v\"}", null, null)));

        final GetConfigItemsRequest request = new GetConfigItemsRequest();
        request.setApplicationId(APP_ID);
        request.setScope(CLIENT_ACTIVATION);

        final GetConfigItemsResponse response = tested.getConfigItems(request);

        assertEquals(1, response.getConfigs().size());
        assertEquals(CLIENT_ACTIVATION, response.getConfigs().get(0).getScope());
        verify(configStoreService, never()).findAllForApplication(anyString());
    }

    @Test
    void testGet_applicationLevel_emptyConfig_returnsEmptyList() throws Exception {
        when(applicationRepository.findById(APP_ID)).thenReturn(Optional.of(application(APP_ID)));
        when(configStoreService.findAllForApplication(APP_ID)).thenReturn(List.of());

        final GetConfigItemsRequest request = new GetConfigItemsRequest();
        request.setApplicationId(APP_ID);

        final GetConfigItemsResponse response = tested.getConfigItems(request);

        assertTrue(response.getConfigs().isEmpty());
    }

    @Test
    void testGet_applicationLevel_unknownApplication_throws() {
        when(applicationRepository.findById(APP_ID)).thenReturn(Optional.empty());
        when(localizationProvider.buildExceptionForCode(anyString()))
                .thenReturn(new GenericServiceException(ServiceError.INVALID_APPLICATION, "Invalid application"));

        final GetConfigItemsRequest request = new GetConfigItemsRequest();
        request.setApplicationId(APP_ID);

        assertThrows(GenericServiceException.class, () -> tested.getConfigItems(request));
    }

    @Test
    void testFetch_applicationScope_returnsApplicationItems() throws Exception {
        final ApplicationEntity application = application(APP_ID);
        when(applicationRepository.findById(APP_ID)).thenReturn(Optional.of(application));
        when(configStoreService.findVisibleForApplication(APP_ID)).thenReturn(List.of(
                new ConfigStoreItem(1L, application, null, ConfigScope.APPLICATION, "{\"base_url\":\"https://example.com\"}", null, null)));

        final FetchConfigRequest request = new FetchConfigRequest();
        request.setApplicationId(APP_ID);

        final FetchConfigResponse response = tested.fetchConfig(request);

        assertEquals(1, response.getConfigs().size());
        assertEquals("base_url", response.getConfigs().get(0).getKey());
        assertEquals(CLIENT_APPLICATION, response.getConfigs().get(0).getScope());
    }

    @Test
    void testFetch_applicationScope_emptyConfig_returnsEmptyList() throws Exception {
        when(applicationRepository.findById(APP_ID)).thenReturn(Optional.of(application(APP_ID)));
        when(configStoreService.findVisibleForApplication(APP_ID)).thenReturn(List.of());

        final FetchConfigRequest request = new FetchConfigRequest();
        request.setApplicationId(APP_ID);

        final FetchConfigResponse response = tested.fetchConfig(request);

        assertTrue(response.getConfigs().isEmpty());
    }

    @Test
    void testFetch_applicationScope_unknownApplication_throws() {
        when(applicationRepository.findById(APP_ID)).thenReturn(Optional.empty());
        when(localizationProvider.buildExceptionForCode(anyString()))
                .thenReturn(new GenericServiceException(ServiceError.INVALID_APPLICATION, "Invalid application"));

        final FetchConfigRequest request = new FetchConfigRequest();
        request.setApplicationId(APP_ID);

        assertThrows(GenericServiceException.class, () -> tested.fetchConfig(request));
        verify(configStoreService, never()).findVisibleForApplication(anyString());
    }

    @Test
    void testFetch_activationScope_mergesWithCrossScopePrecedence() throws Exception {
        final ActivationRecordEntity activation = activation(ACTIVATION_ID, APP_ID, ActivationStatus.ACTIVE);
        final ApplicationEntity application = activation.getApplication();
        when(activationQueryService.findActivationWithoutLock(ACTIVATION_ID)).thenReturn(Optional.of(activation));
        when(configStoreService.findVisibleForActivation(APP_ID, ACTIVATION_ID)).thenReturn(List.of(
                new ConfigStoreItem(1L, application, null, ConfigScope.APPLICATION, "{\"a\":\"app\",\"shared\":\"app\"}", null, null),
                new ConfigStoreItem(2L, application, null, ConfigScope.ACTIVATION, "{\"b\":\"appAct\",\"shared\":\"appAct\"}", null, null),
                new ConfigStoreItem(3L, application, activation, ConfigScope.ACTIVATION, "{\"c\":\"dev\",\"shared\":\"dev\"}", null, null)));

        final FetchConfigRequest request = new FetchConfigRequest();
        request.setApplicationId(APP_ID);
        request.setActivationId(ACTIVATION_ID);

        final FetchConfigResponse response = tested.fetchConfig(request);

        final Map<String, com.wultra.security.powerauth.client.model.entity.ConfigStoreItem> byKey = new java.util.HashMap<>();
        response.getConfigs().forEach(item -> byKey.put(item.getKey(), item));
        assertEquals(4, byKey.size());
        assertEquals("app", byKey.get("a").getValue());
        assertEquals(CLIENT_APPLICATION, byKey.get("a").getScope());
        assertEquals("appAct", byKey.get("b").getValue());
        assertEquals(CLIENT_ACTIVATION, byKey.get("b").getScope());
        assertEquals("dev", byKey.get("c").getValue());
        assertEquals(CLIENT_ACTIVATION, byKey.get("c").getScope());
        // Device value wins for the shared key (device > app-ACTIVATION > app-APPLICATION).
        assertEquals("dev", byKey.get("shared").getValue());
        assertEquals(CLIENT_ACTIVATION, byKey.get("shared").getScope());
    }

    @Test
    void testFetch_activationScope_notActive_throwsIncorrectState() {
        final ActivationRecordEntity activation = activation(ACTIVATION_ID, APP_ID, ActivationStatus.BLOCKED);
        when(activationQueryService.findActivationWithoutLock(ACTIVATION_ID)).thenReturn(Optional.of(activation));
        when(localizationProvider.buildExceptionForCode(anyString()))
                .thenReturn(new GenericServiceException(ServiceError.ACTIVATION_INCORRECT_STATE, "Invalid activation state"));

        final FetchConfigRequest request = new FetchConfigRequest();
        request.setApplicationId(APP_ID);
        request.setActivationId(ACTIVATION_ID);

        assertThrows(GenericServiceException.class, () -> tested.fetchConfig(request));
        verify(configStoreService, never()).findVisibleForActivation(anyString(), anyString());
    }

    @Test
    void testFetch_activationScope_activationNotFound_throws() {
        when(activationQueryService.findActivationWithoutLock(ACTIVATION_ID)).thenReturn(Optional.empty());
        when(localizationProvider.buildExceptionForCode(anyString()))
                .thenReturn(new GenericServiceException(ServiceError.ACTIVATION_NOT_FOUND, "Activation not found"));

        final FetchConfigRequest request = new FetchConfigRequest();
        request.setApplicationId(APP_ID);
        request.setActivationId(ACTIVATION_ID);

        assertThrows(GenericServiceException.class, () -> tested.fetchConfig(request));
    }

    @Test
    void testFetch_activationScope_activationFromOtherApplication_throws() {
        final ActivationRecordEntity activation = activation(ACTIVATION_ID, "other-app", ActivationStatus.ACTIVE);
        when(activationQueryService.findActivationWithoutLock(ACTIVATION_ID)).thenReturn(Optional.of(activation));
        when(localizationProvider.buildExceptionForCode(anyString()))
                .thenReturn(new GenericServiceException(ServiceError.INVALID_REQUEST, "Invalid request"));

        final FetchConfigRequest request = new FetchConfigRequest();
        request.setApplicationId(APP_ID);
        request.setActivationId(ACTIVATION_ID);

        assertThrows(GenericServiceException.class, () -> tested.fetchConfig(request));
        verify(configStoreService, never()).findVisibleForActivation(anyString(), anyString());
    }

    private static ActivationRecordEntity activation(final String activationId, final String applicationId) {
        final ActivationRecordEntity activation = new ActivationRecordEntity();
        activation.setActivationId(activationId);
        activation.setApplication(application(applicationId));
        return activation;
    }

    private static ActivationRecordEntity activation(final String activationId, final String applicationId, final ActivationStatus status) {
        final ActivationRecordEntity activation = activation(activationId, applicationId);
        activation.setActivationStatus(status);
        return activation;
    }

    private static ApplicationEntity application(final String id) {
        final ApplicationEntity application = new ApplicationEntity();
        application.setId(id);
        return application;
    }
}

