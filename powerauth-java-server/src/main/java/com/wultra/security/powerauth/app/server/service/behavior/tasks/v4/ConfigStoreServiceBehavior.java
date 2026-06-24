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
import com.wultra.security.powerauth.app.server.service.model.AuditType;
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
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Behavior class implementing management of the secure configuration store (key-level CRUD over the
 * scoped JSON documents persisted by {@link ConfigStoreService}).
 * <p>
 * Each configuration document is stored as a single JSON object; a create/remove operation is a
 * load-merge-save of one key into that document, so other keys are preserved. Configuration changes are
 * low-frequency operator actions performed through this management API.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
@Slf4j
@AllArgsConstructor
public class ConfigStoreServiceBehavior {

    /**
     * The allowed configuration key format. Arbitrary keys are accepted, but the format is
     * constrained to a safe character set and a bounded length.
     */
    private static final Pattern KEY_PATTERN = Pattern.compile("^[a-zA-Z0-9_.-]{1,255}$");

    private final LocalizationProvider localizationProvider;
    private final ConfigStoreService configStoreService;
    private final ApplicationRepository applicationRepository;
    private final ActivationQueryService activationQueryService;
    private final ObjectMapper objectMapper;
    private final AuditingServiceBehavior audit;

    /**
     * Create or update a single configuration item (load-merge-save of one key).
     *
     * @param request Create a configuration request.
     * @return Create a configuration store response.
     * @throws GenericServiceException In case of a business logic error.
     */
    @Transactional
    public CreateConfigItemResponse createConfigItem(final CreateConfigItemRequest request) throws GenericServiceException {
        try {
            final String applicationId = request.getApplicationId();
            final String activationId = request.getActivationId();
            final String key = request.getKey();
            validateConfigKey(key);

            final ConfigStoreItem target = findConfigItem(applicationId, activationId, toDbScope(request.getScope()));
            final ObjectNode document = parseDocument(target.configData());
            document.set(key, objectMapper.valueToTree(request.getValue()));
            final String merged = serializeDocument(document);

            configStoreService.createOrUpdate(new ConfigStoreItem(
                    target.id(), target.application(), target.activation(), target.scope(),
                    merged, target.timestampCreated(), target.timestampLastUpdated()));

            audit(target, key, "Created or updated configuration item");

            final CreateConfigItemResponse response = new CreateConfigItemResponse();
            response.setApplicationId(applicationId);
            response.setActivationId(target.activation() != null ? target.activation().getActivationId() : null);
            response.setScope(toClientScope(target.scope()));
            response.setKey(key);
            return response;
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        }
    }

    /**
     * List configuration items.
     *
     * @param request Get configuration items request.
     * @return Get configuration items response.
     * @throws GenericServiceException In case of a business logic error.
     */
    @Transactional(readOnly = true)
    public GetConfigItemsResponse getConfigItems(final GetConfigItemsRequest request) throws GenericServiceException {
        try {
            final String applicationId = request.getApplicationId();
            final String activationId = request.getActivationId();

            final GetConfigItemsResponse response = new GetConfigItemsResponse();
            response.setApplicationId(applicationId);
            response.setActivationId(activationId);

            if (StringUtils.hasText(activationId)) {
                if (request.getScope() != null && toDbScope(request.getScope()) != ConfigScope.ACTIVATION) {
                    logger.warn("Per-device configuration listing must use ACTIVATION scope, requested: {}", request.getScope());
                    throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
                }
                findActivation(applicationId, activationId);
                configStoreService.findByActivationId(activationId)
                        .ifPresent(store -> response.getConfigs().addAll(toItems(store)));
            } else {
                requireApplication(applicationId);
                final List<ConfigStoreItem> documents;
                if (request.getScope() != null) {
                    final ConfigScope scope = toDbScope(request.getScope());
                    documents = configStoreService.findApplicationLevel(applicationId, scope)
                            .map(List::of).orElseGet(List::of);
                } else {
                    documents = configStoreService.findAllForApplication(applicationId);
                }
                documents.forEach(store -> response.getConfigs().addAll(toItems(store)));
            }
            return response;
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        }
    }

    /**
     * Remove a single configuration item (load-merge-save removing one key).
     *
     * @param request Remove a configuration item request.
     * @throws GenericServiceException In case of a business logic error.
     */
    @Transactional
    public void removeConfigItem(final RemoveConfigItemRequest request) throws GenericServiceException {
        try {
            final String applicationId = request.getApplicationId();
            final String activationId = request.getActivationId();
            final String key = request.getKey();
            validateConfigKey(key);

            final ConfigStoreItem target = findConfigItem(applicationId, activationId, toDbScope(request.getScope()));
            if (target.id() == null) {
                return;
            }
            final ObjectNode document = parseDocument(target.configData());
            if (document.remove(key) == null) {
                return;
            }
            final String merged = serializeDocument(document);
            configStoreService.createOrUpdate(new ConfigStoreItem(
                    target.id(), target.application(), target.activation(), target.scope(),
                    merged, target.timestampCreated(), target.timestampLastUpdated()));

            audit(target, key, "Removed configuration item");
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        }
    }

    /**
     * Fetch the configuration items visible to an SDK caller (server-to-server read API), applying
     * eligibility and cross-scope precedence server-side.
     *
     * @param request Fetch configuration request.
     * @return Fetch configuration response.
     * @throws GenericServiceException In case of a business logic error.
     */
    @Transactional(readOnly = true)
    public FetchConfigResponse fetchConfig(final FetchConfigRequest request) throws GenericServiceException {
        try {
            final String applicationId = request.getApplicationId();
            final String activationId = request.getActivationId();

            final FetchConfigResponse response = new FetchConfigResponse();
            response.setApplicationId(applicationId);
            response.setActivationId(activationId);

            if (StringUtils.hasText(activationId)) {
                // Activation scope: requires a resolved, ACTIVE activation that belongs to the application.
                final ActivationRecordEntity activation = findActivation(applicationId, activationId);
                if (activation.getActivationStatus() != ActivationStatus.ACTIVE) {
                    logger.info("Activation is not in ACTIVE state, activation ID: {}", activationId);
                    throw localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_INCORRECT_STATE);
                }
                final List<ConfigStoreItem> documents = configStoreService.findVisibleForActivation(applicationId, activationId);
                response.getConfigs().addAll(mergeWithPrecedence(documents));
            } else {
                // Application scope: only the application-level APPLICATION section.
                requireApplication(applicationId);
                final List<ConfigStoreItem> documents = configStoreService.findVisibleForApplication(applicationId);
                response.getConfigs().addAll(mergeWithPrecedence(documents));
            }
            return response;
        } catch (RuntimeException ex) {
            logger.error("Runtime exception or error occurred, transaction will be rolled back", ex);
            throw ex;
        }
    }

    /**
     * Resolve the target document for writing, returning the existing decrypted document or an
     * empty placeholder (with {@code id == null}) carrying the resolved application, activation, and scope.
     */
    private ConfigStoreItem findConfigItem(final String applicationId, final String activationId, final ConfigScope requestedScope) throws GenericServiceException {
        if (StringUtils.hasText(activationId)) {
            if (requestedScope != ConfigScope.ACTIVATION) {
                logger.warn("Per-device configuration write must use ACTIVATION scope, requested: {}", requestedScope);
                throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
            }
            final ActivationRecordEntity activation = findActivation(applicationId, activationId);
            return configStoreService.findByActivationId(activationId)
                    .orElseGet(() -> new ConfigStoreItem(null, activation.getApplication(), activation, ConfigScope.ACTIVATION, "{}", null, null));
        } else {
            final ApplicationEntity application = applicationRepository.findById(applicationId).orElseThrow(() -> {
                logger.info("Application not found, application ID: {}", applicationId);
                return localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
            });
            return configStoreService.findApplicationLevel(applicationId, requestedScope)
                    .orElseGet(() -> new ConfigStoreItem(null, application, null, requestedScope, "{}", null, null));
        }
    }

    /**
     * Resolve an activation by its identifier, verifying it exists and belongs to the given application.
     *
     * @param applicationId Application the activation must belong to.
     * @param activationId Activation identifier.
     * @return The resolved activation record.
     * @throws GenericServiceException In case of a business logic error.
     */
    private ActivationRecordEntity findActivation(final String applicationId, final String activationId) throws GenericServiceException {
        final ActivationRecordEntity activation = activationQueryService.findActivationWithoutLock(activationId).orElseThrow(() -> {
            logger.info("Activation not found, activation ID: {}", activationId);
            return localizationProvider.buildExceptionForCode(ServiceError.ACTIVATION_NOT_FOUND);
        });
        if (!activation.getApplication().getId().equals(applicationId)) {
            logger.warn("Activation {} does not belong to application {}", activationId, applicationId);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        return activation;
    }

    private void requireApplication(final String applicationId) throws GenericServiceException {
        if (applicationRepository.findById(applicationId).isEmpty()) {
            logger.info("Application not found, application ID: {}", applicationId);
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_APPLICATION);
        }
    }

    private void validateConfigKey(final String key) throws GenericServiceException {
        if (key == null || !KEY_PATTERN.matcher(key).matches()) {
            logger.warn("Invalid configuration key format");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_INPUT_FORMAT);
        }
    }

    private ConfigScope toDbScope(final com.wultra.security.powerauth.client.model.enumeration.ConfigScope scope) throws GenericServiceException {
        if (scope == null) {
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_REQUEST);
        }
        return ConfigScope.valueOf(scope.name());
    }

    private com.wultra.security.powerauth.client.model.enumeration.ConfigScope toClientScope(final ConfigScope scope) {
        return com.wultra.security.powerauth.client.model.enumeration.ConfigScope.valueOf(scope.name());
    }

    private ObjectNode parseDocument(final String configData) throws GenericServiceException {
        if (!StringUtils.hasText(configData)) {
            return objectMapper.createObjectNode();
        }
        try {
            final JsonNode node = objectMapper.readTree(configData);
            if (node instanceof ObjectNode objectNode) {
                return objectNode;
            }
            logger.warn("Stored configuration document is not a JSON object");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_INPUT_FORMAT);
        } catch (JacksonException ex) {
            logger.warn("Stored configuration document is not valid JSON");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_INPUT_FORMAT);
        }
    }

    private String serializeDocument(final ObjectNode document) throws GenericServiceException {
        try {
            return objectMapper.writeValueAsString(document);
        } catch (JacksonException ex) {
            logger.warn("Unable to serialize configuration document");
            throw localizationProvider.buildExceptionForCode(ServiceError.INVALID_INPUT_FORMAT);
        }
    }

    /**
     * Merge a set of configuration documents into a flat list of items, applying cross-scope precedence.
     */
    private List<com.wultra.security.powerauth.client.model.entity.ConfigStoreItem> mergeWithPrecedence(final List<ConfigStoreItem> documents) {
        final Map<String, RankedItem> byKey = new LinkedHashMap<>();
        for (final ConfigStoreItem store : documents) {
            final int rank = precedenceRank(store);
            for (final com.wultra.security.powerauth.client.model.entity.ConfigStoreItem item : toItems(store)) {
                final RankedItem existing = byKey.get(item.getKey());
                if (existing == null || rank > existing.rank()) {
                    byKey.put(item.getKey(), new RankedItem(item, rank));
                }
            }
        }
        final List<com.wultra.security.powerauth.client.model.entity.ConfigStoreItem> result = new ArrayList<>();
        for (final RankedItem ranked : byKey.values()) {
            result.add(ranked.item());
        }
        return result;
    }

    /**
     * Determine the cross-scope precedence rank of a configuration document: per-device records rank highest,
     * then application-level {@code ACTIVATION}, then application-level {@code APPLICATION}.
     */
    private static int precedenceRank(final ConfigStoreItem store) {
        if (store.scope() == ConfigScope.ACTIVATION) {
            return store.activation() != null ? 3 : 2;
        }
        return 1;
    }

    private List<com.wultra.security.powerauth.client.model.entity.ConfigStoreItem> toItems(final ConfigStoreItem store) {
        final List<com.wultra.security.powerauth.client.model.entity.ConfigStoreItem> items = new ArrayList<>();
        final JsonNode node;
        try {
            node = StringUtils.hasText(store.configData()) ? objectMapper.readTree(store.configData()) : objectMapper.createObjectNode();
        } catch (JacksonException ex) {
            logger.warn("Skipping configuration document that is not valid JSON, id: {}", store.id());
            return items;
        }
        if (node instanceof ObjectNode objectNode) {
            for (final Map.Entry<String, JsonNode> field : objectNode.properties()) {
                final com.wultra.security.powerauth.client.model.entity.ConfigStoreItem item = new com.wultra.security.powerauth.client.model.entity.ConfigStoreItem();
                item.setKey(field.getKey());
                item.setValue(objectMapper.convertValue(field.getValue(), Object.class));
                item.setScope(toClientScope(store.scope()));
                items.add(item);
            }
        }
        return items;
    }

    private void audit(final ConfigStoreItem target, final String key, final String message) {
        final AuditDetail auditDetail = AuditDetail.builder()
                .type(AuditType.CONFIGURATION.getCode())
                .param("applicationId", target.application().getId())
                .param("activationId", target.activation() != null ? target.activation().getActivationId() : null)
                .param("scope", target.scope().name())
                .param("key", key)
                .build();
        audit.log(AuditLevel.INFO, message + ", key: {}", auditDetail, key);
    }

    /**
     * Holder pairing a resolved configuration item with its cross-scope precedence rank.
     */
    private record RankedItem(com.wultra.security.powerauth.client.model.entity.ConfigStoreItem item, int rank) {}

}
