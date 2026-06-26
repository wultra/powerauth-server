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

import com.wultra.security.powerauth.client.model.entity.ConfigStoreItem;
import com.wultra.security.powerauth.client.model.enumeration.ConfigScope;
import com.wultra.security.powerauth.client.model.request.v4.CreateConfigItemRequest;
import com.wultra.security.powerauth.client.model.request.v4.FetchConfigRequest;
import com.wultra.security.powerauth.client.model.request.v4.RemoveConfigItemRequest;
import com.wultra.security.powerauth.client.model.response.v4.FetchConfigResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.jdbc.Sql;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end lifecycle test for the configuration store.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@SpringBootTest
@ActiveProfiles("test")
@Sql("ConfigStoreLifecycleTest.sql")
@Transactional
class ConfigStoreItemLifecycleTest {

    private static final String APP_ID = "PA_ConfigStore_Tests";
    private static final String ACTIVATION_ID = "cf9a1100-0000-4000-8000-000000000001";
    private static final String ACTIVATION_ID_2 = "cf9a1100-0000-4000-8000-000000000002";

    @Autowired
    private ConfigStoreServiceBehavior tested;

    @Test
    void testFullLifecycle_acrossScopes() throws Exception {
        // 1) Operator adds values in three different "buckets": application-level APPLICATION,
        //    application-level ACTIVATION, and the activation's per-device document.
        createAppLevel(ConfigScope.APPLICATION, "app_base_url", "https://app.example.com");
        createAppLevel(ConfigScope.ACTIVATION, "feature_flag", true);
        createPerDevice("device_token", "tok-123");

        // 2) Pre-activation SDK read (application scope) sees only the APPLICATION section.
        final Map<String, ConfigStoreItem> appViewStep2 = resolveApplicationScope();
        assertEquals(1, appViewStep2.size());
        assertEquals("https://app.example.com", appViewStep2.get("app_base_url").getValue());
        assertEquals(ConfigScope.APPLICATION, appViewStep2.get("app_base_url").getScope());

        // 3) Activated SDK read (activation scope) sees the whole entitled set, each tagged with its scope.
        final Map<String, ConfigStoreItem> actViewStep3 = resolveActivationScope();
        assertEquals(3, actViewStep3.size());
        assertEquals("https://app.example.com", actViewStep3.get("app_base_url").getValue());
        assertEquals(ConfigScope.APPLICATION, actViewStep3.get("app_base_url").getScope());
        assertEquals(true, actViewStep3.get("feature_flag").getValue());
        assertEquals(ConfigScope.ACTIVATION, actViewStep3.get("feature_flag").getScope());
        assertEquals("tok-123", actViewStep3.get("device_token").getValue());
        assertEquals(ConfigScope.ACTIVATION, actViewStep3.get("device_token").getScope());

        // 4) Operator updates existing values and adds a new application-level key.
        createAppLevel(ConfigScope.APPLICATION, "app_base_url", "https://app2.example.com");
        createAppLevel(ConfigScope.APPLICATION, "timeout", 30);
        createPerDevice("device_token", "tok-456");

        // 5) Read again — both scopes reflect the updates; the upsert preserved untouched keys.
        final Map<String, ConfigStoreItem> appViewStep5 = resolveApplicationScope();
        assertEquals(2, appViewStep5.size());
        assertEquals("https://app2.example.com", appViewStep5.get("app_base_url").getValue());
        assertEquals(30, appViewStep5.get("timeout").getValue());

        final Map<String, ConfigStoreItem> actViewStep5 = resolveActivationScope();
        assertEquals(4, actViewStep5.size());
        assertEquals("https://app2.example.com", actViewStep5.get("app_base_url").getValue());
        assertEquals("tok-456", actViewStep5.get("device_token").getValue());
        assertEquals(true, actViewStep5.get("feature_flag").getValue());
        assertEquals(30, actViewStep5.get("timeout").getValue());

        // 6) Operator removes one application-level key and the per-device key.
        removeAppLevel(ConfigScope.APPLICATION, "app_base_url");
        removePerDevice(ACTIVATION_ID, "device_token");

        // 7) Read again — the removed keys are gone from both scopes.
        final Map<String, ConfigStoreItem> appViewStep7 = resolveApplicationScope();
        assertEquals(1, appViewStep7.size());
        assertNull(appViewStep7.get("app_base_url"));
        assertEquals(30, appViewStep7.get("timeout").getValue());

        final Map<String, ConfigStoreItem> actViewStep7 = resolveActivationScope();
        assertEquals(2, actViewStep7.size());
        assertNull(actViewStep7.get("app_base_url"));
        assertNull(actViewStep7.get("device_token"));
        assertEquals(true, actViewStep7.get("feature_flag").getValue());
        assertEquals(30, actViewStep7.get("timeout").getValue());

        // 8) Remove everything that remains; both scopes resolve to an empty list (never an error).
        removeAppLevel(ConfigScope.APPLICATION, "timeout");
        removeAppLevel(ConfigScope.ACTIVATION, "feature_flag");

        assertTrue(resolveApplicationScope().isEmpty());
        assertTrue(resolveActivationScope().isEmpty());
    }

    @Test
    void testCrossScopePrecedence_deviceValueWinsForSharedKey() throws Exception {
        // The same key is published in all three buckets with different values.
        createAppLevel(ConfigScope.APPLICATION, "shared", "from-application");
        createAppLevel(ConfigScope.ACTIVATION, "shared", "from-app-activation");
        createPerDevice("shared", "from-device");

        // Application scope only sees the APPLICATION value.
        final Map<String, ConfigStoreItem> appView = resolveApplicationScope();
        assertEquals(1, appView.size());
        assertEquals("from-application", appView.get("shared").getValue());
        assertEquals(ConfigScope.APPLICATION, appView.get("shared").getScope());

        // Activation scope merges with precedence device > app-ACTIVATION > app-APPLICATION: device wins.
        final Map<String, ConfigStoreItem> actView = resolveActivationScope();
        assertEquals(1, actView.size());
        assertEquals("from-device", actView.get("shared").getValue());
        assertEquals(ConfigScope.ACTIVATION, actView.get("shared").getScope());
    }

    @Test
    void testActivationScope_appLevelSectionSharedAcrossDevices_perDeviceDocumentIsolated() throws Exception {
        // APPLICATION section: visible to everyone.
        createAppLevel(ConfigScope.APPLICATION, "app_base_url", "https://app.example.com");
        // Application-level ACTIVATION section: the SAME for all devices/activations of the application.
        createAppLevel(ConfigScope.ACTIVATION, "rollout_group", "beta");
        // Per-device documents: DEVICE-SPECIFIC, one per activation, sharing the same key with different values.
        createPerDevice(ACTIVATION_ID, "device_token", "device-1-token");
        createPerDevice(ACTIVATION_ID_2, "device_token", "device-2-token");

        // Device 1 sees: the APPLICATION item, the shared app-level ACTIVATION item, and ONLY its own per-device value.
        final Map<String, ConfigStoreItem> device1 = resolveActivationScope(ACTIVATION_ID);
        assertEquals(3, device1.size());
        assertEquals("https://app.example.com", device1.get("app_base_url").getValue());
        assertEquals(ConfigScope.APPLICATION, device1.get("app_base_url").getScope());
        assertEquals("beta", device1.get("rollout_group").getValue());
        assertEquals(ConfigScope.ACTIVATION, device1.get("rollout_group").getScope());
        assertEquals("device-1-token", device1.get("device_token").getValue());
        assertEquals(ConfigScope.ACTIVATION, device1.get("device_token").getScope());

        // Device 2 sees: the same APPLICATION item, the same shared app-level ACTIVATION item, and ONLY its own per-device value.
        final Map<String, ConfigStoreItem> device2 = resolveActivationScope(ACTIVATION_ID_2);
        assertEquals(3, device2.size());
        assertEquals("https://app.example.com", device2.get("app_base_url").getValue());
        // The application-level ACTIVATION section is identical for both devices.
        assertEquals("beta", device2.get("rollout_group").getValue());
        assertEquals(ConfigScope.ACTIVATION, device2.get("rollout_group").getScope());
        // Per-device isolation: device 2 must NOT see device 1's value and vice versa.
        assertEquals("device-2-token", device2.get("device_token").getValue());

        // Removing device 1's per-device document leaves device 2's intact and the shared sections untouched.
        removePerDevice(ACTIVATION_ID, "device_token");
        final Map<String, ConfigStoreItem> device1AfterRemove = resolveActivationScope(ACTIVATION_ID);
        assertEquals(2, device1AfterRemove.size());
        assertNull(device1AfterRemove.get("device_token"));
        assertEquals("beta", device1AfterRemove.get("rollout_group").getValue());

        final Map<String, ConfigStoreItem> device2AfterRemove = resolveActivationScope(ACTIVATION_ID_2);
        assertEquals(3, device2AfterRemove.size());
        assertEquals("device-2-token", device2AfterRemove.get("device_token").getValue());
    }

    @Test
    void testApplicationScopeRead_echoesApplicationIdAndReturnsItem() throws Exception {
        createAppLevel(ConfigScope.APPLICATION, "k", "v");

        final FetchConfigRequest request = new FetchConfigRequest();
        request.setApplicationId(APP_ID);
        final FetchConfigResponse response = tested.fetchConfig(request);

        assertEquals(APP_ID, response.getApplicationId());
        assertEquals(1, response.getConfigs().size());
        assertEquals("v", response.getConfigs().get(0).getValue());
    }

    @Test
    void testRemoveAppLevelActivationItem_requiresMatchingScope() throws Exception {
        // An application-wide, ACTIVATION-scope item (activationId absent).
        createAppLevel(ConfigScope.ACTIVATION, "base_url", "https://api.example2.com");

        // Removing with the wrong scope (APPLICATION) is a no-op: the ACTIVATION-scope document is untouched.
        removeAppLevel(ConfigScope.APPLICATION, "base_url");
        Map<String, ConfigStoreItem> activationView = resolveActivationScope(ACTIVATION_ID);
        assertEquals("https://api.example2.com", activationView.get("base_url").getValue());
        assertEquals(ConfigScope.ACTIVATION, activationView.get("base_url").getScope());

        // Removing with the matching scope (ACTIVATION, no activationId) removes it.
        removeAppLevel(ConfigScope.ACTIVATION, "base_url");
        activationView = resolveActivationScope(ACTIVATION_ID);
        assertNull(activationView.get("base_url"));
    }

    private void createAppLevel(final ConfigScope scope, final String key, final Object value) throws Exception {
        final CreateConfigItemRequest request = new CreateConfigItemRequest();
        request.setApplicationId(APP_ID);
        request.setScope(scope);
        request.setKey(key);
        request.setValue(value);
        tested.createConfigItem(request);
    }

    private void createPerDevice(final String key, final Object value) throws Exception {
        createPerDevice(ACTIVATION_ID, key, value);
    }

    private void createPerDevice(final String activationId, final String key, final Object value) throws Exception {
        final CreateConfigItemRequest request = new CreateConfigItemRequest();
        request.setApplicationId(APP_ID);
        request.setActivationId(activationId);
        request.setScope(ConfigScope.ACTIVATION);
        request.setKey(key);
        request.setValue(value);
        tested.createConfigItem(request);
    }

    private void removeAppLevel(final ConfigScope scope, final String key) throws Exception {
        final RemoveConfigItemRequest request = new RemoveConfigItemRequest();
        request.setApplicationId(APP_ID);
        request.setScope(scope);
        request.setKey(key);
        tested.removeConfigItem(request);
    }

    private void removePerDevice(final String activationId, final String key) throws Exception {
        final RemoveConfigItemRequest request = new RemoveConfigItemRequest();
        request.setApplicationId(APP_ID);
        request.setActivationId(activationId);
        request.setScope(ConfigScope.ACTIVATION);
        request.setKey(key);
        tested.removeConfigItem(request);
    }

    private Map<String, ConfigStoreItem> resolveApplicationScope() throws Exception {
        final FetchConfigRequest request = new FetchConfigRequest();
        request.setApplicationId(APP_ID);
        return toMap(tested.fetchConfig(request).getConfigs());
    }

    private Map<String, ConfigStoreItem> resolveActivationScope() throws Exception {
        return resolveActivationScope(ACTIVATION_ID);
    }

    private Map<String, ConfigStoreItem> resolveActivationScope(final String activationId) throws Exception {
        final FetchConfigRequest request = new FetchConfigRequest();
        request.setApplicationId(APP_ID);
        request.setActivationId(activationId);
        return toMap(tested.fetchConfig(request).getConfigs());
    }

    private static Map<String, ConfigStoreItem> toMap(final List<ConfigStoreItem> items) {
        return Optional.ofNullable(items).orElseGet(List::of).stream()
                .collect(Collectors.toMap(ConfigStoreItem::getKey, item -> item));
    }
}
