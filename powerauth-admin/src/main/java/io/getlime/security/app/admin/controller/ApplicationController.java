/*
 * Copyright 2017 Wultra s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.getlime.security.app.admin.controller;

import com.google.common.collect.Lists;
import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.enumeration.CallbackUrlType;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.v3.*;
import io.micrometer.core.instrument.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Controller related to application and application version management.
 *
 * @author Petr Dvorak
 */
@Controller
public class ApplicationController {

    private static final Logger logger = LoggerFactory.getLogger(ApplicationController.class);

    private final List<String> CALLBACK_ATTRIBUTES_OPTIONAL = Arrays.asList("attr_userId", "attr_activationName", "attr_deviceInfo", "attr_platform", "attr_activationFlags", "attr_activationStatus", "attr_blockedReason", "attr_applicationId");

    private final PowerAuthClient client;

    @Autowired
    public ApplicationController(PowerAuthClient client) {
        this.client = client;
    }

    /**
     * Redirect '/' URL to the list of application.
     *
     * @return Redirect view to list of applications.
     */
    @GetMapping("/")
    public String homePage() {
        try {
            List<GetApplicationListResponse.Applications> applicationList = client.getApplicationList();
            if (applicationList.isEmpty()) {
                return "redirect:/application/list";
            } else {
                return "redirect:/activation/list";
            }
        } catch (PowerAuthClientException ex) {
            logger.warn(ex.getMessage(), ex);
            return "error";
        }
    }

    /**
     * Show list of applications.
     *
     * @param model Model with passed parameters.
     * @return "applications" view.
     */
    @GetMapping("/application/list")
    public String applicationList(Map<String, Object> model) {
        try {
            final List<GetApplicationListResponse.Applications> applicationList = client.getApplicationList();
            final List<GetApplicationListResponse.Applications> sortedList = applicationList.stream()
                    .sorted(Comparator.comparing(GetApplicationListResponse.Applications::getApplicationId))
                    .collect(Collectors.toList());
            model.put("applications", sortedList);
            return "applications";
        } catch (PowerAuthClientException ex) {
            logger.warn(ex.getMessage(), ex);
            return "error";
        }
    }

    /**
     * Show application detail.
     *
     * @param id    Application ID.
     * @param model Model with passed parameters.
     * @return "applicationDetail" view.
     */
    @GetMapping("/application/detail/{applicationId}")
    public String applicationDetail(@PathVariable("applicationId") String id, Map<String, Object> model) {
        try {
            GetApplicationDetailResponse applicationDetails = client.getApplicationDetail(id);
            GetRecoveryConfigResponse recoveryConfig = client.getRecoveryConfig(id);
            List<GetCallbackUrlListResponse.CallbackUrlList> callbackUrlList = client.getCallbackUrlList(id);
            model.put("id", applicationDetails.getApplicationId());
            model.put("masterPublicKey", applicationDetails.getMasterPublicKey());
            model.put("activationRecoveryEnabled", recoveryConfig.isActivationRecoveryEnabled());
            model.put("recoveryPostcardEnabled", recoveryConfig.isRecoveryPostcardEnabled());
            model.put("allowMultipleRecoveryCodes", recoveryConfig.isAllowMultipleRecoveryCodes());
            model.put("postcardPublicKey", recoveryConfig.getPostcardPublicKey());
            model.put("remotePostcardPublicKey", recoveryConfig.getRemotePostcardPublicKey());
            model.put("versions", Lists.reverse(applicationDetails.getVersions()));
            model.put("roles", applicationDetails.getApplicationRoles());
            model.put("callbacks", callbackUrlList);
            return "applicationDetail";
        } catch (PowerAuthClientException ex) {
            logger.warn(ex.getMessage(), ex);
            return "error";
        }
    }

    /**
     * Returns view to create a new application.
     *
     * @return "applicationCreate" view.
     */
    @GetMapping("/application/create")
    public String applicationCreate() {
        return "applicationCreate";
    }

    /**
     * Returns view to create a new application version.
     *
     * @param id    Application ID
     * @param model Model with passed parameters.
     * @return "applicationVersionCreate" view.
     */
    @GetMapping("/application/detail/{applicationId}/version/create")
    public String applicationVersionCreate(@PathVariable("applicationId") String id, Map<String, Object> model) {
        model.put("applicationId", id);
        return "applicationVersionCreate";
    }

    /**
     * Show application callback create form.
     *
     * @param id    Application ID.
     * @param model Model with passed parameters.
     * @return "callbackCreate" view.
     */
    @GetMapping("/application/detail/{applicationId}/callback/create")
    public String applicationCreateCallback(@PathVariable("applicationId") String id, Map<String, Object> model) {
        model.put("applicationId", id);
        return "callbackCreate";
    }

    /**
     * Show application callback update form.
     *
     * @param applicationId Application ID.
     * @param callbackId Callback ID.
     * @param model Model with passed parameters.
     * @return "callbackUpdate" view.
     */
    @GetMapping("/application/detail/{applicationId}/callback/update")
    public String applicationUpdateCallback(@PathVariable("applicationId") String applicationId,
                                            @RequestParam String callbackId,
                                            Map<String, Object> model) {
        if (callbackId == null) {
            logger.warn("Missing callback ID");
            return "error";
        }
        try {
            List<GetCallbackUrlListResponse.CallbackUrlList> callbacks = client.getCallbackUrlList(applicationId);
            for (GetCallbackUrlListResponse.CallbackUrlList callback: callbacks) {
                if (callback.getId().equals(callbackId)) {
                    model.put("callbackId", callbackId);
                    model.put("applicationId", applicationId);
                    model.put("name", callback.getName());
                    model.put("callbackUrl", callback.getCallbackUrl());
                    for (String attribute: callback.getAttributes()) {
                        model.put("attr_" + attribute, true);
                    }
                    HttpAuthenticationPublic httpAuthentication = callback.getAuthentication();
                    if (httpAuthentication != null) {
                        if (httpAuthentication.getCertificate() == null) {
                            model.put("auth_certificateEnabled", false);
                        } else {
                            HttpAuthenticationPublic.Certificate certificateAuth = httpAuthentication.getCertificate();
                            model.put("auth_certificateEnabled", certificateAuth.isEnabled());
                            model.put("auth_useCustomKeyStore", certificateAuth.isUseCustomKeyStore());
                            model.put("auth_keyStoreLocation", certificateAuth.getKeyStoreLocation());
                            model.put("auth_keyStorePasswordSet", certificateAuth.isKeyStorePasswordSet());
                            model.put("auth_keyAlias", certificateAuth.getKeyAlias());
                            model.put("auth_keyPasswordSet", certificateAuth.isKeyPasswordSet());
                            model.put("auth_useCustomTrustStore", certificateAuth.isUseCustomTrustStore());
                            model.put("auth_trustStoreLocation", certificateAuth.getTrustStoreLocation());
                            model.put("auth_trustStorePasswordSet", certificateAuth.isTrustStorePasswordSet());
                        }
                        if (httpAuthentication.getHttpBasic() == null) {
                            model.put("auth_httpBasicEnabled", false);
                        } else {
                            HttpAuthenticationPublic.HttpBasic httpBasicAuth = httpAuthentication.getHttpBasic();
                            model.put("auth_httpBasicEnabled", httpBasicAuth.isEnabled());
                            model.put("auth_httpBasicUsername", httpBasicAuth.getUsername());
                            model.put("auth_httpBasicPasswordSet", httpBasicAuth.isPasswordSet());
                        }
                    }
                    return "callbackUpdate";
                }
            }
            logger.warn("Callback not found, application ID: {}, callback ID: {}", applicationId, callbackId);
            return "error";
        } catch (PowerAuthClientException ex) {
            logger.warn(ex.getMessage(), ex);
            return "error";
        }
    }

    /**
     * Show application role create form.
     *
     * @param id Application ID.
     * @param model Model with passed parameters.
     * @return "roleCreate" view.
     */
    @GetMapping("/application/detail/{applicationId}/role/create")
    public String applicationCreateRole(@PathVariable("applicationId") String id, Map<String, Object> model) {
        model.put("applicationId", id);
        return "roleCreate";
    }

    /**
     * Execute the application create action by calling the SOAP service.
     *
     * @param id Application ID.
     * @param redirectAttributes Redirect attributes.
     * @return Redirect to the new application details.
     */
    @PostMapping("/application/create/do.submit")
    public String applicationCreateAction(@RequestParam String id, RedirectAttributes redirectAttributes) {
        try {
            if (id == null || id.trim().isEmpty()) {
                redirectAttributes.addFlashAttribute("error", "Application ID must not be empty.");
                return "redirect:/application/create";
            }
            CreateApplicationResponse application = client.createApplication(id);
            return "redirect:/application/detail/" + application.getApplicationId();
        } catch (PowerAuthClientException ex) {
            logger.warn(ex.getMessage(), ex);
            return "error";
        }
    }

    /**
     * Execute the application version create action by calling the SOAP service.
     *
     * @param applicationId Application ID.
     * @param applicationVersionId Application version ID.
     * @param redirectAttributes Redirect attributes.
     * @return Redirect to application detail (application versions are visible there).
     */
    @PostMapping("/application/detail/{applicationId}/version/create/do.submit")
    public String applicationVersionCreateAction(@PathVariable String applicationId, @RequestParam String applicationVersionId, RedirectAttributes redirectAttributes) {
        try {
            if (applicationVersionId == null || applicationVersionId.trim().isEmpty()) {
                redirectAttributes.addFlashAttribute("error", "Application version ID must not be empty.");
                return "redirect:/application/detail/" + applicationId + "/version/create";
            }
            client.createApplicationVersion(applicationId, applicationVersionId);
            return "redirect:/application/detail/" + applicationId;
        } catch (PowerAuthClientException ex) {
            logger.warn(ex.getMessage(), ex);
            return "error";
        }
    }

    /**
     * Execute the action that marks application version supported / unsupported.
     *
     * @param version Application version.
     * @param enabled True for supported, False for unsupported
     * @param id      Application ID (path variable), for the redirect purposes
     * @return Redirect to application detail (application versions are visible there).
     */
    @PostMapping("/application/detail/{applicationId}/version/update/do.submit")
    public String applicationUpdateAction(
            @PathVariable("applicationId") String id,
            @RequestParam(value = "version", required = false) String version,
            @RequestParam("enabled") Boolean enabled) {
        try {
            if (enabled) {
                client.supportApplicationVersion(id, version);
            } else {
                client.unsupportApplicationVersion(id, version);
            }
            return "redirect:/application/detail/" + id;
        } catch (PowerAuthClientException ex) {
            logger.warn(ex.getMessage(), ex);
            return "error";
        }
    }

    /**
     * Execute the action that creates a new callback on given application.
     *
     * @param allParams All request parameters.
     * @param applicationId Application ID.
     * @param redirectAttributes Redirect attributes.
     * @return Redirect to application detail, callbacks tab.
     */
    @PostMapping("/application/detail/{applicationId}/callback/create/do.submit")
    public String applicationCreateCallbackAction(
            @RequestParam Map<String, String> allParams,
            @PathVariable("applicationId") String applicationId, RedirectAttributes redirectAttributes) {
        try {
            String name = allParams.get("name");
            String callbackUrl = allParams.get("callbackUrl");
            String error = null;
            if (name == null || name.trim().isEmpty()) {
                error = "Callback name must not be empty.";
            } else if (callbackUrl == null || callbackUrl.trim().isEmpty()) {
                error = "Callback URL must not be empty.";
            } else {
                try {
                    new URL(callbackUrl);
                } catch (MalformedURLException e) {
                    error = "Callback URL is not in a valid format";
                }
            }
            String errorAuth = getErrorForAuthentication(allParams);
            if (errorAuth != null) {
                error = errorAuth;
            }
            if (error != null) {
                for (String attribute: CALLBACK_ATTRIBUTES_OPTIONAL) {
                    if (allParams.get(attribute) != null) {
                        redirectAttributes.addFlashAttribute(attribute, true);
                    }
                }
                redirectAttributes.addFlashAttribute("error", error);
                redirectAttributes.addFlashAttribute("name", name);
                redirectAttributes.addFlashAttribute("callbackUrl", callbackUrl);
                return "redirect:/application/detail/" + applicationId + "/callback/create";
            }
            List<String> attributes = new ArrayList<>();
            attributes.add("activationId");
            for (String attribute: CALLBACK_ATTRIBUTES_OPTIONAL) {
                if (allParams.get(attribute) != null) {
                    attributes.add(attribute.replace("attr_", ""));
                }
            }
            HttpAuthenticationPrivate httpAuthentication = prepareHttpAuthentication(allParams);
            client.createCallbackUrl(applicationId, name, CallbackUrlType.ACTIVATION_STATUS_CHANGE, callbackUrl, attributes, httpAuthentication);
            return "redirect:/application/detail/" + applicationId + "#callbacks";
        } catch (PowerAuthClientException ex) {
            logger.warn(ex.getMessage(), ex);
            return "error";
        }
    }

    /**
     * Execute the action that creates a new callback on given application.
     *
     * @param allParams All request parameters.
     * @param applicationId    Application ID.
     * @param redirectAttributes Redirect attributes.
     * @return Redirect to application detail, callbacks tab.
     */
    @PostMapping("/application/detail/{applicationId}/callback/update/do.submit")
    public String applicationUpdateCallbackAction(
            @PathVariable("applicationId") String applicationId,
            @RequestParam Map<String, String> allParams,
            RedirectAttributes redirectAttributes) {
        try {
            String name = allParams.get("name");
            String callbackUrl = allParams.get("callbackUrl");
            String callbackId = allParams.get("callbackId");
            String error = null;
            if (name == null || name.trim().isEmpty()) {
                error = "Callback name must not be empty.";
            } else if (callbackUrl == null || callbackUrl.trim().isEmpty()) {
                error = "Callback URL must not be empty.";
            } else {
                try {
                    new URL(callbackUrl);
                } catch (MalformedURLException e) {
                    error = "Callback URL is not in a valid format";
                }
            }
            String errorAuth = getErrorForAuthentication(allParams);
            if (errorAuth != null) {
                error = errorAuth;
            }
            if (error != null) {
                redirectAttributes.addAttribute("callbackId", callbackId);
                redirectAttributes.addFlashAttribute("error", error);
                redirectAttributes.addFlashAttribute("name", name);
                redirectAttributes.addFlashAttribute("callbackUrl", callbackUrl);
                return "redirect:/application/detail/" + applicationId + "/callback/update";
            }
            List<String> attributes = new ArrayList<>();
            attributes.add("activationId");
            for (String attribute: CALLBACK_ATTRIBUTES_OPTIONAL) {
                if (allParams.get(attribute) != null) {
                    attributes.add(attribute.replace("attr_", ""));
                }
            }
            HttpAuthenticationPrivate httpAuthentication = prepareHttpAuthentication(allParams);
            client.updateCallbackUrl(callbackId, applicationId, name, callbackUrl, attributes, httpAuthentication);
            return "redirect:/application/detail/" + applicationId + "#callbacks";
        } catch (PowerAuthClientException ex) {
            logger.warn(ex.getMessage(), ex);
            return "error";
        }
    }

    private String getErrorForAuthentication(Map<String, String> allParams) {
        String error = null;
        if ("on".equals(allParams.get("auth_useCustomKeyStore"))) {
            if (StringUtils.isBlank(allParams.get("auth_keyStoreLocation"))
                        || StringUtils.isBlank(allParams.get("auth_keyAlias"))) {
                error = "Invalid keystore configuration";
            } else {
                try {
                    new URL(allParams.get("auth_keyStoreLocation"));
                } catch (MalformedURLException ex) {
                    error = "Invalid keystore location format";
                }
            }
        }
        if ("on".equals(allParams.get("auth_useCustomTrustStore"))) {
            if (StringUtils.isBlank(allParams.get("auth_trustStoreLocation"))) {
                error = "Invalid truststore configuration";
            } else {
                try {
                    new URL(allParams.get("auth_trustStoreLocation"));
                } catch (MalformedURLException ex) {
                    error = "Invalid truststore location format";
                }
            }
        }
        if ("on".equals(allParams.get("auth_httpBasicEnabled")) &&
                StringUtils.isBlank(allParams.get("auth_httpBasicUsername"))) {
            error = "Invalid HTTP Basic authentication configuration";
        }
        return error;
    }

    /**
     * Execute the action that removes a callback with given ID.
     *
     * @param id    Application ID.
     * @param callbackId Callback ID.
     * @return Redirect to application detail, callbacks tab.
     */
    @PostMapping("/application/detail/{applicationId}/callback/remove/do.submit")
    public String applicationRemoveCallbackAction(
            @RequestParam("callbackId") String callbackId,
            @PathVariable("applicationId") String id) {
        try {
            client.removeCallbackUrl(callbackId);
            return "redirect:/application/detail/" + id + "#callbacks";
        } catch (PowerAuthClientException ex) {
            logger.warn(ex.getMessage(), ex);
            return "error";
        }
    }

    /**
     * Execute the action that creates a new role assigned to given application.
     *
     * @param id Application ID.
     * @param name Role name.
     * @param redirectAttributes Redirect attributes.
     * @return Redirect to application detail, roles tab.
     */
    @PostMapping("/application/detail/{applicationId}/role/create/do.submit")
    public String applicationCreateRoleAction(
            @PathVariable("applicationId") String id,
            @RequestParam("name") String name,
            RedirectAttributes redirectAttributes) {
        try {
            String error = null;
            if (name == null || name.trim().isEmpty()) {
                error = "Role name must not be empty.";
            }
            if (error != null) {
                redirectAttributes.addFlashAttribute("error", error);
                redirectAttributes.addFlashAttribute("name", name);
                return "redirect:/application/detail/" + id + "/role/create";
            }
            client.addApplicationRoles(id, Collections.singletonList(name));
            return "redirect:/application/detail/" + id + "#roles";
        } catch (PowerAuthClientException ex) {
            logger.warn(ex.getMessage(), ex);
            return "error";
        }
    }

    /**
     * Execute the action that removes a callback with given ID.
     *
     * @param id Application ID.
     * @param name Role name.
     * @return Redirect to application detail, roles tab.
     */
    @PostMapping("/application/detail/{applicationId}/role/remove/do.submit")
    public String applicationRemoveRoleAction(
            @PathVariable("applicationId") String id,
            @RequestParam("name") String name) {
        try {
            client.removeApplicationRoles(id, Collections.singletonList(name));
            return "redirect:/application/detail/" + id + "#roles";
        } catch (PowerAuthClientException ex) {
            logger.warn(ex.getMessage(), ex);
            return "error";
        }
    }

    /**
     * Update recovery configuration.
     * @param id Application ID.
     * @param activationRecoveryEnabled Whether activation recovery is enabled.
     * @param recoveryPostcardEnabled Whether recovery postcard is enabled.
     * @param allowMultipleRecoveryCodes Whether multiple recovery codes are allowed per user.
     * @param remotePostcardPublicKey Base64 encoded printing center public key.
     * @return Redirect to application detail, recovery tab.
     */
    @PostMapping("/application/detail/{applicationId}/recovery/update/do.submit")
    public String applicationUpdateRecoveryConfigAction(
            @PathVariable("applicationId") String id,
            @RequestParam(value = "activationRecoveryEnabled", required = false) boolean activationRecoveryEnabled,
            @RequestParam(value = "recoveryPostcardEnabled", required = false) boolean recoveryPostcardEnabled,
            @RequestParam(value = "allowMultipleRecoveryCodes", required = false) boolean allowMultipleRecoveryCodes,
            @RequestParam(value = "remotePostcardPublicKey", required = false) String remotePostcardPublicKey) {
        try {
            if (!activationRecoveryEnabled && recoveryPostcardEnabled) {
                // Turn off recovery postcard in case activation recovery is disabled
                recoveryPostcardEnabled = false;
            }
            client.updateRecoveryConfig(id, activationRecoveryEnabled, recoveryPostcardEnabled, allowMultipleRecoveryCodes, remotePostcardPublicKey);
            return "redirect:/application/detail/" + id + "#recovery";
        } catch (PowerAuthClientException ex) {
            logger.warn(ex.getMessage(), ex);
            return "error";
        }
    }

    /**
     * Prepare HTTP authentication based on request parameters.
     * @param allParams Request parameters.
     * @return HTTP authentication.
     */
    private HttpAuthenticationPrivate prepareHttpAuthentication(Map<String, String> allParams) {
        HttpAuthenticationPrivate httpAuthentication = new HttpAuthenticationPrivate();
        if ("on".equals(allParams.get("auth_certificateEnabled"))) {
            HttpAuthenticationPrivate.Certificate certificateAuth = new HttpAuthenticationPrivate.Certificate();
            certificateAuth.setEnabled(true);
            certificateAuth.setUseCustomKeyStore("on".equals(allParams.get("auth_useCustomKeyStore")));
            certificateAuth.setKeyStoreLocation(allParams.get("auth_keyStoreLocation"));
            if ("true".equals(allParams.get("auth_keyStorePasswordChanged"))) {
                certificateAuth.setKeyStorePassword(allParams.get("auth_keyStorePassword"));
            }
            certificateAuth.setKeyAlias(allParams.get("auth_keyAlias"));
            if ("true".equals(allParams.get("auth_keyPasswordChanged"))) {
                certificateAuth.setKeyPassword(allParams.get("auth_keyPassword"));
            }
            certificateAuth.setUseCustomTrustStore("on".equals(allParams.get("auth_useCustomTrustStore")));
            certificateAuth.setTrustStoreLocation(allParams.get("auth_trustStoreLocation"));
            if ("true".equals(allParams.get("auth_trustStorePasswordChanged"))) {
                certificateAuth.setTrustStorePassword(allParams.get("auth_trustStorePassword"));
            }
            httpAuthentication.setCertificate(certificateAuth);
        }
        if ("on".equals(allParams.get("auth_httpBasicEnabled"))) {
            HttpAuthenticationPrivate.HttpBasic httpBasicAuth = new HttpAuthenticationPrivate.HttpBasic();
            httpBasicAuth.setEnabled(true);
            httpBasicAuth.setUsername(allParams.get("auth_httpBasicUsername"));
            if ("true".equals(allParams.get("auth_httpBasicPasswordChanged"))) {
                httpBasicAuth.setPassword(allParams.get("auth_httpBasicPassword"));
            }
            httpAuthentication.setHttpBasic(httpBasicAuth);
        }
        return httpAuthentication;
    }

}
