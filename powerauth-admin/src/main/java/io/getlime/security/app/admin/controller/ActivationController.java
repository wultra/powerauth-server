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

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.entity.Activation;
import com.wultra.security.powerauth.client.model.entity.ActivationHistoryItem;
import com.wultra.security.powerauth.client.model.enumeration.ActivationOtpValidation;
import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.request.CommitActivationRequest;
import com.wultra.security.powerauth.client.model.response.*;
import io.getlime.security.app.admin.converter.SignatureAuditItemConverter;
import io.getlime.security.app.admin.model.SignatureAuditItem;
import io.getlime.security.app.admin.util.QRUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.security.Principal;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * Controller class related to PowerAuth activation management.
 *
 * @author Petr Dvorak
 */
@Controller
public class ActivationController {

    private static final Logger logger = LoggerFactory.getLogger(ActivationController.class);

    private final PowerAuthClient client;

    @Autowired
    public ActivationController(PowerAuthClient client) {
        this.client = client;
    }

    private final SignatureAuditItemConverter signatureAuditItemConverter = new SignatureAuditItemConverter();

    /**
     * Return the list of activations for given users.
     *
     * @param userId User ID to lookup the activations for.
     * @param showAllActivations Indicates if activations in REMOVED state should be returned.
     * @param showAllRecoveryCodes Indicates if recovery codes in REVOKED state should be returned.
     * @param model Model with passed parameters.
     * @return "activations" view.
     */
    @GetMapping("/activation/list")
    public String activationList(@RequestParam(value = "userId", required = false) String userId, @RequestParam(value = "showAllActivations", required = false) Boolean showAllActivations,
                                 @RequestParam(value = "showAllRecoveryCodes", required = false) Boolean showAllRecoveryCodes, Map<String, Object> model) {
        try {
            if (userId != null) {
                List<Activation> activationList = client.getActivationListForUser(userId);
                activationList.sort((o1, o2) -> o2.getTimestampLastUsed().compareTo(o1.getTimestampLastUsed()));

                model.put("activations", activationList);
                model.put("userId", userId);
                model.put("showAllActivations", showAllActivations);
                model.put("showAllRecoveryCodes", showAllRecoveryCodes);

                final GetApplicationListResponse applications = client.getApplicationList();
                model.put("applications", applications.getApplications());

                LookupRecoveryCodesResponse response = client.lookupRecoveryCodes(userId, null, null, null, null);
                model.put("recoveryCodes", response.getRecoveryCodes());
            }
            return "activations";
        } catch (PowerAuthClientException ex) {
            logger.warn(ex.getMessage(), ex);
            return "error";
        }
    }

    /**
     * Get detail of a given activation.
     *
     * @param id    Activation ID.
     * @param fromDate Optional filter for date from.
     * @param toDate Optional filter for date to.
     * @param model Model with passed parameters.
     * @return "activationDetail" view.
     */
    @GetMapping("/activation/detail/{id}")
    public String activationDetail(
            @PathVariable("id") String id,
            @RequestParam(value = "fromDate", required = false) String fromDate,
            @RequestParam(value = "toDate", required = false) String toDate,
            Map<String, Object> model) {
        try {

            DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
            Date startingDate;
            Date endingDate;
            Date currentTimePlusOneSecond;
            Calendar cal = Calendar.getInstance();
            // Add one second to avoid filtering out the most recent signatures and activation changes.
            cal.add(Calendar.SECOND, 1);
            currentTimePlusOneSecond = cal.getTime();
            try {
                if (toDate != null) {
                    endingDate = dateFormat.parse(toDate);
                } else {
                    endingDate = currentTimePlusOneSecond;
                    toDate = dateFormat.format(endingDate);
                }
                model.put("toDate", toDate);
                if (fromDate != null) {
                    startingDate = dateFormat.parse(fromDate);
                } else {
                    startingDate = new Date(endingDate.getTime() - (30L * 24L * 60L * 60L * 1000L));
                    fromDate = dateFormat.format(startingDate);
                }
                model.put("fromDate", fromDate);
            } catch (ParseException e) {
                // Date parsing didn't work, OK - clear the values...
                endingDate = currentTimePlusOneSecond;
                startingDate = new Date(endingDate.getTime() - (30L * 24L * 60L * 60L * 1000L));
                fromDate = dateFormat.format(startingDate);
                toDate = dateFormat.format(endingDate);
                model.put("fromDate", fromDate);
                model.put("toDate", toDate);
            }

            GetActivationStatusResponse activation = client.getActivationStatus(id);
            model.put("activationId", activation.getActivationId());
            model.put("activationName", activation.getActivationName());
            model.put("status", activation.getActivationStatus());
            model.put("blockedReason", activation.getBlockedReason());
            model.put("timestampCreated", activation.getTimestampCreated());
            model.put("timestampLastUsed", activation.getTimestampLastUsed());
            model.put("activationFingerprint", activation.getDevicePublicKeyFingerprint());
            model.put("userId", activation.getUserId());
            model.put("version", activation.getVersion());
            model.put("platform", activation.getPlatform());
            model.put("deviceInfo", activation.getDeviceInfo());
            model.put("protocol", activation.getProtocol());
            model.put("externalId", activation.getExternalId());
            model.put("activationFlags", activation.getActivationFlags());
            if (activation.getActivationStatus() == ActivationStatus.PENDING_COMMIT && activation.getActivationOtpValidation() == ActivationOtpValidation.ON_COMMIT) {
                model.put("showOtpInput", true);
            } else {
                model.put("showOtpInput", false);
            }

            GetApplicationDetailResponse application = client.getApplicationDetail(activation.getApplicationId());
            model.put("applicationId", application.getApplicationId());

            LookupRecoveryCodesResponse response = client.lookupRecoveryCodes(activation.getUserId(), activation.getActivationId(), activation.getApplicationId(), null, null);
            model.put("recoveryCodes", response.getRecoveryCodes());

            final List<com.wultra.security.powerauth.client.model.entity.SignatureAuditItem> auditItems = client.getSignatureAuditLog(activation.getUserId(), application.getApplicationId(), startingDate, endingDate);
            List<SignatureAuditItem> auditItemsFixed = new ArrayList<>();
            for (com.wultra.security.powerauth.client.model.entity.SignatureAuditItem item : auditItems) {
                if (item.getActivationId().equals(activation.getActivationId())) {
                    auditItemsFixed.add(signatureAuditItemConverter.fromSignatureAuditResponseItem(item));
                }
            }
            if (auditItemsFixed.size() > 100) {
                auditItemsFixed = auditItemsFixed.subList(0, 100);
            }
            model.put("signatures", auditItemsFixed);

            List<ActivationHistoryItem> activationHistoryItems = client.getActivationHistory(activation.getActivationId(), startingDate, endingDate);
            List<ActivationHistoryItem> trimmedActivationHistoryItems;
            if (activationHistoryItems.size() > 100) {
                trimmedActivationHistoryItems = activationHistoryItems.subList(0, 100);
            } else {
                trimmedActivationHistoryItems = activationHistoryItems;
            }
            model.put("history", trimmedActivationHistoryItems);

            if (activation.getActivationStatus() == ActivationStatus.CREATED) {
                String activationSignature = activation.getActivationSignature();
                model.put("activationCode", activation.getActivationCode());
                model.put("activationSignature", activationSignature);
                model.put("activationQR", QRUtil.encode(activation.getActivationCode() + "#" + activationSignature, 400));
            }

            return "activationDetail";
        } catch (PowerAuthClientException ex) {
            logger.warn(ex.getMessage(), ex);
            return "error";
        }
    }

    /**
     * Create a new activation.
     *
     * @param applicationId           Application ID of an associated application.
     * @param userId                  User ID.
     * @param activationOtpValidation Activation OTP validation mode.
     * @param activationOtp           Activation OTP code.
     * @param model                   Model with passed parameters.
     * @param redirectAttributes      Redirect attributes.
     * @return Redirect the user to activation detail.
     */
    @GetMapping("/activation/create")
    public String activationCreate(@RequestParam("applicationId") String applicationId, @RequestParam("userId") String userId,
                                   @RequestParam("activationOtpValidation") String activationOtpValidation,
                                   @RequestParam("activationOtp") String activationOtp,
                                   Map<String, Object> model, RedirectAttributes redirectAttributes) {
        try {
            InitActivationResponse response;

            if (!"NONE".equals(activationOtpValidation) && (activationOtp == null || activationOtp.isEmpty())) {
                redirectAttributes.addFlashAttribute("error", "Please specify the OTP validation code.");
                return "redirect:/activation/list?userId=" + userId;
            }
            switch (activationOtpValidation) {
                case "NONE" ->
                        response = client.initActivation(userId, applicationId);
                case "ON_KEY_EXCHANGE" ->
                        response = client.initActivation(userId, applicationId, ActivationOtpValidation.ON_KEY_EXCHANGE, activationOtp);
                case "ON_COMMIT" ->
                        response = client.initActivation(userId, applicationId, ActivationOtpValidation.ON_COMMIT, activationOtp);
                default -> {
                    redirectAttributes.addFlashAttribute("error", "Invalid OTP validation mode.");
                    return "redirect:/activation/list?userId=" + userId;
                }
            }


            model.put("activationCode", response.getActivationCode());
            model.put("activationId", response.getActivationId());
            model.put("activationSignature", response.getActivationSignature());

            return "redirect:/activation/detail/" + response.getActivationId();
        } catch (PowerAuthClientException ex) {
            logger.warn(ex.getMessage(), ex);
            return "error";
        }
    }

    /**
     * Commit activation.
     *
     * @param activationId Activation ID.
     * @param model        Model with passed parameters.
     * @param principal    Principal entity.
     * @return Redirect the user to activation detail.
     */
    @PostMapping("/activation/create/do.submit")
    public String activationCreateCommitAction(@RequestParam("activationId") String activationId, Map<String, Object> model, Principal principal) {
        try {
            String username = extractUsername(principal);
            CommitActivationResponse commitActivation = client.commitActivation(activationId, username);
            return "redirect:/activation/detail/" + commitActivation.getActivationId();
        } catch (PowerAuthClientException ex) {
            logger.warn(ex.getMessage(), ex);
            return "error";
        }
    }

    /**
     * Block activation.
     *
     * @param activationId Activation ID
     * @param userId       User ID identifying user for redirect to the list of activations
     * @param model        Model with passed parameters.
     * @param principal    Principal entity.
     * @return Redirect user to given URL or to activation detail, in case 'redirect' is null or empty.
     */
    @PostMapping("/activation/block/do.submit")
    public String blockActivation(@RequestParam("activationId") String activationId, @RequestParam("redirectUserId") String userId, Map<String, Object> model, Principal principal) {
        try {
            String username = extractUsername(principal);
            BlockActivationResponse blockActivation = client.blockActivation(activationId, null, username);
            if (userId != null && !userId.trim().isEmpty()) {
                return "redirect:/activation/list?userId=" + userId;
            }
            return "redirect:/activation/detail/" + blockActivation.getActivationId();
        } catch (PowerAuthClientException ex) {
            logger.warn(ex.getMessage(), ex);
            return "error";
        }
    }

    /**
     * Unblock activation.
     *
     * @param activationId Activation ID
     * @param userId       User ID identifying user for redirect to the list of activations
     * @param model        Model with passed parameters.
     * @param principal    Principal entity.
     * @return Redirect user to given URL or to activation detail, in case 'redirect' is null or empty.
     */
    @PostMapping("/activation/unblock/do.submit")
    public String unblockActivation(@RequestParam("activationId") String activationId, @RequestParam("redirectUserId") String userId, Map<String, Object> model, Principal principal) {
        try {
            String username = extractUsername(principal);
            UnblockActivationResponse unblockActivation = client.unblockActivation(activationId, username);
            if (userId != null && !userId.trim().isEmpty()) {
                return "redirect:/activation/list?userId=" + userId;
            }
            return "redirect:/activation/detail/" + unblockActivation.getActivationId();
        } catch (PowerAuthClientException ex) {
            logger.warn(ex.getMessage(), ex);
            return "error";
        }
    }

    /**
     * Commit activation.
     *
     * @param activationId       Activation ID.
     * @param userId             User ID identifying user for redirect to the list of activations.
     * @param activationOtp      Activation OTP code.
     * @param model              Model with passed parameters.
     * @param principal          Principal entity.
     * @param redirectAttributes Redirect attributes.
     * @return Redirect user to given URL or to activation detail, in case 'redirect' is null or empty.
     */
    @PostMapping("/activation/commit/do.submit")
    public String commitActivation(@RequestParam("activationId") String activationId,
                                   @RequestParam("redirectUserId") String userId,
                                   @RequestParam(value = "activationOtp", required = false) String activationOtp,
                                   Map<String, Object> model, Principal principal,
                                   RedirectAttributes redirectAttributes) {
        String username = extractUsername(principal);
        CommitActivationRequest request = new CommitActivationRequest();
        request.setActivationId(activationId);
        request.setExternalUserId(username);
        if (activationOtp != null) {
            request.setActivationOtp(activationOtp);
        }
        try {
            CommitActivationResponse commitActivation = client.commitActivation(request);
            if (userId != null && !userId.trim().isEmpty()) {
                return "redirect:/activation/list?userId=" + userId;
            }
            return "redirect:/activation/detail/" + commitActivation.getActivationId();
        } catch (PowerAuthClientException ex) {
            logger.warn(ex.getMessage(), ex);
            redirectAttributes.addFlashAttribute("error", "Activation commit failed.");
            return "redirect:/activation/detail/" + activationId;
        }
    }

    /**
     * Remove activation.
     *
     * @param activationId Activation ID
     * @param userId       User ID identifying user for redirect to the list of activations
     * @param model        Model with passed parameters.
     * @param principal    Principal entity.
     * @return Redirect user to given URL or to activation detail, in case 'redirect' is null or empty.
     */
    @PostMapping("/activation/remove/do.submit")
    public String removeActivation(@RequestParam("activationId") String activationId, @RequestParam("redirectUserId") String userId, Map<String, Object> model, Principal principal) {
        try {
            String username = extractUsername(principal);
            RemoveActivationResponse removeActivation = client.removeActivation(activationId, username);
            if (userId != null && !userId.trim().isEmpty()) {
                return "redirect:/activation/list?userId=" + userId;
            }
            return "redirect:/activation/detail/" + removeActivation.getActivationId() + "#versions";
        } catch (PowerAuthClientException ex) {
            logger.warn(ex.getMessage(), ex);
            return "error";
        }
    }

    /**
     * Show activation flag create form.
     *
     * @param activationId Activation ID
     * @param model Model with passed parameters.
     * @return The "activationFlagCreate" view.
     */
    @GetMapping("/activation/detail/{activationId}/flag/create")
    public String applicationCreateFlag(@PathVariable("activationId") String activationId, Map<String, Object> model) {
        model.put("activationId", activationId);
        return "activationFlagCreate";
    }

    /**
     * Add an activation flag.
     *
     * @param activationId Activation ID.
     * @param name Activation flag name.
     * @param redirectAttributes Redirect attributes.
     * @return Redirect the user to activation detail.
     */
    @PostMapping("/activation/detail/{activationId}/flag/create/do.submit")
    public String activationCreateFlagAction(@PathVariable("activationId") String activationId, @RequestParam("name") String name,
                                             RedirectAttributes redirectAttributes) {
        String error = null;
        if (name == null || name.trim().isEmpty()) {
            error = "Flag name must not be empty.";
        }
        if (error != null) {
            redirectAttributes.addFlashAttribute("error", error);
            redirectAttributes.addFlashAttribute("name", name);
            return "redirect:/activation/detail/" + activationId + "/flag/create";
        }
        try {
            client.addActivationFlags(activationId, Collections.singletonList(name));
            return "redirect:/activation/detail/" + activationId;
        } catch (Exception ex) {
            logger.warn(ex.getMessage(), ex);
            return "error";
        }
    }

    /**
     * Remove activation flag.
     *
     * @param activationId Activation ID.
     * @param name Activation flag name.
     * @return Redirect user to given URL or to activation detail.
     */
    @PostMapping("/activation/detail/{activationId}/flag/remove/do.submit")
    public String activationRemoveFlagAction(@PathVariable("activationId") String activationId, @RequestParam("name") String name) {
        try {
            client.removeActivationFlags(activationId, Collections.singletonList(name));
            return "redirect:/activation/detail/" + activationId;
        } catch (PowerAuthClientException ex) {
            logger.warn(ex.getMessage(), ex);
            return "error";
        }
    }

    /**
     * Revoke recovery code.
     * @param recoveryCodeId Recovery code ID.
     * @param activationId Activation ID.
     * @param userId User ID.
     * @param model Request model.
     * @return Redirect user to given URL or to activation detail - recovery tab, in case 'redirect' is null or empty.
     */
    @PostMapping("/activation/recovery/revoke/do.submit")
    public String revokeRecoveryCode(@RequestParam("recoveryCodeId") Long recoveryCodeId, @RequestParam(value = "activationId", required = false) String activationId,
                                     @RequestParam(value = "userId", required = false) String userId, Map<String, Object> model) {
        try {
            List<Long> recoveryCodeIds = new ArrayList<>();
            recoveryCodeIds.add(recoveryCodeId);
            client.revokeRecoveryCodes(recoveryCodeIds);
            if (activationId != null) {
                return "redirect:/activation/detail/" + activationId + "#recovery";
            } else {
                return "redirect:/activation/list?userId=" + userId;
            }
        } catch (PowerAuthClientException ex) {
            logger.warn(ex.getMessage(), ex);
            return "error";
        }
    }

    /**
     * Extract username from principal.
     * @param principal Principal entity.
     * @return Extracted username or null for principal without authentication.
     */
    private String extractUsername(Principal principal) {
        if (principal == null || "anonymous".equals(principal.getName())) {
            return null;
        }
        return principal.getName();
    }

}
