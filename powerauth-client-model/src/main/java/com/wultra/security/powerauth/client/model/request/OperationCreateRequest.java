package com.wultra.security.powerauth.client.model.request;

import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.annotation.Nulls;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.*;
import lombok.Data;

import java.util.*;

@Data
public class OperationCreateRequest {

    @Schema(description = "The identifier of the user")
    @Size(min = 1, message = "User ID must not be empty when creating operation")
    private String userId;

    @Schema(description = "List of associated applications")
    @NotNull(message = "Application ID list must not be null when creating operation")
    @Size(min = 1, message = "Application ID list must not be empty when creating operation")
    private List<String> applications = new ArrayList<>();

    @Schema(description = "Activation flag associated with the operation")
    private String activationFlag;

    @Schema(description = "Name of the template used for creating the operation")
    @NotBlank(message = "Template name must not be empty when creating operation")
    private String templateName;

    @Schema(description = "Timestamp of when the operation will expire, overrides expiration period from operation template")
    private Date timestampExpires;

    @Schema(description = "External identifier of the operation, i.e., ID from transaction system")
    private String externalId;

    @Schema(description = "Parameters of the operation, will be filled to the operation data")
    @JsonSetter(nulls = Nulls.SKIP)
    private final Map<String, String> parameters = new LinkedHashMap<>();

    @Schema(description = "Additional data associated with the operation to initialize the operation context")
    @JsonSetter(nulls = Nulls.SKIP)
    private Map<String, Object> additionalData = new LinkedHashMap<>();

    @Schema(description = "Whether proximity check should be used, overrides configuration from operation template")
    private Boolean proximityCheckEnabled;

    @Schema(description = "Activation ID. It is possible to specify a single device (otherwise all user's activations are taken into account).")
    @Size(max = 37, message = "Activation ID must not exceed 37 characters when creating operation")
    private String activationId;
}
