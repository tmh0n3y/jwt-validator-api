package com.github.tmh0n3y;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Data Transfer Object representing the standard JSON payload returned by the authentication endpoint.
 * <p>
 * Null fields (like {@code reason} for valid tokens) are omitted from the JSON output.
 */
@JsonInclude(JsonInclude.Include.NON_NULL) 
public class AuthResponse {

    private boolean valid;
    private String reason;

    // valid response!
    public AuthResponse(boolean valid) {
        this.valid = valid;
    }

    // invalid response!
    public AuthResponse(boolean valid, String reason) {
        this.valid = valid;
        this.reason = reason;
    }

    /**
     * Indicates whether the token was found to be valid.
     *
     * @return {@code true} if valid, {@code false} otherwise
     */
    public boolean isValid() {
        return valid;
    }

    /**
     * Retrieves the explanation for a validation failure, if present.
     *
     * @return the failure reason, or {@code null} if the token is valid
     */
    public String getReason() {
        return reason;
    }
}