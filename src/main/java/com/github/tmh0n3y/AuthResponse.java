package com.github.tmh0n3y;

import com.fasterxml.jackson.annotation.JsonInclude;

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

    public boolean isValid() {
        return valid;
    }

    public String getReason() {
        return reason;
    }
}