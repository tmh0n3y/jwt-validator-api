package com.github.tmh0n3y;

import java.security.PublicKey;
import java.util.Base64;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * REST controller that handles incoming authentication requests by validating JSON Web Tokens.
 */
@RestController
public class AuthController {

    private final ValidationService validationService; 

    public AuthController(ValidationService validationService) {
        this.validationService = validationService;
    }

    /**
     * Validates an incoming JWT from the Authorization header.
     * Checks structure, decodes header claims, checks timestamps (iat/exp), fetches public key via x5u URL, and verifies the cryptographic signature.
     * 
     * @param authHeader the HTTP Authorization header expected in "Bearer &lt;token&gt;" format
     * @return {@link ResponseEntity} containing {@link AuthResponse}:
     *         <ul>
     *           <li><b>200 OK</b> - Token is structurally fine, unexpired, and signature matches</li>
     *           <li><b>400 Bad Request</b> - Malformed header, missing parts, bad JSON, or certificate fetch failure</li>
     *           <li><b>401 Unauthorized</b> - Invalid or expired timestamps or failed signature verification</li>
     *         </ul>
     */
    @GetMapping("/auth")
    public ResponseEntity<AuthResponse> validateJwt(@RequestHeader(value = "Authorization", required = false) String authHeader) { //get auth header without throwing exception if null

        // is the header format ok
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(400).body(new AuthResponse(false, "Missing or invalid Authorization header format."));
        }

        // cut bearer prefix and get token and its parts
        String token = authHeader.substring(7).trim();
        String[] parts = token.split("\\."); //[0] = header [1] = payload [2] = signature

        //check if the token has 3 parts
        if (parts.length != 3) {
            return ResponseEntity.status(400).body(new AuthResponse(false, "Invalid JWT format."));
        }

        //header contains the x5u value that we need to decode from base64 to standard json
        String x5uUrl = null;
        try {
            String headerJson = new String(Base64.getUrlDecoder().decode(parts[0])); 

            ObjectMapper mapper = new ObjectMapper();
            JsonNode headerNode = mapper.readTree(headerJson);
            if (headerNode.has("x5u")) {
                x5uUrl = headerNode.get("x5u").asText();
            }
        } catch (Exception e) {
           return ResponseEntity.status(400).body(new AuthResponse(false, "Failed to decode or parse JWT header."));
        }

        //check expiration and issue date
        if (validationService.hasInvalidTimestamps(parts[1])) {
            return ResponseEntity.status(401).body(new AuthResponse(false, "Token has invalid timestamps."));
        }

        //fetch public key
        PublicKey publicKey;
        try {
            publicKey = validationService.fetchPublicKey(x5uUrl);
        } catch (Exception e) {
            return ResponseEntity.status(400).body(new AuthResponse(false, "Failed to retrieve public key from x5u URL."));
        }

        //verify signature
        String headerAndPayload = parts[0] + "." + parts[1];

        boolean isValid = validationService.verifySignature(headerAndPayload, parts[2], publicKey);

        if (!isValid) {
            return ResponseEntity.status(401).body(new AuthResponse(false, "Invalid JWT signature."));
        }

        //after all checks passed its valid!!
        return ResponseEntity.ok(new AuthResponse(true));
    }
}
