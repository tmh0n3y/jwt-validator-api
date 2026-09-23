package com.github.tmh0n3y;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@Service 
public class ValidationService {
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    public ValidationService() {
        this.restTemplate = new RestTemplate();
        this.objectMapper = new ObjectMapper();
    }

    public PublicKey fetchPublicKey(String x5uUrl) throws Exception {
        //get raw pem certificate from x5u url
        String certPem = restTemplate.getForObject(x5uUrl, String.class);

        if (certPem == null || certPem.isEmpty()) {
            throw new IllegalArgumentException("Empty response from x5u URL.");
        }

        //clean and decode certificate
        String cleanPem = certPem.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replaceAll("\\s+", "");
        byte[] certBytes = Base64.getDecoder().decode(cleanPem);

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certBytes));

        return cert.getPublicKey();
    }

    public boolean hasInvalidTimestamps(String base64UrlPayload) {
        try {
            byte[] bytes = Base64.getUrlDecoder().decode(base64UrlPayload);
            JsonNode payloadJson = objectMapper.readTree(bytes);
            long currentTimestamp = System.currentTimeMillis() / 1000;

            //check expiration date
            if (payloadJson.has("exp")) {
                long expTimestamp = payloadJson.get("exp").asLong();
                if (currentTimestamp > expTimestamp) {
                    return true;
                }
            }

            //check issue date
            if (payloadJson.has("iat")) {
                long iatTimestamp = payloadJson.get("iat").asLong();
                if (iatTimestamp > currentTimestamp) {
                    return true;
                }
            }

            return false; 
        } catch (Exception e) {
            return true; 
        }
    }

    public boolean verifySignature(String headerAndPayload, String base64UrlSignature, PublicKey publicKey) {
        try {
            //signature initialization with SHA256withRSA algorithm
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);

            //add the signed data
            signature.update(headerAndPayload.getBytes());

            //add the signature bytes from base64
            byte[] signatureBytes = Base64.getUrlDecoder().decode(base64UrlSignature);

            return signature.verify(signatureBytes);
        } catch (Exception e) {
            return false;
        }
    }



}
