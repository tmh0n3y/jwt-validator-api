package com.github.tmh0n3y;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service 
public class ValidationService {
    private final RestTemplate restTemplate;

    public ValidationService() {
        this.restTemplate = new RestTemplate();
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



}
