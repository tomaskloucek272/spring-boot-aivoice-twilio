package com.example.demo.mvc;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Map;

@RestController
public class ElevenLabsWebhookController {
    @Value("${elevenlabs.webhook.secret}")
    private String webhookSecret;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @PostMapping("/webhook")
    public ResponseEntity<Map<String, String>> handleWebhook(HttpServletRequest request) throws Exception {
        byte[] bodyBytes = request.getInputStream().readAllBytes();
        String rawBody = new String(bodyBytes, StandardCharsets.UTF_8);

        String signatureHeader = request.getHeader("ElevenLabs-Signature");

        if (signatureHeader == null || !isValidSignature(rawBody, signatureHeader, webhookSecret)) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid signature"));
        }

        JsonNode event = objectMapper.readTree(rawBody);
        String type = event.path("type").asText();

        System.out.println("Event type: " + type);

        if ("post_call_transcription".equals(type)) {
            JsonNode data = event.path("data");

            JsonNode analysis = data.path("analysis");

            if (!analysis.isMissingNode()) {
                JsonNode dataCollection = analysis.path("data_collection_results");
                System.out.println("Data collection results: " + dataCollection.toPrettyString());
            }
        }

        return ResponseEntity.ok(Map.of("status", "received"));
    }

    private boolean isValidSignature(String rawBody, String signatureHeader, String secret) {
        try {
            String timestamp = null;
            String receivedSignature = null;

            for (String part : signatureHeader.split(",")) {
                String[] kv = part.trim().split("=", 2);
                if (kv.length == 2) {
                    if ("t".equals(kv[0])) timestamp = kv[1];
                    if ("v0".equals(kv[0])) receivedSignature = kv[1];
                }
            }

            if (timestamp == null || receivedSignature == null) return false;

            String signedPayload = timestamp + "." + rawBody;

            Mac hmac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            hmac.init(keySpec);
            byte[] hash = hmac.doFinal(signedPayload.getBytes(StandardCharsets.UTF_8));
            String expected = HexFormat.of().formatHex(hash);

            return MessageDigest.isEqual(
                    expected.getBytes(StandardCharsets.UTF_8),
                    receivedSignature.getBytes(StandardCharsets.UTF_8)
            );
        } catch (Exception e) {
            return false;
        }
    }
}
