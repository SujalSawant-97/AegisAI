package com.security.engine.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "security.engine")
public record EngineProperties(
    String fastapiUrl,
    int timeoutSeconds,
    int maxInMemorySizeMb
) {
    public EngineProperties {
        if (fastapiUrl == null || fastapiUrl.isBlank()) {
            fastapiUrl = "http://localhost:8000";
        }
        if (timeoutSeconds <= 0) {
            timeoutSeconds = 180;
        }
        if (maxInMemorySizeMb <= 0) {
            maxInMemorySizeMb = 16;
        }
    }
}
