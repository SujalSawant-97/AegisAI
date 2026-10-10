package com.security.engine.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "scan_sessions")
public class ScanSession {

    @Id
    private String id;

    @Indexed(unique = true)
    private String engineScanId; // SESSION-xxx or SCAN-xxx from Python engine

    private String targetId;

    @Indexed
    private String targetUrl;

    @Builder.Default
    private ScanStatus status = ScanStatus.PENDING;

    @Builder.Default
    private List<String> requestedScanners = new ArrayList<>();

    @Builder.Default
    private List<String> completedScanners = new ArrayList<>();

    @Builder.Default
    private ScanSummary summary = new ScanSummary();

    @Builder.Default
    private List<ScannerExecutionError> scannerErrors = new ArrayList<>();

    private String errorMessage;

    @CreatedDate
    private Instant startedAt;

    private Instant completedAt;

    @LastModifiedDate
    private Instant updatedAt;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ScanSummary {
        private int totalEndpoints;
        private int scannedEndpointsCount;
        private int totalFindings;
        @Builder.Default
        private Map<String, Integer> findingsBySeverity = new HashMap<>();
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ScannerExecutionError {
        private String scanner;
        private String error;
        @Builder.Default
        private Map<String, Object> metadata = new HashMap<>();
    }
}
