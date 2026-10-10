package com.security.engine.client.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

public class EngineDtos {

    public record DiscoverRequest(
            @JsonProperty("target") String target
    ) {}

    public record EndpointParameterDto(
            @JsonProperty("name") String name,
            @JsonProperty("location") String location,
            @JsonProperty("required") boolean required,
            @JsonProperty("type") String type
    ) {}

    public record EndpointDto(
            @JsonProperty("method") String method,
            @JsonProperty("path") String path,
            @JsonProperty("authentication_required") boolean authenticationRequired,
            @JsonProperty("description") String description,
            @JsonProperty("parameters") List<EndpointParameterDto> parameters
    ) {}

    public record ScanRequest(
            @JsonProperty("target") String target,
            @JsonProperty("scanners") List<String> scanners,
            @JsonProperty("auth_token") String authToken,
            @JsonProperty("low_priv_token") String lowPrivToken
    ) {}

    public record FindingDto(
            @JsonProperty("id") String id,
            @JsonProperty("scanner") String scanner,
            @JsonProperty("vulnerability_type") String vulnerabilityType,
            @JsonProperty("severity") String severity,
            @JsonProperty("confidence") Double confidence,
            @JsonProperty("endpoint") String endpoint,
            @JsonProperty("method") String method,
            @JsonProperty("parameter") String parameter,
            @JsonProperty("title") String title,
            @JsonProperty("description") String description,
            @JsonProperty("evidence") String evidence,
            @JsonProperty("recommendation") String recommendation,
            @JsonProperty("references") List<String> references,
            @JsonProperty("metadata") Map<String, Object> metadata
    ) {}

    public record ScannerErrorDto(
            @JsonProperty("scanner") String scanner,
            @JsonProperty("error") String error,
            @JsonProperty("metadata") Map<String, Object> metadata
    ) {}

    public record ScanResponse(
            @JsonProperty("scan_id") String scanId,
            @JsonProperty("target") String target,
            @JsonProperty("status") String status,
            @JsonProperty("summary") Map<String, Object> summary,
            @JsonProperty("findings") List<FindingDto> findings,
            @JsonProperty("scanner_errors") List<ScannerErrorDto> scannerErrors
    ) {}

    public record SessionCreateRequest(
            @JsonProperty("target") String target,
            @JsonProperty("auth_token") String authToken,
            @JsonProperty("low_priv_token") String lowPrivToken
    ) {}

    public record SessionCreateResponse(
            @JsonProperty("session_id") String sessionId,
            @JsonProperty("summary") Map<String, Object> summary
    ) {}

    public record SessionScanRequest(
            @JsonProperty("scanners") List<String> scanners
    ) {}

    public record SessionScanResponse(
            @JsonProperty("session_id") String sessionId,
            @JsonProperty("new_findings_count") int newFindingsCount,
            @JsonProperty("summary") Map<String, Object> summary,
            @JsonProperty("findings") List<FindingDto> findings
    ) {}

    public record SessionDiscoverResponse(
            @JsonProperty("session_id") String sessionId,
            @JsonProperty("total_endpoints") int totalEndpoints
    ) {}

    public record ScannerMetadataDto(
            @JsonProperty("name") String name,
            @JsonProperty("description") String description,
            @JsonProperty("vulnerability_types") List<String> vulnerabilityTypes,
            @JsonProperty("risk_level") String riskLevel
    ) {}

    public record AgentRunRequest(
            @JsonProperty("target") String target,
            @JsonProperty("prompt") String prompt,
            @JsonProperty("session_id") String sessionId
    ) {}

    public record AgentChatRequest(
            @JsonProperty("message") String message,
            @JsonProperty("target") String target,
            @JsonProperty("session_id") String sessionId
    ) {}

    public record AgentResponse(
            @JsonProperty("session_id") String sessionId,
            @JsonProperty("target") String target,
            @JsonProperty("response") @JsonDeserialize(using = FlexibleStringDeserializer.class) String response,
            @JsonProperty("messages_count") int messagesCount
    ) {}
}
