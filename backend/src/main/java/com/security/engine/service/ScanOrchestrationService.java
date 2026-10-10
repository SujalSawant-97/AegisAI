package com.security.engine.service;

import com.security.engine.client.FastApiClient;
import com.security.engine.client.dto.EngineDtos.*;
import com.security.engine.model.*;
import com.security.engine.repository.DiscoveredEndpointRepository;
import com.security.engine.repository.ScanSessionRepository;
import com.security.engine.repository.VulnerabilityFindingRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class ScanOrchestrationService {

    private final FastApiClient fastApiClient;
    private final ScanSessionRepository sessionRepository;
    private final VulnerabilityFindingRepository findingRepository;
    private final DiscoveredEndpointRepository endpointRepository;
    private final TargetService targetService;

    public ScanSession executeOneShotScan(ScanRequest request) {
        targetService.validateTargetUrl(request.target());

        List<String> scanners = (request.scanners() == null || request.scanners().isEmpty())
                ? List.of("all")
                : request.scanners();

        ScanSession session = ScanSession.builder()
                .targetUrl(request.target())
                .status(ScanStatus.RUNNING)
                .requestedScanners(scanners)
                .startedAt(Instant.now())
                .build();
        session = sessionRepository.save(session);

        try {
            log.info("Triggering one-shot scan on {} with scanners {}", request.target(), scanners);
            ScanResponse engineResponse = fastApiClient.executeOneShotScan(request).block();

            if (engineResponse == null) {
                throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Empty response from security engine.");
            }

            session.setEngineScanId(engineResponse.scanId());
            session.setStatus(ScanStatus.COMPLETED);
            session.setCompletedAt(Instant.now());

            // Process findings
            List<VulnerabilityFinding> savedFindings = saveEngineFindings(
                    session.getId(),
                    session.getTargetUrl(),
                    engineResponse.findings()
            );

            // Process summary
            Map<String, Object> rawSummary = engineResponse.summary();
            ScanSession.ScanSummary summary = mapSummary(rawSummary, savedFindings.size());
            session.setSummary(summary);

            // Process errors
            if (engineResponse.scannerErrors() != null) {
                List<ScanSession.ScannerExecutionError> errors = engineResponse.scannerErrors().stream()
                        .map(e -> ScanSession.ScannerExecutionError.builder()
                                .scanner(e.scanner())
                                .error(e.error())
                                .metadata(e.metadata())
                                .build())
                        .toList();
                session.setScannerErrors(errors);
            }

            // Also record completed scanners
            if (rawSummary != null && rawSummary.get("completed_scanners") instanceof List<?> list) {
                session.setCompletedScanners(list.stream().map(Object::toString).toList());
            }

            return sessionRepository.save(session);
        } catch (Exception ex) {
            log.error("Scan execution failed for target {}: {}", request.target(), ex.getMessage(), ex);
            session.setStatus(ScanStatus.FAILED);
            session.setErrorMessage(ex.getMessage());
            session.setCompletedAt(Instant.now());
            return sessionRepository.save(session);
        }
    }

    public ScanSession createSession(SessionCreateRequest request) {
        targetService.validateTargetUrl(request.target());

        SessionCreateResponse engineResp = fastApiClient.createSession(request).block();
        if (engineResp == null || engineResp.sessionId() == null) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to initialize engine session.");
        }

        ScanSession session = ScanSession.builder()
                .engineScanId(engineResp.sessionId())
                .targetUrl(request.target())
                .status(ScanStatus.PENDING)
                .startedAt(Instant.now())
                .summary(mapSummary(engineResp.summary(), 0))
                .build();

        return sessionRepository.save(session);
    }

    public List<DiscoveredEndpoint> discoverSessionEndpoints(String sessionId) {
        ScanSession session = getSessionByAnyId(sessionId);

        // Run engine discovery
        fastApiClient.triggerSessionDiscover(session.getEngineScanId()).block();

        // Fetch discovered endpoints
        List<EndpointDto> endpointDtos = fastApiClient.discoverEndpoints(session.getTargetUrl()).block();
        if (endpointDtos == null) {
            endpointDtos = Collections.emptyList();
        }

        endpointRepository.deleteByScanSessionId(session.getId());

        List<DiscoveredEndpoint> entities = endpointDtos.stream().map(dto -> {
            List<DiscoveredEndpoint.EndpointParameter> params = (dto.parameters() == null)
                    ? Collections.emptyList()
                    : dto.parameters().stream().map(p -> DiscoveredEndpoint.EndpointParameter.builder()
                            .name(p.name())
                            .location(p.location())
                            .required(p.required())
                            .schemaType(p.type())
                            .build()).toList();

            return DiscoveredEndpoint.builder()
                    .scanSessionId(session.getId())
                    .targetUrl(session.getTargetUrl())
                    .method(dto.method())
                    .path(dto.path())
                    .authenticationRequired(dto.authenticationRequired())
                    .description(dto.description())
                    .parameters(params)
                    .discoveredAt(Instant.now())
                    .build();
        }).toList();

        List<DiscoveredEndpoint> saved = endpointRepository.saveAll(entities);

        // Update session summary
        ScanSession.ScanSummary summary = session.getSummary();
        if (summary == null) summary = new ScanSession.ScanSummary();
        summary.setTotalEndpoints(saved.size());
        session.setSummary(summary);
        sessionRepository.save(session);

        log.info("Discovered and saved {} endpoints for session {}", saved.size(), session.getId());
        return saved;
    }

    public List<VulnerabilityFinding> runSessionScan(String sessionId, List<String> scanners) {
        ScanSession session = getSessionByAnyId(sessionId);

        List<String> toRun = (scanners == null || scanners.isEmpty()) ? List.of("all") : scanners;
        session.setStatus(ScanStatus.RUNNING);
        sessionRepository.save(session);

        try {
            SessionScanResponse response = fastApiClient.triggerSessionScan(session.getEngineScanId(), toRun).block();
            if (response == null) {
                throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Empty response from engine during scan.");
            }

            List<VulnerabilityFinding> savedFindings = saveEngineFindings(
                    session.getId(),
                    session.getTargetUrl(),
                    response.findings()
            );

            session.setStatus(ScanStatus.COMPLETED);
            session.setCompletedAt(Instant.now());

            int totalFindings = (int) findingRepository.findByScanSessionId(session.getId()).size();
            session.setSummary(mapSummary(response.summary(), totalFindings));

            if (response.summary() != null && response.summary().get("completed_scanners") instanceof List<?> list) {
                session.setCompletedScanners(list.stream().map(Object::toString).toList());
            }

            sessionRepository.save(session);
            return savedFindings;
        } catch (Exception ex) {
            log.error("Session scan failed: {}", ex.getMessage(), ex);
            session.setStatus(ScanStatus.FAILED);
            session.setErrorMessage(ex.getMessage());
            sessionRepository.save(session);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Scan execution failed: " + ex.getMessage());
        }
    }

    public List<ScanSession> getAllSessions() {
        return sessionRepository.findAllByOrderByStartedAtDesc();
    }

    public ScanSession getSessionByAnyId(String idOrEngineId) {
        return sessionRepository.findById(idOrEngineId)
                .or(() -> sessionRepository.findByEngineScanId(idOrEngineId))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Scan session not found: " + idOrEngineId));
    }

    public void deleteSession(String sessionId) {
        ScanSession session = getSessionByAnyId(sessionId);
        try {
            if (session.getEngineScanId() != null) {
                fastApiClient.deleteSession(session.getEngineScanId()).block();
            }
        } catch (Exception ex) {
            log.warn("Could not delete session from engine: {}", ex.getMessage());
        }
        findingRepository.deleteByScanSessionId(session.getId());
        endpointRepository.deleteByScanSessionId(session.getId());
        sessionRepository.delete(session);
        log.info("Deleted session and associated data: id={}", sessionId);
    }

    private List<VulnerabilityFinding> saveEngineFindings(
            String scanSessionId,
            String targetUrl,
            List<FindingDto> dtos
    ) {
        if (dtos == null || dtos.isEmpty()) {
            return Collections.emptyList();
        }

        List<VulnerabilityFinding> findings = dtos.stream().map(dto -> {
            Severity severity;
            try {
                severity = Severity.valueOf(dto.severity().toUpperCase());
            } catch (Exception e) {
                severity = Severity.MEDIUM;
            }

            return VulnerabilityFinding.builder()
                    .engineFindingId(dto.id())
                    .scanSessionId(scanSessionId)
                    .targetUrl(targetUrl)
                    .scanner(dto.scanner())
                    .vulnerabilityType(dto.vulnerabilityType())
                    .severity(severity)
                    .confidence(dto.confidence())
                    .title(dto.title())
                    .description(dto.description())
                    .endpoint(dto.endpoint())
                    .method(dto.method())
                    .parameter(dto.parameter())
                    .evidence(dto.evidence())
                    .recommendation(dto.recommendation())
                    .references(dto.references() != null ? dto.references() : Collections.emptyList())
                    .metadata(dto.metadata() != null ? dto.metadata() : Collections.emptyMap())
                    .status(FindingStatus.OPEN)
                    .build();
        }).toList();

        return findingRepository.saveAll(findings);
    }

    private ScanSession.ScanSummary mapSummary(Map<String, Object> rawSummary, int totalFindings) {
        if (rawSummary == null) {
            return ScanSession.ScanSummary.builder().totalFindings(totalFindings).build();
        }

        int totalEndpoints = rawSummary.containsKey("total_endpoints")
                ? ((Number) rawSummary.get("total_endpoints")).intValue()
                : 0;

        int scannedEndpoints = rawSummary.containsKey("scanned_endpoints_count")
                ? ((Number) rawSummary.get("scanned_endpoints_count")).intValue()
                : 0;

        int findingsCount = rawSummary.containsKey("total_findings")
                ? ((Number) rawSummary.get("total_findings")).intValue()
                : totalFindings;

        Map<String, Integer> sevMap = new HashMap<>();
        if (rawSummary.get("findings_by_severity") instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (entry.getValue() instanceof Number num) {
                    sevMap.put(entry.getKey().toString(), num.intValue());
                }
            }
        }

        return ScanSession.ScanSummary.builder()
                .totalEndpoints(totalEndpoints)
                .scannedEndpointsCount(scannedEndpoints)
                .totalFindings(findingsCount)
                .findingsBySeverity(sevMap)
                .build();
    }
}
