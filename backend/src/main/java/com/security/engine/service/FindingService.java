package com.security.engine.service;

import com.security.engine.model.FindingStatus;
import com.security.engine.model.Severity;
import com.security.engine.model.VulnerabilityFinding;
import com.security.engine.repository.VulnerabilityFindingRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class FindingService {

    private final VulnerabilityFindingRepository findingRepository;

    public List<VulnerabilityFinding> getFindings(
            String scanSessionId,
            String targetUrl,
            Severity severity,
            FindingStatus status
    ) {
        if (scanSessionId != null && !scanSessionId.isBlank()) {
            return findingRepository.findByScanSessionId(scanSessionId);
        }
        if (targetUrl != null && !targetUrl.isBlank()) {
            if (severity != null) {
                return findingRepository.findByTargetUrlAndSeverity(targetUrl, severity);
            }
            return findingRepository.findByTargetUrl(targetUrl);
        }
        if (severity != null) {
            return findingRepository.findBySeverity(severity);
        }
        if (status != null) {
            return findingRepository.findByStatus(status);
        }
        return findingRepository.findAll();
    }

    public VulnerabilityFinding getFindingById(String id) {
        return findingRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Finding not found: " + id));
    }

    public VulnerabilityFinding updateStatus(String id, FindingStatus newStatus, String notes) {
        VulnerabilityFinding finding = getFindingById(id);
        finding.setStatus(newStatus);
        if (notes != null) {
            finding.setNotes(notes);
        }
        VulnerabilityFinding updated = findingRepository.save(finding);
        log.info("Updated finding {} status to {}", id, newStatus);
        return updated;
    }

    public Map<String, Object> getMetrics() {
        Map<String, Object> metrics = new HashMap<>();

        Map<String, Long> bySeverity = new HashMap<>();
        for (Severity s : Severity.values()) {
            bySeverity.put(s.name(), findingRepository.countBySeverity(s));
        }
        metrics.put("by_severity", bySeverity);

        Map<String, Long> byStatus = new HashMap<>();
        for (FindingStatus s : FindingStatus.values()) {
            byStatus.put(s.name(), findingRepository.countByStatus(s));
        }
        metrics.put("by_status", byStatus);
        metrics.put("total_findings", findingRepository.count());

        return metrics;
    }
}
