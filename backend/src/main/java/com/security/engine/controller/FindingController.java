package com.security.engine.controller;

import com.security.engine.model.FindingStatus;
import com.security.engine.model.Severity;
import com.security.engine.model.VulnerabilityFinding;
import com.security.engine.service.FindingService;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/findings")
@RequiredArgsConstructor
public class FindingController {

    private final FindingService findingService;

    @GetMapping
    public List<VulnerabilityFinding> getFindings(
            @RequestParam(required = false) String scanSessionId,
            @RequestParam(required = false) String targetUrl,
            @RequestParam(required = false) Severity severity,
            @RequestParam(required = false) FindingStatus status
    ) {
        return findingService.getFindings(scanSessionId, targetUrl, severity, status);
    }

    @GetMapping("/{id}")
    public VulnerabilityFinding getFinding(@PathVariable String id) {
        return findingService.getFindingById(id);
    }

    @PatchMapping("/{id}/status")
    public VulnerabilityFinding updateStatus(
            @PathVariable String id,
            @RequestBody StatusUpdateRequest request
    ) {
        return findingService.updateStatus(id, request.getStatus(), request.getNotes());
    }

    @GetMapping("/stats")
    public Map<String, Object> getMetrics() {
        return findingService.getMetrics();
    }

    @Data
    public static class StatusUpdateRequest {
        private FindingStatus status;
        private String notes;
    }
}
