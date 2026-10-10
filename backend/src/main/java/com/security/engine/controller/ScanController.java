package com.security.engine.controller;

import com.security.engine.client.dto.EngineDtos.*;
import com.security.engine.model.DiscoveredEndpoint;
import com.security.engine.model.ScanSession;
import com.security.engine.model.VulnerabilityFinding;
import com.security.engine.service.ScanOrchestrationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/scans")
@RequiredArgsConstructor
public class ScanController {

    private final ScanOrchestrationService scanService;

    @PostMapping("/one-shot")
    public ScanSession executeOneShotScan(@RequestBody ScanRequest request) {
        return scanService.executeOneShotScan(request);
    }

    @PostMapping("/sessions")
    @ResponseStatus(HttpStatus.CREATED)
    public ScanSession createSession(@RequestBody SessionCreateRequest request) {
        return scanService.createSession(request);
    }

    @PostMapping("/sessions/{id}/discover")
    public List<DiscoveredEndpoint> discoverEndpoints(@PathVariable String id) {
        return scanService.discoverSessionEndpoints(id);
    }

    @PostMapping("/sessions/{id}/scan")
    public List<VulnerabilityFinding> runSessionScan(
            @PathVariable String id,
            @RequestBody(required = false) SessionScanRequest request
    ) {
        List<String> scanners = (request != null && request.scanners() != null)
                ? request.scanners()
                : List.of("all");
        return scanService.runSessionScan(id, scanners);
    }

    @GetMapping("/sessions/{id}")
    public ScanSession getSession(@PathVariable String id) {
        return scanService.getSessionByAnyId(id);
    }

    @GetMapping
    public List<ScanSession> listSessions() {
        return scanService.getAllSessions();
    }

    @DeleteMapping("/sessions/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteSession(@PathVariable String id) {
        scanService.deleteSession(id);
    }
}
