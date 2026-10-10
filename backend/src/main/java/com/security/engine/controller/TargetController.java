package com.security.engine.controller;

import com.security.engine.model.TargetApp;
import com.security.engine.service.TargetService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/targets")
@RequiredArgsConstructor
public class TargetController {

    private final TargetService targetService;

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public TargetApp createTarget(@Valid @RequestBody TargetApp target) {
        return targetService.registerTarget(target);
    }

    @GetMapping
    public List<TargetApp> listTargets() {
        return targetService.getAllTargets();
    }

    @GetMapping("/{id}")
    public TargetApp getTarget(@PathVariable String id) {
        return targetService.getTargetById(id);
    }

    @PutMapping("/{id}")
    public TargetApp updateTarget(@PathVariable String id, @RequestBody TargetApp updated) {
        return targetService.updateTarget(id, updated);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteTarget(@PathVariable String id) {
        targetService.deleteTarget(id);
    }
}
