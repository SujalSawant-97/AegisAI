package com.security.engine.repository;

import com.security.engine.model.ScanSession;
import com.security.engine.model.ScanStatus;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface ScanSessionRepository extends MongoRepository<ScanSession, String> {

    Optional<ScanSession> findByEngineScanId(String engineScanId);

    List<ScanSession> findByTargetUrlOrderByStartedAtDesc(String targetUrl);

    List<ScanSession> findByStatus(ScanStatus status);

    List<ScanSession> findAllByOrderByStartedAtDesc();
}
