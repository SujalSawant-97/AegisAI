package com.security.engine.repository;

import com.security.engine.model.TargetApp;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface TargetAppRepository extends MongoRepository<TargetApp, String> {
    Optional<TargetApp> findByBaseUrl(String baseUrl);
    boolean existsByBaseUrl(String baseUrl);
}
