package com.security.engine.repository;

import com.security.engine.model.DiscoveredEndpoint;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface DiscoveredEndpointRepository extends MongoRepository<DiscoveredEndpoint, String> {
    List<DiscoveredEndpoint> findByScanSessionId(String scanSessionId);
    List<DiscoveredEndpoint> findByTargetUrl(String targetUrl);
    void deleteByScanSessionId(String scanSessionId);
}
