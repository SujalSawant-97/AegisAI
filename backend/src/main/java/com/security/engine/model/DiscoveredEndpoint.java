package com.security.engine.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.CompoundIndex;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "discovered_endpoints")
@CompoundIndex(name = "session_endpoint_idx", def = "{'scanSessionId': 1, 'method': 1, 'path': 1}")
public class DiscoveredEndpoint {

    @Id
    private String id;

    @Indexed
    private String scanSessionId;

    @Indexed
    private String targetUrl;

    private String method;

    private String path;

    private boolean authenticationRequired;

    private String description;

    @Builder.Default
    private List<EndpointParameter> parameters = new ArrayList<>();

    @CreatedDate
    private Instant discoveredAt;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class EndpointParameter {
        private String name;
        private String location; // query, path, header, body
        private boolean required;
        private String schemaType;
        private String description;
    }
}
