package com.security.engine.client.dto;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;

import java.io.IOException;

/**
 * Flexible deserializer for String fields that may be returned as either:
 * 1. Plain String: "Hello world"
 * 2. Array of objects (multimodal parts): [{"type": "text", "text": "Hello world"}]
 * 3. Array of strings: ["Hello", "world"]
 * 4. Arbitrary JSON Node
 */
public class FlexibleStringDeserializer extends JsonDeserializer<String> {

    @Override
    public String deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        JsonNode node = p.getCodec().readTree(p);
        if (node == null || node.isNull()) {
            return "";
        }

        if (node.isTextual()) {
            return node.asText();
        }

        if (node.isArray()) {
            StringBuilder sb = new StringBuilder();
            for (JsonNode item : node) {
                if (item.isTextual()) {
                    sb.append(item.asText()).append("\n\n");
                } else if (item.isObject()) {
                    if (item.has("text") && !item.get("text").isNull()) {
                        sb.append(item.get("text").asText()).append("\n\n");
                    } else if (item.has("content") && !item.get("content").isNull()) {
                        sb.append(item.get("content").asText()).append("\n\n");
                    }
                }
            }
            String result = sb.toString().trim();
            return result.isEmpty() ? node.toString() : result;
        }

        return node.toString();
    }
}
