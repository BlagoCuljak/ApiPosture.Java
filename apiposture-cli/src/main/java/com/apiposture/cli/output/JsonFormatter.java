package com.apiposture.cli.output;

import com.apiposture.core.models.ScanResult;
import com.apiposture.core.models.Severity;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * JSON output formatter.
 */
public class JsonFormatter implements OutputFormatter {

    private final ObjectMapper objectMapper;

    public JsonFormatter() {
        this.objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .enable(SerializationFeature.INDENT_OUTPUT)
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }

    @Override
    public String format(ScanResult result) {
        try {
            // Create a structured output object
            Map<String, Object> output = new LinkedHashMap<>();

            // Summary section
            Map<String, Object> summary = new LinkedHashMap<>();
            summary.put("projectPath", result.projectPath());
            summary.put("scannedFiles", result.scannedFiles());
            summary.put("scanDurationMs", result.scanDuration().toMillis());
            summary.put("timestamp", result.timestamp().toString());
            summary.put("totalEndpoints", result.getTotalEndpoints());
            summary.put("totalFindings", result.getTotalFindings());
            output.put("summary", summary);

            // Severity counts
            Map<String, Integer> severityCounts = new LinkedHashMap<>();
            Map<Severity, Integer> counts = result.getSeverityCounts();
            for (Severity severity : Severity.values()) {
                severityCounts.put(severity.name().toLowerCase(), counts.getOrDefault(severity, 0));
            }
            output.put("severityCounts", severityCounts);

            // Endpoints
            output.put("endpoints", result.endpoints());

            // Findings
            output.put("findings", result.findings());

            return objectMapper.writeValueAsString(output);

        } catch (JsonProcessingException e) {
            return "{\"error\": \"Failed to serialize results: " + e.getMessage() + "\"}";
        }
    }
}
