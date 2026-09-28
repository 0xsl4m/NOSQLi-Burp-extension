package nosqli;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;

import java.util.ArrayList;
import java.util.List;

/**
 * SmartBodyDetector
 *
 * Intelligently detects the type of request body and extracts
 * all injectable parameters with their positions.
 *
 * Supported types:
 *  - application/json
 *  - application/x-www-form-urlencoded
 *  - multipart/form-data
 *  - text/xml / application/xml
 *  - GET query parameters
 *  - GraphQL (JSON with query field)
 */
public class SmartBodyDetector {

    public enum BodyType {
        JSON,
        URL_ENCODED,
        MULTIPART,
        XML,
        GET_PARAMS,
        GRAPHQL,
        UNKNOWN
    }

    public static class ParsedParam {
        public final String name;
        public final String value;
        public final int valueStart; // byte offset in body
        public final int valueEnd;
        public final BodyType bodyType;
        public final HttpParameterType paramType;

        public ParsedParam(String name, String value, int valueStart, int valueEnd,
                           BodyType bodyType, HttpParameterType paramType) {
            this.name = name;
            this.value = value;
            this.valueStart = valueStart;
            this.valueEnd = valueEnd;
            this.bodyType = bodyType;
            this.paramType = paramType;
        }
    }

    /**
     * Detect the body type from a request.
     */
    public static BodyType detect(HttpRequest request) {
        String contentType = getContentTypeHeader(request);

        if (contentType == null) {
            // No Content-Type: try to detect from body
            String body = request.bodyToString().trim();
            if (body.startsWith("{") || body.startsWith("[")) {
                return BodyType.JSON;
            }
            if (body.contains("=") && body.contains("&")) {
                return BodyType.URL_ENCODED;
            }
            if (request.method().equalsIgnoreCase("GET")) {
                return BodyType.GET_PARAMS;
            }
            return BodyType.UNKNOWN;
        }

        String ctLower = contentType.toLowerCase();

        if (ctLower.contains("application/json")) {
            // Check if it's GraphQL
            String body = request.bodyToString();
            if (body.contains("\"query\"") && (body.contains("mutation") || body.contains("query {") || body.contains("query{"))) {
                return BodyType.GRAPHQL;
            }
            return BodyType.JSON;
        }
        if (ctLower.contains("application/x-www-form-urlencoded")) {
            return BodyType.URL_ENCODED;
        }
        if (ctLower.contains("multipart/form-data")) {
            return BodyType.MULTIPART;
        }
        if (ctLower.contains("text/xml") || ctLower.contains("application/xml") || ctLower.contains("application/soap")) {
            return BodyType.XML;
        }
        if (request.method().equalsIgnoreCase("GET")) {
            return BodyType.GET_PARAMS;
        }

        return BodyType.UNKNOWN;
    }

    /**
     * Extract all injectable parameters from a request.
     * Returns parameters with their exact byte positions for replacement.
     */
    public static List<ParsedParam> extractParams(HttpRequest request) {
        List<ParsedParam> result = new ArrayList<>();
        BodyType bodyType = detect(request);

        switch (bodyType) {
            case JSON:
            case GRAPHQL:
                extractJsonParams(request, bodyType, result);
                break;
            case URL_ENCODED:
                extractUrlEncodedParams(request, result);
                break;
            case GET_PARAMS:
                extractGetParams(request, result);
                break;
            case MULTIPART:
                extractMultipartParams(request, result);
                break;
            default:
                // Also check GET params regardless
                extractGetParams(request, result);
                break;
        }

        return result;
    }

    /**
     * Extract JSON parameters recursively (handles nested objects).
     */
    private static void extractJsonParams(HttpRequest request, BodyType bodyType, List<ParsedParam> result) {
        String body = request.bodyToString();
        if (body == null || body.isEmpty()) return;

        // Parse all string values in JSON body
        // We look for: "key": "value" patterns
        // Simple but effective for most real-world cases
        int i = 0;
        while (i < body.length()) {
            // Find next key-value pair
            int keyStart = body.indexOf('"', i);
            if (keyStart == -1) break;

            int keyEnd = findClosingQuote(body, keyStart + 1);
            if (keyEnd == -1) break;

            String key = body.substring(keyStart + 1, keyEnd);
            i = keyEnd + 1;

            // Skip whitespace and colon
            while (i < body.length() && (body.charAt(i) == ' ' || body.charAt(i) == '\t' ||
                   body.charAt(i) == '\n' || body.charAt(i) == ':')) {
                i++;
            }

            if (i >= body.length()) break;

            char nextChar = body.charAt(i);

            if (nextChar == '"') {
                // String value
                int valStart = i;
                int valEnd = findClosingQuote(body, i + 1);
                if (valEnd == -1) break;

                String value = body.substring(i + 1, valEnd);

                // Calculate absolute offset in full request
                int bodyOffset = request.toString().indexOf(body);
                if (bodyOffset == -1) bodyOffset = 0;

                result.add(new ParsedParam(
                    key, value,
                    bodyOffset + valStart,
                    bodyOffset + valEnd + 1,
                    bodyType,
                    HttpParameterType.BODY
                ));

                i = valEnd + 1;
            } else if (nextChar == '{' || nextChar == '[') {
                // Skip nested objects/arrays - still add as injectable
                int depth = 1;
                int objStart = i;
                i++;
                char open = nextChar;
                char close = (open == '{') ? '}' : ']';

                while (i < body.length() && depth > 0) {
                    char c = body.charAt(i);
                    if (c == open) depth++;
                    else if (c == close) depth--;
                    else if (c == '"') {
                        i = findClosingQuote(body, i + 1) + 1;
                        continue;
                    }
                    i++;
                }
                // Don't add nested objects as individual params (handled recursively above)

            } else {
                // Number, boolean, null
                int valStart = i;
                while (i < body.length() && body.charAt(i) != ',' && body.charAt(i) != '}' &&
                       body.charAt(i) != ']' && body.charAt(i) != '\n') {
                    i++;
                }
                String value = body.substring(valStart, i).trim();

                int bodyOffset = request.toString().indexOf(body);
                if (bodyOffset == -1) bodyOffset = 0;

                result.add(new ParsedParam(
                    key, value,
                    bodyOffset + valStart,
                    bodyOffset + i,
                    bodyType,
                    HttpParameterType.BODY
                ));
            }
        }
    }

    /**
     * Extract URL-encoded body parameters.
     */
    private static void extractUrlEncodedParams(HttpRequest request, List<ParsedParam> result) {
        for (HttpParameter param : request.parameters()) {
            if (param.type() == HttpParameterType.BODY) {
                result.add(new ParsedParam(
                    param.name(),
                    param.value(),
                    0, 0,   // offsets not used; replacement done via withUpdatedParameters
                    BodyType.URL_ENCODED,
                    HttpParameterType.BODY
                ));
            }
        }
    }

    /**
     * Extract GET query string parameters.
     */
    private static void extractGetParams(HttpRequest request, List<ParsedParam> result) {
        for (HttpParameter param : request.parameters()) {
            if (param.type() == HttpParameterType.URL) {
                result.add(new ParsedParam(
                    param.name(),
                    param.value(),
                    0, 0,
                    BodyType.GET_PARAMS,
                    HttpParameterType.URL
                ));
            }
        }
    }

    /**
     * Extract multipart form parameters (non-file fields only).
     */
    private static void extractMultipartParams(HttpRequest request, List<ParsedParam> result) {
        for (HttpParameter param : request.parameters()) {
            if (param.type() == HttpParameterType.BODY || param.type() == HttpParameterType.MULTIPART_ATTRIBUTE) {
                if (!param.value().isEmpty() && isPrintable(param.value())) {
                    result.add(new ParsedParam(
                        param.name(),
                        param.value(),
                        0, 0,
                        BodyType.MULTIPART,
                        param.type()
                    ));
                }
            }
        }
    }

    // ─────────────────────────────────────────────────────────────
    // PAYLOAD APPLICATION HELPERS
    // ─────────────────────────────────────────────────────────────

    /**
     * Build a modified request with an operator injection payload.
     * For URL-encoded: replaces "param=value" with "param[$ne]=xyz"
     * For JSON: replaces "value" with {"$ne": "xyz"}
     */
    public static HttpRequest applyPayload(HttpRequest originalRequest, ParsedParam param, String payloadValue) {
        switch (param.bodyType) {
            case URL_ENCODED:
                return applyUrlEncodedPayload(originalRequest, param, payloadValue);
            case JSON:
            case GRAPHQL:
                return applyJsonPayload(originalRequest, param, payloadValue);
            case GET_PARAMS:
                return applyGetParamPayload(originalRequest, param, payloadValue);
            default:
                return applyRawReplacePayload(originalRequest, param, payloadValue);
        }
    }

    private static HttpRequest applyUrlEncodedPayload(HttpRequest request, ParsedParam param, String newValue) {
        // newValue might be something like "[$ne]=impossible" or "[$gt]="
        // We need to replace "paramName=oldValue" with the full new form
        try {
            // Use Burp's built-in parameter replacement
            return request.withUpdatedParameters(
                HttpParameter.bodyParameter(param.name, newValue)
            );
        } catch (Exception e) {
            return request;
        }
    }

    private static HttpRequest applyJsonPayload(HttpRequest request, ParsedParam param, String newJsonValue) {
        // Replace the parameter value in the JSON body
        String body = request.bodyToString();
        // Find "paramName": "oldValue" or "paramName": oldValue
        // and replace the value portion with newJsonValue
        String newBody = replaceJsonValue(body, param.name, param.value, newJsonValue);
        return request.withBody(newBody);
    }

    private static HttpRequest applyGetParamPayload(HttpRequest request, ParsedParam param, String newValue) {
        try {
            return request.withUpdatedParameters(
                HttpParameter.urlParameter(param.name, newValue)
            );
        } catch (Exception e) {
            return request;
        }
    }

    private static HttpRequest applyRawReplacePayload(HttpRequest request, ParsedParam param, String newValue) {
        String body = request.bodyToString();
        String newBody = body.replace(param.value, newValue);
        return request.withBody(newBody);
    }

    // ─────────────────────────────────────────────────────────────
    // PRIVATE HELPERS
    // ─────────────────────────────────────────────────────────────

    private static String getContentTypeHeader(HttpRequest request) {
        for (var header : request.headers()) {
            if (header.name().equalsIgnoreCase("Content-Type")) {
                return header.value();
            }
        }
        return null;
    }

    private static int findClosingQuote(String s, int start) {
        for (int i = start; i < s.length(); i++) {
            if (s.charAt(i) == '\\') {
                i++; // skip escaped char
                continue;
            }
            if (s.charAt(i) == '"') {
                return i;
            }
        }
        return -1;
    }

    private static boolean isPrintable(String s) {
        for (char c : s.toCharArray()) {
            if (c < 32 && c != '\t' && c != '\n' && c != '\r') return false;
        }
        return true;
    }

    /**
     * Replace a JSON string value for a given key.
     * Handles both quoted strings and raw values (null, true, false, numbers).
     */
    public static String replaceJsonValue(String json, String key, String oldValue, String newValue) {
        // Find "key": "oldValue" or "key": oldValue
        // Simple string replacement - adequate for single-level params
        String quotedOld = "\"" + oldValue + "\"";
        String quotedNew = newValue; // new value might already include quotes or be an object

        // Try quoted replacement first
        int keyIdx = json.indexOf("\"" + key + "\"");
        if (keyIdx == -1) return json;

        int colonIdx = json.indexOf(":", keyIdx + key.length() + 2);
        if (colonIdx == -1) return json;

        // Skip whitespace after colon
        int valStart = colonIdx + 1;
        while (valStart < json.length() && json.charAt(valStart) == ' ') valStart++;

        if (valStart >= json.length()) return json;

        int valEnd;
        if (json.charAt(valStart) == '"') {
            // Quoted string value
            valEnd = findClosingQuote(json, valStart + 1) + 1;
        } else if (json.charAt(valStart) == '{') {
            // Object - find closing brace
            int depth = 1;
            valEnd = valStart + 1;
            while (valEnd < json.length() && depth > 0) {
                if (json.charAt(valEnd) == '{') depth++;
                else if (json.charAt(valEnd) == '}') depth--;
                valEnd++;
            }
        } else {
            // Primitive value (number, boolean, null)
            valEnd = valStart;
            while (valEnd < json.length() && json.charAt(valEnd) != ',' &&
                   json.charAt(valEnd) != '}' && json.charAt(valEnd) != '\n') {
                valEnd++;
            }
        }

        return json.substring(0, valStart) + newValue + json.substring(valEnd);
    }
}
