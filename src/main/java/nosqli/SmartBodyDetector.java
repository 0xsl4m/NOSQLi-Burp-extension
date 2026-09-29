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
                // The walker also covers GraphQL: every leaf under "variables"
                // is extracted as its own injectable parameter.
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
            case XML:
                // XML bodies are not supported yet — extract nothing so the
                // scans report "No parameters found" instead of misfiring.
                break;
            default:
                // Also check GET params regardless
                extractGetParams(request, result);
                break;
        }

        return result;
    }

    /**
     * Extract JSON parameters via the zero-dependency walker: every leaf
     * value — nested objects/arrays included — becomes an injectable
     * parameter. Offsets are relative to the BODY string; value is the raw
     * JSON text of the leaf.
     */
    private static void extractJsonParams(HttpRequest request, BodyType bodyType, List<ParsedParam> result) {
        String body = request.bodyToString();
        if (body == null || body.isEmpty()) return;
        for (JsonWalker.Leaf leaf : JsonWalker.leaves(body)) {
            result.add(new ParsedParam(
                leaf.key, leaf.raw, leaf.start, leaf.end, bodyType, HttpParameterType.BODY));
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
     * Apply a VALUE-LEVEL payload: the given string replaces the parameter's
     * value only — the parameter name stays the same. Used for error chars,
     * JS injection and time-based payloads.
     *
     * NOT suitable for operator-injection payloads: those change the parameter
     * NAME itself ("user[$ne]=x"), which cannot be expressed as a value
     * replacement. Use {@link #applyOperatorPayload} for those.
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

    /**
     * Apply an OPERATOR-INJECTION payload.
     *
     *  - URL-encoded / GET: the payload is a full "name=value" pair whose name
     *    may differ from the original (e.g. "user[$ne]=x"), so the original
     *    pair is REMOVED and the new one added — withUpdatedParameters cannot
     *    do this because it only rewrites the value under the same name.
     *  - JSON / GraphQL: the payload replaces the parameter's JSON value,
     *    usually with an object (e.g. {"$ne": "x"}).
     *
     * For body types where operator pairs make no sense (multipart, raw), the
     * original request is returned unchanged, so the true/false requests are
     * identical and can never produce a differential finding.
     */
    public static HttpRequest applyOperatorPayload(HttpRequest originalRequest, ParsedParam param, String pairPayload) {
        switch (param.bodyType) {
            case URL_ENCODED:
                return applyUrlEncodedPairPayload(originalRequest, param, pairPayload);
            case GET_PARAMS:
                return applyGetParamPairPayload(originalRequest, param, pairPayload);
            case JSON:
            case GRAPHQL:
                return applyJsonPayload(originalRequest, param, pairPayload);
            default:
                return originalRequest;
        }
    }

    private static HttpRequest applyUrlEncodedPairPayload(HttpRequest request, ParsedParam param, String pair) {
        try {
            int eq = pair.indexOf('=');
            if (eq <= 0) return request;
            HttpParameter newParam = HttpParameter.bodyParameter(pair.substring(0, eq), pair.substring(eq + 1));
            return request
                .withRemovedParameters(HttpParameter.bodyParameter(param.name, param.value))
                .withAddedParameters(newParam);
        } catch (Exception e) {
            return request;
        }
    }

    private static HttpRequest applyGetParamPairPayload(HttpRequest request, ParsedParam param, String pair) {
        try {
            int eq = pair.indexOf('=');
            if (eq <= 0) return request;
            HttpParameter newParam = HttpParameter.urlParameter(pair.substring(0, eq), pair.substring(eq + 1));
            return request
                .withRemovedParameters(HttpParameter.urlParameter(param.name, param.value))
                .withAddedParameters(newParam);
        } catch (Exception e) {
            return request;
        }
    }

    private static HttpRequest applyUrlEncodedPayload(HttpRequest request, ParsedParam param, String newValue) {
        // VALUE-LEVEL: newValue replaces the value under the SAME parameter name.
        try {
            return request.withUpdatedParameters(
                HttpParameter.bodyParameter(param.name, newValue)
            );
        } catch (Exception e) {
            return request;
        }
    }

    private static HttpRequest applyJsonPayload(HttpRequest request, ParsedParam param, String newJsonValue) {
        String body = request.bodyToString();

        // Fast path: the recorded offsets still point at the same raw value,
        // so replace by exact position (immune to duplicate/substring keys).
        if (param.valueStart >= 0 && param.valueEnd > param.valueStart
                && param.valueEnd <= body.length()
                && body.substring(param.valueStart, param.valueEnd).equals(param.value)) {
            String replacement = jsonValueForPosition(body.charAt(param.valueStart), newJsonValue);
            return request.withBody(body.substring(0, param.valueStart)
                + replacement + body.substring(param.valueEnd));
        }

        // Fallback: replace the first leaf with the matching key.
        String updated = JsonWalker.replaceFirstKey(body, param.name, newJsonValue);
        return updated.equals(body) ? request : request.withBody(updated);
    }

    /**
     * Decide how newJsonValue is spliced at a value position. Object/array/
     * string/null/true/false/number literals are valid JSON on their own;
     * anything else (e.g. JavaScript payload text) must be quoted when it
     * replaces a string value, or the JSON structure breaks.
     */
    private static String jsonValueForPosition(char currentFirstChar, String newValue) {
        String t = newValue.trim();
        boolean rawValid = t.startsWith("{") || t.startsWith("[") || t.startsWith("\"")
            || t.equals("null") || t.equals("true") || t.equals("false")
            || t.matches("-?\\d+(\\.\\d+)?([eE][+-]?\\d+)?");
        if (rawValid) return newValue;
        if (currentFirstChar == '"') return quoteJsonLiteral(newValue);
        return newValue; // non-string position — best effort, insert as-is
    }

    private static String quoteJsonLiteral(String s) {
        StringBuilder sb = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"'  -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default   -> sb.append(c < 0x20 ? String.format("\\u%04x", (int) c) : String.valueOf(c));
            }
        }
        return sb.append('"').toString();
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

    private static boolean isPrintable(String s) {
        for (char c : s.toCharArray()) {
            if (c < 32 && c != '\t' && c != '\n' && c != '\r') return false;
        }
        return true;
    }

    /**
     * Replace the first leaf whose key matches. Kept for compatibility with
     * the old signature; the JsonWalker does the structural work now.
     */
    public static String replaceJsonValue(String json, String key, String oldValue, String newValue) {
        return JsonWalker.replaceFirstKey(json, key, newValue);
    }
}
