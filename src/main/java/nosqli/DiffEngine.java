package nosqli;

import java.util.regex.Pattern;

/**
 * DiffEngine — shared differential-analysis engine for TRUE/FALSE response
 * comparisons.
 *
 * Fixes two false-positive/false-negative sources in raw response comparison:
 *
 *  1. A response that merely REFLECTS the injected payload differs from the
 *     other side by the payload length itself — strip the injected value
 *     (raw + URL-encoded form) before comparing sizes or content.
 *  2. Dynamic per-response content (CSRF tokens, nonces, timestamps, request
 *     ids) differs between ANY two requests to the same endpoint — mask it.
 *
 * All methods are pure string logic so they can be unit-tested without Burp.
 */
public final class DiffEngine {

    private DiffEngine() {}

    /** name[=:]value forms of fields that change on every request/response. */
    private static final Pattern DYNAMIC_FIELD = Pattern.compile(
        "(?i)((?:csrf[-_a-z]*|_?token|authenticity_token|xsrf[-_a-z]*|nonce|state|"
        + "ts|timestamp|request[_-]?id|session_state|viewstate)[\\w.\\-]*\\s*[=:]\\s*)"
        + "(\"[^\"]{6,}\"|[A-Za-z0-9+/=_\\-]{6,})");

    /** HTML form style: <input name='csrf_token' ... value='...'> */
    private static final Pattern DYNAMIC_HTML_FIELD = Pattern.compile(
        "(?i)((?:name|id)\\s*=\\s*[\"']?(?:csrf[-_a-z]*|_?token|authenticity_token|"
        + "xsrf[-_a-z]*|nonce|viewstate)[\\w.\\-]*[\"']?[^>]{0,80}?value\\s*=\\s*[\"']?)"
        + "([A-Za-z0-9+/=_\\-]{6,})");

    /** 13-digit epoch-milliseconds timestamps. */
    private static final Pattern EPOCH_MS = Pattern.compile("\\b1[3-9]\\d{11}\\b");

    /**
     * Normalize a response body for comparison: remove the injected value
     * (raw and URL-encoded) and mask dynamic per-response fields.
     */
    public static String normalize(String body, String injectedValue) {
        if (body == null) return "";
        String out = body;
        if (injectedValue != null && !injectedValue.isEmpty()) {
            out = out.replace(injectedValue, "");
            String enc = urlEncode(injectedValue);
            if (!enc.equals(injectedValue)) out = out.replace(enc, "");
        }
        out = DYNAMIC_HTML_FIELD.matcher(out).replaceAll("$1MASKED");
        out = DYNAMIC_FIELD.matcher(out).replaceAll("$1MASKED");
        out = EPOCH_MS.matcher(out).replaceAll("MASKED");
        return out;
    }

    /** Signals measured between a TRUE and a FALSE response. */
    public static final class Signals {
        public final boolean statusDiff;
        public final boolean sizeDiff;
        public final boolean pathDiff;
        public final boolean keywordDiff;

        Signals(boolean statusDiff, boolean sizeDiff, boolean pathDiff, boolean keywordDiff) {
            this.statusDiff = statusDiff;
            this.sizeDiff = sizeDiff;
            this.pathDiff = pathDiff;
            this.keywordDiff = keywordDiff;
        }

        public boolean any() { return statusDiff || sizeDiff || pathDiff || keywordDiff; }

        public String describe() {
            StringBuilder sb = new StringBuilder();
            if (statusDiff)  sb.append("status ");
            if (sizeDiff)    sb.append("size ");
            if (pathDiff)    sb.append("path ");
            if (keywordDiff) sb.append("keywords ");
            return sb.toString().trim();
        }
    }

    /**
     * Evaluate a TRUE/FALSE pair. Lengths and bodies must already be
     * normalized ({@link #normalize}); paths are extracted Location paths.
     */
    public static Signals evaluate(boolean statusDiff, int trueLen, int falseLen,
                                   String trueBody, String falseBody,
                                   String truePath, String falsePath) {
        boolean sizeDiff = isSignificantDiff(trueLen, falseLen);
        boolean pathDiff = !safeEquals(truePath, falsePath);
        boolean keywordDiff = keywordFlip(trueBody, falseBody);
        return new Signals(statusDiff, sizeDiff, pathDiff, keywordDiff);
    }

    /** Normalized-size difference above the 15% boolean threshold. */
    public static boolean isSignificantDiff(int a, int b) {
        return (Math.abs(a - b) / Math.max((a + b) / 2.0, 1)) > 0.15;
    }

    /**
     * Auth-keyword flip between a TRUE and a FALSE response: TRUE shows a
     * success keyword FALSE lacks, or FALSE shows a failure keyword TRUE
     * lacks. Deliberately asymmetric — kept identical to the historical
     * isContentDifferent semantics.
     */
    public static boolean keywordFlip(String trueBody, String falseBody) {
        if (trueBody == null || falseBody == null) return false;
        boolean tSuccess = containsAny(trueBody,  PayloadDatabase.AUTH_SUCCESS_KEYWORDS);
        boolean fSuccess = containsAny(falseBody, PayloadDatabase.AUTH_SUCCESS_KEYWORDS);
        boolean tFail    = containsAny(trueBody,  PayloadDatabase.AUTH_FAILURE_KEYWORDS);
        boolean fFail    = containsAny(falseBody, PayloadDatabase.AUTH_FAILURE_KEYWORDS);
        return (tSuccess && !fSuccess) || (!tFail && fFail);
    }

    public static boolean containsAny(String text, String[] keywords) {
        if (text == null) return false;
        String lower = text.toLowerCase();
        for (String kw : keywords)
            if (lower.contains(kw.toLowerCase())) return true;
        return false;
    }

    private static boolean safeEquals(String a, String b) {
        if (a == null && b == null) return true;
        if (a == null || b == null) return false;
        return a.equals(b);
    }

    private static String urlEncode(String s) {
        return java.net.URLEncoder.encode(s, java.nio.charset.StandardCharsets.UTF_8);
    }
}
