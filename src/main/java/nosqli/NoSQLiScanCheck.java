package nosqli;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;

import java.util.ArrayList;
import java.util.List;

import static burp.api.montoya.scanner.AuditResult.auditResult;
import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;

public class NoSQLiScanCheck implements ScanCheck {

    private final MontoyaApi api;
    private final FindingsLogger flog;

    private static final long   TIME_THRESHOLD_MS       = 2500;
    private static final int    TIME_CONFIRMATION_COUNT = 2;
    private static final double BOOLEAN_DIFF_THRESHOLD  = 0.15;

    public NoSQLiScanCheck(MontoyaApi api) {
        this.api  = api;
        this.flog = FindingsLogger.getInstance();
    }

    // ─── ACTIVE AUDIT ────────────────────────────────────────────

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRR, AuditInsertionPoint insertionPoint) {
        List<AuditIssue> issues = new ArrayList<>();

        String baselineBody   = baseRR.response() != null ? baseRR.response().bodyToString() : "";
        int    baselineLen    = baseRR.response() != null ? baseRR.response().body().length() : 0;
        int    baselineStatus = baseRR.response() != null ? baseRR.response().statusCode()   : 0;
        String baselinePath   = extractPath(baseRR.response() != null ? baseRR.response().headerValue("Location") : null);

        SmartBodyDetector.BodyType bodyType = SmartBodyDetector.detect(baseRR.request());

        flog.log("[NoSQLi] Scanning param=" + insertionPoint.name() +
                 " bodyType=" + bodyType + " url=" + baseRR.request().url());

        // Stage 1 — Error
        AuditIssue e = runErrorDetection(baseRR, insertionPoint, baselineBody, baselinePath);
        if (e != null) { issues.add(e); return auditResult(issues); }

        // Stage 2 — Boolean
        AuditIssue b = runBooleanDetection(baseRR, insertionPoint, baselineLen, baselineStatus,
                                            baselineBody, baselinePath, bodyType);
        if (b != null) { issues.add(b); return auditResult(issues); }

        // Stage 3 — Time
        AuditIssue t = runTimeBasedDetection(baseRR, insertionPoint);
        if (t != null) { issues.add(t); }

        return auditResult(issues);
    }

    // ─── PASSIVE AUDIT ───────────────────────────────────────────

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRR) {
        List<AuditIssue> issues = new ArrayList<>();
        if (baseRR.response() == null) return auditResult(issues);

        String body = baseRR.response().bodyToString();
        for (String sig : PayloadDatabase.MONGODB_ERROR_SIGNATURES) {
            if (body.contains(sig)) {
                flog.log("[PASSIVE] Error leakage found: " + sig + " in " + baseRR.request().url());
                issues.add(auditIssue(
                    "NoSQL Error Information Leakage",
                    "<p>Response leaks DB error: <b>" + sig + "</b></p>",
                    "<p>Suppress database errors on production.</p>",
                    baseRR.request().url(),
                    AuditIssueSeverity.LOW,
                    AuditIssueConfidence.FIRM,
                    null, null, null,
                    baseRR
                ));
                break;
            }
        }
        return auditResult(issues);
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
        return newIssue.name().equals(existingIssue.name())
            ? ConsolidationAction.KEEP_EXISTING
            : ConsolidationAction.KEEP_BOTH;
    }

    // ─── STAGE 1: ERROR ──────────────────────────────────────────

    private AuditIssue runErrorDetection(HttpRequestResponse baseRR,
            AuditInsertionPoint pt, String baselineBody, String baselinePath) {

        for (String c : PayloadDatabase.ERROR_DETECTION_CHARS) {
            HttpRequest req = pt.buildHttpRequestWithPayload(
                burp.api.montoya.core.ByteArray.byteArray(c.getBytes()));
            HttpRequestResponse rr = api.http().sendRequest(req.withService(baseRR.httpService()));
            if (rr.response() == null) continue;

            String body = rr.response().bodyToString();

            for (String sig : PayloadDatabase.MONGODB_ERROR_SIGNATURES) {
                if (body.toLowerCase().contains(sig.toLowerCase()) &&
                    !baselineBody.toLowerCase().contains(sig.toLowerCase())) {

                    flog.log("[NoSQLi] ✅ ERROR-BASED: param=" + pt.name() + " payload=" + c + " sig=" + sig);

                    // Report to FindingsLogger with full request
                    flog.reportFinding(new FindingsLogger.Finding(
                        "ERROR-BASED", "HIGH",
                        baseRR.request().url(),
                        pt.name(), c,
                        req.withService(baseRR.httpService()).toString(),
                        "DB error signature found: " + sig,
                        null
                    ));

                    return auditIssue(
                        "NoSQL Injection — Error Based",
                        buildErrorDetail(c, sig, pt.name(), req.withService(baseRR.httpService()).toString()),
                        buildErrorRem(),
                        baseRR.request().url(),
                        AuditIssueSeverity.HIGH, AuditIssueConfidence.CERTAIN,
                        null, null, null, baseRR, rr);
                }
            }
            for (String sig : PayloadDatabase.COUCHDB_ERROR_SIGNATURES) {
                if (body.toLowerCase().contains(sig.toLowerCase()) &&
                    !baselineBody.toLowerCase().contains(sig.toLowerCase())) {

                    flog.log("[NoSQLi] ✅ COUCHDB ERROR: param=" + pt.name() + " sig=" + sig);

                    flog.reportFinding(new FindingsLogger.Finding(
                        "COUCHDB-ERROR", "HIGH",
                        baseRR.request().url(),
                        pt.name(), c,
                        req.withService(baseRR.httpService()).toString(),
                        "CouchDB error signature found: " + sig,
                        null
                    ));

                    return auditIssue(
                        "NoSQL Injection — CouchDB Error Based",
                        buildErrorDetail(c, sig, pt.name(), req.withService(baseRR.httpService()).toString()),
                        buildErrorRem(),
                        baseRR.request().url(),
                        AuditIssueSeverity.HIGH, AuditIssueConfidence.CERTAIN,
                        null, null, null, baseRR, rr);
                }
            }
        }
        return null;
    }

    // ─── STAGE 2: BOOLEAN ────────────────────────────────────────

    private AuditIssue runBooleanDetection(HttpRequestResponse baseRR,
            AuditInsertionPoint pt, int baselineLen, int baselineStatus,
            String baselineBody, String baselinePath,
            SmartBodyDetector.BodyType bodyType) {

        List<PayloadDatabase.BooleanPair> pairs =
            (bodyType == SmartBodyDetector.BodyType.JSON ||
             bodyType == SmartBodyDetector.BodyType.GRAPHQL)
            ? PayloadDatabase.getJsonBooleanPairs()
            : PayloadDatabase.getUrlEncodedBooleanPairs(pt.name());

        int confirmed = 0;
        String bestDesc = null;
        String bestPayload = null;
        HttpRequestResponse trueEv = null, falseEv = null;
        HttpRequest bestReq = null;

        for (PayloadDatabase.BooleanPair pair : pairs) {
            HttpRequest trueReq = pt.buildHttpRequestWithPayload(
                burp.api.montoya.core.ByteArray.byteArray(pair.truePayload.getBytes()));
            HttpRequest falseReq = pt.buildHttpRequestWithPayload(
                burp.api.montoya.core.ByteArray.byteArray(pair.falsePayload.getBytes()));

            HttpRequestResponse trueRR  = api.http().sendRequest(trueReq.withService(baseRR.httpService()));
            HttpRequestResponse falseRR = api.http().sendRequest(falseReq.withService(baseRR.httpService()));

            if (trueRR.response() == null || falseRR.response() == null) continue;

            int tLen = trueRR.response().body().length();
            int fLen = falseRR.response().body().length();

            // ── Content change detection ──
            boolean statusDiff  = trueRR.response().statusCode() != falseRR.response().statusCode();
            boolean sizeDiff    = isSignificantDiff(tLen, fLen);
            boolean trueCloser  = Math.abs(tLen - baselineLen) <= Math.abs(fLen - baselineLen);

            // ── URL path change detection (auth redirect) ──
            String truePath  = extractPath(trueRR.response().headerValue("Location"));
            String falsePath = extractPath(falseRR.response().headerValue("Location"));
            boolean pathDiff = !safeEquals(truePath, falsePath) || !safeEquals(truePath, baselinePath);

            // ── Body content change ──
            boolean bodyChanged = isContentDifferent(
                trueRR.response().bodyToString(),
                falseRR.response().bodyToString()
            );

            if ((statusDiff || sizeDiff || pathDiff || bodyChanged) && trueCloser) {
                confirmed++;
                if (bestDesc == null) {
                    bestDesc    = pair.description;
                    bestPayload = pair.truePayload;
                    trueEv      = trueRR;
                    falseEv     = falseRR;
                    bestReq     = trueReq.withService(baseRR.httpService());
                }
            }
            if (confirmed >= 2) break;
        }

        if (confirmed < 2) return null;

        String evidence = buildBooleanEvidence(trueEv, falseEv, baselineLen, baselinePath);

        flog.log("[NoSQLi] ✅ BOOLEAN-BASED: param=" + pt.name() + " (" + confirmed + " pairs)");
        flog.reportFinding(new FindingsLogger.Finding(
            "BLIND-BOOLEAN", "HIGH",
            baseRR.request().url(),
            pt.name(), bestPayload,
            bestReq != null ? bestReq.toString() : "",
            evidence,
            extractPath(trueEv != null && trueEv.response() != null
                ? trueEv.response().headerValue("Location") : null)
        ));

        return auditIssue(
            "NoSQL Injection — Blind Boolean Based",
            buildBooleanDetail(bestDesc, pt.name(), bestPayload,
                bestReq != null ? bestReq.toString() : "", evidence),
            buildBooleanRem(),
            baseRR.request().url(),
            AuditIssueSeverity.HIGH, AuditIssueConfidence.FIRM,
            null, null, null, baseRR, trueEv, falseEv);
    }

    // ─── STAGE 3: TIME-BASED ─────────────────────────────────────

    private AuditIssue runTimeBasedDetection(HttpRequestResponse baseRR, AuditInsertionPoint pt) {
        long baseline = measureBaseline(baseRR.request(), baseRR.httpService(), 3);

        for (PayloadDatabase.TimedPayload tp : PayloadDatabase.getTimeBasedPayloads()) {
            HttpRequest req = pt.buildHttpRequestWithPayload(
                burp.api.montoya.core.ByteArray.byteArray(tp.payload.getBytes()))
                .withService(baseRR.httpService());

            long s = System.currentTimeMillis();
            HttpRequestResponse rr = api.http().sendRequest(req);
            long elapsed = System.currentTimeMillis() - s;

            if (elapsed < TIME_THRESHOLD_MS || elapsed < baseline * 2.5) continue;

            int conf = 0;
            for (int i = 0; i < TIME_CONFIRMATION_COUNT; i++) {
                long cs = System.currentTimeMillis();
                api.http().sendRequest(req);
                long ce = System.currentTimeMillis() - cs;
                if (ce >= TIME_THRESHOLD_MS && ce >= baseline * 2.5) conf++;
            }

            if (conf >= 1) {
                flog.log("[NoSQLi] ✅ TIME-BASED: param=" + pt.name() +
                    " elapsed=" + elapsed + "ms baseline=" + baseline + "ms");

                flog.reportFinding(new FindingsLogger.Finding(
                    "TIME-BASED", "HIGH",
                    baseRR.request().url(),
                    pt.name(), tp.payload,
                    req.toString(),
                    "Baseline=" + baseline + "ms | Injected=" + elapsed + "ms (×" +
                        String.format("%.1f", (double)elapsed / Math.max(baseline,1)) + ")",
                    null
                ));

                return auditIssue(
                    "NoSQL Injection — Time-Based Blind (SSJS)",
                    buildTimeDetail(tp.description, elapsed, baseline, pt.name(), req.toString()),
                    buildTimeRem(),
                    baseRR.request().url(),
                    AuditIssueSeverity.HIGH, AuditIssueConfidence.FIRM,
                    null, null, null, baseRR, rr);
            }
        }
        return null;
    }

    // ─── HELPERS ─────────────────────────────────────────────────

    private long measureBaseline(HttpRequest req, HttpService svc, int n) {
        long total = 0;
        for (int i = 0; i < n; i++) {
            long s = System.currentTimeMillis();
            api.http().sendRequest(req.withService(svc));
            total += System.currentTimeMillis() - s;
        }
        return total / n;
    }

    private boolean isSignificantDiff(int a, int b) {
        return (Math.abs(a - b) / Math.max((a + b) / 2.0, 1)) > BOOLEAN_DIFF_THRESHOLD;
    }

    /**
     * هل في فرق مهم في محتوى الصفحة؟
     * بيشوف كلمات دالة على Auth success/failure
     */
    private boolean isContentDifferent(String trueBody, String falseBody) {
        if (trueBody == null || falseBody == null) return false;

        // شوف لو الـ true body فيه keyword نجاح والـ false مفيهوش
        boolean trueHasSuccess  = containsAny(trueBody,  PayloadDatabase.AUTH_SUCCESS_KEYWORDS);
        boolean falseHasSuccess = containsAny(falseBody, PayloadDatabase.AUTH_SUCCESS_KEYWORDS);
        boolean trueHasFail     = containsAny(trueBody,  PayloadDatabase.AUTH_FAILURE_KEYWORDS);
        boolean falseHasFail    = containsAny(falseBody, PayloadDatabase.AUTH_FAILURE_KEYWORDS);

        return (trueHasSuccess && !falseHasSuccess) ||
               (!trueHasFail   && falseHasFail);
    }

    private boolean containsAny(String text, String[] keywords) {
        if (text == null) return false;
        String lower = text.toLowerCase();
        for (String kw : keywords)
            if (lower.contains(kw.toLowerCase())) return true;
        return false;
    }

    /** استخرج الـ path من Location header */
    private String extractPath(String locationHeader) {
        if (locationHeader == null || locationHeader.isEmpty()) return "";
        try {
            java.net.URI uri = new java.net.URI(locationHeader);
            return uri.getPath();
        } catch (Exception e) {
            return locationHeader;
        }
    }

    private boolean safeEquals(String a, String b) {
        if (a == null && b == null) return true;
        if (a == null || b == null) return false;
        return a.equals(b);
    }

    // ─── DETAIL BUILDERS ─────────────────────────────────────────

    private String buildErrorDetail(String p, String sig, String param, String fullRequest) {
        return "<p><b>Parameter:</b> " + esc(param) + "</p>" +
               "<p><b>Payload:</b> <code>" + esc(p) + "</code></p>" +
               "<p><b>DB Error signature found (not in baseline):</b> <b>" + esc(sig) + "</b></p>" +
               "<p>Input is injected directly into a NoSQL query. " +
               "Attacker can bypass auth, extract data, or run server-side JS.</p>" +
               "<p><b>CVSS 9.8 Critical</b></p>" +
               "<hr><p><b>Full HTTP Request with Payload:</b></p>" +
               "<pre>" + esc(truncate(fullRequest, 2000)) + "</pre>";
    }

    private String buildBooleanDetail(String desc, String param, String payload,
                                       String fullRequest, String evidence) {
        return "<p><b>Parameter:</b> " + esc(param) + "</p>" +
               "<p><b>Method:</b> " + esc(desc) + "</p>" +
               "<p><b>Payload (TRUE condition):</b> <code>" + esc(payload) + "</code></p>" +
               "<p><b>Evidence:</b> " + esc(evidence) + "</p>" +
               "<p>2+ independent payload pairs returned consistent differential responses. " +
               "Detection based on: response size diff &gt;15%, status code change, " +
               "URL path change (redirect), OR body content change (auth keywords).</p>" +
               "<p><b>CVSS 8.8 High</b></p>" +
               "<hr><p><b>Full HTTP Request with Payload:</b></p>" +
               "<pre>" + esc(truncate(fullRequest, 2000)) + "</pre>";
    }

    private String buildTimeDetail(String desc, long elapsed, long baseline,
                                    String param, String fullRequest) {
        return "<p><b>Parameter:</b> " + esc(param) + "</p>" +
               "<p><b>Payload:</b> " + esc(desc) + "</p>" +
               "<p>Baseline: " + baseline + "ms | Injected: " + elapsed + "ms (×" +
               String.format("%.1f", (double)elapsed / Math.max(baseline,1)) + "). " +
               "JavaScript executed via MongoDB <code>$where</code>. Confirmed twice.</p>" +
               "<p><b>CVSS 8.8 High</b></p>" +
               "<hr><p><b>Full HTTP Request with Payload:</b></p>" +
               "<pre>" + esc(truncate(fullRequest, 2000)) + "</pre>";
    }

    private String buildBooleanEvidence(HttpRequestResponse trueRR, HttpRequestResponse falseRR,
                                         int baselineLen, String baselinePath) {
        if (trueRR == null || falseRR == null) return "N/A";
        int tLen = trueRR.response() != null ? trueRR.response().body().length() : 0;
        int fLen = falseRR.response() != null ? falseRR.response().body().length() : 0;
        int tStatus = trueRR.response() != null ? trueRR.response().statusCode() : 0;
        int fStatus = falseRR.response() != null ? falseRR.response().statusCode() : 0;
        String tPath = extractPath(trueRR.response() != null ? trueRR.response().headerValue("Location") : null);
        String fPath = extractPath(falseRR.response() != null ? falseRR.response().headerValue("Location") : null);

        return String.format(
            "TRUE: %db/%d%s | FALSE: %db/%d%s | baseline: %db%s",
            tLen, tStatus, tPath.isEmpty() ? "" : " → " + tPath,
            fLen, fStatus, fPath.isEmpty() ? "" : " → " + fPath,
            baselineLen,
            baselinePath.isEmpty() ? "" : " → " + baselinePath
        );
    }

    private String buildErrorRem() {
        return "<ul><li>Never concatenate user input into NoSQL queries.</li>" +
               "<li>Validate and cast input types strictly.</li>" +
               "<li>Disable SSJS: <code>security.javascriptEnabled: false</code></li>" +
               "<li>Enable Mongoose <code>sanitizeFilter: true</code></li>" +
               "<li>Allowlist MongoDB operators.</li></ul>";
    }

    private String buildBooleanRem() { return buildErrorRem(); }

    private String buildTimeRem() {
        return buildErrorRem() +
               "<p>Also: reject any input containing <code>$where</code> or <code>$function</code>.</p>";
    }

    private String esc(String s) {
        if (s == null) return "";
        return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;");
    }

    private String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "\n...[truncated]" : s;
    }
}
