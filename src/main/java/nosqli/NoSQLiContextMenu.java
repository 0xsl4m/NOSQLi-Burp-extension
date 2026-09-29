package nosqli;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
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
 * التحسينات:
 *  - كل finding بيتسجّل مع الـ full HTTP request body/URL كامل
 *  - Auth detection بتعتمد على content change + URL path redirect مش status code بس
 *  - كل اللوج بيروح للـ FindingsLogger المشترك (بيظهر في التاب)
 */
public class NoSQLiContextMenu implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final FindingsLogger flog;
    private final ExecutorService executor;

    private static final long REQUEST_DELAY_MS = 150;

    public NoSQLiContextMenu(MontoyaApi api) {
        this.api      = api;
        this.flog     = FindingsLogger.getInstance();
        this.executor = Executors.newFixedThreadPool(4);
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> items = new ArrayList<>();

        List<HttpRequestResponse> selectedRRs = event.messageEditorRequestResponse()
            .map(msgEditor -> List.of(msgEditor.requestResponse()))
            .orElseGet(() -> event.selectedRequestResponses());

        if (selectedRRs == null || selectedRRs.isEmpty()) return items;
        HttpRequestResponse selectedRR = selectedRRs.get(0);

        JMenu mainMenu = new JMenu("🔍 NoSQLi Hunter");

        SmartBodyDetector.BodyType bodyType = SmartBodyDetector.detect(selectedRR.request());
        JMenuItem bodyTypeInfo = new JMenuItem("📋 Body Type: " + bodyType.name());
        bodyTypeInfo.setEnabled(false);
        mainMenu.add(bodyTypeInfo);
        mainMenu.addSeparator();

        // Auth Bypass
        JMenu authMenu = new JMenu("🔓 Authentication Bypass");
        JMenuItem authUrl = new JMenuItem("URL-Encoded ($ne, $gt, $regex, $nin, $in, $exists)");
        authUrl.addActionListener(e -> executor.submit(() -> runAuthBypass(selectedRR, SmartBodyDetector.BodyType.URL_ENCODED)));
        JMenuItem authJson = new JMenuItem("JSON Operator Bypass");
        authJson.addActionListener(e -> executor.submit(() -> runAuthBypass(selectedRR, SmartBodyDetector.BodyType.JSON)));
        authMenu.add(authUrl);
        authMenu.add(authJson);
        mainMenu.add(authMenu);

        // Operator Scan
        JMenuItem operatorScan = new JMenuItem("⚙️ Operator Injection Scan");
        operatorScan.addActionListener(e -> executor.submit(() -> runOperatorScan(selectedRR)));
        mainMenu.add(operatorScan);

        // JS Injection
        JMenuItem jsScan = new JMenuItem("💻 JavaScript Injection ($where)");
        jsScan.addActionListener(e -> executor.submit(() -> runJsScan(selectedRR)));
        mainMenu.add(jsScan);

        // Time-Based
        JMenuItem timeScan = new JMenuItem("⏱️ Time-Based Blind (3s delay)");
        timeScan.addActionListener(e -> executor.submit(() -> runTimeScan(selectedRR)));
        mainMenu.add(timeScan);

        // Content-Type Confusion
        JMenuItem ctConfusion = new JMenuItem("🔄 Content-Type Confusion (→ JSON ops)");
        ctConfusion.addActionListener(e -> executor.submit(() -> runContentTypeConfusion(selectedRR)));
        mainMenu.add(ctConfusion);

        // Aggregation Pipeline
        JMenuItem aggScan = new JMenuItem("🗄️ Aggregation Pipeline Injection");
        aggScan.addActionListener(e -> executor.submit(() -> runAggregationScan(selectedRR)));
        mainMenu.add(aggScan);

        // Mongoose CVE
        JMenuItem mongoose = new JMenuItem("🦦 Mongoose CVE-2025-23061 ($where via $or)");
        mongoose.addActionListener(e -> executor.submit(() -> runMongooseBypass(selectedRR)));
        mainMenu.add(mongoose);

        mainMenu.addSeparator();

        // Full Scan
        JMenuItem fullScan = new JMenuItem("🚀 Full NoSQL Injection Scan (All Techniques)");
        fullScan.addActionListener(e -> executor.submit(() -> runFullScan(selectedRR)));
        mainMenu.add(fullScan);

        items.add(mainMenu);
        return items;
    }

    // ─────────────────────────────────────────────────────────────
    // AUTH BYPASS
    // ─────────────────────────────────────────────────────────────

    private void runAuthBypass(HttpRequestResponse baseRR, SmartBodyDetector.BodyType forceType) {
        flog.log("\n[AUTH BYPASS] Starting → " + baseRR.request().url());

        List<SmartBodyDetector.ParsedParam> params = SmartBodyDetector.extractParams(baseRR.request());
        if (params.isEmpty()) {
            flog.log("[AUTH BYPASS] No parameters found.");
            return;
        }

        String userField = guessField(params, "user","username","email","login","name","uname","uid");
        String passField = guessField(params, "pass","password","pwd","secret","passwd","token","key");
        if (userField == null) userField = params.get(0).name;
        if (passField == null && params.size() > 1) passField = params.get(1).name;
        if (passField == null) passField = "password";

        flog.log("[AUTH BYPASS] Targeting fields: user=" + userField + ", pass=" + passField);

        List<String> payloads = forceType == SmartBodyDetector.BodyType.JSON
            ? PayloadDatabase.getAuthBypassJson(userField, passField)
            : PayloadDatabase.getAuthBypassUrlEncoded(userField, passField);

        // Baseline
        HttpRequestResponse baseline = api.http().sendRequest(baseRR.request());
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

        SmartBodyDetector.ParsedParam passParam = null;
        for (SmartBodyDetector.ParsedParam p : params) {
            if (p.name.equals(passField)) { passParam = p; break; }
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

            baseline = api.http().sendRequest(
                SmartBodyDetector.applyPayload(baseRR.request(), passParam, wrongPw));
            baselineStatus = baseline.response() != null ? baseline.response().statusCode() : 0;
            baselineBody   = baseline.response() != null ? baseline.response().bodyToString() : "";
            baselinePath   = extractPath(baseline.response() != null
                ? baseline.response().headerValue("Location") : null);
            flog.log("[AUTH BYPASS] Failure baseline: status=" + baselineStatus);
        }

        boolean errorLeadReported = false;

        for (String payload : payloads) {
            throttle();
            HttpRequest modified = forceType == SmartBodyDetector.BodyType.JSON
                ? baseRR.request().withBody(payload).withUpdatedHeader("Content-Type","application/json")
                : baseRR.request().withBody(payload);

            HttpRequestResponse rr = api.http().sendRequest(modified);
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

            // URL path change: redirect to dashboard/profile = login success
            boolean pathChanged     = !safeEquals(pathAfter, baselinePath)
                                   && isAuthSuccessPath(pathAfter);

            // A real bypass always answers with a normal status (200/302).
            // 4xx/5xx are errors, never bypasses: an operator payload that
            // crashes the query (e.g. it matched several records) proves the
            // operator reached the query, but nobody got authenticated.
            boolean bypass = status < 400 &&
                (statusBypass || successAppeared || failureGone || pathChanged);

            // Error-based lead: a healthy target that 4xx/5xxes on operator
            // payloads is telling us the operators reached the query. That is
            // a thread to pull, not a bypass — report it ONCE per scan as a
            // MEDIUM finding with the visible error text as evidence.
            boolean errorLead = !bypass && baselineStatus < 400 && status >= 400 &&
                (status >= 500 || containsAny(body, PayloadDatabase.MONGODB_ERROR_SIGNATURES_STRICT));

            if (errorLead && !errorLeadReported) {
                errorLeadReported = true;
                flog.log("[AUTH BYPASS] ⚠️  Error " + status + " on operator payload — operators likely " +
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
            } else if (!bypass && status >= 500) {
                flog.log("[AUTH BYPASS] ⚠️  Server error (" + status + ") on operator payload — " +
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

            flog.log("[AUTH BYPASS] " + (bypass ? "✅ BYPASS!" : "❌ No bypass") +
                " | " + evidence + " | payload=" + truncate(payload, 60));

            if (bypass) {
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
                showNotification("NoSQLi Auth Bypass FOUND", baseRR.request().url(), payload, evidence);
            }
        }
        flog.log("[AUTH BYPASS] Completed.");
    }

    // ─────────────────────────────────────────────────────────────
    // OPERATOR SCAN
    // ─────────────────────────────────────────────────────────────

    private void runOperatorScan(HttpRequestResponse baseRR) {
        flog.log("\n[OPERATOR SCAN] Starting → " + baseRR.request().url());

        List<SmartBodyDetector.ParsedParam> params = SmartBodyDetector.extractParams(baseRR.request());
        if (params.isEmpty()) {
            flog.log("[OPERATOR SCAN] No injectable parameters found.");
            return;
        }

        HttpRequestResponse baseline = api.http().sendRequest(baseRR.request());
        int    baselineLen    = baseline.response() != null ? baseline.response().body().length() : 0;
        int    baselineStatus = baseline.response() != null ? baseline.response().statusCode() : 0;
        String baselineBody   = baseline.response() != null ? baseline.response().bodyToString() : "";
        String baselinePath   = extractPath(baseline.response() != null
            ? baseline.response().headerValue("Location") : null);

        for (SmartBodyDetector.ParsedParam param : params) {
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
                throttle();
                HttpRequest trueReq  = SmartBodyDetector.applyOperatorPayload(baseRR.request(), param, pair.truePayload);
                HttpRequest falseReq = SmartBodyDetector.applyOperatorPayload(baseRR.request(), param, pair.falsePayload);

                HttpRequestResponse trueRR  = api.http().sendRequest(trueReq);
                HttpRequestResponse falseRR = api.http().sendRequest(falseReq);
                if (trueRR.response() == null || falseRR.response() == null) continue;

                int trueLen  = trueRR.response().body().length();
                int falseLen = falseRR.response().body().length();
                int trueStatus = trueRR.response().statusCode();
                int falseStatus = falseRR.response().statusCode();

                String truePath  = extractPath(trueRR.response().headerValue("Location"));
                String falsePath = extractPath(falseRR.response().headerValue("Location"));

                boolean sizeDiff   = isSignificantDiff(trueLen, falseLen);
                boolean statusDiff = trueStatus != falseStatus;
                boolean pathDiff   = !safeEquals(truePath, falsePath);
                boolean bodyDiff   = isContentDifferent(
                    trueRR.response().bodyToString(), falseRR.response().bodyToString());

                String evidence = String.format(
                    "TRUE: %db/%d%s | FALSE: %db/%d%s",
                    trueLen, trueStatus, truePath.isEmpty() ? "" : " → " + truePath,
                    falseLen, falseStatus, falsePath.isEmpty() ? "" : " → " + falsePath
                );

                boolean diff = sizeDiff || statusDiff || pathDiff || bodyDiff;

                flog.log("[OPERATOR SCAN]   " + param.name + " | " + pair.description +
                    " | " + evidence + " | " + (diff ? "⚠️ DIFFERENT" : "Same"));

                if (diff) {
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
                flog.log("[OPERATOR SCAN] ✅ CONFIRMED injectable: " + param.name);
                flog.reportFinding(new FindingsLogger.Finding(
                    "OPERATOR-INJECTION", "HIGH",
                    baseRR.request().url(),
                    param.name,
                    bestPayload,
                    bestReq != null ? bestReq.toString() : "",
                    bestEvidence + " | " + hits + " pairs confirmed",
                    null
                ));
                showNotification("NoSQLi Operator Injection in: " + param.name,
                    baseRR.request().url(), bestPayload, bestEvidence);
            }
        }
        flog.log("[OPERATOR SCAN] Completed.");
    }

    // ─────────────────────────────────────────────────────────────
    // JS INJECTION
    // ─────────────────────────────────────────────────────────────

    private void runJsScan(HttpRequestResponse baseRR) {
        flog.log("\n[JS INJECTION] Starting → " + baseRR.request().url());

        List<SmartBodyDetector.ParsedParam> params = SmartBodyDetector.extractParams(baseRR.request());
        HttpRequestResponse baseline = api.http().sendRequest(baseRR.request());
        String baselineBody = baseline.response() != null ? baseline.response().bodyToString() : "";
        String baselinePath = extractPath(baseline.response() != null
            ? baseline.response().headerValue("Location") : null);
        int baselineLen = baselineBody.length();
        List<PayloadDatabase.JsPair> jsPairs = PayloadDatabase.getJsInjectionPairs();

        for (SmartBodyDetector.ParsedParam param : params) {
            flog.log("[JS INJECTION] Testing parameter: " + param.name);

            for (PayloadDatabase.JsPair pair : jsPairs) {
                throttle();
                HttpRequest trueReq  = SmartBodyDetector.applyPayload(baseRR.request(), param, pair.truePayload);
                HttpRequest falseReq = SmartBodyDetector.applyPayload(baseRR.request(), param, pair.falsePayload);

                HttpRequestResponse trueRR  = api.http().sendRequest(trueReq);
                HttpRequestResponse falseRR = api.http().sendRequest(falseReq);
                if (trueRR.response() == null || falseRR.response() == null) continue;

                int trueLen  = trueRR.response().body().length();
                int falseLen = falseRR.response().body().length();
                String trueBody = trueRR.response().bodyToString();
                String truePath = extractPath(trueRR.response().headerValue("Location"));

                boolean hasError  = containsAny(trueBody, PayloadDatabase.MONGODB_ERROR_SIGNATURES_STRICT);
                boolean sizeDiff  = isSignificantDiff(trueLen, falseLen);
                boolean statusDiff = trueRR.response().statusCode() != falseRR.response().statusCode();
                boolean pathDiff  = !safeEquals(truePath, baselinePath);
                boolean bodyDiff  = isContentDifferent(trueBody, falseRR.response().bodyToString());

                boolean found = sizeDiff || statusDiff || pathDiff || bodyDiff || hasError;

                String evidence = String.format(
                    "true=%db false=%db status=%d/%d path=%s%s",
                    trueLen, falseLen,
                    trueRR.response().statusCode(),
                    falseRR.response().statusCode(),
                    truePath.isEmpty() ? "none" : truePath,
                    hasError ? " [DB ERROR]" : ""
                );

                flog.log("[JS INJECTION] " + (found ? "⚠️  " : "   ") +
                    pair.description + " | param=" + param.name + " | " + evidence);

                if (found) {
                    flog.reportFinding(new FindingsLogger.Finding(
                        "JS-INJECTION", "HIGH",
                        baseRR.request().url(),
                        param.name,
                        pair.truePayload,
                        trueReq.toString(),   // ← full request
                        evidence,
                        truePath
                    ));
                    api.siteMap().add(trueRR);
                }
            }
        }
        flog.log("[JS INJECTION] Completed.");
    }

    // ─────────────────────────────────────────────────────────────
    // TIME-BASED
    // ─────────────────────────────────────────────────────────────

    private void runTimeScan(HttpRequestResponse baseRR) {
        flog.log("\n[TIME-BASED] Starting → " + baseRR.request().url());

        long baselineTime = 0;
        for (int i = 0; i < 3; i++) {
            long s = System.currentTimeMillis();
            api.http().sendRequest(baseRR.request());
            baselineTime += System.currentTimeMillis() - s;
        }
        baselineTime /= 3;
        flog.log("[TIME-BASED] Baseline avg: " + baselineTime + "ms");

        List<SmartBodyDetector.ParsedParam> params = SmartBodyDetector.extractParams(baseRR.request());

        for (SmartBodyDetector.ParsedParam param : params) {
            flog.log("[TIME-BASED] Testing: " + param.name);

            for (PayloadDatabase.TimedPayload tp : PayloadDatabase.getTimeBasedPayloads()) {
                throttle();
                HttpRequest injected = SmartBodyDetector.applyPayload(baseRR.request(), param, tp.payload);

                long s = System.currentTimeMillis();
                HttpRequestResponse rr = api.http().sendRequest(injected);
                long elapsed = System.currentTimeMillis() - s;

                boolean delayed = elapsed >= 2500 && elapsed >= baselineTime * 2.0;

                flog.log("[TIME-BASED]   " + param.name + " | " + tp.description +
                    " | elapsed=" + elapsed + "ms baseline=" + baselineTime + "ms | " +
                    (delayed ? "⚠️  DELAYED!" : "Normal"));

                if (delayed) {
                    long cs = System.currentTimeMillis();
                    api.http().sendRequest(injected);
                    long confirmElapsed = System.currentTimeMillis() - cs;

                    if (confirmElapsed >= 2500) {
                        String evidence = "Baseline=" + baselineTime + "ms | 1st=" + elapsed +
                            "ms | 2nd=" + confirmElapsed + "ms";
                        flog.log("[TIME-BASED] ✅ CONFIRMED: " + param.name);

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
                        showNotification("NoSQLi Time-Based CONFIRMED: " + param.name,
                            baseRR.request().url(), tp.payload, evidence);
                    }
                }
            }
        }
        flog.log("[TIME-BASED] Completed.");
    }

    // ─────────────────────────────────────────────────────────────
    // CONTENT-TYPE CONFUSION
    // ─────────────────────────────────────────────────────────────

    private void runContentTypeConfusion(HttpRequestResponse baseRR) {
        flog.log("\n[CT CONFUSION] Starting → " + baseRR.request().url());

        List<SmartBodyDetector.ParsedParam> params = SmartBodyDetector.extractParams(baseRR.request());
        if (params.isEmpty()) { flog.log("[CT CONFUSION] No params."); return; }

        HttpRequestResponse baseline = api.http().sendRequest(baseRR.request());
        int    baselineStatus = baseline.response() != null ? baseline.response().statusCode() : 0;
        int    baselineLen    = baseline.response() != null ? baseline.response().body().length() : 0;
        String baselinePath   = extractPath(baseline.response() != null
            ? baseline.response().headerValue("Location") : null);
        String baselineBody   = baseline.response() != null ? baseline.response().bodyToString() : "";

        for (SmartBodyDetector.ParsedParam param : params) {
            for (String jsonPayload : PayloadDatabase.getContentTypeConfusionPayloads(param.name)) {
                throttle();
                HttpRequest confused = baseRR.request()
                    .withBody(jsonPayload)
                    .withUpdatedHeader("Content-Type","application/json");

                HttpRequestResponse rr = api.http().sendRequest(confused);
                if (rr.response() == null) continue;

                int    status   = rr.response().statusCode();
                int    len      = rr.response().body().length();
                String body     = rr.response().bodyToString();
                String path     = extractPath(rr.response().headerValue("Location"));

                boolean hasError    = containsAny(body, PayloadDatabase.MONGODB_ERROR_SIGNATURES_STRICT);
                boolean statusDiff  = status != baselineStatus;
                boolean sizeDiff    = isSignificantDiff(len, baselineLen);
                boolean pathDiff    = !safeEquals(path, baselinePath) && isAuthSuccessPath(path);
                boolean bodyDiff    = isContentDifferent(body, baselineBody);

                boolean interesting = hasError || statusDiff || sizeDiff || pathDiff || bodyDiff;

                String evidence = String.format(
                    "status=%d(was %d) len=%d(was %d) path=%s%s",
                    status, baselineStatus, len, baselineLen,
                    path.isEmpty() ? "none" : path,
                    hasError ? " [DB ERROR]" : ""
                );

                flog.log("[CT CONFUSION]   " + param.name + " | " +
                    truncate(jsonPayload, 50) + " | " + evidence +
                    (interesting ? " ⚠️  INTERESTING!" : ""));

                if (interesting) {
                    flog.reportFinding(new FindingsLogger.Finding(
                        "CT-CONFUSION", "HIGH",
                        baseRR.request().url(),
                        param.name,
                        jsonPayload,
                        confused.toString(),   // ← full request
                        evidence,
                        path
                    ));
                    api.siteMap().add(rr);
                }
            }
        }
        flog.log("[CT CONFUSION] Completed.");
    }

    // ─────────────────────────────────────────────────────────────
    // AGGREGATION PIPELINE
    // ─────────────────────────────────────────────────────────────

    private void runAggregationScan(HttpRequestResponse baseRR) {
        flog.log("\n[AGGREGATION] Starting → " + baseRR.request().url());

        HttpRequestResponse baseline = api.http().sendRequest(baseRR.request());
        int baselineLen = baseline.response() != null ? baseline.response().body().length() : 0;

        for (String payload : PayloadDatabase.getAggregationPayloads()) {
            throttle();
            HttpRequest modified = baseRR.request()
                .withBody(payload)
                .withUpdatedHeader("Content-Type","application/json");

            HttpRequestResponse rr = api.http().sendRequest(modified);
            if (rr.response() == null) continue;

            int    len      = rr.response().body().length();
            int    status   = rr.response().statusCode();
            boolean bigResp = len > baselineLen * 1.5;
            boolean hasError = containsAny(rr.response().bodyToString(), PayloadDatabase.MONGODB_ERROR_SIGNATURES_STRICT);

            String evidence = String.format("status=%d len=%d (baseline=%d) %s%s",
                status, len, baselineLen,
                bigResp ? "[LARGER RESPONSE]" : "",
                hasError ? "[DB ERROR]" : "");

            flog.log("[AGGREGATION]   " + truncate(payload, 60) + " | " + evidence);

            if (bigResp || hasError) {
                flog.reportFinding(new FindingsLogger.Finding(
                    "AGGREGATION", "HIGH",
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
        flog.log("[AGGREGATION] Completed.");
    }

    // ─────────────────────────────────────────────────────────────
    // MONGOOSE CVE-2025-23061
    // ─────────────────────────────────────────────────────────────

    private void runMongooseBypass(HttpRequestResponse baseRR) {
        flog.log("\n[MONGOOSE CVE] Starting → " + baseRR.request().url());

        HttpRequestResponse baseline = api.http().sendRequest(baseRR.request());
        int    baselineStatus = baseline.response() != null ? baseline.response().statusCode() : 0;
        String baselineBody   = baseline.response() != null ? baseline.response().bodyToString() : "";
        String baselinePath   = extractPath(baseline.response() != null
            ? baseline.response().headerValue("Location") : null);

        boolean errorLeadReported = false;

        for (String payload : PayloadDatabase.getMongooseBypassPayloads()) {
            throttle();
            HttpRequest modified = baseRR.request()
                .withBody(payload)
                .withUpdatedHeader("Content-Type","application/json");

            HttpRequestResponse rr = api.http().sendRequest(modified);
            if (rr.response() == null) continue;

            int    status  = rr.response().statusCode();
            String body    = rr.response().bodyToString();
            String path    = extractPath(rr.response().headerValue("Location"));

            boolean statusDiff    = status != baselineStatus;
            boolean successFound  = containsAny(body, PayloadDatabase.AUTH_SUCCESS_KEYWORDS)
                                 && !containsAny(baselineBody, PayloadDatabase.AUTH_SUCCESS_KEYWORDS);
            boolean failureGone   = !containsAny(body, PayloadDatabase.AUTH_FAILURE_KEYWORDS)
                                 && containsAny(baselineBody, PayloadDatabase.AUTH_FAILURE_KEYWORDS);
            boolean pathChanged   = !safeEquals(path, baselinePath) && isAuthSuccessPath(path);

            // Same rule as the auth bypass scan: errors are never bypasses,
            // but a healthy target erroring on $where payloads is a lead.
            boolean statusBypass  = statusDiff && status >= 200 && status < 300
                                 && !containsAny(body, PayloadDatabase.AUTH_FAILURE_KEYWORDS);
            boolean bypass = status < 400 &&
                (statusBypass || successFound || failureGone || pathChanged);

            boolean errorLead = !bypass && baselineStatus < 400 && status >= 400 &&
                (status >= 500 || containsAny(body, PayloadDatabase.MONGODB_ERROR_SIGNATURES_STRICT));

            if (errorLead && !errorLeadReported) {
                errorLeadReported = true;
                flog.log("[MONGOOSE CVE] ⚠️  Error " + status + " on $where payload — reported as MEDIUM lead");
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

            flog.log("[MONGOOSE CVE] " + (bypass ? "✅ BYPASS!" : "❌ No bypass") +
                " | " + evidence + " | " + truncate(payload, 60));

            if (bypass) {
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
                showNotification("Mongoose CVE-2025-23061 BYPASS FOUND",
                    baseRR.request().url(), payload, evidence);
            }
        }
        flog.log("[MONGOOSE CVE] Completed.");
    }

    // ─────────────────────────────────────────────────────────────
    // FULL SCAN
    // ─────────────────────────────────────────────────────────────

    private void runFullScan(HttpRequestResponse baseRR) {
        flog.log("\n[FULL SCAN] Starting all techniques → " + baseRR.request().url());
        runAuthBypass(baseRR, SmartBodyDetector.detect(baseRR.request()));
        runOperatorScan(baseRR);
        runJsScan(baseRR);
        runContentTypeConfusion(baseRR);
        runAggregationScan(baseRR);
        runMongooseBypass(baseRR);
        runTimeScan(baseRR); // last (slowest)
        flog.log("[FULL SCAN] All techniques completed.");
    }

    // ─────────────────────────────────────────────────────────────
    // UTILITIES
    // ─────────────────────────────────────────────────────────────

    private String guessField(List<SmartBodyDetector.ParsedParam> params, String... candidates) {
        for (SmartBodyDetector.ParsedParam p : params)
            for (String c : candidates)
                if (p.name.toLowerCase().contains(c.toLowerCase())) return p.name;
        return null;
    }

    private boolean containsAny(String text, String[] keywords) {
        if (text == null) return false;
        String lower = text.toLowerCase();
        for (String kw : keywords)
            if (lower.contains(kw.toLowerCase())) return true;
        return false;
    }

    private boolean isSignificantDiff(int a, int b) {
        return (Math.abs(a - b) / Math.max((a + b) / 2.0, 1)) > 0.15;
    }

    /**
     * هل الـ URL path دا بيشير لـ Auth success؟
     */
    private boolean isAuthSuccessPath(String path) {
        if (path == null || path.isEmpty()) return false;
        String lower = path.toLowerCase();
        for (String kw : new String[]{
            "dashboard","home","account","profile","welcome","panel",
            "admin","user","member","portal","my","overview","main"
        }) {
            if (lower.contains(kw)) return true;
        }
        return false;
    }

    /**
     * هل محتوى الـ response اتغيّر بشكل دال على Auth؟
     */
    private boolean isContentDifferent(String body1, String body2) {
        if (body1 == null || body2 == null) return false;
        boolean s1 = containsAny(body1, PayloadDatabase.AUTH_SUCCESS_KEYWORDS);
        boolean s2 = containsAny(body2, PayloadDatabase.AUTH_SUCCESS_KEYWORDS);
        boolean f1 = containsAny(body1, PayloadDatabase.AUTH_FAILURE_KEYWORDS);
        boolean f2 = containsAny(body2, PayloadDatabase.AUTH_FAILURE_KEYWORDS);
        return (s1 && !s2) || (!f1 && f2);
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

    /** Small pause between manual-scan requests to avoid burst rate-limits. */
    private void throttle() {
        try {
            Thread.sleep(REQUEST_DELAY_MS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
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

    private void showNotification(String title, String url, String payload, String evidence) {
        SwingUtilities.invokeLater(() -> {
            // Plain JTextArea in a scroll pane: HTML labels render as literal
            // markup inside Burp, and long URLs/payloads must wrap instead of
            // stretching the dialog to infinity.
            JTextArea area = new JTextArea();
            area.setEditable(false);
            area.setLineWrap(true);
            area.setWrapStyleWord(true);
            area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 14));
            area.setText(title + "\n\n"
                + "URL:      " + url + "\n\n"
                + "Payload:  " + truncate(payload, 200) + "\n\n"
                + "Evidence: " + truncate(evidence, 200));
            area.setCaretPosition(0);

            JScrollPane scroll = new JScrollPane(area);
            scroll.setPreferredSize(new Dimension(720, 280));

            JOptionPane.showMessageDialog(null, scroll,
                "⚠️ NoSQLi Hunter — Finding", JOptionPane.WARNING_MESSAGE);
        });
    }
}
