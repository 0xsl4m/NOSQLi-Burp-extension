package nosqli;

import burp.api.montoya.logging.Logging;

import javax.swing.*;
import java.awt.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * FindingsLogger — Shared singleton
 *
 * مسؤول عن:
 *  - تخزين كل الـ findings مع full request body + URL
 *  - إبلاغ كل الـ listeners (UI tab) بالتحديثات
 *  - كتابة اللوج في Burp Output بالتوازي
 */
public class FindingsLogger {

    // ── Singleton ──────────────────────────────────────────────────
    private static FindingsLogger INSTANCE;

    public static synchronized FindingsLogger getInstance() {
        if (INSTANCE == null) INSTANCE = new FindingsLogger();
        return INSTANCE;
    }

    // ── Finding Record ──────────────────────────────────────────────
    public static class Finding {
        public final String timestamp;
        public final String technique;   // ERROR / BOOLEAN / TIME / AUTH / OPERATOR / JS
        public final String severity;    // HIGH / MEDIUM / LOW / INFO
        public final String url;
        public final String parameter;
        public final String payload;
        public final String fullRequest; // كامل الـ HTTP request مع الـ payload
        public final String evidence;    // ملاحظة عن الفرق في الـ response
        public final String urlPath;     // الـ path بعد الـ redirect لو حصل

        public Finding(String technique, String severity, String url,
                       String parameter, String payload,
                       String fullRequest, String evidence, String urlPath) {
            this.timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
            this.technique = technique;
            this.severity  = severity;
            this.url       = url;
            this.parameter = parameter;
            this.payload   = payload;
            this.fullRequest = fullRequest;
            this.evidence  = evidence;
            this.urlPath   = urlPath;
        }
    }

    // ── State ───────────────────────────────────────────────────────
    private final List<Finding> findings = new CopyOnWriteArrayList<>();
    private final List<Consumer<Finding>> listeners = new CopyOnWriteArrayList<>();
    private final List<Consumer<String>>  logListeners = new CopyOnWriteArrayList<>();
    private final java.util.Set<String> seenKeys = java.util.Collections.synchronizedSet(new java.util.HashSet<>());
    private Logging burpLog;

    // ── Setup ───────────────────────────────────────────────────────
    public void setBurpLogging(Logging log) {
        this.burpLog = log;
    }

    public void addFindingListener(Consumer<Finding> listener) {
        listeners.add(listener);
    }

    public void addLogListener(Consumer<String> listener) {
        logListeners.add(listener);
    }

    // ── Logging ─────────────────────────────────────────────────────
    public void log(String message) {
        String ts = LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        String line = "[" + ts + "] " + message;

        if (burpLog != null) burpLog.logToOutput(line);

        for (Consumer<String> l : logListeners) {
            SwingUtilities.invokeLater(() -> l.accept(line + "\n"));
        }
    }

    // ── Report Finding ──────────────────────────────────────────────
    /**
     * Duplicates (same technique + parameter + URL) are suppressed: repeated
     * scans of the same endpoint must not pile up identical findings.
     * Clear Findings resets the dedup set.
     */
    public boolean reportFinding(Finding f) {
        String key = f.technique + "|" + f.parameter + "|" + f.url;
        if (!seenKeys.add(key)) {
            log("Duplicate suppressed: " + f.technique + " on " + f.parameter + " (" + f.url + ")");
            return false;
        }
        findings.add(f);

        // أيضاً نكتبه في اللوج العادي
        log(" [" + f.technique + "/" + f.severity + "] param=" + f.parameter +
            " url=" + f.url +
            (f.urlPath != null && !f.urlPath.isEmpty() ? " → redirect=" + f.urlPath : "") +
            " | evidence=" + f.evidence);

        // نبلّغ كل الـ UI listeners
        for (Consumer<Finding> l : listeners) {
            SwingUtilities.invokeLater(() -> l.accept(f));
        }
        return true;
    }

    public List<Finding> getFindings() {
        return new ArrayList<>(findings);
    }

    public void clearFindings() {
        findings.clear();
        seenKeys.clear();
    }
}
