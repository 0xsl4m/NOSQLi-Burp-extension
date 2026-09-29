package nosqli;

/**
 * ScanState — tracks the currently running manual scan.
 *
 * Best-effort one-scan-per-host guard (a scan older than 15 minutes is
 * considered abandoned and can be replaced) plus a global cancel flag the
 * tool tab can set from any thread.
 */
public final class ScanState {

    private static volatile String activeHost;
    private static volatile long   startedAt;
    private static volatile boolean cancelled;

    private ScanState() {}

    /** Returns false if a scan is already running against the same host. */
    public static synchronized boolean tryBegin(String host) {
        long now = System.currentTimeMillis();
        if (activeHost != null && activeHost.equals(host)
                && now - startedAt < 15 * 60 * 1000L) {
            return false;
        }
        activeHost = host;
        startedAt = now;
        cancelled = false;
        return true;
    }

    public static synchronized void end(String host) {
        if (host != null && host.equals(activeHost)) {
            activeHost = null;
            cancelled = false;
        }
    }

    /** Cancel all running manual scans. */
    public static void cancel() { cancelled = true; }

    public static boolean isCancelled() { return cancelled; }

    public static String activeHost() { return activeHost; }
}
