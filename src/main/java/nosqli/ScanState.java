package nosqli;

/**
 * ScanState — tracks the currently running manual scan.
 *
 * Best-effort one-scan-per-host guard (a scan older than 15 minutes is
 * considered abandoned and can be replaced) plus cancellation the tool tab
 * can trigger from any thread.
 *
 * Locking rules (learned the hard way):
 *  - Only the top-level menu entry points take the lock (tryBegin/end).
 *    Full Scan takes it ONCE and drives the unlocked doX techniques with
 *    its own handle, so a nested tryBegin can never reject a sub-scan.
 *  - Every lock owner releases in a finally block — including cancel
 *    paths — so a cancelled host is immediately scannable again.
 *  - Cancellation is an epoch counter, not a boolean: a Handle records the
 *    epoch it started at and stays cancelled forever; end() never clears
 *    it. This keeps a cancelled Full Scan from resuming through its
 *    remaining techniques, while a freshly started scan is never affected
 *    by an older cancel.
 */
public final class ScanState {

    private static volatile String activeHost;
    private static volatile long startedAt;
    private static volatile long cancelEpoch;

    private ScanState() {}

    /**
     * One running scan. {@link #cancelled()} is true forever once
     * {@link #cancel()} fires after this scan started.
     */
    public static final class Handle {
        private final String host;
        private final long epoch;

        Handle(String host, long epoch) {
            this.host = host;
            this.epoch = epoch;
        }

        public String host() { return host; }

        public boolean cancelled() { return cancelEpoch != epoch; }
    }

    /** Returns null if a scan is already running against the same host. */
    public static synchronized Handle tryBegin(String host) {
        long now = System.currentTimeMillis();
        if (activeHost != null && activeHost.equals(host)
                && now - startedAt < 15 * 60 * 1000L) {
            return null;
        }
        activeHost = host;
        startedAt = now;
        return new Handle(host, cancelEpoch);
    }

    /** Release the host lock. Never touches cancellation state. */
    public static synchronized void end(Handle scan) {
        if (scan != null && scan.host.equals(activeHost)) {
            activeHost = null;
        }
    }

    /** Cancel every scan started before now. */
    public static void cancel() { cancelEpoch++; }

    /** Clear all state (extension unload). */
    public static synchronized void reset() {
        activeHost = null;
        startedAt = 0;
        cancelEpoch++;
    }

    public static String activeHost() { return activeHost; }
}
