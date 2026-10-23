package nosqli;

import java.util.HashMap;
import java.util.Map;

/**
 * ScanState — tracks the currently running manual scans.
 *
 * Best-effort one-scan-per-HOST guard (a scan older than 15 minutes is
 * considered abandoned and can be replaced) plus cancellation the tool tab
 * can trigger from any thread. Scans on different hosts may run in
 * parallel; the guard is a per-host map, so interleaving hosts can never
 * admit a second scan onto a host that already has one running.
 *
 * Locking rules (learned the hard way):
 *  - Only the top-level menu entry points take a lock (tryBegin/end).
 *    Full Scan takes it ONCE and drives the unlocked doX techniques with
 *    its own handle, so a nested tryBegin can never reject a sub-scan.
 *  - Every lock owner releases in a finally block — including cancel
 *    paths — so a cancelled host is scannable again as soon as the scan
 *    thread notices the cancel.
 *  - Cancellation is an epoch counter, not a boolean: a Handle records the
 *    epoch it started at and stays cancelled forever; end() never clears
 *    it. This keeps a cancelled Full Scan from resuming through its
 *    remaining techniques, while a freshly started scan is never affected
 *    by an older cancel.
 */
public final class ScanState {

    private static final long STALE_MS = 15 * 60 * 1000L;

    private static final Map<String, Handle> activeByHost = new HashMap<>();
    private static long cancelEpoch;

    private ScanState() {}

    /**
     * One running scan. {@link #cancelled()} is true forever once
     * {@link #cancel()} fires after this scan started.
     */
    public static final class Handle {
        private final String host;
        private final long epoch;
        private final long startedAt;

        Handle(String host, long epoch, long startedAt) {
            this.host = host;
            this.epoch = epoch;
            this.startedAt = startedAt;
        }

        public String host() { return host; }

        public boolean cancelled() { return cancelEpoch != epoch; }
    }

    /** Returns null if a scan is already running against the same host. */
    public static synchronized Handle tryBegin(String host) {
        long now = System.currentTimeMillis();
        Handle existing = activeByHost.get(host);
        if (existing != null && now - existing.startedAt < STALE_MS) {
            return null;
        }
        Handle scan = new Handle(host, cancelEpoch, now);
        activeByHost.put(host, scan);
        return scan;
    }

    /** Release the host lock. Never touches cancellation state. */
    public static synchronized void end(Handle scan) {
        if (scan != null && activeByHost.get(scan.host) == scan) {
            activeByHost.remove(scan.host);
        }
    }

    /** Cancel every scan started before now. */
    public static synchronized void cancel() { cancelEpoch++; }

    /** Clear all state (extension unload). */
    public static synchronized void reset() {
        activeByHost.clear();
        cancelEpoch++;
    }

    /** One of the currently active scan hosts, for busy messages. */
    public static synchronized String activeHost() {
        return activeByHost.isEmpty() ? null
            : activeByHost.keySet().iterator().next();
    }
}
