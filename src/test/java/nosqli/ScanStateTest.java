package nosqli;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Regression tests for the scan locking / cancellation model.
 *
 * These encode the two bugs fixed with the Handle redesign: a Full Scan
 * used to lock the host and then have every nested technique refuse to
 * start ("A scan is already running"), and cancelling left the host lock
 * held for 15 minutes.
 */
public class ScanStateTest {

    @BeforeEach
    void resetState() {
        ScanState.reset();
    }

    @Test
    void sameHostIsBlockedWhileActive() {
        assertNotNull(ScanState.tryBegin("a.example"));
        assertNull(ScanState.tryBegin("a.example"), "second scan on the same host must be refused");
    }

    @Test
    void differentHostIsAllowed() {
        assertNotNull(ScanState.tryBegin("a.example"));
        assertNotNull(ScanState.tryBegin("b.example"), "a different host must not be blocked");
    }

    @Test
    void endReleasesHostForImmediateRestart() {
        ScanState.Handle first = ScanState.tryBegin("a.example");
        assertNotNull(first);
        ScanState.end(first);
        assertNotNull(ScanState.tryBegin("a.example"),
            "host must be scannable again right after end() — no 15-minute lockout");
    }

    @Test
    void endDoesNotClearCancellation() {
        ScanState.Handle scan = ScanState.tryBegin("a.example");
        ScanState.cancel();
        assertTrue(scan.cancelled());
        ScanState.end(scan);
        assertTrue(scan.cancelled(),
            "end() must never resurrect a cancelled scan (Full Scan used to resume its remaining techniques)");
    }

    @Test
    void freshScanIsUnaffectedByOlderCancel() {
        ScanState.Handle doomed = ScanState.tryBegin("a.example");
        ScanState.cancel();
        ScanState.end(doomed);

        ScanState.Handle fresh = ScanState.tryBegin("a.example");
        assertNotNull(fresh);
        assertFalse(fresh.cancelled(), "a newly started scan must not inherit an old cancel");
        assertTrue(doomed.cancelled(), "the old handle stays cancelled forever");
    }

    @Test
    void cancelStopsEveryRunningScan() {
        ScanState.Handle a = ScanState.tryBegin("a.example");
        ScanState.cancel();
        assertTrue(a.cancelled());
    }

    @Test
    void hostInterleavingCannotDoubleBookAHost() {
        // A → B → A used to be admitted with the old single-slot guard:
        // starting host B overwrote the slot, freeing host A while its
        // scan still ran. The per-host map must keep A locked throughout.
        ScanState.Handle a1 = ScanState.tryBegin("a.example");
        assertNotNull(a1);
        assertNotNull(ScanState.tryBegin("b.example"));
        assertNull(ScanState.tryBegin("a.example"),
            "a scan on another host must never unlock a busy host");

        // ending the B scan must not release A either
        ScanState.Handle b = ScanState.tryBegin("c.example"); // slot juggling is gone; still busy:
        assertNotNull(b);
        ScanState.end(b);
        assertNull(ScanState.tryBegin("a.example"));
    }

    @Test
    void endOnlyReleasesItsOwnHost() {
        ScanState.Handle a = ScanState.tryBegin("a.example");
        ScanState.Handle b = ScanState.tryBegin("b.example");
        ScanState.end(a);
        assertNotNull(ScanState.tryBegin("a.example"), "A released");
        assertNull(ScanState.tryBegin("b.example"), "B must stay locked until its own end()");
    }
}
