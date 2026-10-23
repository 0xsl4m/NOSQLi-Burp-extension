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
}
