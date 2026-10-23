package nosqli;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the pure differential-analysis logic — no Burp APIs involved.
 */
public class DiffEngineTest {

    @Test
    void normalizeStripsReflectedPayloadRawAndUrlEncoded() {
        String body = "echo: user[$ne] | echo2: user%5B%24ne%5D | end";
        String out = DiffEngine.normalize(body, "user[$ne]");
        // Both the raw payload and its URL-encoded form are stripped, so a
        // reflected payload can never fake a size difference on its own.
        assertEquals("echo:  | echo2:  | end", out);
    }

    @Test
    void normalizeMasksDynamicTokenFields() {
        String body = "<input name='csrf_token' value='ABCDEF123456'>";
        String out = DiffEngine.normalize(body, null);
        assertFalse(out.contains("ABCDEF123456"));
        assertTrue(out.contains("MASKED"));
    }

    @Test
    void dynamicFieldMaskingIsAnchoredToWordStart() {
        // "ts"/"state" as SUBSTRINGS of ordinary field names must not mask
        // their values — that erased real boolean differences.
        String body1 = "details: invalid credentials entered";
        String body2 = "details: welcome back you are logged in";
        assertFalse(DiffEngine.normalize(body1, null).contains("MASKED"));
        assertFalse(DiffEngine.normalize(body2, null).contains("MASKED"));
        assertFalse(DiffEngine.normalize("credits: 123456", null).contains("MASKED"));
        // a REAL ts= field is still masked
        assertTrue(DiffEngine.normalize("ts: 1700000000000x", null).contains("MASKED"));
    }

    @Test
    void normalizeMasksEpochTimestamps() {
        String out = DiffEngine.normalize("ts=1700000000000", null);
        assertFalse(out.contains("1700000000000"));
        assertTrue(out.contains("MASKED"));
    }

    @Test
    void normalizeStripsPairValuePart() {
        // Reflective page echoing only the VALUE of an operator pair: the
        // full pair string is not present, so the value part must be
        // stripped via the second argument or TRUE/FALSE sizes fake a diff.
        String body = "Results for: ^impossible_xyz_no_match_12345$ | done";
        String out = DiffEngine.normalize(body,
            "filter[$regex]=^impossible_xyz_no_match_12345$",
            DiffEngine.valuePartOf("filter[$regex]=^impossible_xyz_no_match_12345$"));
        assertEquals("Results for:  | done", out);
    }

    @Test
    void valuePartOfSplitsAtFirstEquals() {
        assertEquals("nosqlhunter_x", DiffEngine.valuePartOf("user[$ne]=nosqlhunter_x"));
        assertEquals("", DiffEngine.valuePartOf("user[$gt]="));
        // JSON pair payloads (no '=') pass through untouched
        assertEquals("{\"$ne\": \"x\"}", DiffEngine.valuePartOf("{\"$ne\": \"x\"}"));
        assertNull(DiffEngine.valuePartOf(null));
    }

    @Test
    void sizeDiffThreshold() {
        assertTrue(DiffEngine.isSignificantDiff(1000, 1200));   // ~18%
        assertFalse(DiffEngine.isSignificantDiff(1000, 1100));  // ~9.5%
    }

    @Test
    void evaluateFlagsRealDifferences() {
        DiffEngine.Signals sig = DiffEngine.evaluate(
            true,                       // status differs
            1000, 1300,
            "<html>dashboard logout</html>",
            "<html>invalid username or password</html>",
            "/my-account", "/login");
        assertTrue(sig.any());
        assertTrue(sig.statusDiff);
        assertTrue(sig.sizeDiff);
        assertTrue(sig.pathDiff);
        assertTrue(sig.keywordDiff);
        assertEquals("status size path keywords", sig.describe());
    }

    @Test
    void evaluateQuietOnEquivalentResponses() {
        DiffEngine.Signals sig = DiffEngine.evaluate(
            false, 1200, 1200,
            "<html>invalid username or password</html>",
            "<html>invalid username or password</html>",
            "", "");
        assertFalse(sig.any());
    }

    @Test
    void keywordFlipAsymmetricSemanticsPreserved() {
        // TRUE shows success keyword FALSE lacks → flip
        assertTrue(DiffEngine.keywordFlip("<p>welcome back</p>", "<p>invalid</p>"));
        // FALSE shows failure keyword TRUE lacks → flip
        assertTrue(DiffEngine.keywordFlip("<p>ok</p>", "<p>invalid username</p>"));
        // TRUE carrying the failure text while FALSE is clean is NOT a flip
        // (historical asymmetric semantics — avoids one FP direction).
        assertFalse(DiffEngine.keywordFlip("<p>invalid request</p>", "<p>ok</p>"));
    }
}
