package nosqli;

import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the zero-dependency JSON walker (leaf enumeration + rewrites).
 */
public class JsonWalkerTest {

    @Test
    void enumeratesFlatLeaves() {
        List<JsonWalker.Leaf> leaves = JsonWalker.leaves("{\"a\": \"x\", \"b\": 1}");
        assertEquals(2, leaves.size());
        assertEquals("a", leaves.get(0).key);
        assertEquals("\"x\"", leaves.get(0).raw);          // strings keep their quotes
        assertEquals("b", leaves.get(1).key);
        assertEquals("1", leaves.get(1).raw);
    }

    @Test
    void enumeratesNestedObjectsAndArrays() {
        List<JsonWalker.Leaf> leaves = JsonWalker.leaves(
            "{\"user\": {\"name\": \"wiener\"}, \"items\": [{\"id\": 1}, {\"id\": 2}]}");
        assertEquals(3, leaves.size());
        assertEquals("$.user.name", leaves.get(0).path);
        assertEquals("$.items[0].id", leaves.get(1).path);
        assertEquals("$.items[1].id", leaves.get(2).path);
    }

    @Test
    void duplicateKeysGetOccurrencePaths() {
        List<JsonWalker.Leaf> leaves = JsonWalker.leaves("{\"a\": 1, \"a\": 2}");
        assertEquals("$.a", leaves.get(0).path);
        assertEquals("$.a#2", leaves.get(1).path);
    }

    @Test
    void escapedStringsAreHandled() {
        List<JsonWalker.Leaf> leaves = JsonWalker.leaves("{\"s\": \"a\\\"b\\\\c\"}");
        assertEquals(1, leaves.size());
        assertEquals("a\"b\\c", leaves.get(0).raw.substring(1, leaves.get(0).raw.length() - 1)
            .replace("\\\"", "\"").replace("\\\\", "\\"));
    }

    @Test
    void replaceFirstKeySplicesByOffset() {
        String out = JsonWalker.replaceFirstKey(
            "{\"username\": \"admin\", \"password\": \"pw\"}",
            "password", "{\"$ne\": null}");
        assertEquals("{\"username\": \"admin\", \"password\": {\"$ne\": null}}", out);
    }

    @Test
    void replaceFirstKeyHandlesSubstringKeyCollisions() {
        // "user" is a substring of "username" — a naive indexOf match would
        // corrupt the body; the walker matches whole keys only.
        String out = JsonWalker.replaceFirstKey(
            "{\"username\": \"wiener\"}", "user", "\"evil\"");
        assertEquals("{\"username\": \"wiener\"}", out);
    }

    @Test
    void replaceFirstKeyKeepsUnmatchedBodyUntouched() {
        String body = "{\"a\": 1}";
        assertEquals(body, JsonWalker.replaceFirstKey(body, "missing", "null"));
    }

    @Test
    void malformedJsonReturnsPartialWithoutThrowing() {
        assertDoesNotThrow(() -> JsonWalker.leaves("{\"a\": \"ok\", \"b\": "));
        assertEquals(1, JsonWalker.leaves("{\"a\": \"ok\", \"b\": ").size());
        assertTrue(JsonWalker.leaves("not json at all").isEmpty());
    }
}
