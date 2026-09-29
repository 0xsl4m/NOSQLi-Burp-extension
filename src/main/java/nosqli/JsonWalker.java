package nosqli;

import java.util.ArrayList;
import java.util.List;

/**
 * JsonWalker — minimal zero-dependency JSON walker.
 *
 * Enumerates every leaf value with its exact location so rewrites happen by
 * offset instead of fragile string matching. Handles string escapes, nested
 * objects/arrays, and duplicate keys (paths carry an occurrence suffix).
 * Not a validator: input is assumed to be JSON-ish; on the first structural
 * surprise the walker stops and returns whatever leaves were found so far.
 */
public final class JsonWalker {

    private JsonWalker() {}

    public static final class Leaf {
        public final String path;   // e.g. $.user.password or $.items[2]
        public final String key;    // last segment: "password" / "[2]"
        public final String raw;    // raw JSON text of the value (strings include quotes)
        public final int start;     // value start offset in the source
        public final int end;       // offset just past the value

        Leaf(String path, String key, String raw, int start, int end) {
            this.path = path;
            this.key = key;
            this.raw = raw;
            this.start = start;
            this.end = end;
        }
    }

    public static List<Leaf> leaves(String json) {
        List<Leaf> out = new ArrayList<>();
        if (json == null) return out;
        try {
            int[] i = {0};
            skipWs(json, i);
            if (i[0] < json.length()
                    && (json.charAt(i[0]) == '{' || json.charAt(i[0]) == '[')) {
                walk(json, i, "$", out);
            }
        } catch (RuntimeException ignored) {
            // malformed/truncated JSON: return whatever leaves were found
        }
        return out;
    }

    private static void walk(String s, int[] i, String path, List<Leaf> out) {
        skipWs(s, i);
        if (i[0] >= s.length()) return;
        char c = s.charAt(i[0]);

        if (c == '{') {
            i[0]++;
            skipWs(s, i);
            if (i[0] < s.length() && s.charAt(i[0]) == '}') { i[0]++; return; }
            List<String> seen = new ArrayList<>();
            while (i[0] < s.length()) {
                skipWs(s, i);
                String key = parseString(s, i);
                skipWs(s, i);
                if (i[0] >= s.length() || s.charAt(i[0]) != ':')
                    throw new RuntimeException("expected ':'");
                i[0]++;
                skipWs(s, i);
                int prior = 0;
                for (String k : seen) if (k.equals(key)) prior++;
                seen.add(key);
                String childPath = path + "." + key + (prior > 0 ? "#" + (prior + 1) : "");
                walk(s, i, childPath, out);
                skipWs(s, i);
                if (i[0] < s.length() && s.charAt(i[0]) == ',') { i[0]++; continue; }
                if (i[0] < s.length() && s.charAt(i[0]) == '}') { i[0]++; return; }
                throw new RuntimeException("expected ',' or '}'");
            }
        } else if (c == '[') {
            i[0]++;
            skipWs(s, i);
            if (i[0] < s.length() && s.charAt(i[0]) == ']') { i[0]++; return; }
            int index = 0;
            while (i[0] < s.length()) {
                skipWs(s, i);
                walk(s, i, path + "[" + index + "]", out);
                index++;
                skipWs(s, i);
                if (i[0] < s.length() && s.charAt(i[0]) == ',') { i[0]++; continue; }
                if (i[0] < s.length() && s.charAt(i[0]) == ']') { i[0]++; return; }
                throw new RuntimeException("expected ',' or ']'");
            }
        } else {
            int start = i[0];
            String raw;
            if (c == '"') {
                parseString(s, i);
                raw = s.substring(start, i[0]);
            } else {
                while (i[0] < s.length()) {
                    char d = s.charAt(i[0]);
                    if (d == ',' || d == '}' || d == ']'
                            || d == ' ' || d == '\n' || d == '\r' || d == '\t') break;
                    i[0]++;
                }
                raw = s.substring(start, i[0]);
            }
            String key = path.substring(path.lastIndexOf('.') + 1);
            out.add(new Leaf(path, key, raw, start, i[0]));
        }
    }

    /** Parse a JSON string starting at the opening quote; advances past the closing quote. */
    private static String parseString(String s, int[] i) {
        if (i[0] >= s.length() || s.charAt(i[0]) != '"')
            throw new RuntimeException("expected string");
        StringBuilder sb = new StringBuilder();
        i[0]++;
        while (i[0] < s.length()) {
            char c = s.charAt(i[0]);
            if (c == '\\') {
                i[0]++;
                if (i[0] >= s.length()) throw new RuntimeException("unterminated escape");
                char e = s.charAt(i[0]);
                if (e == 'u') {
                    if (i[0] + 4 >= s.length()) throw new RuntimeException("bad \\u escape");
                    sb.append((char) Integer.parseInt(s.substring(i[0] + 1, i[0] + 5), 16));
                    i[0] += 5;
                } else {
                    switch (e) {
                        case 'n' -> sb.append('\n');
                        case 't' -> sb.append('\t');
                        case 'r' -> sb.append('\r');
                        case 'b' -> sb.append('\b');
                        case 'f' -> sb.append('\f');
                        default  -> sb.append(e);
                    }
                    i[0]++;
                }
            } else if (c == '"') {
                i[0]++;
                return sb.toString();
            } else {
                sb.append(c);
                i[0]++;
            }
        }
        throw new RuntimeException("unterminated string");
    }

    private static void skipWs(String s, int[] i) {
        while (i[0] < s.length()) {
            char c = s.charAt(i[0]);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') i[0]++;
            else break;
        }
    }

    /** Replace the value of the FIRST leaf whose key matches, with raw JSON text. */
    public static String replaceFirstKey(String json, String key, String newRawValue) {
        for (Leaf leaf : leaves(json)) {
            if (leaf.key.equals(key)) {
                return json.substring(0, leaf.start) + newRawValue + json.substring(leaf.end);
            }
        }
        return json;
    }
}
