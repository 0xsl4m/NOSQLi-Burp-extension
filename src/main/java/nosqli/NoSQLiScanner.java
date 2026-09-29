package nosqli;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

/**
 * NoSQLi Hunter v2.1.0
 *
 * Changes from v2.0.0:
 *  - FindingsLogger singleton: connects ScanCheck + ContextMenu → Tab UI live
 *  - Auth detection: content change + URL path redirect (not just status code)
 *  - All findings logged with FULL HTTP request body (headers + injected body)
 *  - Copy buttons fixed in Payload Cheatsheet
 *  - Findings table: double-click shows full request popup
 *  - Added Mongoose CVE-2025-23061 right-click option
 *  - FP fixes: generic "mongo" terms removed from error signatures
 *    (strict list for baseline-less contexts), auth keywords tightened,
 *    non-2xx status change no longer reports auth bypass alone
 *  - Operator injection now actually replaces the parameter NAME
 *    (user[$ne]=x) instead of stuffing the pair into the value —
 *    context-menu operator scan AND active-scan boolean stage
 *  - Active scan: 150ms pause between requests
 */
public class NoSQLiScanner implements BurpExtension {

    public static final String EXTENSION_NAME = "NoSQLi Hunter";
    public static final String VERSION        = "2.1.0";

    @Override
    public void initialize(MontoyaApi api) {
        // 1. Init shared logger (must be FIRST — tab hooks into it)
        FindingsLogger.getInstance().setBurpLogging(api.logging());

        // 2. Set Burp extension name
        api.extension().setName(EXTENSION_NAME + " v" + VERSION);

        // 3. Build and register UI tab FIRST (so it can receive log events)
        NoSQLiTab tab = new NoSQLiTab(api);
        api.userInterface().registerSuiteTab(EXTENSION_NAME, tab.getComponent());

        // 4. Context menu (right-click)
        api.userInterface().registerContextMenuItemsProvider(new NoSQLiContextMenu(api));

        // 5. Active/passive scanner check — the Scanner API is
        //    "[Professional only]". Guard it so Burp Community loads the
        //    extension cleanly: the tab and right-click scans work everywhere.
        try {
            api.scanner().registerScanCheck(new NoSQLiScanCheck(api));
        } catch (Exception e) {
            FindingsLogger.getInstance().log("Scanner check not registered (" +
                     e.getClass().getSimpleName() +
                     "): active/passive auditing requires Burp Suite Professional. " +
                     "Right-click scans and the NoSQLi Hunter tab work on Community.");
        }

        // 6. Banner
        FindingsLogger flog = FindingsLogger.getInstance();
        flog.log("==============================================");
        flog.log(" NoSQLi Hunter v" + VERSION + " — Loaded ");
        flog.log(" Auth Detection : Content + URL Path (not just status)");
        flog.log(" Findings       : Full HTTP request per finding");
        flog.log(" CVE Coverage   : CVE-2025-23061 Mongoose $where/$or");
        flog.log(" Techniques     : Error, Boolean, Time, Auth, CT-Confusion");
        flog.log("==============================================");
    }
}
