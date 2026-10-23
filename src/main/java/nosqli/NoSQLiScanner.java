package nosqli;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

/**
 * NoSQLi Hunter v2.1.1
 *
 * Changes from v2.1.0:
 *  - Full Scan fixed: it takes the per-host lock ONCE and drives the
 *    unlocked techniques with a shared cancel handle (it used to lock the
 *    host and then every nested technique refused to start, sending zero
 *    requests)
 *  - Cancel no longer leaves the host locked for 15 minutes (locks release
 *    in finally, cancellation is an epoch — a cancelled Full Scan never
 *    resumes through its remaining techniques)
 *  - $regex field extraction works on urlencoded bodies, not just JSON
 *  - Scanner boolean stage no longer requires TRUE-closer-to-baseline
 *    (false-negative on login endpoints; criteria now match the manual scan)
 *  - JS scan: normalized comparison + resend stability + one finding per
 *    parameter + WAF-block skipping (was the noisiest technique)
 *  - CT Confusion preserves every other body field (CSRF) instead of
 *    replacing the whole body and reporting the guaranteed 403
 *  - normalize() strips the reflected pair VALUE too (reflective pages
 *    could fake a size difference between TRUE/FALSE)
 *  - Redirect-to-success detection tightened (failure keywords veto,
 *    narrower path keywords) — error-page redirects no longer count
 *  - $out removed from the aggregation scan payloads (detection stays
 *    read-only); available as reference-only list
 *  - Extension unload handler cancels scans and shuts the worker pool
 *
 * Earlier (v2.1.0):
 *  - FindingsLogger singleton: connects ScanCheck + ContextMenu → Tab UI live
 *  - Auth detection: content change + URL path redirect (not just status code)
 *  - All findings logged with FULL HTTP request body (headers + injected body)
 *  - Operator injection actually replaces the parameter NAME (user[$ne]=x)
 *  - FP fixes: strict signature list without baseline, auth keywords
 *    tightened, per-field auth-bypass rewriting keeps CSRF tokens
 */
public class NoSQLiScanner implements BurpExtension {

    public static final String EXTENSION_NAME = "NoSQLi Hunter";
    public static final String VERSION        = "2.1.1";

    private NoSQLiContextMenu contextMenu;

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
        contextMenu = new NoSQLiContextMenu(api);
        api.userInterface().registerContextMenuItemsProvider(contextMenu);

        // 5. On unload: cancel running scans and stop the worker pool so no
        //    thread keeps firing requests after the extension is gone.
        api.extension().registerUnloadingHandler(() -> {
            contextMenu.shutdown();
            ScanState.reset();
            FindingsLogger.getInstance().log("[NoSQLi] Extension unloaded — scans cancelled.");
        });

        // 6. Active/passive scanner check — the Scanner API is
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

        // 7. Banner
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
