package jpamb.cases.advanced;

import jpamb.utils.*;

/*
 * Cases for the taint-guided fuzzer: 3 CWE-502 + 3 CWE-470 entry points with
 * small call graphs. Each one shows something a taint analysis adds before
 * fuzzing:
 *
 *  1. Automatic detection: CWE-502 and CWE-470 share this file, so the file
 *     name does not say which values to try (SER|Class|args payloads or bare
 *     class names). The category of the taint finding does.
 *  2. Focus: every entry point takes several Strings, and the ones that never
 *     reach the sink are compared against many literals (more dictionary
 *     strings, more noise). The taint analysis names the one parameter that
 *     reaches the sink (relevant_parameters), and the fuzzer favours it.
 *  3. Sanitizers: sanitizePayload / sanitizeCommand are correct allowlists
 *     declared in taint_analysis/summaries.py, so deser_sanitized and
 *     reflect_sanitized are reported clean. filterCommand is not declared, and
 *     it is a broken blocklist: reflect_filtered stays tainted and the fuzzer
 *     confirms the exploit.
 */
public class taint_cases {

    public static void canary() {
        throw new AssertionError("Vulnerability Reached: Canary Loaded!");
    }

    private static final String EXPECTED_HEADER = "SER";
    private static final String PKG = "jpamb.cases.advanced.taint_cases$";

    public static class __CANARY__Command {
        public __CANARY__Command() { canary(); }
    }

    public static class SafeGadget {
        public SafeGadget() {}
    }

    public static class SafeCommand {
        public SafeCommand() {}
    }

    // =====================================================================
    // CWE-502 machinery (simulated ObjectInputStream.readObject)
    // =====================================================================

    public static String simulateResolveClassName(String payload) throws Exception {
        String[] parts = payload.split("\\|", -1);
        if (parts.length < 3 || !EXPECTED_HEADER.equals(parts[0])) {
            throw new IllegalArgumentException("Invalid payload");
        }
        return parts[1];
    }

    public static Object simulateReadObject(String payload) throws Exception {
        String className = simulateResolveClassName(payload);
        String[] parts = payload.split("\\|", -1);

        if (className.equals("SafeGadget")) return new SafeGadget();
        if (className.equals("__CANARY__Command")) return new __CANARY__Command();

        if (className.equals("Loader") && parts.length >= 4) {
            return new Loader(parts[2], Integer.parseInt(parts[3]));
        }

        throw new ClassNotFoundException("Invalid class");
    }

    // Gadget: SER|Loader|<mode>|<level> loads the canary only for PLUGIN at level 2
    public static class Loader {
        public Loader(String mode, int level) {
            if ("PLUGIN".equals(mode) && level == 2) {
                new __CANARY__Command();
            }
        }
    }

    // Declared sanitizer (summaries.py): the payload passes unchanged only when
    // it decodes to exactly SafeGadget
    public static String sanitizePayload(String payload) {
        String[] parts = payload.split("\\|", -1);
        if (parts.length != 3) return "SER|SafeGadget|";
        if (!EXPECTED_HEADER.equals(parts[0])) return "SER|SafeGadget|";
        if (!"SafeGadget".equals(parts[1])) return "SER|SafeGadget|";
        return payload;
    }

    // =====================================================================
    // CWE-470 machinery (reflection)
    // =====================================================================

    // Like an allowlist at the call site, which here even admits the canary
    private static void invokeReflection(String shortName) {
        if (!"SafeCommand".equals(shortName) && !"__CANARY__Command".equals(shortName)) {
            return;
        }
        try {
            Class<?> cmdClass = Class.forName(PKG + shortName);
            cmdClass.newInstance();
        } catch (Exception e) {
            return;
        }
    }

    // Declared sanitizer (summaries.py): only the allowlisted name passes
    public static String sanitizeCommand(String cmd) {
        if ("SafeCommand".equals(cmd)) return cmd;
        return "SafeCommand";
    }

    // NOT declared, and broken: it blocks the canary by prefix, but resolves
    // "<namespace>:<command>" aliases to their last segment only after the check,
    // so "SafeCommand:__CANARY__Command" gets through
    public static String filterCommand(String cmd) {
        if (cmd.startsWith("__CANARY__")) return "SafeCommand";
        String[] parts = cmd.split(":", -1);
        return parts[parts.length - 1];
    }

    // =====================================================================
    // CWE-502 entry points
    // =====================================================================

    // Only payload reaches the sink; tenant and region just pick an audit tag
    @Case("(s'acme', s'eu', s'bin', s'SER|SafeGadget|') -> ok")
    @Case("(s'acme', s'eu', s'json', s'SER|__CANARY__Command|') -> ok")
    @Case("(s'acme', s'eu', s'bin', s'SER|__CANARY__Command|') -> assertion error")
    public static void deser_import(String tenant, String region, String format, String payload) {
        String audit = "import";
        if (tenant.startsWith("acme")) {
            audit = audit + ":acme";
        } else if (tenant.startsWith("globex")) {
            audit = audit + ":globex";
        } else if (tenant.startsWith("initech")) {
            audit = audit + ":initech";
        }
        if ("eu".equals(region) || "us".equals(region) || "apac".equals(region)) {
            audit = audit + ":" + region;
        }
        if (!"bin".equals(format)) {
            return;
        }
        try { simulateReadObject(payload); } catch (Exception e) {}
    }

    // A one-step gadget chain: the payload must name Loader with the right fields
    @Case("(s'svc_sync', s'nightly', s'SER|Loader|PLUGIN|1') -> ok")
    @Case("(s'svc_sync', s'nightly', s'SER|Loader|THEME|2') -> ok")
    @Case("(s'bob', s'nightly', s'SER|Loader|PLUGIN|2') -> ok")
    @Case("(s'svc_sync', s'nightly', s'SER|Loader|PLUGIN|2') -> assertion error")
    public static void deser_gadget(String user, String note, String payload) {
        int priority = 0;
        if (note.contains("urgent")) {
            priority = 2;
        } else if (note.contains("nightly")) {
            priority = 1;
        } else if (note.contains("manual")) {
            priority = 3;
        }
        if (!user.startsWith("svc_")) {
            return;
        }
        try { simulateReadObject(payload); } catch (Exception e) {}
    }

    // The payload reaches the sink only through the declared sanitizer
    @Case("(s'acme', s'eu', s'SER|SafeGadget|') -> ok")
    @Case("(s'acme', s'eu', s'SER|__CANARY__Command|') -> ok")
    @Case("(s'acme', s'us', s'SER|Loader|PLUGIN|2') -> ok")
    public static void deser_sanitized(String tenant, String region, String payload) {
        if (!tenant.startsWith("acme")) {
            return;
        }
        String clean = sanitizePayload(payload);
        if ("eu".equals(region) || "us".equals(region)) {
            try { simulateReadObject(clean); } catch (Exception e) {}
        }
    }

    // =====================================================================
    // CWE-470 entry points
    // =====================================================================

    // Only cmd reaches Class.forName; verb just picks a log tag
    @Case("(s'op_admin', s'run', s'SafeCommand') -> ok")
    @Case("(s'guest', s'run', s'__CANARY__Command') -> ok")
    @Case("(s'op_admin', s'run', s'__CANARY__Command') -> assertion error")
    public static void reflect_command(String user, String verb, String cmd) {
        String log = "cmd";
        if ("run".equals(verb)) {
            log = log + ":run";
        } else if ("show".equals(verb)) {
            log = log + ":show";
        } else if ("stop".equals(verb)) {
            log = log + ":stop";
        } else if ("list".equals(verb)) {
            log = log + ":list";
        }
        if (!user.startsWith("op_")) {
            return;
        }
        invokeReflection(cmd);
    }

    // cmd goes through filterCommand, which is not declared as a sanitizer: the
    // taint analysis keeps it tainted, and rightly so, since the filter is broken
    @Case("(s'ops', s'audit', s'SafeCommand') -> ok")
    @Case("(s'ops', s'audit', s'__CANARY__Command') -> ok")
    @Case("(s'ops', s'audit', s'SafeCommand:SafeCommand') -> ok")
    @Case("(s'ops', s'audit', s'SafeCommand:__CANARY__Command') -> assertion error")
    public static void reflect_filtered(String team, String reason, String cmd) {
        String ticket = "ticket";
        if ("ops".equals(team) || "sre".equals(team)) {
            ticket = ticket + ":" + team;
        }
        if (reason.startsWith("audit")) {
            ticket = ticket + ":audit";
        } else if (reason.startsWith("hotfix")) {
            ticket = ticket + ":hotfix";
        }
        invokeReflection(filterCommand(cmd));
    }

    // cmd reaches Class.forName only through the declared sanitizer
    @Case("(s'admin', s'SafeCommand', s'direct') -> ok")
    @Case("(s'admin', s'__CANARY__Command', s'direct') -> ok")
    @Case("(s'admin', s'SafeCommand:__CANARY__Command', s'queued') -> ok")
    @Case("(s'intern', s'__CANARY__Command', s'direct') -> ok")
    public static void reflect_sanitized(String role, String cmd, String mode) {
        if (!"admin".equals(role) && !"ops".equals(role)) {
            return;
        }
        String clean = sanitizeCommand(cmd);
        if ("direct".equals(mode) || "queued".equals(mode)) {
            invokeReflection(clean);
        }
    }
}
