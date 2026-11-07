
package jpamb.cases.advanced;

import jpamb.utils.*;

/**
 * ADVANCED: CWE-470 Unsafe Reflection.
 *
 * Compatible with the custom dynamic interpreter.
 *
 * Only supported String operations are used:
 * equals, equalsIgnoreCase, startsWith, endsWith,
 * contains, isEmpty, length, charAt, split.
 */
public class Extended470 {

    // =========================================================
    // SINK
    // =========================================================

    public static void canary() {
        throw new AssertionError("Vulnerability Reached: Canary Loaded!");
    }

    // =========================================================
    // DEPENDENCIES
    // =========================================================

    public static class __CANARY__Command {
        public __CANARY__Command() {
            canary();
        }
    }

    public static class SafeCommand {
        public void doAction() {
            return;
        }
    }

    public static class ExportCommand extends SafeCommand {}
    public static class BackupCommand extends SafeCommand {}
    public static class ReportCommand extends SafeCommand {}
    public static class CleanupCommand extends SafeCommand {}

    public static class SafeWrapperCommand extends __CANARY__Command {}

    // =========================================================
    // SHARED HELPERS
    // =========================================================

    private static String classPrefix() {
        return "jpamb.cases.advanced.Extended470$";
    }

    private static String buildClassName(String command) {
        return classPrefix() + command + "Command";
    }

    private static void instantiate(String className) {
        try {
            Class<?> cmdClass = Class.forName(className);
            SafeCommand cmd = (SafeCommand) cmdClass.newInstance();
            cmd.doAction();
        } catch (Exception e) {
            return;
        }
    }

    // =========================================================
    // SANITIZATION HELPERS
    // =========================================================

    /**
     * Simulated sanitization:
     * rejects semicolons but does not validate the identifier.
     */
    private static String sanitizeInput(String input) {
        if (input.contains(";")) {
            return "Safe";
        }
        return input;
    }

    /**
     * Simulated path normalization:
     * handles ../ but does not validate class names.
     */
    private static String normalizePath(String input) {
        if (input.contains("../")) {
            return "Safe";
        }
        return input;
    }

    /**
     * Weak identifier validation.
     * Checks for a few forbidden characters but accepts
     * arbitrary identifiers composed of other characters.
     */
    private static String sanitizeIdentifier(String input) {
        if (input.contains("/")) {
            return "Safe";
        }

        if (input.contains(" ")) {
            return "Safe";
        }

        return input;
    }

    private static boolean weakValidation(String input) {
        return input != null
                && input.length() > 2
                && input.length() < 40;
    }

    private static boolean prefixValidation(String input) {
        return input != null && input.startsWith("Safe");
    }

    // =========================================================
    // CASE 1: DIRECT REFLECTION
    // =========================================================

    @Case("(s'Safe') -> ok")
    @Case("(s'__CANARY__') -> assertion error")
    public static void unsafe_dispatcher(String ctl) {

        String className = buildClassName(ctl);

        instantiate(className);
    }

    // =========================================================
    // CASE 2: WEAK PREFIX VALIDATION
    // =========================================================

    @Case("(s'Safe') -> ok")
    @Case("(s'SafeWrapper') -> assertion error")
    public static void weak_dispatcher(String ctl) {

        if (!ctl.startsWith("Safe")) {
            return;
        }

        instantiate(buildClassName(ctl));
    }

    // =========================================================
    // CASE 3: STRICT VALIDATION
    // =========================================================

    @Case("(s'Any') -> ok")
    public static void strict_safe_dispatcher(String ctl) {

        if (!"Safe".equals(ctl)) {
            return;
        }

        instantiate(buildClassName(ctl));
    }

    // =========================================================
    // CASE 4: TWO-STEP DISPATCH
    // =========================================================

    @Case("(s'Any', i'0') -> ok")
    @Case("(s'__CANARY__', i'1') -> assertion error")
    public static void two_step_dispatcher(
            String ctl, int guard) {

        if (guard == 0) {
            return;
        }

        unsafe_dispatcher(ctl);
    }

    // =========================================================
    // CASE 5: MULTI-PARAMETER DISPATCH
    // =========================================================

    @Case("(s'__CANARY__', s'production', s'admin', i'1', i'0') -> assertion error")
    @Case("(s'Safe', s'production', s'admin', i'1', i'0') -> ok")
    public static void multi_parameter_dispatcher(
            String tenant,
            String environment,
            String role,
            int authenticated,
            int debug) {

        if (authenticated != 1) return;
        if (!"production".equals(environment)) return;
        if (!"admin".equals(role)) return;
        if (debug != 0) return;

        instantiate(buildClassName(tenant));
    }

    // =========================================================
    // CASE 6: SANITIZATION
    // =========================================================

    @Case("(s'__CANARY__') -> assertion error")
    @Case("(s'Safe') -> ok")
    public static void sanitized_dispatcher(String ctl) {

        String cleaned = sanitizeIdentifier(ctl);

        if (!weakValidation(cleaned)) return;

        instantiate(buildClassName(cleaned));
    }

    // =========================================================
    // CASE 7: MULTI-HOP INTERPROCEDURAL DISPATCH
    // =========================================================

    private static String prepareCommand(String input) {
        return sanitizeInput(input);
    }

    private static String resolveCommand(String input) {
        return buildClassName(input);
    }

    private static void executeResolvedCommand(String className) {
        instantiate(className);
    }

    @Case("(s'__CANARY__') -> assertion error")
    @Case("(s'Safe') -> ok")
    public static void multi_hop_dispatcher(String ctl) {

        String prepared = prepareCommand(ctl);

        if (!weakValidation(prepared)) {
            return;
        }

        String resolved = resolveCommand(prepared);

        executeResolvedCommand(resolved);
    }

    // =========================================================
    // CASE 8: INCOMPLETE CHARACTER VALIDATION
    // =========================================================

    @Case("(s'__CANARY__') -> assertion error")
    @Case("(s'Safe') -> ok")
    public static void regex_dispatcher(String ctl) {

        if (ctl.contains("/")) return;
        if (ctl.contains(" ")) return;
        if (ctl.isEmpty()) return;

        instantiate(buildClassName(ctl));
    }

    // =========================================================
    // CASE 9: PREFIX VALIDATION + LENGTH
    // =========================================================

    @Case("(s'Safe') -> ok")
    @Case("(s'SafeWrapper') -> assertion error")
    public static void prefix_dispatcher(String ctl) {

        String normalized = sanitizeInput(ctl);

        if (!prefixValidation(normalized)) {
            return;
        }

        if (normalized.length() > 30) {
            return;
        }

        instantiate(buildClassName(normalized));
    }

    // =========================================================
    // CASE 10: INDIRECT CLASS NAME CONSTRUCTION
    // =========================================================

    private static String getNamespace(int version) {

        if (version == 1) {
            return classPrefix();
        }

        return classPrefix();
    }

    private static String getSuffix(boolean legacy) {

        if (legacy) {
            return "Command";
        }

        return "Command";
    }

    @Case("(s'__CANARY__', i'1', i'1') -> assertion error")
    @Case("(s'Safe', i'1', i'1') -> ok")
    public static void indirect_construction_dispatcher(
            String ctl,
            int version,
            int legacy) {

        if (version < 1 || version > 3) return;
        if (legacy != 1) return;

        String namespace = getNamespace(version);
        String suffix = getSuffix(legacy == 1);

        String className =
                namespace + sanitizeInput(ctl) + suffix;

        instantiate(className);
    }

    // =========================================================
    // CASE 11: MULTI-PARAMETER PROPAGATION
    // =========================================================

    private static String prepareRequest(
            String command,
            String tenant,
            String environment,
            String operation) {

        if (!"production".equals(environment)) {
            return "Safe";
        }

        if (!"execute".equals(operation)) {
            return "Safe";
        }

        if (tenant.isEmpty()) {
            return "Safe";
        }

        return command;
    }

    private static void processRequest(
            String command,
            String tenant,
            String environment,
            String operation) {

        String prepared = prepareRequest(
                command,
                tenant,
                environment,
                operation);

        instantiate(buildClassName(prepared));
    }

    @Case("(s'__CANARY__', s'tenant1', s'production', s'execute') -> assertion error")
    @Case("(s'Safe', s'tenant1', s'production', s'execute') -> ok")
    public static void object_propagation_dispatcher(
            String ctl,
            String tenant,
            String environment,
            String operation) {

        processRequest(
                ctl,
                tenant,
                environment,
                operation);
    }

    // =========================================================
    // CASE 12: TWO-STAGE VALIDATION
    // =========================================================

    private static boolean checkRole(String role) {

        return "operator".equals(role)
                || "admin".equals(role);
    }

    private static boolean checkEnvironment(String environment) {

        return "production".equals(environment)
                || "staging".equals(environment);
    }

    @Case("(s'__CANARY__', s'admin', s'production', i'1') -> assertion error")
    @Case ("(s'Safe', s'admin', s'production', i'1') -> ok")
    public static void two_stage_validation_dispatcher(
            String ctl,
            String role,
            String environment,
            int approved) {

        if (!checkRole(role)) return;
        if (!checkEnvironment(environment)) return;
        if (approved != 1) return;

        String cleaned = normalizePath(ctl);

        if (!weakValidation(cleaned)) return;

        instantiate(buildClassName(cleaned));
    }

    // =========================================================
    // CASE 13: ALIAS-BASED INDIRECT DISPATCH
    // =========================================================

    private static String resolveAlias(String input) {

        if ("export".equals(input)) {
            return "Export";
        }

        if ("backup".equals(input)) {
            return "Backup";
        }

        if ("report".equals(input)) {
            return "Report";
        }

        // Unsafe fallback.
        return input;
    }

    @Case("(s'__CANARY__') -> assertion error")
    @Case("(s'export') -> ok")
    public static void alias_dispatcher(String ctl) {

        String command = resolveAlias(ctl);

        if (!weakValidation(command)) return;

        instantiate(buildClassName(command));
    }

    // =========================================================
    // CASE 14: CHAINED SANITIZATION
    // =========================================================

    private static String firstSanitization(String input) {

        if (input.startsWith(" ")) {
            return "Safe";
        }

        return input;
    }

    private static String secondSanitization(String input) {

        if (input.contains("-")) {
            return "Safe";
        }

        return input;
    }

    private static String thirdSanitization(String input) {

        if (input.endsWith(" ")) {
            return "Safe";
        }

        return input;
    }

    @Case("(s'__CANARY__') -> assertion error")
    @Case("(s'Safe') -> ok")
    public static void chained_sanitization_dispatcher(String ctl) {

        String value = firstSanitization(ctl);
        value = secondSanitization(value);
        value = thirdSanitization(value);
        value = sanitizeIdentifier(value);

        if (!weakValidation(value)) return;

        instantiate(buildClassName(value));
    }

    // =========================================================
    // CASE 15: CONTROL-FLOW DEPENDENT DISPATCH
    // =========================================================

    private static boolean checkFeatureFlag(int feature) {
        return feature == 1;
    }

    private static boolean checkPermission(int permission) {
        return permission > 0 && permission < 5;
    }

    @Case("(s'__CANARY__', i'1', i'2', i'1') -> assertion error")
    @Case("(s'Safe', i'1', i'2', i'1') -> ok")
    public static void conditional_dispatcher(
            String ctl,
            int feature,
            int permission,
            int authenticated) {

        if (!checkFeatureFlag(feature)) return;
        if (!checkPermission(permission)) return;
        if (authenticated != 1) return;

        String command = sanitizeInput(ctl);

        if (command.length() < 3) return;

        instantiate(buildClassName(command));
    }

    // =========================================================
    // CASE 16: DEEP CALL CHAIN + MULTIPLE PARAMETERS
    // =========================================================

    private static String stageOne(
            String command,
            String tenant,
            int version) {

        if (version != 2) return "Safe";
        if (tenant.isEmpty()) return "Safe";

        return command;
    }

    private static String stageTwo(
            String command,
            String environment,
            boolean enabled) {

        if (!enabled) return "Safe";

        if (!"production".equals(environment)) {
            return "Safe";
        }

        return command;
    }

    private static String stageThree(
            String command,
            int priority,
            boolean authorized) {

        if (!authorized) return "Safe";
        if (priority < 1) return "Safe";

        return buildClassName(command);
    }

    private static void stageFour(
            String className,
            String auditId,
            int executionMode) {

        if (executionMode != 1) return;
        if (auditId.isEmpty()) return;

        instantiate(className);
    }

    @Case("(s'__CANARY__', s'tenant1', i'2', s'production', i'1', s'audit1', i'1') -> assertion error")
    @Case("(s'Safe', s'tenant1', i'2', s'production', i'1', s'audit1', i'1') -> ok")
    public static void deep_chain_dispatcher(
            String ctl,
            String tenant,
            int version,
            String environment,
            int priority,
            String auditId,
            int executionMode) {

        String first = stageOne(
                ctl,
                tenant,
                version);

        String second = stageTwo(
                first,
                environment,
                true);

        String third = stageThree(
                second,
                priority,
                true);

        stageFour(
                third,
                auditId,
                executionMode);
    }

    // =========================================================
    // CASE 17: PARTIAL ALLOWLIST WITH UNSAFE FALLBACK
    // =========================================================

    private static boolean isKnownCommand(String input) {

        return "Safe".equals(input)
                || "Export".equals(input)
                || "Backup".equals(input);
    }

    private static String validateOrFallback(String input) {

        if (isKnownCommand(input)) {
            return input;
        }

        // Incorrect fallback: original input survives.
        return sanitizeIdentifier(input);
    }

    @Case("(s'__CANARY__') -> assertion error")
    @Case("(s'Safe') -> ok")
    public static void fallback_dispatcher(String ctl) {

        String command = validateOrFallback(ctl);

        if (!weakValidation(command)) return;

        instantiate(buildClassName(command));
    }

    // =========================================================
    // CASE 18: SAFE ALLOWLIST DISPATCHER
    // =========================================================

    private static boolean isAllowed(String input) {

        return "Safe".equals(input)
                || "Export".equals(input)
                || "Backup".equals(input)
                || "Report".equals(input)
                || "Cleanup".equals(input);
    }

    @Case("(s'Safe') -> ok")
    @Case("(s'__CANARY__') -> ok")
    public static void allowlist_dispatcher(String ctl) {

        if (ctl == null) return;
        if (!isAllowed(ctl)) return;

        instantiate(buildClassName(ctl));
    }
}
