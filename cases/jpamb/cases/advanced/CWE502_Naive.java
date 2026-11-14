package jpamb.cases.advanced;

import jpamb.utils.*;

public class CWE502_Naive {

    public static void canary() {
        throw new AssertionError("Vulnerability Reached: Canary Loaded!");
    }

    private static final String EXPECTED_HEADER = "SER";

    public static String simulateResolveClassName(String payload) throws Exception {
        String[] parts = payload.split("\\|", -1);
        if (parts.length != 3 || !EXPECTED_HEADER.equals(parts[0])) {
            throw new IllegalArgumentException("Invalid payload");
        }
        return parts[1];
    }

    public static Object simulateReadObject(String payload) throws Exception {
        String className = simulateResolveClassName(payload);
        String[] parts = payload.split("\\|", -1);
        String params = parts[2];

        if (className.equals("SafeCommand")) return new SafeCommand();
        if (className.equals("__CANARY__Command")) return new __CANARY__Command();
        if (className.equals("UpdatedLibrary")) return new UpdatedLibrary();
        
        if (className.equals("ParametricGadget")) {
            int token = Integer.parseInt(params);
            return new ParametricGadget(token);
        }
        
        throw new ClassNotFoundException("Invalid class");
    }

    public static class __CANARY__Command {
        public __CANARY__Command() { canary(); }
    }
    public static class SafeCommand {}
    public static class NotMaintainedDependency {
        public NotMaintainedDependency() { new __CANARY__Command(); }
    }
    public static class UpdatedLibrary {
        public UpdatedLibrary() { new NotMaintainedDependency(); }
    }
    
    public static class ParametricGadget {
        public ParametricGadget(int token) {
            if (token == 9) {
                canary();
            }
        }
    }

    @Case("(s'SER|SafeCommand|') -> ok")
    @Case("(s'SER|__CANARY__Command|') -> assertion error")
    public static void direct_deserialization(String payload) {
        try { simulateReadObject(payload); } catch (Exception e) {}
    }

    @Case("(s'SER|__CANARY__Command|', i'0') -> ok")
    @Case("(s'SER|__CANARY__Command|', i'1') -> assertion error")
    public static void int_boolean_guarded(String payload, int trigger) {
        if (trigger != 1) return;
        try { simulateReadObject(payload); } catch (Exception e) {}
    }

    @Case("(s'SER|SafeCommand|', i'0') -> ok")
    @Case("(s'SER|__CANARY__Command|', i'7') -> assertion error")
    public static void int_guarded_function(String payload, int token) {
        if (token != 7) return;
        try { simulateReadObject(payload); } catch (Exception e) {}
    }

    @Case("(s'SER|ParametricGadget|0') -> ok")
    @Case("(s'SER|ParametricGadget|9') -> assertion error")
    public static void object_param_deserialization(String payload) {
        try { simulateReadObject(payload); } catch (Exception e) {}
    }

    @Case("(s'SER|__CANARY__Command|') -> ok")
    @Case("(s'SER|UpdatedLibrary|') -> assertion error")
    public static void blacklist_deserialization(String payload) {
        try {
            String className = simulateResolveClassName(payload);
            if (className.equals("__CANARY__Command")) return;
            simulateReadObject(payload);
        } catch (Exception e) {}
    }
}