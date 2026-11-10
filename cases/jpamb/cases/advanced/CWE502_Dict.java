package jpamb.cases.advanced;

import jpamb.utils.*;

public class CWE502_Dict {

    public static void canary() {
        throw new AssertionError("Vulnerability Reached: Canary Loaded via Deserialization!");
    }

    private static final String EXPECTED_HEADER = "SER";

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
        if (className.equals("__CANARY__Gadget")) return new __CANARY__Gadget();
        
        if (className.equals("ParametricGadget")) {
            int token = Integer.parseInt(parts[2]);
            String command = parts[3];
            return new ParametricGadget(token, command);
        }
        
        throw new ClassNotFoundException("Invalid class");
    }

    public static class __CANARY__Gadget {
        public __CANARY__Gadget() { canary(); }
    }
    
    public static class SafeGadget {
        public SafeGadget() {}
    }

    public static class ParametricGadget {
        public ParametricGadget(int token, String command) {
            if (token == 9 && "EXEC".equals(command)) {
                canary();
            }
        }
    }

    // ---------------------------------------------------------
    // TEST CASES
    // ---------------------------------------------------------

    @Case("(s'V1.0:TRUSTED:SER|SafeGadget|') -> ok")
    @Case("(s'V1.0:TRUSTED:SER|__CANARY__Gadget|') -> assertion error")
    public static void protocol_split(String payload) {
        String[] parts = payload.split(":");
        if (parts.length != 3) return;
        if (!parts[0].equals("V1.0")) return;
        if (!parts[1].equals("TRUSTED")) return;
        
        try { simulateReadObject(parts[2]); } catch (Exception e) {}
    }

    @Case("(s'OBJ_START_SER|SafeGadget|_OBJ_END') -> ok")
    @Case("(s'OBJ_START_SER|__CANARY__Gadget|_OBJ_END') -> assertion error")
    public static void signed_envelope(String payload) {
        if (!payload.startsWith("OBJ_START_")) return;
        if (!payload.endsWith("_OBJ_END")) return;
        
        String serializedData = payload.substring(10, payload.length() - 8);
        
        try { simulateReadObject(serializedData); } catch (Exception e) {}
    }

    @Case("(s'API_KEY_99', s'v2', s'PROD', s'admin', s'SER|SafeGadget|') -> ok")
    @Case("(s'API_KEY_99', s'v2', s'PROD', s'admin', s'SER|__CANARY__Gadget|') -> assertion error")
    public static void combinatorial_auth(String key, String version, String env, String role, String serPayload) {
        if (!key.equals("API_KEY_99")) return;
        if (!version.equals("v2")) return;
        if (!env.equals("PROD")) return;
        if (!role.equals("admin")) return;
        
        try { simulateReadObject(serPayload); } catch (Exception e) {}
    }

    @Case("(s'ENVELOPE:SER|ParametricGadget|0|SAFE') -> ok")
    @Case("(s'ENVELOPE:SER|ParametricGadget|9|EXEC') -> assertion error")
    public static void envelope_and_object_params(String payload) {
        if (!payload.startsWith("ENVELOPE:")) return;
        
        String serializedData = payload.substring(9);
        
        try { simulateReadObject(serializedData); } catch (Exception e) {}
    }
}