package jpamb.cases.advanced;

import jpamb.utils.*;

public class CWE502_Graph {

    public static void canary() {
        throw new AssertionError("Vulnerability Reached: Canary Loaded via Gadget Chain!");
    }

    private static final String EXPECTED_HEADER = "SER";

    public static String simulateResolveClassName(String payload) throws Exception {
        String[] parts = payload.split("\\|", -1);
        if (parts.length < 3 || !EXPECTED_HEADER.equals(parts[0])) {
            throw new IllegalArgumentException("Invalid payload");
        }
        return parts[1];
    }

    // Each entry point accepts only two classes, like an ObjectInputFilter
    public static Object simulateReadObject(String payload, String allowedA, String allowedB) throws Exception {
        String className = simulateResolveClassName(payload);
        String[] parts = payload.split("\\|", -1);

        if (!allowedA.equals(className) && !allowedB.equals(className)) {
            throw new ClassNotFoundException("Class not allowed");
        }

        if (className.equals("SafeGadget")) return new SafeGadget();
        if (className.equals("__CANARY__Command")) return new __CANARY__Command();
        
        if (className.equals("Chain2_Start")) {
            return new Chain2_Start();
        }
        
        if (className.equals("Chain3_Start") && parts.length >= 4) {
            return new Chain3_Start(parts[2], parts[3]);
        }
        
        if (className.equals("Chain4_Start") && parts.length >= 3) {
            return new Chain4_Start(parts[2]);
        }
        
        if (className.equals("Chain5_Start") && parts.length >= 6) {
            return new Chain5_Start(parts[2], parts[3], parts[4], parts[5]);
        }

        throw new ClassNotFoundException("Invalid class");
    }

    public static class SafeGadget {
        public SafeGadget() {}
    }
    public static class __CANARY__Command {
        public __CANARY__Command() { canary(); }
    }

    public static class Chain2_Start {
        public Chain2_Start() { new Chain2_End(); }
    }
    public static class Chain2_End {
        public Chain2_End() { new __CANARY__Command(); }
    }

    public static class Chain3_Start {
        public Chain3_Start(String auth, String cmd) {
            if ("ROOT".equals(auth)) {
                new Chain3_Middle(cmd);
            }
        }
    }
    public static class Chain3_Middle {
        public Chain3_Middle(String cmd) {
            if ("EXEC".equals(cmd)) {
                new Chain3_End();
            }
        }
    }
    public static class Chain3_End {
        public Chain3_End() { new __CANARY__Command(); }
    }

    public static class Chain4_Start {
        public Chain4_Start(String route) {
            if ("FAKE".equals(route)) {
                new Chain4_Fake1();
            } else if ("REAL".equals(route)) {
                new Chain4_Real();
            }
        }
    }
    public static class Chain4_Fake1 {
        public Chain4_Fake1() {
            String decoy = "trap";
            if (decoy.length() == 4) {
                if (decoy.startsWith("tr")) {
                    String ignored = decoy + "_end";
                }
            }
        }
    }
    public static class Chain4_Real {
        public Chain4_Real() { new __CANARY__Command(); }
    }

    public static class Chain5_Start {
        public Chain5_Start(String p1, String p2, String p3, String p4) {
            if ("ALPHA".equals(p1)) {
                if ("BETA".equals(p2)) {
                    if ("BAIT".equals(p3)) {
                        String bait = "stuck";
                    }
                    if ("GAMMA".equals(p3)) {
                        if ("DELTA".equals(p4)) {
                            new Chain5_End();
                        }
                    }
                }
            }
        }
    }
    public static class Chain5_End {
        public Chain5_End() { new __CANARY__Command(); }
    }



    @Case("(s'API_ADMIN', s'TOKEN_OK', s'SER|SafeGadget|') -> ok")
    @Case("(s'API_ADMIN', s'TOKEN_OK', s'SER|__CANARY__Command|') -> assertion error")
    public static void multiple_checks(String p1, String p2, String payload) {
        if (p1 != null && p1.startsWith("API_")) {
            if (p2 != null && p2.endsWith("_OK")) {
                if ("API_ADMIN".equals(p1) && "TOKEN_OK".equals(p2)) {
                    try { simulateReadObject(payload, "SafeGadget", "__CANARY__Command"); } catch (Exception e) {}
                }
            }
        }
    }

    @Case("(s'SER|SafeGadget|') -> ok")
    @Case("(s'SER|Chain2_Start|') -> assertion error")
    public static void two_step_chain(String payload) {
        try { simulateReadObject(payload, "SafeGadget", "Chain2_Start"); } catch (Exception e) {}
    }

    @Case("(s'SER|Chain3_Start|USER|SAFE') -> ok")
    @Case("(s'SER|Chain3_Start|ROOT|EXEC') -> assertion error")
    public static void scattered_checks_chain(String payload) {
        try { simulateReadObject(payload, "SafeGadget", "Chain3_Start"); } catch (Exception e) {}
    }

    @Case("(s'SER|Chain4_Start|FAKE') -> ok")
    @Case("(s'SER|Chain4_Start|REAL') -> assertion error")
    public static void deadend_callgraph(String payload) {
        try { simulateReadObject(payload, "SafeGadget", "Chain4_Start"); } catch (Exception e) {}
    }

    @Case("(s'SER|Chain5_Start|WRONG|BETA|GAMMA|DELTA') -> ok")
    @Case("(s'SER|Chain5_Start|ALPHA|BETA|GAMMA|DELTA') -> assertion error")
    public static void many_params_chain(String payload) {
        try { simulateReadObject(payload, "SafeGadget", "Chain5_Start"); } catch (Exception e) {}
    }
}