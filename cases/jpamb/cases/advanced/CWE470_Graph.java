package jpamb.cases.advanced;

import jpamb.utils.*;

public class CWE470_Graph {

    public static void canary() {
        throw new AssertionError("Vulnerability Reached: Canary Loaded via Reflection Chain!");
    }

    public static class __CANARY__Command {
        public __CANARY__Command() { canary(); }
    }
    
    public static class SafeCommand {
        public SafeCommand() {}
    }

    // Each call site accepts only two command classes, so the fuzzer cannot
    private static void invokeReflection(String shortName, String allowedA, String allowedB) {
        if (!allowedA.equals(shortName) && !allowedB.equals(shortName)) {
            return;
        }
        try {
            String fullName = "jpamb.cases.advanced.CWE470_Graph$" + shortName;
            Class<?> cmdClass = Class.forName(fullName);
            cmdClass.newInstance();
        } catch (Exception e) {
            return;
        }
    }

    public static class PreChain_Router {
        public void route(String auth, String payload) {
            if ("VALID".equals(auth)) {
                new PreChain_Handler().handle(payload);
            }
        }
    }

    public static class PreChain_Handler {
        public void handle(String payload) {
            invokeReflection(payload, "SafeCommand", "__CANARY__Command");
        }
    }

    public static class Deep_Dispatcher {
        public void dispatch(String p3, String p4, String payload) {
            if ("GAMMA".equals(p3) && "DELTA".equals(p4)) {
                invokeReflection(payload, "SafeCommand", "__CANARY__Command");
            }
        }
    }

    public static class Chain3_Start {
        public Chain3_Start() {
            String state = "READY";
            if ("READY".equals(state)) {
                new Chain3_Middle();
            }
        }
    }
    public static class Chain3_Middle {
        public Chain3_Middle() {
            String check = "OK";
            if (check.length() == 2) {
                if ("OK".equals(check)) {
                    new Chain3_End();
                }
            }
        }
    }
    public static class Chain3_End {
        public Chain3_End() { canary(); }
    }

    public static class DeadEnd_Router {
        public DeadEnd_Router() {
            String dummy = "trap";
            if ("trap".equals(dummy)) {
                String moreDummy = dummy + "_coverage";
                if (moreDummy.startsWith("trap")) {
                    String finalDummy = "stuck";
                }
            }
        }
    }

    @Case("(s'AUTH_ADMIN', s'TOKEN_99', s'SafeCommand') -> ok")
    @Case("(s'AUTH_ADMIN', s'TOKEN_99', s'__CANARY__Command') -> assertion error")
    public static void complex_multiple_checks(String p1, String p2, String payload) {
        if (p1 != null && p1.startsWith("AUTH_")) {
            if (p2 != null && p2.endsWith("_99")) {
                if ("AUTH_ADMIN".equals(p1) && "TOKEN_99".equals(p2)) {
                    invokeReflection(payload, "SafeCommand", "__CANARY__Command");
                }
            }
        }
    }

    @Case("(s'VALID', s'SafeCommand') -> ok")
    @Case("(s'VALID', s'__CANARY__Command') -> assertion error")
    public static void pre_reflection_chain(String auth, String payload) {
        new PreChain_Router().route(auth, payload);
    }

    @Case("(s'SafeCommand') -> ok")
    @Case("(s'Chain3_Start') -> assertion error")
    public static void post_reflection_chain(String payload) {
        invokeReflection(payload, "SafeCommand", "Chain3_Start");
    }

    @Case("(s'FAKE', s'SafeCommand') -> ok")
    @Case("(s'REAL', s'__CANARY__Command') -> assertion error")
    public static void deadend_callgraph(String route, String payload) {
        if ("FAKE".equals(route)) {
            new DeadEnd_Router(); 
        } else if ("REAL".equals(route)) {
            new PreChain_Router().route("VALID", payload); 
        }
    }

    @Case("(s'ALPHA', s'BETA', s'GAMMA', s'DELTA', s'SafeCommand') -> ok")
    @Case("(s'ALPHA', s'BETA', s'GAMMA', s'DELTA', s'__CANARY__Command') -> assertion error")
    public static void many_params_deep_sink(String p1, String p2, String p3, String p4, String payload) {
        if ("ALPHA".equals(p1)) {
            if (p2 != null && p2.contains("BETA")) {
                new Deep_Dispatcher().dispatch(p3, p4, payload);
            }
        }
    }
}