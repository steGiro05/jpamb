package jpamb.cases.advanced;

import jpamb.utils.*;

public class CWE470_Naive {

    public static void canary() {
        throw new AssertionError("Vulnerability Reached: Canary Loaded!");
    }

    public static class __CANARY__Command {
        public __CANARY__Command() { canary(); }
    }
    public static class SafeCommand {
        public void doAction() {}
    }
    public static class SafeWrapperCommand extends __CANARY__Command {}

    private static void invokeReflection(String ctl) {
        String className = "jpamb.cases.advanced.CWE470_Naive$" + ctl;
        try {
            Class<?> cmdClass = Class.forName(className);
            SafeCommand ao = (SafeCommand) cmdClass.newInstance();
            ao.doAction();
        } catch (Exception e) {
            return;
        }
    }

    @Case("(s'SafeCommand') -> ok")
    @Case("(s'__CANARY__Command') -> assertion error")
    public static void direct_reflection(String ctl) {
        invokeReflection(ctl);
    }

    @Case("(s'__CANARY__Command', i'0') -> ok")
    @Case("(s'__CANARY__Command', i'1') -> assertion error")
    public static void int_boolean_guarded(String ctl, int enable) {
        if (enable != 1) return;
        invokeReflection(ctl);
    }

    @Case("(s'SafeCommand', i'0') -> ok")
    @Case("(s'__CANARY__Command', i'4') -> assertion error")
    public static void int_guarded(String ctl, int pin) {
        if (pin != 4) return;
        invokeReflection(ctl);
    }

    @Case("(s'SafeCommand', i'0', i'0') -> ok")
    @Case("(s'__CANARY__Command', i'9', i'9') -> assertion error")
    public static void math_guarded(String ctl, int a, int b) {
        if (a + b != 18) return;
        invokeReflection(ctl);
    }

    @Case("(s'__CANARY__Command') -> ok")
    @Case("(s'SafeWrapperCommand') -> assertion error")
    public static void blacklist_evasion(String ctl) {
        if ("__CANARY__Command".equals(ctl)) return;
        invokeReflection(ctl);
    }
}


/* CONSIDERATIONS */
// The naive approach manages to score max on this test case, however the case math_guarded with two integer combinations require running the interpreter with 10000 tests to exploit the combination 9,9