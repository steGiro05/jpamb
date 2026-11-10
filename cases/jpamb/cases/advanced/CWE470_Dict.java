package jpamb.cases.advanced;

import jpamb.utils.*;

public class CWE470_Dict {

    public static void canary() {
        throw new AssertionError("Vulnerability Reached: Canary Loaded!");
    }

    public static class __CANARY__Command {
        public __CANARY__Command() { canary(); }
    }
    public static class SafeCommand {
        public SafeCommand() {}
    }

    private static void invokeReflection(String shortName) {
        try {
            String fullName = "jpamb.cases.advanced.CWE470_Dict$" + shortName;
            Class<?> cmdClass = Class.forName(fullName);
            cmdClass.newInstance();
        } catch (Exception e) {
            return;
        }
    }

    @Case("(s'AUTH:EXEC:SafeCommand') -> ok")
    @Case("(s'AUTH:EXEC:__CANARY__Command') -> assertion error")
    public static void split_payload(String payload) {
        String[] parts = payload.split(":");
        if (parts.length != 3) return;
        if (!parts[0].equals("AUTH")) return;
        if (!parts[1].equals("EXEC")) return;
        
        invokeReflection(parts[2]);
    }

    @Case("(s'CMD_START:SafeCommand:CMD_END') -> ok")
    @Case("(s'CMD_START:__CANARY__Command:CMD_END') -> assertion error")
    public static void wrapped_payload(String payload) {
        if (!payload.startsWith("CMD_START:")) return;
        if (!payload.endsWith(":CMD_END")) return;
        
        String shortName = payload.substring(10, payload.length() - 8);
        invokeReflection(shortName);
    }

    @Case("(s'ALPHA', s'BETA', s'GAMMA', s'DELTA', s'SafeCommand') -> ok")
    @Case("(s'ALPHA', s'BETA', s'GAMMA', s'DELTA', s'__CANARY__Command') -> assertion error")
    public static void combinatorial_explosion(String p1, String p2, String p3, String p4, String shortName) {
        if (!p1.equals("ALPHA")) return;
        if (!p2.equals("BETA")) return;
        if (!p3.equals("GAMMA")) return;
        if (!p4.equals("DELTA")) return;
        invokeReflection(shortName);
    }
    
    @Case("(s'__ADMIN__SafeCommand__EXEC__') -> ok")
    @Case("(s'__ADMIN____CANARY__Command__EXEC__') -> assertion error")
    public static void length_and_bounds(String payload) {
        if (payload.length() < 25) return;
        if (!payload.startsWith("__ADMIN__")) return;
        if (!payload.endsWith("__EXEC__")) return;
        
        String shortName = payload.substring(9, payload.length() - 8);
        invokeReflection(shortName);
    }
}