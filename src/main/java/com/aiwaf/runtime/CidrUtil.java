package com.aiwaf.runtime;

public final class CidrUtil {
    private CidrUtil() {}

    public static boolean contains(String cidr, String ip) {
        try {
            String[] parts = cidr.split("/");
            if (parts.length != 2) return false;
            int prefix = Integer.parseInt(parts[1]);
            long net = ipToLong(parts[0]);
            long target = ipToLong(ip);
            long mask = prefix == 0 ? 0L : 0xFFFFFFFFL << (32 - prefix);
            return (net & mask) == (target & mask);
        } catch (Exception e) {
            return false;
        }
    }

    private static long ipToLong(String ip) {
        String[] s = ip.split("\\.");
        if (s.length != 4) throw new IllegalArgumentException("invalid ip");
        long a = Long.parseLong(s[0]);
        long b = Long.parseLong(s[1]);
        long c = Long.parseLong(s[2]);
        long d = Long.parseLong(s[3]);
        return (a << 24) | (b << 16) | (c << 8) | d;
    }
}
