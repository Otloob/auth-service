package org.spring.authservice.service;

import java.util.Locale;

public final class DeviceNameResolver {
    private DeviceNameResolver() {}

    public static String resolve(String userAgent) {
        if (userAgent == null || userAgent.isBlank()) return "Unknown device";

        String agent = userAgent.toLowerCase(Locale.ROOT);
        String platform = firstMatch(agent,
                new String[][] {
                        {"ipad", "iPad"},
                        {"iphone", "iPhone"},
                        {"android", "Android"},
                        {"windows", "Windows"},
                        {"mac os", "macOS"},
                        {"linux", "Linux"}
                });
        String browser = firstMatch(agent,
                new String[][] {
                        {"edg/", "Edge"},
                        {"firefox/", "Firefox"},
                        {"chrome/", "Chrome"},
                        {"safari/", "Safari"},
                        {"postmanruntime", "Postman"}
                });

        String name = platform.equals("Unknown") ? browser : browser.equals("Unknown")
                ? platform
                : platform + " · " + browser;
        if (name.equals("Unknown")) return "Unknown device";
        return name.length() <= 100 ? name : name.substring(0, 100);
    }

    private static String firstMatch(String value, String[][] candidates) {
        for (String[] candidate : candidates) {
            if (value.contains(candidate[0])) return candidate[1];
        }
        return "Unknown";
    }
}
