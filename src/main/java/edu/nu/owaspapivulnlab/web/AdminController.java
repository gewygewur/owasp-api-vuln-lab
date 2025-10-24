package edu.nu.owaspapivulnlab.web;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.util.HashMap;
import java.util.Map;

import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final AppUserRepository users;

    public AdminController(AppUserRepository users) {
        this.users = users;
    }

    // FIXED(API7: Security Misconfiguration)
    // Restrict /metrics to ADMIN only and avoid exposing detailed system info to regular users
    @GetMapping("/metrics")
    public ResponseEntity<?> metrics(Authentication auth) {
        AppUser me = users.findByUsername(auth.getName()).orElse(null);
        if (me == null) {
            return ResponseEntity.status(401).body("Unauthorized - please log in");
        }

        if (!me.isAdmin()) {
            return ResponseEntity.status(403).body("Forbidden - only admins can access server metrics");
        }

        RuntimeMXBean rt = ManagementFactory.getRuntimeMXBean();
        Map<String, Object> metricsMap = new HashMap<>();
        metricsMap.put("uptimeMs", rt.getUptime());
        metricsMap.put("javaVersion", System.getProperty("java.version"));
        metricsMap.put("threadCount", ManagementFactory.getThreadMXBean().getThreadCount());
        return ResponseEntity.ok(metricsMap);
    }
}
