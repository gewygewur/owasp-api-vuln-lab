package edu.nu.owaspapivulnlab.web;

import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.HashMap;
import java.util.Map;

// FIXED(API7: Security Misconfiguration) - reduced error detail in responses, safe logging
@ControllerAdvice
public class GlobalErrorHandler {

    // Generic error handler (safe response)
    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleGeneric(Exception e) {
        // Log detailed error internally for debugging
        System.err.println("Internal Server Error: " + e.getClass().getName() + " - " + e.getMessage());

        // Send a generic response to clients
        Map<String, String> errorMap = new HashMap<>();
        errorMap.put("error", "Internal server error occurred");
        errorMap.put("hint", "Please contact support if the issue persists");
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorMap);
    }

    // Database error handler (safe output)
    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<?> handleDatabase(DataAccessException e) {
        // Log technical details internally
        System.err.println("Database Error: " + e.getMessage());

        // Return safe, non-verbose message
        Map<String, String> errorMap = new HashMap<>();
        errorMap.put("error", "A database error occurred");
        errorMap.put("hint", "Please try again later");
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorMap);
    }
}
