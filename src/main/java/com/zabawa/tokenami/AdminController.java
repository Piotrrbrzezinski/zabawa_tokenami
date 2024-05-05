package com.zabawa.tokenami;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin")
public class AdminController {

    @GetMapping("/data")
    @PreAuthorize("hasRole('ADMIN')")  // Wymaga roli ADMIN do dostępu
    public ResponseEntity<String> getAdminData() {
        return ResponseEntity.ok("Tajne dane dostępne tylko dla adminów");
    }
}
