rule Email_Single {
    meta:
        description = "Detect single email address in sensitive context"
        severity = "medium"
        author = "HybridDLP"
        confidence = "medium"
    
    strings:
        // Email pattern (improved to reduce false positives)
        $email = /\b[a-zA-Z0-9][a-zA-Z0-9._%+-]*@[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}\b/
        
        // Context keywords indicating sensitive context
        $keyword1 = "email" nocase
        $keyword2 = "contact" nocase
        $keyword3 = "mail" nocase
        $keyword4 = "gmail" nocase
        $keyword5 = "outlook" nocase
        $keyword6 = "yahoo" nocase
        $keyword7 = "CMND" nocase  // Email with ID = sensitive
        $keyword8 = "CCCD" nocase
        $keyword9 = "nhân viên" nocase  // Employee email
        $keyword10 = "employee" nocase
        $keyword11 = "customer" nocase
        $keyword12 = "khách hàng" nocase
        $keyword13 = "client" nocase
        $keyword14 = "user" nocase
        $keyword15 = "account" nocase
        $keyword16 = "tài khoản" nocase
        $keyword17 = "đăng nhập" nocase
        $keyword18 = "login" nocase
    
    condition:
        // Match email AND sensitive context
        $email and
        ($keyword1 or $keyword2 or $keyword3 or $keyword4 or $keyword5 or 
         $keyword6 or $keyword7 or $keyword8 or $keyword9 or $keyword10 or
         $keyword11 or $keyword12 or $keyword13 or $keyword14 or $keyword15 or
         $keyword16 or $keyword17 or $keyword18)
}
