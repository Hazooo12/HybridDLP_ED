rule Phone_Number_Single {
    meta:
        description = "Detect single phone number in sensitive context"
        severity = "medium"
        author = "HybridDLP"
        confidence = "medium"
    
    strings:
        // Vietnam phone numbers
        // Mobile: 09x, 08x, 07x, 03x (10 digits)
        $mobile = /\b(09|08|07|03)[0-9]{8}\b/
        
        // Landline: 02x (9-10 digits)
        $landline = /\b02[0-9]{7,8}\b/
        
        // International format (with country code)
        $international = /\b\+84[0-9]{9,10}\b/
        $international2 = /\b84[0-9]{9,10}\b/  // Without +
        
        // Context keywords indicating sensitive context
        $keyword1 = "số điện thoại" nocase
        $keyword2 = "phone" nocase
        $keyword3 = "mobile" nocase
        $keyword4 = "contact" nocase
        $keyword5 = "danh bạ" nocase
        $keyword6 = "điện thoại" nocase
        $keyword7 = "hotline" nocase
        $keyword8 = "liên hệ" nocase
        $keyword9 = "call" nocase
        $keyword10 = "tel" nocase
        $keyword11 = "CMND" nocase  // Phone with ID = sensitive
        $keyword12 = "CCCD" nocase
        $keyword13 = "nhân viên" nocase  // Employee phone
        $keyword14 = "customer" nocase
        $keyword15 = "khách hàng" nocase
    
    condition:
        // Match phone number AND sensitive context
        ($mobile or $landline or $international or $international2) and
        ($keyword1 or $keyword2 or $keyword3 or $keyword4 or $keyword5 or 
         $keyword6 or $keyword7 or $keyword8 or $keyword9 or $keyword10 or
         $keyword11 or $keyword12 or $keyword13 or $keyword14 or $keyword15)
}
