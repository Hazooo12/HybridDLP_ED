rule Phone_Number_Bulk {
    meta:
        description = "Detect bulk phone numbers (potential contact list)"
        severity = "medium"
        author = "HybridDLP"
    
    strings:
        // Vietnam phone numbers
        // Mobile: 09x, 08x, 07x, 03x (10 digits)
        // Landline: 02x (9-10 digits)
        $mobile = /\b(09|08|07|03)[0-9]{8}\b/
        $landline = /\b02[0-9]{7,8}\b/
        
        // International format (with country code)
        $international = /\b\+84[0-9]{9,10}\b/
        
        // Keywords indicating phone list (English)
        $keyword1 = "phone" nocase
        $keyword2 = "mobile" nocase
        $keyword3 = "contact" nocase
        $keyword4 = "contact list" nocase
        $keyword5 = "phone number" nocase
        $keyword6 = "telephone" nocase
        $keyword7 = "call" nocase
        $keyword8 = "tel" nocase
        
        // Keywords (Vietnamese)
        $keyword9 = "số điện thoại" nocase
        $keyword10 = "danh bạ" nocase
        $keyword11 = "điện thoại" nocase
        $keyword12 = "liên hệ" nocase
        $keyword13 = "hotline" nocase
    
    condition:
        // Match if multiple phone numbers found (potential contact list)
        (#mobile + #landline + #international) > 5 and
        ($keyword1 or $keyword2 or $keyword3 or $keyword4 or $keyword5 or $keyword6 or
         $keyword7 or $keyword8 or $keyword9 or $keyword10 or $keyword11 or $keyword12 or $keyword13)
}
