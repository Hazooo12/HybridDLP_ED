rule Vietnam_ID_Card {
    meta:
        description = "Detect Vietnam ID card numbers (CMND/CCCD) with keywords"
        severity = "high"
        author = "HybridDLP"
        confidence = "high"  // High vì có keywords
    
    strings:
        // CMND: exactly 9 digits (standalone)
        $cmnd = /\b[0-9]{9}\b/
        
        // CCCD: exactly 12 digits (standalone)
        $cccd = /\b[0-9]{12}\b/
        
        // Keywords (Vietnamese)
        $keyword1 = "CMND" nocase
        $keyword2 = "CCCD" nocase
        $keyword3 = "Chứng minh nhân dân" nocase
        $keyword4 = "Căn cước công dân" nocase
        $keyword5 = "Căn cước" nocase
        $keyword6 = "Số CMND" nocase
        $keyword7 = "Số CCCD" nocase
        $keyword8 = "Mã số" nocase
        $keyword9 = "Số định danh" nocase
        $keyword10 = "định danh" nocase
        $keyword11 = "chứng minh" nocase
        
        // Keywords (English)
        $keyword12 = "ID number" nocase
        $keyword13 = "ID card" nocase
        $keyword14 = "identity card" nocase
        $keyword15 = "citizen ID" nocase
        $keyword16 = "national ID" nocase
        $keyword17 = "identification" nocase
    
    condition:
        // Match CMND or CCCD WITH keywords (high confidence)
        ($cmnd or $cccd) and 
        ($keyword1 or $keyword2 or $keyword3 or $keyword4 or $keyword5 or
         $keyword6 or $keyword7 or $keyword8 or $keyword9 or $keyword10 or $keyword11 or
         $keyword12 or $keyword13 or $keyword14 or $keyword15 or $keyword16 or $keyword17)
}
