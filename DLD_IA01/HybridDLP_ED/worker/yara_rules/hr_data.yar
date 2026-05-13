rule HR_Data {
    meta:
        description = "Detect HR and employee data"
        severity = "high"
        author = "HybridDLP"
    
    strings:
        // HR keywords (Vietnamese)
        $keyword1 = "nhân sự" nocase
        $keyword2 = "nhân viên" nocase
        $keyword3 = "lương" nocase
        $keyword4 = "thông tin nhân viên" nocase
        $keyword5 = "bảng lương" nocase
        $keyword6 = "đánh giá" nocase
        $keyword7 = "thông tin nhân sự" nocase
        $keyword8 = "tiền lương" nocase
        $keyword9 = "lương thưởng" nocase
        
        // Keywords (English)
        $keyword10 = "HR" nocase
        $keyword11 = "human resources" nocase
        $keyword12 = "employee" nocase
        $keyword13 = "staff" nocase
        $keyword14 = "salary" nocase
        $keyword15 = "employee data" nocase
        $keyword16 = "payroll" nocase
        $keyword17 = "performance" nocase
        $keyword18 = "review" nocase
        $keyword19 = "personnel" nocase
        $keyword20 = "compensation" nocase
        
        // PII in HR context
        $cmnd = /\b[0-9]{9}\b/
        $cccd = /\b[0-9]{12}\b/
        $phone = /\b(09|08|07|03)[0-9]{8}\b/
        $email = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/
        $bank_account = /\b[0-9]{9,14}\b/
    
    condition:
        // Match if HR keywords AND PII found
        ($keyword1 or $keyword2 or $keyword3 or $keyword4 or $keyword5 or 
         $keyword6 or $keyword7 or $keyword8 or $keyword9 or $keyword10 or
         $keyword11 or $keyword12 or $keyword13 or $keyword14 or $keyword15 or
         $keyword16 or $keyword17 or $keyword18 or $keyword19 or $keyword20) and
        ($cmnd or $cccd or $phone or $email or $bank_account)
}
