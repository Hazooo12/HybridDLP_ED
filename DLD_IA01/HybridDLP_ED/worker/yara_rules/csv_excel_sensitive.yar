rule CSV_Excel_Sensitive_Data {
    meta:
        description = "Detect sensitive data in CSV/Excel exports (PII, financial, etc.)"
        severity = "high"
        author = "HybridDLP"
    
    strings:
        // PII Patterns
        $cmnd = /\b[0-9]{9}\b/  // CMND
        $cccd = /\b[0-9]{12}\b/  // CCCD
        $phone = /\b(09|08|07|03)[0-9]{8}\b/  // Phone
        $email = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/
        
        // Financial
        $bank_account = /\b[0-9]{9,14}\b/
        $amount1 = /\b[0-9]{1,3}[.,][0-9]{3}\s*VND/i
        $amount2 = /\b[0-9]{1,3}[.,][0-9]{3}\s*đồng/i
        $amount3 = /\b[0-9]{1,3}[.,][0-9]{3}\s*vnđ/i
        $amount4 = /\b[0-9]{1,3}[.,][0-9]{3}\s*\$/
        
        // CSV/Excel indicators
        $csv_indicator = /,.*,.*,/  // Multiple commas (CSV format)
        $excel_indicator = /\t.*\t/  // Tabs (Excel format)
        
        // Sensitive keywords (English)
        $keyword1 = "CMND" nocase
        $keyword2 = "CCCD" nocase
        $keyword3 = "email" nocase
        $keyword4 = "customer" nocase
        $keyword5 = "client" nocase
        $keyword6 = "account" nocase
        $keyword7 = "revenue" nocase
        $keyword8 = "profit" nocase
        $keyword9 = "phone" nocase
        $keyword10 = "contact" nocase
        
        // Keywords (Vietnamese)
        $keyword13 = "số điện thoại" nocase
        $keyword14 = "tài khoản" nocase
        $keyword15 = "doanh thu" nocase
        $keyword16 = "lợi nhuận" nocase
        $keyword17 = "khách hàng" nocase
        $keyword18 = "liên hệ" nocase
    
    condition:
        // Match if CSV/Excel format AND contains sensitive data
        ($csv_indicator or $excel_indicator) and
        (
            (($cmnd or $cccd) and ($keyword1 or $keyword2)) or
            ($phone and ($keyword3 or $keyword9 or $keyword13 or $keyword18)) or
            ($email and ($keyword3 or $keyword10)) or
            ($bank_account and ($keyword4 or $keyword5 or $keyword6 or $keyword8 or $keyword9 or $keyword10 or $keyword14 or $keyword17)) or
            (($amount1 or $amount2 or $amount3 or $amount4) and ($keyword6 or $keyword7 or $keyword15 or $keyword16))
        )
}
