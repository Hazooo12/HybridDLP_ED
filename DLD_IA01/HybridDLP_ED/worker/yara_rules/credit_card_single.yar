rule Credit_Card_Single {
    meta:
        description = "Detect single credit card numbers with format validation"
        severity = "high"
        author = "HybridDLP"
        confidence = "high"  // High vì có format validation
    
    strings:
        // Visa: 13 or 16 digits, starts with 4
        $visa1 = /\b4[0-9]{12}\b/  // 13 digits
        $visa2 = /\b4[0-9]{15}\b/  // 16 digits
        $visa3 = /\b4[0-9]{3}\s[0-9]{4}\s[0-9]{4}\s[0-9]{4}\b/  // With spaces
        $visa4 = /\b4[0-9]{3}-[0-9]{4}-[0-9]{4}-[0-9]{4}\b/  // With dashes
        
        // MasterCard: 16 digits, starts with 51-55
        $mastercard1 = /\b5[1-5][0-9]{14}\b/
        $mastercard2 = /\b5[1-5][0-9]{3}\s[0-9]{4}\s[0-9]{4}\s[0-9]{4}\b/
        $mastercard3 = /\b5[1-5][0-9]{3}-[0-9]{4}-[0-9]{4}-[0-9]{4}\b/
        
        // Amex: 15 digits, starts with 34 or 37
        $amex1 = /\b34[0-9]{13}\b/
        $amex2 = /\b37[0-9]{13}\b/
        $amex3 = /\b34[0-9]{2}\s[0-9]{6}\s[0-9]{5}\b/
        $amex4 = /\b37[0-9]{2}\s[0-9]{6}\s[0-9]{5}\b/
        
        // Discover: 16 digits, starts with 6011, 65, or 622126-622925
        $discover1 = /\b6011[0-9]{12}\b/
        $discover2 = /\b65[0-9]{14}\b/
        $discover3 = /\b622[1-9][0-9]{2}[0-9]{10}\b/
        
        // JCB: 16 digits, starts with 35
        $jcb = /\b35[0-9]{14}\b/
        
        // Diners Club: 14 digits, starts with 30, 36, or 38
        $diners1 = /\b30[0-9]{12}\b/
        $diners2 = /\b36[0-9]{12}\b/
        $diners3 = /\b38[0-9]{12}\b/
        
        // Context keywords (optional, increases confidence) - English
        $keyword1 = "credit" nocase
        $keyword2 = "debit" nocase
        $keyword3 = "card" nocase
        $keyword4 = "card number" nocase
        $keyword5 = "cardholder" nocase
        $keyword6 = "payment" nocase
        $keyword7 = "visa" nocase
        $keyword8 = "mastercard" nocase
        $keyword9 = "amex" nocase
        
        // Keywords (Vietnamese)
        $keyword10 = "thẻ" nocase
        $keyword11 = "số thẻ" nocase
        $keyword12 = "thẻ tín dụng" nocase
        $keyword13 = "thẻ ghi nợ" nocase
        $keyword14 = "chủ thẻ" nocase
        $keyword15 = "thanh toán" nocase
    
    condition:
        // Match any credit card format
        (($visa1 or $visa2 or $visa3 or $visa4) or 
         ($mastercard1 or $mastercard2 or $mastercard3) or 
         ($amex1 or $amex2 or $amex3 or $amex4) or
         ($discover1 or $discover2 or $discover3) or
         $jcb or
         ($diners1 or $diners2 or $diners3)) and
        // Keywords optional but still referenced to avoid dead strings
        any of ($keyword*)
}
