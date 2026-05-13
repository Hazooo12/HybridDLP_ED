rule Credit_Card {
    meta:
        description = "Detect credit card numbers"
        severity = "high"
        author = "HybridDLP"
    
    strings:
        // Visa: 13 or 16 digits, starts with 4 (with or without spaces)
        $visa1 = /4[0-9]{12}/
        $visa2 = /4[0-9]{15}/
        $visa3 = /4[0-9]{3}\s[0-9]{4}\s[0-9]{4}\s[0-9]{4}/
        $visa4 = /4[0-9]{3}-[0-9]{4}-[0-9]{4}-[0-9]{4}/
        
        // MasterCard: 16 digits, starts with 5
        $mastercard1 = /5[1-5][0-9]{14}/
        $mastercard2 = /5[1-5][0-9]{3}\s[0-9]{4}\s[0-9]{4}\s[0-9]{4}/
        
        // Amex: 15 digits, starts with 34 or 37
        $amex1 = /34[0-9]{13}/
        $amex2 = /37[0-9]{13}/
        $amex3 = /34[0-9]{2}\s[0-9]{6}\s[0-9]{5}/
        $amex4 = /37[0-9]{2}\s[0-9]{6}\s[0-9]{5}/
        
        // Keywords (English)
        $keyword1 = "credit" nocase
        $keyword2 = "debit" nocase
        $keyword3 = "card" nocase
        $keyword4 = "card number" nocase
        $keyword5 = "card holder" nocase
        $keyword6 = "cardholder" nocase
        $keyword7 = "payment" nocase
        $keyword8 = "visa" nocase
        $keyword9 = "mastercard" nocase
        $keyword10 = "amex" nocase
        
        // Keywords (Vietnamese)
        $keyword11 = "thẻ" nocase
        $keyword12 = "thẻ tín dụng" nocase
        $keyword13 = "thẻ ghi nợ" nocase
        $keyword14 = "số thẻ" nocase
        $keyword15 = "chủ thẻ" nocase
        $keyword16 = "thanh toán" nocase
    
    condition:
        (($visa1 or $visa2 or $visa3 or $visa4) or 
         ($mastercard1 or $mastercard2) or 
         ($amex1 or $amex2 or $amex3 or $amex4)) and 
        ($keyword1 or $keyword2 or $keyword3 or $keyword4 or $keyword5 or $keyword6 or
         $keyword7 or $keyword8 or $keyword9 or $keyword10 or $keyword11 or $keyword12 or
         $keyword13 or $keyword14 or $keyword15 or $keyword16)
}
