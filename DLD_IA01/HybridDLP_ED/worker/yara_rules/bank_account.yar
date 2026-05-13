rule Bank_Account_Vietnam {
    meta:
        description = "Detect Vietnam bank account numbers in banking context"
        severity = "high"
        author = "HybridDLP"
        confidence = "medium"

    strings:
        // Potential account number: 9-15 digits.
        $stk = /\b[0-9]{9,15}\b/
        $phone = /\b(03|05|07|08|09)[0-9]{8}\b/

        // Banking context keywords
        $k1 = "so tai khoan" nocase
        $k2 = "stk" nocase
        $k3 = "tai khoan ngan hang" nocase
        $k4 = "bank account" nocase
        $k5 = "account number" nocase
        $k6 = "acc no" nocase

        // Popular bank names
        $b1 = "vietcombank" nocase
        $b2 = "vietinbank" nocase
        $b3 = "techcombank" nocase
        $b4 = "agribank" nocase
        $b5 = "bidv" nocase
        $b6 = "mbbank" nocase
        $b7 = "tpbank" nocase
        $b8 = "vpbank" nocase
        $b9 = "acb" nocase
        $b10 = "sacombank" nocase

    condition:
        $stk and not $phone and (any of ($k*) or any of ($b*))
}