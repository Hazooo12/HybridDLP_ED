/*
  Vietnam bank account numbers often written with spaces: 1903 8057 4310 14
*/

rule Vietnam_Bank_Account_Spaced {
    meta:
        description = "Bank STK with digit groups separated by spaces + bank keyword"
        severity = "high"
        author = "HybridDLP"

    strings:
        // 3-4 digit groups, 3+ groups, total digit-heavy (typical VN STK formatting)
        // e.g. 1903 8057 4310 14 (last group may be 2 digits)
        $stk_spaced = /\b[0-9]{2,4}(\s+[0-9]{2,4}){3,6}\b/
        $k1 = "tai khoan" nocase
        $k2 = "Tài khoản"
        $k3 = "STK"
        $k4 = "chuyen khoan" nocase
        $b1 = "Techcombank" nocase
        $b2 = "VPBank" nocase
        $b3 = "Vietcombank" nocase
        $b4 = "BIDV" nocase
        $b5 = "Agribank" nocase

    condition:
        $stk_spaced and (1 of ($k*) or 1 of ($b*))
}
