rule Contract_Legal_Document {
    meta:
        description = "Detect contracts/legal agreements with sensitive business clauses"
        severity = "high"
        author = "HybridDLP"
    
    strings:
        // Core contract markers
        $k1 = "hợp đồng" nocase
        $k2 = "thoa thuan" nocase
        $k3 = "thỏa thuận" nocase
        $k4 = "contract" nocase
        $k5 = "agreement" nocase
        $k6 = "điều khoản" nocase
        $k7 = "dieu khoan" nocase

        // Typical VN contract structure
        $p1 = "bên a" nocase
        $p2 = "bên b" nocase
        $p3 = "đại diện" nocase
        $p4 = "mã số thuế" nocase
        $p5 = "địa chỉ" nocase
        $p6 = "pham vi cong viec" nocase
        $p7 = "phạm vi công việc" nocase
        $p8 = "giá trị hợp đồng" nocase
        $p9 = "gia tri hop dong" nocase
        $p10 = "phương thức thanh toán" nocase
        $p11 = "phuong thuc thanh toan" nocase
        $p12 = "số tài khoản" nocase
        $p13 = "so tai khoan" nocase

        // Sensitive legal/compliance clauses
        $s1 = "bảo mật thông tin" nocase
        $s2 = "bao mat thong tin" nocase
        $s3 = "không được chia sẻ" nocase
        $s4 = "khong duoc chia se" nocase
        $s5 = "dữ liệu khách hàng" nocase
        $s6 = "du lieu khach hang" nocase
        $s7 = "bồi thường" nocase
        $s8 = "boi thuong" nocase
        $s9 = "chế tài vi phạm" nocase
        $s10 = "che tai vi pham" nocase

        // Legal form patterns
        $date_pattern = /\b\d{1,2}\/\d{1,2}\/\d{4}\b/
        $money_vnd = /\b[0-9]{1,3}([.,][0-9]{3}){1,5}\s*(đồng|dong|VND|VNĐ)\b/i
        $signature = /ky|ký|signature|chữ ký/i
    
    condition:
        // Contract-like document + structure + sensitive/legal/payment evidence
        (2 of ($k*)) and
        (3 of ($p*)) and
        ((2 of ($s*)) or $money_vnd) and
        ($date_pattern or $signature)
}
