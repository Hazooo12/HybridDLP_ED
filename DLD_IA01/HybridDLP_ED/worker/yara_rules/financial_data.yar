rule Financial_Data_Vietnam_Optimized {
    meta:
        description = "Detects financial amounts, currency (VND/USD), and transaction documents"
        severity = "high"
        author = "HybridDLP_Enhanced"
        confidence = "high"

    strings:
        // 1. Regex cho tiền tệ VND: Hỗ trợ 1.000.000, 1,000,000 hoặc 1000000 
        // Hỗ trợ đơn vị: VND, VNĐ, đồng, đ.
        $currency_vnd = /\b[0-9]{1,3}([.,][0-9]{3}){1,5}\s*(VND|VNĐ|đồng|đ)\b/i
        $currency_vnd_plain = /\b[0-9]{7,15}\s*(VND|VNĐ|đồng|đ)\b/i

        // 2. Regex cho tiền tệ USD: $1,000.00 hoặc $1000000
        $currency_usd = /\$\s*[0-9]{1,3}([.,][0-9]{3}){0,5}([.,][0-9]{2})?\b/
        $currency_usd_suffix = /\b[0-9]{1,3}([.,][0-9]{3}){0,5}\s*USD\b/i

        // 3. Nhóm từ khóa hành động/đối tượng tài chính (Cần đi kèm số tiền)
        $k_finance = /(doanh thu|lợi nhuận|chi phí|ngân sách|số dư|giao dịch|thanh toán|hóa đơn|tạm ứng|hoàn tiền|revenue|profit|budget|transaction|payment|invoice|balance|expenditure)/ nocase

        // 4. Nhóm từ khóa định danh tài liệu (Đứng một mình cũng có nguy cơ)
        $doc_high = /(báo cáo tài chính|financial report|financial statement|bảng cân đối kế toán|balance sheet|p&l statement)/ nocase

        // 5. Loại trừ các trường hợp số phiên bản hoặc địa chỉ IP (Giảm False Positive)
        $fp_ip = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/

    condition:
        // Case 1: Có từ khóa tài liệu quan trọng (Độ tin tưởng cao nhất)
        any of ($doc_high) or

        // Case 2: Có số tiền đi kèm với từ khóa tài chính trong cùng một vùng dữ liệu
        (
            (any of ($currency*)) and (any of ($k_finance))
        ) or

        // Case 3: Có ít nhất 3 cụm số tiền xuất hiện (Dấu hiệu của một bảng biểu/danh sách tài chính)
        (
            #currency_vnd > 3 or #currency_usd > 3
        )
        
        // Loại trừ IP để tránh bắt nhầm log server
        and not $fp_ip
}