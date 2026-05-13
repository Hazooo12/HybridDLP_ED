rule Email_List_Leak_Detection {
    meta:
        description = "Detects bulk email addresses (potential mailing list leaks)"
        severity = "medium"
        author = "HybridDLP_Enhanced"
        confidence = "high"

    strings:
        // Regex email tối ưu: thêm word boundary và hạn chế độ dài để tránh ngốn RAM
        $email = /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,100}\.[A-Za-z]{2,10}\b/

        // Gom nhóm từ khóa tiếng Anh & tiếng Việt (Sử dụng Regex nocase cho gọn)
        $k_leak = / (danh sách|danh bạ|mailing list|contact list|address book|customer list|danh sách khách hàng)/ nocase
        $k_label = / (email|thư điện tử|liên hệ|địa chỉ email|contact)/ nocase

        // Loại trừ các email hệ thống phổ biến để giảm False Positive
        $exclude_sys = / (no-reply|noreply|support|admin|info|webmaster|postmaster)@/ nocase

    condition:
        // 1. Phải có ít nhất 1 từ khóa về "Danh sách" HOẶC 2 từ khóa nhãn email
        (any of ($k_leak) or (#k_label > 1)) and

        // 2. Phát hiện số lượng email lớn (ví dụ trên 10 email khác nhau)
        #email > 10 and

        // 3. Logic thông minh: Số lượng email tìm thấy phải nhiều hơn số email hệ thống
        #email > #exclude_sys + 5
}