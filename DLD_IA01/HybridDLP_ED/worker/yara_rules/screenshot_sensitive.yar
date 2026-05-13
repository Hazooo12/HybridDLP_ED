rule Screenshot_Confidential_Keywords {
    meta:
        description = "Detect confidentiality markers in OCR-extracted screenshot text"
        severity = "high"
        author = "HybridDLP"
        category = "screenshot_dlp"

    strings:
        // English confidentiality markers
        $en1 = "Confidential" nocase
        $en2 = "Internal Only" nocase
        $en3 = "Strictly Confidential" nocase
        $en4 = "Do Not Distribute" nocase
        $en5 = "Do Not Copy" nocase
        $en6 = "Top Secret" nocase
        $en7 = "For Internal Use Only" nocase
        $en8 = "Restricted" nocase
        $en9 = "Proprietary" nocase
        $en10 = "Company Confidential" nocase
        $en11 = "Not For Distribution" nocase
        $en12 = "CLASSIFIED" nocase

        // Vietnamese confidentiality markers
        $vi1 = "Mat" nocase
        $vi2 = "Noi bo" nocase
        $vi3 = "Tuyet mat" nocase
        $vi4 = "Bi mat" nocase
        $vi5 = "Chi luu hanh noi bo" nocase
        $vi6 = "Khong phan phoi" nocase
        $vi7 = "Han che pho bien" nocase

        // UTF-8 Vietnamese (for Tesseract output)
        $vi_utf1 = "M\xe1\xba\xadt" nocase
        $vi_utf2 = "N\xe1\xbb\x99i b\xe1\xbb\x99" nocase
        $vi_utf3 = "Tuy\xe1\xbb\x87t m\xe1\xba\xadt" nocase
        $vi_utf4 = "B\xc3\xad m\xe1\xba\xadt" nocase
        $vi_utf5 = "Ch\xe1\xbb\x89 l\xc6\xb0u h\xc3\xa0nh n\xe1\xbb\x99i b\xe1\xbb\x99" nocase

    condition:
        
        (3 of ($en*, $vi*, $vi_utf*))
}

rule Screenshot_PII_Context {
    meta:
        description = "Detect PII context keywords in OCR-extracted screenshot text (salary, HR, finance)"
        severity = "high"
        author = "HybridDLP"
        category = "screenshot_dlp"

    strings:
        // Salary / Payroll
        $salary1 = "salary" nocase
        $salary2 = "payroll" nocase
        $salary3 = "bang luong" nocase
        $salary4 = "l\xc6\xb0\xc6\xa1ng" nocase

        // Finance
        $fin1 = "balance sheet" nocase
        $fin2 = "bao cao tai chinh" nocase
        $fin3 = "b\xe1\xba\xa3o c\xc3\xa1o t\xc3\xa0i ch\xc3\xadnh" nocase
        $fin4 = "profit" nocase
        $fin5 = "revenue" nocase
        $fin6 = "doanh thu" nocase

        // HR / Personnel
        $hr1 = "personnel" nocase
        $hr2 = "employee record" nocase
        $hr3 = "nhan su" nocase
        $hr4 = "danh sach nhan vien" nocase
        $hr5 = "h\xe1\xbb\x93 s\xc6\xa1 nh\xc3\xa2n vi\xc3\xaan" nocase

        // Require at least one keyword + some digit content (numbers appear in sensitive docs)
        $digits = /\d{4,}/

    condition:
        $digits and (2 of ($salary*) or 2 of ($fin*) or 2 of ($hr*) or
                     (1 of ($salary*) and 1 of ($fin*)) or
                     (1 of ($salary*) and 1 of ($hr*)) or
                     (1 of ($fin*) and 1 of ($hr*)))
}
