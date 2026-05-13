rule Vietnam_ID_Single {
    meta:
        description = "Detect single Vietnam ID card numbers (CMND/CCCD) without requiring keywords"
        severity = "high"
        author = "HybridDLP"
        confidence = "medium"

    strings:
        // CMND: exactly 9 digits
        $cmnd = /\b[0-9]{9}\b/

        // CCCD: exactly 12 digits
        $cccd = /\b[0-9]{12}\b/

    condition:
        ($cmnd or $cccd) and
        // Avoid common VN mobile numbers matching 9-digit CMND branch
        not (/\b(09|08|07|03|05)[0-9]{8}\b/ and $cmnd) and
        // Avoid year-like values in 9-digit branch
        not (/\b(19|20)[0-9]{2}\b/ and $cmnd)
}