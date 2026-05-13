/*
  Payroll / salary roster exports (test-risk4): TSV/CSV with role and VND salary columns.
*/

rule Payroll_Salary_Schedule_Export {
    meta:
        description = "Payroll or salary roster table (position, monthly salary, VND)"
        severity = "high"
        author = "HybridDLP"

    strings:
        $h1 = "Monthly Salary" nocase
        $h2 = "Base salary" nocase
        $h3 = "Total Monthly Salary" nocase
        $h4 = "Salary Type" nocase
        $h5 = "Employment Type" nocase
        $h6 = "Employer Insurance" nocase
        $h7 = "compensation" nocase
        $vnd = "VND"

    condition:
        $vnd and 3 of ($h1, $h2, $h3, $h4, $h5, $h6, $h7)
}

rule Payroll_Position_Salary_Row {
    meta:
        description = "Tabular salary lines: role + Monthly Salary + 7+ digit amount"
        severity = "medium"
        author = "HybridDLP"

    strings:
        $ms = "Monthly Salary" nocase
        // Amount like 20,000,000 or 25000000 near salary context
        $amt = /\b[0-9]{1,3}(,[0-9]{3}){2,3}\b/

    condition:
        $ms and #amt >= 5
}
