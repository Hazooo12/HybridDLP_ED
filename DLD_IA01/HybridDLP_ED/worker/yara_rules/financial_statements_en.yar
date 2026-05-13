/*
  English P&L / income statement patterns (test-risk1 style).
  Small rules for easier tuning and fewer false positives than one mega-rule.
*/

rule Financial_Income_Statement_EN {
    meta:
        description = "Income statement / P&L headings (English)"
        severity = "high"
        author = "HybridDLP"

    strings:
        $a = "INCOME STATEMENT" nocase
        $b = "NET INCOME" nocase
        $c = "EBITDA" nocase
        $d = "EBIT"
        $e = "Cost of goods sold" nocase
        $f = "COGS" nocase
        $g = "Gross profit" nocase
        $h = "Earnings before interest" nocase
        $i = "Operating Expenses" nocase
        $j = "Net profit margin" nocase

    condition:
        2 of them
}

rule Financial_Revenue_Table_EN {
    meta:
        description = "Large revenue / sales table without VND suffix (comma-separated millions)"
        severity = "medium"
        author = "HybridDLP"

    strings:
        $sales = "Sales" nocase
        $rev = "revenues" nocase
        $net = "Net sales" nocase
        // Lines like 10,399,950,000 (>=10 digits with comma groups)
        $bigmoney = /\b[0-9]{1,3}(,[0-9]{3}){2,4}\b/

    condition:
        ($sales or $rev or $net) and #bigmoney >= 3
}
