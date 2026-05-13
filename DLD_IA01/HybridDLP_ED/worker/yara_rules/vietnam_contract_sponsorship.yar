/*
  Vietnamese sponsorship / support contracts (hop dong tai tro).
  Looser than contract_legal.yar — catches templates that miss strict clause counts.
*/

rule Vietnam_Sponsorship_Contract_Structure {
    meta:
        description = "Hop dong tai tro / ho tro with parties and identity or payment signals"
        severity = "high"
        author = "HybridDLP"

    strings:
        $hd1 = "HỢP ĐỒNG TÀI TRỢ" nocase
        $hd2 = "Hợp đồng tài trợ" nocase
        $hd3 = "HỢP ĐỒNG TÀI TRỢ - HỖ TRỢ" nocase
        $ben_a = "BÊN A" nocase
        $ben_b = "BÊN B" nocase
        $cccd_lbl = "CCCD" nocase
        $cccd_num = /\b[0-9]{12}\b/
        $mst = "Mã số thuế" nocase
        $dai_dien = "Đại diện" nocase
        $bank_tcb = "Techcombank" nocase
        $bank_vpb = "VPBank" nocase
        $bank_bidv = "BIDV" nocase
        $stk_label = "Tài khoản" nocase

    condition:
        (1 of ($hd*)) and $ben_a and $ben_b and
        (
            ($cccd_lbl and $cccd_num) or $mst or
            1 of ($bank_tcb, $bank_vpb, $bank_bidv) or $stk_label
        ) and
        $dai_dien
}
