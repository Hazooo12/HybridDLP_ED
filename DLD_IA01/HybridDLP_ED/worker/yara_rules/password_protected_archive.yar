rule Password_Protected_Archive {
    meta:
        description = "Detect password-protected archive indicators in command lines or file content"
        severity = "high"
        author = "HybridDLP"
    
    strings:
        // Archive command patterns with password
        $zip_password = /zip.*-p|zip.*--password|7z.*-p|7z.*-pwd|rar.*-p|rar.*-hp/
        $winrar_password = /winrar.*-p|winrar.*-hp/
        $powershell_password = /Compress-Archive.*-Password|Compress-Archive.*-p/
        
        // Password keywords in context (English)
        $keyword1 = "password" nocase
        $keyword2 = "encrypt" nocase
        $keyword3 = "protected" nocase
        $keyword4 = "encrypted" nocase
        $keyword5 = "secure" nocase
        $keyword6 = "locked" nocase
        $keyword7 = "passphrase" nocase
        
        // Keywords (Vietnamese)
        $keyword8 = "mật khẩu" nocase
        $keyword9 = "mã hóa" nocase
        $keyword10 = "bảo vệ" nocase
        $keyword11 = "được mã hóa" nocase
        $keyword12 = "khóa" nocase
        $keyword13 = "bảo mật" nocase
        
        // Archive file extensions
        $ext1 = ".zip"
        $ext2 = ".rar"
        $ext3 = ".7z"
        $ext4 = ".tar.gz"
    
    condition:
        // Match if password-protected archive command found
        ($zip_password or $winrar_password or $powershell_password) or
        // Or if archive file with password keywords
        ($ext1 or $ext2 or $ext3 or $ext4) and
        ($keyword1 or $keyword2 or $keyword3 or $keyword4 or $keyword5 or $keyword6 or
         $keyword7 or $keyword8 or $keyword9 or $keyword10 or $keyword11 or $keyword12 or $keyword13)
}
