rule Source_Code {
    meta:
        description = "Detect source code and internal code patterns"
        severity = "high"
        author = "HybridDLP"
    
    strings:
        // Common code patterns
        $function_def1 = /function\s+\w+/
        $function_def2 = /def\s+\w+/
        $function_def3 = /class\s+\w+/
        $function_def4 = /public\s+\w+/
        $function_def5 = /private\s+\w+/
        $function_def6 = /protected\s+\w+/
        $import_statement1 = /import\s+[\w.]+/
        $import_statement2 = /require\s+[\w.]+/
        $import_statement3 = /include\s+[\w.]+/
        $import_statement4 = /using\s+[\w.]+/
        $variable_assignment = /\w+\s*=\s*["'`]/
        $code_comment = /\/\/|\/\*|#\s*\w+/
        
        // Code keywords (English)
        $keyword1 = "source code" nocase
        $keyword2 = "internal code" nocase
        $keyword3 = "proprietary" nocase
        $keyword4 = "confidential code" nocase
        $keyword5 = "API" nocase
        $keyword6 = "endpoint" nocase
        $keyword7 = "database" nocase
        $keyword8 = "connection string" nocase
        $keyword9 = "config" nocase
        $keyword10 = "secret" nocase
        $keyword11 = "password" nocase
        $keyword12 = "private code" nocase
        $keyword13 = "internal" nocase
        $keyword14 = "proprietary code" nocase
        
        // Keywords (Vietnamese)
        $keyword15 = "mã nguồn" nocase
        $keyword16 = "code nội bộ" nocase
        $keyword17 = "mã độc quyền" nocase
        $keyword18 = "mã bảo mật" nocase
        $keyword19 = "API" nocase
        $keyword20 = "điểm cuối" nocase
        $keyword21 = "cơ sở dữ liệu" nocase
        $keyword22 = "chuỗi kết nối" nocase
        $keyword23 = "cấu hình" nocase
        $keyword24 = "bí mật" nocase
        $keyword25 = "mật khẩu" nocase
        
        // File extensions in content (code files)
        $ext1 = ".py"
        $ext2 = ".js"
        $ext3 = ".java"
        $ext4 = ".cpp"
        $ext5 = ".cs"
        $ext6 = ".php"
        $ext7 = ".sql"
    
    condition:
        // Match if code patterns found with keywords
        ((($function_def1 or $function_def2 or $function_def3 or $function_def4 or $function_def5 or $function_def6) or
          ($import_statement1 or $import_statement2 or $import_statement3 or $import_statement4) or
          $variable_assignment or $code_comment) and
         ($keyword1 or $keyword2 or $keyword3 or $keyword4 or $keyword5 or $keyword6 or
          $keyword7 or $keyword8 or $keyword9 or $keyword10 or $keyword11 or $keyword12 or
          $keyword13 or $keyword14 or $keyword15 or $keyword16 or $keyword17 or $keyword18 or
          $keyword19 or $keyword20 or $keyword21 or $keyword22 or $keyword23 or $keyword24 or $keyword25)) or
        // Or if code file extensions mentioned
        ($ext1 or $ext2 or $ext3 or $ext4 or $ext5 or $ext6 or $ext7) and
        ($keyword1 or $keyword2 or $keyword3 or $keyword15 or $keyword16)
}
