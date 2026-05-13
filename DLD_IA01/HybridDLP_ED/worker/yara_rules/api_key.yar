rule API_Key {
    meta:
        description = "Detect API keys and secrets"
        severity = "high"
        author = "HybridDLP"
    
    strings:
        // AWS Access Key ID
        $aws_key = /AKIA[0-9A-Z]{16}/
        $aws_secret = /aws_secret_access_key/i
        
        // GitHub tokens
        $github_pat = /ghp_[a-zA-Z0-9]{36}/  // Personal Access Token
        $github_oauth = /gho_[a-zA-Z0-9]{36}/  // OAuth token
        $github_user = /ghu_[a-zA-Z0-9]{36}/  // User-to-server token
        $github_app = /ghs_[a-zA-Z0-9]{36}/  // Server-to-server token
        $github_refresh = /ghr_[a-zA-Z0-9]{76}/  // Refresh token
        
        // Google API keys
        $google_api = /AIza[0-9A-Za-z_-]{35}/
        $google_oauth = /ya29\.[a-zA-Z0-9_-]+/
        
        // Azure keys
        $azure_key = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/
        
        // JWT tokens (starts with eyJ)
        $jwt = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/
        
        // Generic API key pattern (32+ hex chars)
        $api_key = /\b[a-fA-F0-9]{32,}\b/
        
        // Database connection strings
        $db_mysql = /mysql:\/\/[^:]+:[^@]+@/
        $db_postgres = /postgresql:\/\/[^:]+:[^@]+@/
        $db_mongodb = /mongodb:\/\/[^:]+:[^@]+@/
        $db_connection = /connection.*string/i
        
        // Common API key keywords (English)
        $keyword1 = "api_key" nocase
        $keyword2 = "api secret" nocase
        $keyword3 = "access key" nocase
        $keyword4 = "secret key" nocase
        $keyword5 = "private key" nocase
        $keyword6 = "token" nocase
        $keyword7 = "bearer" nocase
        $keyword8 = "authorization" nocase
        $keyword9 = "apikey" nocase
        $keyword10 = "api-key" nocase
        $keyword11 = "api key" nocase
        $keyword12 = "authentication" nocase
        $keyword13 = "credential" nocase
        
        // Keywords (Vietnamese)
        $keyword14 = "khóa api" nocase
        $keyword15 = "mã api" nocase
        $keyword16 = "chìa khóa" nocase
        $keyword17 = "mật khẩu api" nocase
        $keyword18 = "token" nocase
        $keyword19 = "xác thực" nocase
        $keyword20 = "ủy quyền" nocase
    
    condition:
        // AWS keys
        ($aws_key or $aws_secret) or
        // GitHub tokens
        ($github_pat or $github_oauth or $github_user or $github_app or $github_refresh) or
        // Google keys
        ($google_api or $google_oauth) or
        // Azure-like GUID secrets in key context
        ($azure_key and ($keyword1 or $keyword3 or $keyword4 or $keyword9 or $keyword10 or $keyword11)) or
        // JWT tokens
        $jwt or
        // Database connection strings
        ($db_mysql or $db_postgres or $db_mongodb or ($db_connection and $api_key)) or
        // Generic API key with keywords
        ($api_key and ($keyword1 or $keyword2 or $keyword3 or $keyword4 or $keyword5 or 
                      $keyword6 or $keyword7 or $keyword8 or $keyword9 or $keyword10 or
                      $keyword11 or $keyword12 or $keyword13 or $keyword14 or $keyword15 or
                      $keyword16 or $keyword17 or $keyword18 or $keyword19 or $keyword20))
}
