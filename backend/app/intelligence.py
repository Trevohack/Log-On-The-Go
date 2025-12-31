ENDPOINT_INTENTS = {
    "recon": [
        # Environment & Configuration
        "/.env", "/.env.local", "/.env.backup", "/.env.dev", "/.env.prod", "/.env.production",
        "/.env.staging", "/.env.test", "/.env.example", "/.env.sample", "/.env.old",
        "/config", "/config.php", "/config.yml", "/config.yaml", "/config.json", "/config.xml",
        "/config.ini", "/config.toml", "/config.properties", "/configuration.php",
        "/settings.py", "/settings.php", "/settings.json", "/local_settings.py",
        "/application.properties", "/application.yml", "/application.yaml",
        "/app.config", "/web.config", "/Web.config", "/web.xml",
        "/hibernate.cfg.xml", "/database.yml", "/database.php",
        "/secrets.yml", "/secrets.json", "/credentials.json", 
        "nmap", "masscan", "unicornscan",
        "nc -zv", "ping sweep", "/24",
        "smbclient", "mount.cifs", "\\\\",
        "net use", "net view", "445",
        "wmic /node:", "Get-WmiObject",
        "Invoke-WmiMethod",
        
        # Server Status & Info
        "/server-status", "/server-info", "/status", "/info", "/phpinfo.php",
        "/info.php", "/test.php", "/health", "/healthz", "/readiness",
        "/metrics", "/debug", "/trace", "/monitor",
        
        # Source Control
        "/.git", "/.git/config", "/.git/HEAD", "/.git/index", "/.git/logs/HEAD",
        "/.gitignore", "/.gitmodules", "/.svn", "/.svn/entries", "/.svn/wc.db",
        "/.hg", "/.hg/hgrc", "/.bzr", "/.cvs",
        "/.git-credentials", "/.gitconfig",
        
        # Backups & Archives
        "/backup", "/backups", "/backup.sql", "/backup.zip", "/backup.tar.gz",
        "/old", "/bak", "/copy", "/archive", "/archives",
        ".bak", ".old", ".orig", ".save", ".swp", ".swo", ".tmp",
        ".backup", "~", ".copy", ".zip", ".tar", ".tar.gz", ".tgz",
        ".rar", ".7z", ".sql", ".sql.gz", ".dump",
        "/db_backup", "/database_backup", "/site_backup",
        "/www.zip", "/web.zip", "/html.zip", "/public_html.zip",
        
        # Cloud Metadata
        "/.aws/credentials", "/.aws/config", "/meta-data", "/metadata",
        "/latest/meta-data", "/v1/metadata", "/computeMetadata/v1",
        "169.254.169.254", "/instance-identity", "/user-data",
        "/.azure/credentials", "/.gcloud/credentials",
        "/v1.0/metadata/identity",
        
        # Container & Orchestration
        "/docker-compose.yml", "/docker-compose.yaml", "/Dockerfile",
        "/.dockerignore", "/Jenkinsfile", "/.gitlab-ci.yml",
        "/.travis.yml", "/.circleci/config.yml",
        "/kube/config", "/kubernetes.yml", "/.kube/config",
        "/deployment.yaml", "/service.yaml", "/helm",
        
        # API Documentation
        "/swagger", "/swagger-ui", "/swagger-ui.html", "/swagger-ui/index.html",
        "/swagger/index.html", "/swagger.json", "/swagger.yaml",
        "/v2/swagger.json", "/v3/api-docs", "/openapi.json", "/openapi.yaml",
        "/api-docs", "/api/docs", "/api/swagger", "/redoc", "/docs",
        "/graphql", "/graphiql", "/graphql/console", "/playground",
        "/api/v1/docs", "/api/v2/docs", "/api-explorer",
        
        # Framework Specific
        "/actuator", "/actuator/health", "/actuator/env", "/actuator/metrics",
        "/actuator/mappings", "/actuator/configprops", "/actuator/heapdump",
        "/actuator/threaddump", "/actuator/trace", "/actuator/logfile",
        "/.well-known", "/.well-known/security.txt", "/.well-known/change-password",
        "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
        "/.htaccess", "/.htpasswd", "/.user.ini",
        
        # Laravel
        "/.env", "/storage/logs", "/storage/framework",
        
        # Django
        "/admin/", "/static/admin/", "/__debug__/",
        
        # Node.js
        "/node_modules", "/package.json", "/package-lock.json",
        "/yarn.lock", "/.npmrc",
        
        # Ruby/Rails
        "/Gemfile", "/Gemfile.lock", "/config/database.yml",
        "/config/secrets.yml",
        
        # PHP
        "/composer.json", "/composer.lock", "/vendor",
        
        # .NET
        "/App_Config", "/App_Data", "/bin", "/obj",
        
        # Directory Listings
        "/admin/logs", "/app/logs", "/application/logs",
        "/logs", "/log", "/temp", "/tmp", "/cache",
        "/private", "/includes", "/inc", "/lib", "/libraries",
        "/vendor", "/node_modules", "/bower_components",
        
        # Common Files
        "/README.md", "/README.txt", "/CHANGELOG.md", "/LICENSE",
        "/INSTALL.txt", "/TODO.txt", "/phpunit.xml",
        "/composer.json", "/package.json", "/.DS_Store",
    ],

    "auth_attack": [
        # Standard Login Endpoints
        "/login", "/signin", "/sign-in", "/sign_in", "/auth", "/authenticate",
        "/authorization", "/account/login", "/user/login", "/users/login",
        "/login.php", "/signin.php", "/auth.php", "/login.jsp", "/login.asp",
        "/login.aspx", "/login.html", "/signin.html",
        
        # API Authentication
        "/api/login", "/api/signin", "/api/auth", "/api/authenticate",
        "/api/v1/login", "/api/v2/login", "/api/v1/auth/login",
        "/api/session", "/api/token", "/api/auth/token",
        "/rest/auth", "/rest/login", "/graphql/auth",
        
        # Session Management
        "/session", "/session/new", "/session/create", "/logout", "/signout",
        "/account/logout", "/user/logout",
        
        # Password Reset
        "/forgot-password", "/forgot_password", "/reset-password", "/reset_password",
        "/password/reset", "/password/forgot", "/recover", "/recovery",
        "/account/recovery",
        
        # Registration (for user enum)
        "/register", "/signup", "/sign-up", "/registration",
        "/user/register", "/account/register", "/create-account",
        
        # CMS Authentication
        "/wp-login.php", "/wp-admin/", "/wp-json/wp/v2/users",
        "/wp-json/jwt-auth/v1/token", "/xmlrpc.php",
        "/administrator", "/administrator/index.php",
        "/joomla/administrator", "/drupal/user/login",
        "/user/login", "/admin/login.php",
        
        # SSO & OAuth
        "/oauth/token", "/oauth/authorize", "/oauth/callback",
        "/oauth2/token", "/oauth2/authorize", "/oauth2/callback",
        "/sso", "/sso/login", "/saml", "/saml/login", "/saml2",
        "/cas/login", "/adfs/ls", "/openid/connect",
        "/auth/google", "/auth/facebook", "/auth/github",
        "/.auth/login/aad",
        
        # MFA Endpoints
        "/mfa", "/2fa", "/verify", "/verification", "/otp",
        "/two-factor", "/multifactor",
        
        # Log Phrases (Authentication Failures)
        "invalid password", "incorrect password", "wrong password",
        "authentication failed", "authentication failure", "auth failed",
        "failed login", "login failed", "failed authentication",
        "login failure", "invalid credentials", "bad credentials",
        "access denied", "unauthorized", "forbidden",
        "too many attempts", "account locked", "locked out",
        "brute force", "credential stuffing", "password spray",
        "invalid username", "user not found", "unknown user",
        "session expired", "token expired", "invalid token",
        
        # System Authentication
        "ssh_login", "sshd", "pam_unix", "sudo:", "su:",
        "user not known", "password incorrect", "authentication token",
        "Failed password", "Invalid user", "Connection closed by",
        "maximum authentication attempts",
        
        # Database Authentication
        "Access denied for user", "Login failed for user",
        "authentication failed", "password authentication failed",
        "FATAL: password authentication", "ORA-01017",
        
        # LDAP/AD
        "ldap_bind", "bind failed", "invalid DN", "invalid credentials",
        
        # API Key Attempts
        "invalid api key", "api key not found", "unauthorized api",
        "invalid bearer token", "jwt verification failed",
    ],

    "admin_probe": [
        # Generic Admin Panels
        "/admin", "/admin/", "/admin/login", "/admin/index", "/admin/index.php",
        "/admin.php", "/admin.html", "/admin.asp", "/admin.aspx",
        "/administrator", "/administrator/", "/administration",
        "/controlpanel", "/control-panel", "/cp", "/cpanel",
        "/dashboard", "/backend", "/manage", "/management",
        "/panel", "/webadmin", "/sysadmin", "/root",
        
        # Alternate Admin Paths
        "/admin1", "/admin2", "/admin3", "/admin_area", "/admin-panel",
        "/admin-console", "/admin_console", "/admin-login",
        "/secure/admin", "/secure/administrator", "/_admin", "/_administrator",
        "/secret", "/secret/admin", "/hidden/admin",
        
        # CMS Admin
        "/wp-admin", "/wp-admin/", "/wp-admin/admin-ajax.php", "/wp-admin/admin.php",
        "/wp-admin/index.php", "/wp-admin/post-new.php", "/wp-admin/plugins.php",
        "/joomla/administrator", "/administrator/index.php",
        "/drupal/admin", "/admin/content", "/ghost/admin",
        "/keystone/admin", "/umbraco/backoffice",
        
        # Database Management
        "/phpmyadmin", "/phpmyadmin/", "/pma", "/pma/", "/phpMyAdmin",
        "/dbadmin", "/db", "/database", "/mysql", "/myadmin",
        "/adminer", "/adminer.php", "/adminer-4.8.1.php",
        "/sqlbuddy", "/sqlmanager", "/websql",
        "/pgadmin", "/pgadmin4", "/postgresql",
        "/mongo-express", "/rockmongo",
        
        # Server Panels
        "/plesk", "/cpanel", "/whm", "/webmin", "/virtualmin",
        "/directadmin", "/ispconfig", "/froxlor", "/vesta",
        
        # Java/Middleware Admin
        "/manager", "/manager/html", "/manager/status",
        "/host-manager", "/host-manager/html",
        "/jmx-console", "/jmx-console/HtmlAdaptor",
        "/web-console", "/web-console/Invoker",
        "/console", "/console/login", "/admin-console",
        "/hudson", "/jenkins", "/actuator",
        
        # Application Servers
        "/tomcat", "/tomcat/manager", "/glassfish",
        "/weblogic", "/websphere", "/jboss",
        
        # Configuration UIs
        "/config", "/configuration", "/setup", "/install",
        "/installer", "/install.php", "/setup.php",
        "/upgrade", "/upgrade.php", "/migration",
        
        # Monitoring & Logging
        "/grafana", "/kibana", "/prometheus", "/nagios",
        "/zabbix", "/icinga", "/monit", "/munin",
        "/logs", "/log", "/logging",
        
        # Backup Interfaces
        "/backup", "/backup.php", "/backup-admin",
        "/restore", "/restore.php",
        
        # File Management
        "/filemanager", "/files", "/file-manager",
        "/elfinder", "/filebrowser", "/ckeditor",
        
        # Cache/Queue Management
        "/redis-commander", "/phpredisadmin",
        "/rabbitmq", "/activemq",
        
        # Dev Tools
        "/debug", "/dev", "/developer", "/test",
        "/staging", "/uat",
    ],

    "exploit": [
        # Path Traversal
        "../", "..\\", ".../", "...\\",
        "..%2f", "..%5c", "..%252f", "..%255c",
        "%2e%2e/", "%2e%2e\\", "%2e%2e%2f", "%2e%2e%5c",
        "....//", "....\\\\",
        "..;/", "..;//",
        "/./", "/././", "/.\\", "/..\\/",
        

        # Unix/Linux File Access
        "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/hosts",
        "/etc/hostname", "/etc/issue", "/etc/motd",
        "/etc/ssh/sshd_config", "/etc/mysql/my.cnf",
        "/etc/apache2/apache2.conf", "/etc/nginx/nginx.conf",
        "/proc/self/environ", "/proc/self/cmdline", "/proc/self/status",
        "/proc/version", "/proc/cpuinfo", "/proc/meminfo",
        "/proc/net/tcp", "/proc/net/fib_trie",
        "/var/log/auth.log", "/var/log/apache2/access.log",
        "/var/log/nginx/access.log", "/var/log/syslog",
        "/root/.bash_history", "/root/.ssh/id_rsa",
        "/home/*/.bash_history", "/home/*/.ssh/id_rsa",
        
        # Windows File Access
        "/windows/win.ini", "/winnt/win.ini",
        "/boot.ini", "/windows/system32/config/sam",
        "/windows/system32/config/system",
        "/windows/system32/drivers/etc/hosts",
        "c:\\windows\\win.ini", "c:\\boot.ini",
        
        # Command Injection
        "cmd=", "exec=", "command=", "execute=", "ping=",
        "query=", "jump=", "code=", "reg=", "do=", "func=",
        "arg=", "option=", "load=", "process=", "step=",
        "system(", "exec(", "passthru(", "shell_exec(",
        "popen(", "proc_open(", "pcntl_exec(",
        "eval(", "assert(", "create_function(",
        "include(", "require(", "include_once(", "require_once(",
        
        # Command Execution Indicators
        "; ls", "| ls", "& dir", "| dir", "&& cat", "|| cat",
        "`ls`", "$(ls)", "${IFS}", "$IFS",
        "whoami", "id", "uname -a", "uname", "hostname",
        "ifconfig", "ip addr", "ipconfig", "/all",
        "netstat -an", "netstat", "ps aux", "ps -ef",
        "cat /etc/passwd", "type c:\\windows\\win.ini",
        
        # Payload Fetching
        "curl http", "wget http", "fetch http",
        "nc -", "ncat -", "netcat -",
        "bash -i", "sh -i", "/bin/bash", "/bin/sh",
        "powershell -enc", "powershell -e", "powershell.exe",
        "Invoke-WebRequest", "Invoke-Expression", "IEX",
        "DownloadString", "DownloadFile",
        "certutil -urlcache", "bitsadmin /transfer",
        "mshta http", "regsvr32 /s /n /u /i:http",
        
        # SQL Injection
        "' OR '1'='1", "' OR 1=1--", "' OR '1'='1'--",
        "admin'--", "admin' #", "' UNION SELECT",
        "UNION ALL SELECT", "' AND 1=1--", "' AND '1'='1",
        "1' ORDER BY", "' GROUP BY", "' HAVING 1=1--",
        "'; DROP TABLE", "'; DELETE FROM", "'; UPDATE",
        "'; INSERT INTO", "'; EXEC", "'; EXECUTE",
        "xp_cmdshell", "INTO OUTFILE", "INTO DUMPFILE",
        "LOAD_FILE(", "@@version", "version()", "database(",
        "user()", "system_user(", "session_user(",
        "pg_sleep(", "sleep(", "benchmark(",
        "waitfor delay", "DBMS_PIPE.RECEIVE_MESSAGE",
        
        # XSS Indicators
        "<script>", "</script>", "javascript:", "onerror=",
        "onload=", "onclick=", "onfocus=", "onmouseover=",
        "alert(", "prompt(", "confirm(", "eval(",
        "<img src=x", "<iframe", "<embed", "<object",
        "document.cookie", "document.domain",
        
        # XXE Injection
        "<!DOCTYPE", "<!ENTITY", "SYSTEM", "file://",
        "expect://", "php://filter", "php://input",
        "data://text", "zip://", "phar://",
        
        # Template Injection
        "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}",
        "{{config}}", "{{request}}", "${class.classLoader}",
        "{{''.__class__", "${7*7}", "@{7*7}",
        
        # CVE-Specific
        "${jndi:", "${jndi:ldap://", "${jndi:rmi://",  # Log4Shell
        "${env:", "${sys:", "${java:",
        "${lower:", "${upper:", "${::-",
        "{{constructor.constructor", # Node.js
        "__import__('os')", # Python
        "Runtime.getRuntime().exec", # Java
        "System.Diagnostics.Process", # .NET
        
        # Deserialization
        "rO0", "aced0005", "H4sIAAA", # Java serialized
        "YTox", "YToyOnt", # PHP serialized
        "__reduce__", "pickle", "cPickle",
        
        # LDAP Injection
        "*)(&", "*)(|", "admin*", "*)(uid=*",
        
        # NoSQL Injection
        "[$ne]", "[$gt]", "[$regex]", "[$where]",
        "{$gt:", "{$ne:", "{$regex:",
        
        # SSRF Indicators
        "http://localhost", "http://127.0.0.1",
        "http://[::1]", "http://169.254.169.254",
        "http://metadata", "http://0.0.0.0",
        "file:///", "gopher://", "dict://",
        
        # File Inclusion
        "php://input", "php://filter", "expect://",
        "data:text/plain", "file://", "zip://",
        "phar://", "http://evil.com/shell",
        
        # Code Execution Extensions
        ".phtml", ".phar", ".phpt", ".php3",
        ".php4", ".php5", ".php7", ".pht",
        ".phtml", ".shtml", ".inc", ".hphp",
        ".jsp", ".jspx", ".jsw", ".jsv",
        ".asp", ".aspx", ".cer", ".asa",
        
        # Binary/Reverse Shell
        "/bin/nc", "/bin/bash", "/bin/sh", "cmd.exe",
        "python -c", "perl -e", "ruby -e",
        "php -r", "node -e",
        
        # Misc Exploitation
        "cgi-bin", "/cgi-bin/", "shellshock",
        "() { :;};", "Pragma: no-cache",
        "base64 -d", "base64decode", 
        "unserialize(", "pickle.loads(",
    ],

    "persistence": [
        # Web Shells
        "/shell", "/shell.php", "/webshell", "/webshell.php",
        "/cmd", "/cmd.php", "/c99", "/c99.php",
        "/r57", "/r57.php", "/backdoor", "/backdoor.php",
        "/ws", "/ws.php", "/shell.jsp", "/shell.asp",
        "/shell.aspx", "/cmdasp.asp", "/cmd.asp",
        "/phpshell", "/terminal", "/console.php",
        
        # Common Shell Names
        "b374k", "wso", "c99", "r57", "c100", "shell",
        "alfa", "indoxploit", "mini", "simple-backdoor",
        "404", "404.php", "403.php", "lol.php",
        "test.php", "x.php", "xx.php", "xxx.php",
        
        # Shell Extensions
        ".phtml", ".phar", ".phpt", ".php3", ".php4",
        ".php5", ".php7", ".pht", ".shtml", ".inc",
        ".hphp", ".ctp", ".module",
        
        # Double Extensions
        ".jpg.php", ".png.php", ".gif.php", ".pdf.php",
        ".doc.php", ".txt.php", ".zip.php",
        "shell.php.jpg", "shell.php.png",
        
        # Upload Directories
        "/upload", "/uploads", "/uploaded", "/uploaded_files",
        "/files", "/files/upload", "/file/upload",
        "/media", "/media/upload", "/images", "/images/upload",
        "/assets", "/assets/uploads", "/content/uploads",
        "/public/uploads", "/storage/uploads",
        "/attachments", "/documents", "/downloads",
        "/temp", "/tmp/uploads", "/cache/uploads",
        
        # CMS Upload Paths
        "/wp-content/uploads", "/wp-includes",
        "/sites/default/files", "/sites/all/modules",
        "/administrator/components", "/images/stories",
        "/media/system", "/plugins/content",
        
        # Cron & Scheduled Tasks
        "crontab", "/etc/cron.d", "/etc/cron.daily",
        "/etc/cron.hourly", "/etc/cron.weekly",
        "/etc/cron.monthly", "/var/spool/cron",
        "/var/spool/cron/crontabs",
        "/etc/crontab", "*/5 * * * *",
        
        # System Startup
        "/etc/init.d", "/etc/rc.local", "/etc/rc.d",
        "/etc/systemd/system", "/lib/systemd/system",
        "systemctl enable", "systemctl start",
        "update-rc.d", "chkconfig",
        "/etc/profile", "/etc/bash.bashrc",
        ".bashrc", ".bash_profile", ".profile",
        
        # SSH Persistence
        "authorized_keys", "/.ssh/authorized_keys",
        "/root/.ssh/authorized_keys",
        "/home/*/.ssh/authorized_keys",
        ".ssh/id_rsa", ".ssh/id_dsa", ".ssh/id_ecdsa",
        ".ssh/config", "/etc/ssh/sshd_config",
        
        # Modified System Binaries
        "/usr/bin/curl", "/usr/bin/wget", "/usr/bin/ssh",
        "/bin/bash", "/bin/sh", "/bin/ls",
        
        # Temporary Directory Abuse
        "/tmp/", "/var/tmp/", "/dev/shm/",
        "/var/run/", "/var/lock/",
        "C:\\Windows\\Temp", "C:\\Temp",
        "%TEMP%", "%TMP%",
        
        # Windows Persistence
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        "schtasks /create", "at.exe", "sc create",
        
        # DLL Hijacking
        ".dll", "dll injection", "LoadLibrary",
        "kernel32.dll", "ntdll.dll",
        
        # Registry Modifications
        "reg add", "reg.exe", "regedit", "REG_SZ",
        
        # Service Creation
        "sc create", "sc config", "New-Service",
        "net user /add", "net localgroup administrators",
        
        # Rootkit Indicators
        "/lib/modules", "ld.so.preload", "/etc/ld.so.preload",
        "libc.so", "rootkit", "hide",
        
        # Malicious Scripts
        ".vbs", ".bat", ".cmd", ".ps1", ".psm1",
        "powershell.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe",
        
        # Process Injection
        "process injection", "dll injection",
        "process hollowing", "CreateRemoteThread",
        "WriteProcessMemory", "VirtualAllocEx",
        
        # Docker/Container Escape
        "/var/run/docker.sock", "docker exec",
        "docker run", "kubectl exec", "crictl exec",
        "--privileged", "--pid=host", "--net=host",
        "/proc/*/root", "nsenter",

        # Database Dumps
        "mysqldump", "pg_dump", "mongodump",
        "/backup.sql", "/dump.sql", "/database.sql",
        "/db.sql", "/data.sql", "export.sql",
        
        # Data Transfer
        "curl -T", "wget --post-file", "nc -w",
        "scp", "rsync", "ftp", "tftp", "sftp",
        "POST /upload", "PUT /upload",
        
        # Compression for Transfer
        "tar czf", "tar -czf", "zip -r",
        "7z a", "gzip", "bzip2",
        
        # Encoding/Obfuscation
        "base64", "base32", "base85", "xxd",
        "openssl enc", "gpg --encrypt",
        
        # DNS Exfiltration
        "nslookup", "dig", "host",
        ".exfil.", ".data.",
        
        # Cloud Upload
        "aws s3 cp", "gsutil cp", "az storage",
        "rclone copy", "s3cmd put",
        
        # Paste Services
        "pastebin.com", "paste.ee", "dpaste.com",
        "hastebin.com", "privatebin",
        
        # File Sharing
        "dropbox", "mega.nz", "drive.google",
        "wetransfer", "sendspace",
        
        # Steganography
        "steghide", "outguess", "stegosaurus",
        
        # Large File Access
        "SELECT * FROM", "*.csv", "*.xlsx",
        "*.zip", "*.tar.gz", "*.7z",
        "/etc/passwd", "/etc/shadow",
        
        # Customer Data
        "credit_card", "ssn", "password",
        "api_key", "secret", "token",
        "users.csv", "customers.sql", "payment",
        "psexec", "wmic", "winrm", "evil-winrm",
        "Invoke-Command", "Enter-PSSession",
        "ssh", "ssh -i", "ssh root@",
        "mimikatz", "lazagne", "secretsdump",
        "procdump", "lsass", "SAM", "SYSTEM",
        "/etc/shadow", "hashdump", "pwdump",
        "pth-", "pass the hash", "pth-winexe",
        "sekurlsa::pth",
        "Invoke-TokenManipulation", "incognito",
        "getuid", "steal_token", "getsystem",
        "mstsc", "rdesktop", "xfreerdp",
        "3389", "rdp",
        
        "New-PSSession", "Invoke-Command -ComputerName",
        
        "ldapsearch", "Get-ADUser", "Get-ADComputer",
        "BloodHound", "SharpHound", "adfind",
        
        # Kerberos
        "getTGT", "getST", "Rubeus",
        "kerberoasting", "asreproasting",
    ] 
} 

def classify_endpoint(request: str):
    for intent, patterns in ENDPOINT_INTENTS.items():
        for p in patterns:
            if p.lower() in request.lower():
                return intent
    return "normal" 
