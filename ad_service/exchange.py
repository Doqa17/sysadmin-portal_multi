import logging
import base64
import subprocess
from .powershell import run_ad_command

logger = logging.getLogger(__name__)

def enable_mailbox(username, exchange_server, admin_user=None, admin_password=None):
    """
    Активирует почтовый ящик для пользователя AD через удаленную сессию PowerShell к серверу Exchange.
    Использует явные учетные данные, если они предоставлены.
    """
    # Экранирование для PowerShell
    u = username.replace("'", "''")
    srv = exchange_server.replace("'", "''")
    
    cred_script = ""
    auth_part = "-Authentication Kerberos"
    
    if admin_user and admin_password:
        # Если логин в формате DN (CN=user,OU=...), вырезаем чистое имя для PowerShell
        clean_user = admin_user
        if admin_user.lower().startswith('cn='):
            try:
                # Извлекаем 'ldap_reader' из 'CN=ldap_reader,CN=Users...'
                clean_user = admin_user.split(',')[0].split('=')[1]
            except:
                pass
        
        # Экранируем пароль для SecureString
        pw_esc = admin_password.replace("'", "''")
        user_esc = clean_user.replace("'", "''")
        cred_script = f"""
        $pw = ConvertTo-SecureString '{pw_esc}' -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential('{user_esc}', $pw)
        """
        auth_part = "-Credential $credential"
    
    script_content = f"""
    $ErrorActionPreference = 'Stop'
    {cred_script}
    $session = $null
    try {{
        # Используем специальный канал Exchange, который умеет обходить проблему Double-Hop
        $uri = "http://{srv}/PowerShell/"
        $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $uri {auth_part}
        
        # Выполняем команду прямо на сервере Exchange
        Invoke-Command -Session $session -ScriptBlock {{
            param($id)
            Enable-Mailbox -Identity $id
        }} -ArgumentList "{u}"
        
        Remove-PSSession $session
        return "Success"
    }} catch {{
        if ($session) {{ Remove-PSSession $session }}
        write-host "EXCHANGE_ERROR: $($_.Exception.Message)"
        exit 0
    }}
    """
    
    # Используем существующий механизм выполнения через Base64
    encoded_script = base64.b64encode(script_content.encode('utf-16-le')).decode('utf-8')
    
    try:
        process = subprocess.Popen(
            ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout_bytes, stderr_bytes = process.communicate(timeout=30)
        
        # Декодируем вывод (в Windows консоли обычно cp866)
        try:
            stdout = stdout_bytes.decode('cp866')
            stderr = stderr_bytes.decode('cp866')
        except:
            stdout = stdout_bytes.decode('utf-8', errors='replace')
            stderr = stderr_bytes.decode('utf-8', errors='replace')
        
        # Проверяем stdout на наличие нашей ошибки
        if "EXCHANGE_ERROR:" in stdout:
            err_msg = stdout.split("EXCHANGE_ERROR:")[1].strip()
            logger.error(f"Exchange logic error for {username}: {err_msg}")
            return False, f"Ошибка Exchange: {err_msg}"

        if process.returncode == 0 and "Success" in stdout:
            logger.info(f"Exchange mailbox enabled for {username} on {exchange_server}")
            return True, f"Почтовый ящик активирован на {exchange_server}"
        else:
            err_msg = stderr.strip().split('\n')[0] if stderr else stdout.strip()
            if not err_msg: err_msg = "Неизвестная ошибка (проверьте подключение)"
            logger.error(f"Exchange execution error for {username}: {err_msg}")
            return False, f"Ошибка выполнения: {err_msg}"
            
    except subprocess.TimeoutExpired:
        logger.error(f"Exchange timeout for {username} on {exchange_server}")
        return False, "Таймаут подключения к серверу Exchange"
    except Exception as e:
        logger.error(f"Exchange exception for {username}: {str(e)}")
        return False, f"Ошибка выполнения: {str(e)}"

def test_exchange_connection(settings):
    """
    Проверяет соединение с сервером Exchange и наличие прав на управление.
    """
    if not settings.exchange_server:
        return False, "Сервер Exchange не указан в настройках."
    
    srv = settings.exchange_server.replace("'", "''")
    admin_user = settings.bind_user
    admin_password = settings.bind_password

    cred_script = ""
    auth_part = "-Authentication Kerberos"
    
    if admin_user and admin_password:
        clean_user = admin_user
        if admin_user.lower().startswith('cn='):
            try:
                clean_user = admin_user.split(',')[0].split('=')[1]
            except: pass
        
        pw_esc = admin_password.replace("'", "''")
        user_esc = clean_user.replace("'", "''")
        cred_script = f"""
        $pw = ConvertTo-SecureString '{pw_esc}' -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential('{user_esc}', $pw)
        """
        auth_part = "-Credential $credential"
    
    script_content = f"""
    $ErrorActionPreference = 'Stop'
    {cred_script}
    $session = $null
    try {{
        $uri = "http://{srv}/PowerShell/"
        $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $uri {auth_part}
        
        # Проверяем наличие команды
        $cmd = Invoke-Command -Session $session -ScriptBlock {{ Get-Command Enable-Mailbox -ErrorAction SilentlyContinue }}
        
        Remove-PSSession $session
        if ($cmd) {{
            return "Success: Соединение установлено, команда Enable-Mailbox доступна."
        }} else {{
            write-host "EXCHANGE_ERROR: Соединение установлено, но команда Enable-Mailbox НЕ найдена (проверьте права RBAC)."
            exit 0
        }}
    }} catch {{
        if ($session) {{ Remove-PSSession $session }}
        write-host "EXCHANGE_ERROR: $($_.Exception.Message)"
        exit 0
    }}
    """
    
    encoded_script = base64.b64encode(script_content.encode('utf-16-le')).decode('utf-8')
    
    try:
        process = subprocess.Popen(
            ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout_bytes, stderr_bytes = process.communicate(timeout=20)
        
        try:
            stdout = stdout_bytes.decode('cp866').strip()
        except:
            stdout = stdout_bytes.decode('utf-8', errors='replace').strip()
            
        if "EXCHANGE_ERROR:" in stdout:
            return False, stdout.split("EXCHANGE_ERROR:")[1].strip()
        
        if "Success:" in stdout:
            return True, stdout.split("Success:")[1].strip()
            
        return False, f"Не удалось проверить соединение: {stdout}"
    except Exception as e:
        return False, f"Ошибка при проверке: {str(e)}"
