import subprocess
import logging
import base64

logger = logging.getLogger(__name__)

def run_ad_command(script_content, timeout=5):
    """
    Выполняет скрипт PowerShell через EncodedCommand с таймаутом и чистым выводом ошибок.
    """
    # Оборачиваем скрипт, чтобы поймать системные ошибки в текстовом виде
    wrapped_script = f"""
    try {{
        $ErrorActionPreference = 'Stop'
        {script_content}
    }} catch {{
        write-host "AD_ERROR: $($_.Exception.Message)"
        exit 0
    }}
    """
    
    encoded_script = base64.b64encode(wrapped_script.encode('utf-16-le')).decode('utf-8')
    
    try:
        process = subprocess.Popen(
            ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout_bytes, stderr_bytes = process.communicate(timeout=timeout)
        
        # Декодируем с учетом кириллицы в консоли Windows
        try:
            stdout = stdout_bytes.decode('cp866').strip()
            stderr = stderr_bytes.decode('cp866').strip()
        except:
            stdout = stdout_bytes.decode('utf-8', errors='replace').strip()
            stderr = stderr_bytes.decode('utf-8', errors='replace').strip()

        # Если в выводе наш маркер ошибки
        if "AD_ERROR:" in stdout:
            err_msg = stdout.split("AD_ERROR:")[1].strip()
            logger.error(f"PowerShell logic error: {err_msg}")
            return False, err_msg

        if process.returncode == 0:
            return True, stdout
        else:
            err_msg = stderr.split('\n')[0] if stderr else stdout
            if not err_msg: err_msg = "Неизвестная ошибка PowerShell"
            return False, err_msg
            
    except subprocess.TimeoutExpired:
        logger.warning(f"PowerShell timeout ({timeout}s) expired.")
        return False, f"PowerShell Timeout ({timeout}s)"
    except Exception as e:
        logger.error(f"PowerShell critical failure: {e}")
        return False, str(e)

def change_password(username, new_password):
    u = username.replace("'", "''")
    p = new_password.replace("'", "''")
    script = f"Set-ADAccountPassword -Identity '{u}' -NewPassword (ConvertTo-SecureString '{p}' -AsPlainText -Force) -Reset"
    return run_ad_command(script)

def unlock_account(username):
    u = username.replace("'", "''")
    return run_ad_command(f"Unlock-ADAccount -Identity '{u}'")

def set_account_status(username, enable=True):
    u = username.replace("'", "''")
    cmd = "Enable-ADAccount" if enable else "Disable-ADAccount"
    return run_ad_command(f"{cmd} -Identity '{u}'")

def set_password_never_expires(username, never_expires=True):
    u = username.replace("'", "''")
    val = "$true" if never_expires else "$false"
    return run_ad_command(f"Set-ADUser -Identity '{u}' -PasswordNeverExpires {val}")

def force_password_change(username, force=True):
    u = username.replace("'", "''")
    val = "$true" if force else "$false"
    return run_ad_command(f"Set-ADUser -Identity '{u}' -ChangePasswordAtLogon {val}")

def extend_password(username):
    u = username.replace("'", "''")
    return run_ad_command(f"Set-ADUser -Identity '{u}' -Replace @{{pwdLastSet='-1'}}")

def add_to_group(username, group_dn):
    u = username.replace("'", "''")
    g = group_dn.replace("'", "''")
    return run_ad_command(f"Add-ADGroupMember -Identity '{g}' -Members '{u}'")

def remove_from_group(username, group_dn):
    u = username.replace("'", "''")
    g = group_dn.replace("'", "''")
    return run_ad_command(f"Remove-ADGroupMember -Identity '{g}' -Members '{u}' -Confirm:$false")

def delete_user(username):
    u = username.replace("'", "''")
    return run_ad_command(f"Remove-ADUser -Identity '{u}' -Confirm:$false")

def create_user(username, first_name, last_name, password, target_ou, upn=None, attributes=None):
    u = username.replace("'", "''")
    fn = first_name.replace("'", "''")
    ln = last_name.replace("'", "''")
    pw = password.replace("'", "''")
    ou = target_ou.replace("'", "''")
    
    cmd = f"New-ADUser -Name '{ln} {fn}' -GivenName '{fn}' -Surname '{ln}' -SamAccountName '{u}' -Path '{ou}' -AccountPassword (ConvertTo-SecureString '{pw}' -AsPlainText -Force) -Enabled $true"
    
    if upn:
        upn_esc = upn.replace("'", "''")
        cmd += f" -UserPrincipalName '{upn_esc}'"
    
    if attributes:
        for key, attr in [('mail', 'EmailAddress'), ('department', 'Department'), 
                          ('telephoneNumber', 'OfficePhone'), ('physicalDeliveryOfficeName', 'Office')]:
            if attributes.get(key):
                val = attributes[key].replace("'", "''")
                cmd += f" -{attr} '{val}'"
    
    return run_ad_command(cmd)
