<#
.SYNOPSIS
Deshabilita una cuenta de usuario en Active Directory On-Premise,
remueve todas las membresías de grupo y resetea la contraseña.
Se ejecuta en un Hybrid Runbook Worker.

.PARAMETER UserIdentifier
Identificador del usuario (UserPrincipalName o SamAccountName).

.EXAMPLE
Disable-OnPremUser -UserIdentifier 'usuario.ejemplo@dominio.local'
Disable-OnPremUser -UserIdentifier 'usuarioejemplo'

.NOTES
Requiere el módulo 'ActiveDirectory' de PowerShell en el Hybrid Runbook Worker.
La cuenta de ejecución necesita permisos adecuados en AD.
#>
param(
    [Parameter(Mandatory=$true)]
    [string]$UserIdentifier
)

# --- Configuración ---
# Considera añadir manejo de errores try/catch más robusto
# y logging detallado según tus necesidades.

# --- Validación de Módulo ---
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "El módulo 'ActiveDirectory' no está disponible en este worker. Por favor, instálalo."
    exit 1
}
Import-Module ActiveDirectory -ErrorAction Stop

# --- Lógica Principal ---
try {
    Write-Output "Iniciando desactivación On-Premise para: $UserIdentifier"

    # Identificar al usuario (intentar por UPN y luego por SAMAccountName si falla)
    $adUser = Get-ADUser -Filter "UserPrincipalName -eq '$UserIdentifier' -or SamAccountName -eq '$UserIdentifier'" -Properties MemberOf, AccountExpirationDate
    if (-not $adUser) {
        Write-Error "Usuario '$UserIdentifier' no encontrado en Active Directory On-Premise."
        exit 1
    }
    Write-Output "Usuario encontrado: $($adUser.DistinguishedName)"

    # 1. Deshabilitar la cuenta de usuario (si no está ya deshabilitada)
    if ($adUser.Enabled) {
        Write-Output "Deshabilitando cuenta..."
        Disable-ADAccount -Identity $adUser -ErrorAction Stop
        Write-Output "Cuenta deshabilitada exitosamente."
        # Opcional: Establecer una fecha de expiración en el pasado
        # Set-ADAccountExpiration -Identity $adUser -DateTime ([DateTime]::Now.AddDays(-1))
        # Opcional: Mover a una OU específica de desactivados
        # Move-ADObject -Identity $adUser.DistinguishedName -TargetPath "OU=Desactivados,DC=tu,DC=dominio,DC=local"
    } else {
        Write-Output "La cuenta ya estaba deshabilitada."
    }

    # 2. Remover todas las membresías de grupo (excepto 'Domain Users')
    Write-Output "Removiendo membresías de grupo..."
    $groups = Get-ADPrincipalGroupMembership -Identity $adUser | Where-Object { $_.Name -ne "Domain Users" }
    if ($groups) {
        foreach ($group in $groups) {
            try {
                Write-Output "Removiendo de grupo: $($group.Name)"
                Remove-ADGroupMember -Identity $group -Members $adUser -Confirm:$false -ErrorAction Stop
                Write-Output "Removido de $($group.Name)."
            } catch {
                Write-Warning "No se pudo remover al usuario del grupo '$($group.Name)'. Puede ser un grupo protegido o faltan permisos. Error: $($_.Exception.Message)"
            }
        }
    } else {
        Write-Output "El usuario no es miembro de grupos adicionales (aparte de Domain Users)."
    }


    # 3. Resetear la contraseña a un valor aleatorio complejo y requerir cambio en el próximo inicio de sesión (aunque esté deshabilitado)
    Write-Output "Reseteando contraseña..."
    $newPassword = ConvertTo-SecureString -String (Generate-RandomPassword -Length 16) -AsPlainText -Force
    # Nota: Set-ADAccountPassword no permite requerir cambio. Set-ADUser sí.
    # Usamos Set-ADUser para más control, aunque la cuenta esté deshabilitada.
    Set-ADUser -Identity $adUser -AccountPassword $newPassword -ChangePasswordAtLogon $true -ErrorAction Stop
    Write-Output "Contraseña reseteada exitosamente (requiere cambio al intentar iniciar sesión)."

    Write-Output "Desactivación On-Premise completada para: $UserIdentifier"

} catch {
    Write-Error "Ocurrió un error durante la desactivación On-Premise para '$UserIdentifier': $($_.Exception.Message)"
    # Propagar el error para que la Logic App lo detecte si es necesario
    throw $_
}

# --- Función Auxiliar para Generar Contraseña Aleatoria ---
function Generate-RandomPassword {
    param(
        [int]$Length = 12 # Longitud mínima de 12
    )
    # Asegurar complejidad: al menos una mayúscula, una minúscula, un número y un símbolo.
    $lower = [char[]]'abcdefghijklmnopqrstuvwxyz'
    $upper = [char[]]'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    $number = [char[]]'0123456789'
    $symbol = [char[]]'!@#$%^&*()-_=+[]{}|;:,.<>/?'
    $allChars = $lower + $upper + $number + $symbol

    # Generar contraseña asegurando los requisitos
    do {
        $password = ""
        # Asegurar al menos uno de cada tipo
        $password += Get-Random -InputObject $upper
        $password += Get-Random -InputObject $lower
        $password += Get-Random -InputObject $number
        $password += Get-Random -InputObject $symbol
        # Completar el resto de la longitud
        for ($i = 4; $i -lt $Length; $i++) {
            $password += Get-Random -InputObject $allChars
        }
        # Mezclar los caracteres
        $password = $password.ToCharArray() | Get-Random -Count $password.Length
        $password = -join $password

        # Validar complejidad (por si acaso Get-Random fuera muy repetitivo)
        $complexEnough = $password -match '[A-Z]' -and $password -match '[a-z]' -and $password -match '[0-9]' -and $password -match '[\W_]' # \W es no-Word (símbolo o espacio), _ es underscore

    } while (-not $complexEnough)

    return $password
}