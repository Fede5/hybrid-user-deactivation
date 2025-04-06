<#
.SYNOPSIS
Deshabilita una cuenta de usuario en Entra ID (Azure AD), remueve membresías de grupo,
y revoca las sesiones / resetea métodos MFA. Se ejecuta en Azure Automation.

.PARAMETER UserPrincipalName
El User Principal Name (UPN) del usuario en Entra ID.

.EXAMPLE
Disable-EntraUser -UserPrincipalName 'usuario.ejemplo@tuempresa.com'

.NOTES
Requiere el módulo 'Microsoft.Graph' (específicamente Microsoft.Graph.Users,
Microsoft.Graph.Groups, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Identity.AuthenticationMethods)
en la Cuenta de Automation.
La Managed Identity de la Cuenta de Automation necesita permisos de Graph API:
User.ReadWrite.All, GroupMember.ReadWrite.All, UserAuthenticationMethod.ReadWrite.All, AuditLog.Read.All (opcional para logs).
#>
param(
    [Parameter(Mandatory=$true)]
    [string]$UserPrincipalName
)

# --- Configuración ---
# Definir qué grupos NO remover (ej. grupos de licenciamiento base, si aplica)
$ExcludedGroupNames = @("All Company", "Licencia Base E3") # Ajusta según tus necesidades
$ErrorActionPreference = 'Stop' # Detener el script en caso de error

# --- Conexión a Microsoft Graph usando Managed Identity ---
try {
    Write-Output "Conectando a Microsoft Graph usando Managed Identity..."
    # Asegúrate que la Managed Identity (System o User Assigned) esté habilitada en la Automation Account
    # y tenga los permisos de API de Graph necesarios.
    Connect-MgGraph -Identity
    Write-Output "Conectado exitosamente a Microsoft Graph."
} catch {
    Write-Error "Fallo al conectar a Microsoft Graph con Managed Identity: $($_.Exception.Message)"
    throw $_ # Propagar el error
}

# --- Lógica Principal ---
try {
    Write-Output "Iniciando desactivación en Entra ID para: $UserPrincipalName"

    # Obtener el usuario y su ID de objeto
    $user = Get-MgUser -UserId $UserPrincipalName -ErrorAction SilentlyContinue
    if (-not $user) {
        Write-Error "Usuario '$UserPrincipalName' no encontrado en Entra ID."
        exit 1 # Salir si el usuario no existe
    }
    $userId = $user.Id
    Write-Output "Usuario encontrado: ID $($userId)"

    # 1. Deshabilitar el inicio de sesión (si no está ya deshabilitado)
    if ($user.AccountEnabled) {
        Write-Output "Deshabilitando inicio de sesión (AccountEnabled = false)..."
        Update-MgUser -UserId $userId -AccountEnabled:$false
        Write-Output "Inicio de sesión deshabilitado exitosamente."
    } else {
        Write-Output "El inicio de sesión ya estaba deshabilitado."
    }

    # 2. Remover membresías de grupos de Entra ID (excepto los excluidos)
    Write-Output "Removiendo membresías de grupo de Entra ID..."
    # Usar -All para obtener todas las membresías (maneja paginación)
    $groups = Get-MgUserMemberOf -UserId $userId -All | Where-Object { $_ -is [Microsoft.Graph.PowerShell.Models.MicrosoftGraphGroup] }

    if ($groups) {
        $groupsToRemove = $groups | Where-Object { $ExcludedGroupNames -notcontains $_.DisplayName }
        if ($groupsToRemove) {
            foreach ($group in $groupsToRemove) {
                $groupId = $group.Id
                $groupName = $group.DisplayName
                try {
                    Write-Output "Intentando remover de grupo: '$($groupName)' (ID: $groupId)..."
                    # La forma correcta de remover un miembro de un grupo es usando su ID
                    Remove-MgGroupMemberByRef -GroupId $groupId -DirectoryObjectId $userId
                    Write-Output "Removido del grupo '$($groupName)'."
                } catch {
                    Write-Warning "No se pudo remover al usuario del grupo '$($groupName)' (ID: $groupId). Error: $($_.Exception.Message)"
                    # Considera si este error debe detener el script o solo ser una advertencia
                }
            }
        } else {
             Write-Output "No hay membresías de grupo para remover (después de aplicar exclusiones)."
        }
    } else {
        Write-Output "El usuario no es miembro de ningún grupo en Entra ID."
    }


    # 3. Resetear/Revocar Métodos MFA y Sesiones
    Write-Output "Iniciando reseteo de métodos MFA y revocación de sesiones..."

    # a) Revocar todas las sesiones de inicio de sesión activas
    try {
        Write-Output "Revocando sesiones de inicio de sesión..."
        Revoke-MgUserSignInSession -UserId $userId
        Write-Output "Comando de revocación de sesiones enviado."
        # Nota: La revocación puede no ser instantánea.
    } catch {
        Write-Warning "No se pudo ejecutar la revocación de sesiones para '$UserPrincipalName'. Error: $($_.Exception.Message)"
    }

    # b) Eliminar métodos de autenticación registrados (Fuerza re-registro si la cuenta se reactiva)
    # Esto incluye Teléfono, Authenticator App, FIDO2, etc.
    try {
        Write-Output "Obteniendo métodos de autenticación registrados..."
        $authMethods = Get-MgUserAuthenticationMethod -UserId $userId -All
        if ($authMethods) {
            Write-Output "Se encontraron $($authMethods.Count) métodos de autenticación."
            foreach ($method in $authMethods) {
                $methodType = $method.GetType().Name
                $methodId = $method.Id
                try {
                    Write-Output "Eliminando método: $($methodType) (ID: $methodId)..."
                    Remove-MgUserAuthenticationMethod -UserId $userId -AuthenticationMethodId $methodId
                     Write-Output "Método $($methodType) eliminado."
                } catch {
                     Write-Warning "No se pudo eliminar el método de autenticación '$($methodType)' (ID: $methodId). Error: $($_.Exception.Message)"
                }
            }
        } else {
             Write-Output "No se encontraron métodos de autenticación registrados para eliminar."
        }
    } catch {
        Write-Warning "No se pudieron obtener o eliminar los métodos de autenticación para '$UserPrincipalName'. Error: $($_.Exception.Message)"
    }

    # 4. Opcional: Eliminar dispositivos asociados (si usas Intune/Endpoint Manager, esto podría hacerse allí)
    # La eliminación de métodos (especialmente Microsoft Authenticator) a menudo desvincula el dispositivo del MFA.
    # La eliminación completa del dispositivo de Entra ID/Intune suele ser un paso separado si es necesario.
    # Ejemplo (requiere permisos adicionales como Device.ReadWrite.All):
    # Write-Output "Buscando dispositivos registrados por el usuario..."
    # $devices = Get-MgDeviceRegisteredOwner -DeviceId $userId -All # Esto busca dueños de un dispositivo, no al revés. Necesitamos buscar dispositivos registrados POR el usuario.
    # $userDevices = Get-MgUserRegisteredDevice -UserId $userId -All # Este comando no existe directamente, la relación es Device -> User
    # Una forma es buscar todos los dispositivos y filtrar, o buscar por dueño si se conoce el device ID.
    # Get-MgDevice -Filter "deviceId eq 'guid'" o Get-MgDevice -Filter "startswith(displayName,'nombre')"
    # Si encuentras dispositivos asociados específicamente a este usuario que deban eliminarse:
    # Remove-MgDevice -DeviceId $deviceId

    Write-Output "Desactivación en Entra ID completada para: $UserPrincipalName"

} catch {
    Write-Error "Ocurrió un error durante la desactivación en Entra ID para '$UserPrincipalName': $($_.Exception.Message)"
    throw $_ # Propagar el error
}