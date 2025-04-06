# Hybrid User Deactivation Workflow

![PowerShell](https://img.shields.io/badge/PowerShell-0078D4?logo=powershell&logoColor=white)
![Azure](https://img.shields.io/badge/Azure-0078D4?logo=microsoftazure&logoColor=white)
![Microsoft Graph](https://img.shields.io/badge/Microsoft%20Graph-2B88D8?logo=microsoft&logoColor=white)
![Automation](https://img.shields.io/badge/Automation-Enabled-brightgreen)
![Status](https://img.shields.io/badge/Production%20Ready-Yes-green)

This project provides a complete solution to automate the deactivation of hybrid users across both **on-premises Active Directory (AD)** and **Microsoft Entra ID (Azure AD)** using:

- 💻 PowerShell Automation Runbooks
- 🔗 Azure Logic App for orchestration
- ☁️ Microsoft Graph API for Entra operations

---

## 🧩 Components

### 1. `disable-onpremuser.ps1`
> **Location**: On-Premises Automation (via Hybrid Worker)

- Disables AD account (`Disable-ADAccount`)
- Removes user from all AD groups
- Resets password with strong random string

### 2. `Disable-EntraUser.ps1`
> **Location**: Azure Automation Runbook

- Disables Entra ID account
- Removes group memberships
- Deletes MFA methods and registered devices
- Forces password reset

### 3. `Logicapp.json`
> **Location**: Azure Logic App (Consumption or Standard)

- Trigger: HTTP request with `UserPrincipalName`
- Action 1: Disable on-prem user
- Action 2: Disable Entra ID user

---

## 🚀 Demo

```json
{
  "UserPrincipalName": "jdoe@domain.com"
}
```

- Submit via HTTP to the Logic App trigger URL.
- The user is automatically disabled across both environments.

---

## ✅ Prerequisites

- Azure Automation Account with Hybrid Worker
- Microsoft Graph PowerShell modules
- API Permissions: `User.ReadWrite.All`, `Directory.ReadWrite.All`, `Group.ReadWrite.All`
- Logic App with permission to invoke Automation Jobs

---

## 🔐 Security Considerations

- No passwords logged or exposed
- Secure password generation with high entropy
- MFA methods and registered devices are forcefully removed

---

## 📂 Files in this Repo

| File                   | Description                                |
|------------------------|--------------------------------------------|
| `disable-onpremuser.ps1` | Disables and cleans user in AD              |
| `Disable-EntraUser.ps1`  | Disables and resets user in Entra ID       |
| `Logicapp.json`          | Logic App definition for orchestrated flow |

---

## 🤝 Author

**Harry Federico Argote Carrasco**  
Senior Cloud Engineer | Azure Specialist  
📍 Bella Vista, Buenos Aires, Argentina

---

> Feel free to fork, reuse or suggest improvements via Pull Requests.
