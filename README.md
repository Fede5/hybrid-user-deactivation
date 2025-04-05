# Hybrid User Deactivation Workflow

This project demonstrates an automated hybrid offboarding workflow using Azure Logic Apps and Azure Automation. It deactivates users both in on-premises Active Directory and Entra ID (Azure AD).

## 🔐 What it does

- Disables the user account in AD and Azure AD
- Removes the user from all on-prem and cloud groups
- Resets their password (on-prem)
- Clears MFA methods and devices (Azure)

## 📂 Files

- `runbook.ps1`: PowerShell script to run on a Hybrid Runbook Worker
- `logicapp-workflow.json`: Logic App to trigger deactivation via HTTP or scheduled flow

## 🧰 Requirements

- Azure Automation Account with hybrid worker group connected to domain
- Logic App with HTTP trigger
- AzureAD and ActiveDirectory PowerShell modules

## 🚀 Usage

1. Deploy the Logic App and connect it to your Automation Account.
2. Import the runbook into Azure Automation.
3. Configure credentials and authentication in the Automation Account.
4. Trigger the Logic App with a POST request:

```json
{
  "username": "john.doe@yourdomain.com"
}
```