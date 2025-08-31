# AWS → Azure Migration Demo (Code-First Project)

A hands-on project that **creates sample AWS EC2 sources in code**, then **assesses and migrates them to Azure using Azure Migrate**. Includes IaC for AWS, IaC for the Azure Migrate project, and PowerShell to orchestrate discovery → assessment → replication → test/cutover. Also includes clean-up.

> ⚠️ You will need AWS and Azure credentials configured on your workstation/runner. Treat any secrets (keys, project keys) carefully.

---

## Project layout

```
aws/
  terraform/
    main.tf
    variables.tf
    outputs.tf
    user_data_web.sh
azure/
  bicep/
    migrate-project.bicep
  powershell/
    01-login-and-context.ps1
    02-create-or-get-project.ps1
    03-generate-appliance-key.ps1
    04-create-assessment.ps1
    05-init-replication.ps1
    06-test-and-cutover.ps1
cleanup/
  destroy_aws.sh
  cleanup_azure.ps1
README.md
```

---

## Prereqs

- **AWS:** AWS CLI v2, Terraform ≥ 1.5. `aws configure` with a profile that has EC2/VPC permissions.
- **Azure:** Az PowerShell modules (`Install-Module Az -Scope CurrentUser` including `Az.Migrate`), Bicep CLI or `az deployment` capability, Owner/Contributor rights in the subscription/resource group.
- **Networking:** Outbound internet for the Azure Migrate appliance; allow required ports (documented by Azure Migrate) from source VMs to appliance and to Azure.

---

## 1) AWS: Terraform to create sample EC2 instances

**aws/terraform/variables.tf**

```hcl
variable "aws_region" { type = string  default = "us-east-1" }
variable "name_prefix" { type = string  default = "azmigrate-demo" }
variable "instance_count" { type = number default = 2 }
variable "instance_type" { type = string  default = "t3.micro" }
variable "key_name" { type = string  default = null } # existing key pair name (optional)
variable "create_key_pair" { type = bool default = true }
variable "public_ingress_cidrs" { type = list(string) default = ["0.0.0.0/0"] }
```

**aws/terraform/main.tf**

```hcl
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Use the default VPC to keep the demo simple
data "aws_vpc" "default" { default = true }
data "aws_subnets" "default" { filter { name = "vpc-id" values = [data.aws_vpc.default.id] } }

# Optional: create a demo key pair (unless an existing one is supplied)
resource "tls_private_key" "demo" {
  algorithm = "RSA"
  rsa_bits  = 2048
  count     = var.create_key_pair && var.key_name == null ? 1 : 0
}

resource "aws_key_pair" "demo" {
  count      = var.create_key_pair && var.key_name == null ? 1 : 0
  key_name   = "${var.name_prefix}-key"
  public_key = tls_private_key.demo[0].public_key_openssh
}

# Save PEM locally for SSH if we created it
resource "local_file" "demo_pem" {
  count    = var.create_key_pair && var.key_name == null ? 1 : 0
  filename = "${path.module}/generated_${var.name_prefix}.pem"
  content  = tls_private_key.demo[0].private_key_pem
  file_permission = "0400"
}

# Security group allowing SSH/HTTP (and RDP for Windows if you switch AMI)
resource "aws_security_group" "demo_sg" {
  name        = "${var.name_prefix}-sg"
  description = "Demo SG for Azure Migrate"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.public_ingress_cidrs
    description = "SSH"
  }
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.public_ingress_cidrs
    description = "HTTP"
  }
  # Uncomment for Windows
  # ingress {
  #   from_port   = 3389
  #   to_port     = 3389
  #   protocol    = "tcp"
  #   cidr_blocks = var.public_ingress_cidrs
  #   description = "RDP"
  # }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "${var.name_prefix}-sg" }
}

# Latest Amazon Linux 2023 AMI
data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["137112412989"] # Amazon
  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

# Launch N web instances with simple user_data
resource "aws_instance" "web" {
  count                       = var.instance_count
  ami                         = data.aws_ami.al2023.id
  instance_type               = var.instance_type
  subnet_id                   = data.aws_subnets.default.ids[count.index % length(data.aws_subnets.default.ids)]
  vpc_security_group_ids      = [aws_security_group.demo_sg.id]
  key_name                    = var.key_name != null ? var.key_name : aws_key_pair.demo[0].key_name
  associate_public_ip_address = true

  user_data = file("${path.module}/user_data_web.sh")

  tags = {
    Name              = "${var.name_prefix}-web-${count.index + 1}"
    migration_profile = "azure-migrate-demo"
  }
}
```

**aws/terraform/outputs.tf**

```hcl
output "public_ips" {
  value = [for i in aws_instance.web : i.public_ip]
}
output "private_ips" {
  value = [for i in aws_instance.web : i.private_ip]
}
output "instance_ids" {
  value = [for i in aws_instance.web : i.id]
}
output "ssh_key_path" {
  value       = try(local_file.demo_pem[0].filename, null)
  description = "Path to generated PEM if a key pair was created"
}
```

**aws/terraform/user_data_web.sh**

```bash
#!/bin/bash
set -eux
# Simple web app to identify the source host
amazon-linux-extras enable nginx1
yum -y install nginx
cat > /usr/share/nginx/html/index.html <<'EOF'
<h1>Azure Migrate Demo</h1>
<p>Host: $(hostname -f)</p>
<p>Time: $(date)</p>
EOF
systemctl enable nginx
systemctl start nginx
```

**Commands**

```bash
cd aws/terraform
terraform init
terraform apply -auto-approve \
  -var "name_prefix=azmigrate-demo" \
  -var "instance_count=2" \
  -var "aws_region=us-east-1"
```

---

## 2) Azure: Bicep to create an Azure Migrate Project

**azure/bicep/migrate-project.bicep**

```bicep
@description('Location for the Azure Migrate project metadata (not the target compute).')
param location string = 'eastus'
@description('Resource group name (deployment scope RG recommended).')
param projectName string = 'azmigrate-demo-project'

resource project 'Microsoft.Migrate/assessmentProjects@2019-10-01' = {
  name: projectName
  location: location
  tags: {
    purpose: 'demo'
  }
  properties: {
    # Optional: register a tool hint; can be omitted or set by portal flows
    registeredTool: 'ServerDiscovery'
  }
}

output projectId string = project.id
```

**Deploy**

```bash
# Option A: Bicep CLI via Azure CLI
az group create -n rg-azmigrate-demo -l eastus
az deployment group create -g rg-azmigrate-demo -f azure/bicep/migrate-project.bicep -p projectName=azmigrate-demo-project location=eastus
```

---

## 3) PowerShell: Login & Context

**azure/powershell/01-login-and-context.ps1**

```powershell
# Connect and set subscription
Connect-AzAccount
$SubscriptionId = "<YOUR-SUB-ID>"
Select-AzSubscription -SubscriptionId $SubscriptionId

$ResourceGroup = "rg-azmigrate-demo"
$ProjectName   = "azmigrate-demo-project"
$TargetRegion  = "EastUS"     # where replicated VMs will be created
```

---

## 4) Ensure project exists or fetch it

**azure/powershell/02-create-or-get-project.ps1**

```powershell
. "$PSScriptRoot/01-login-and-context.ps1"

# Try to get project; create via REST if not found (project usually created via Bicep)
$proj = Get-AzMigrateProject -ResourceGroupName $ResourceGroup -ProjectName $ProjectName -ErrorAction SilentlyContinue
if (-not $proj) {
  Write-Host "Project not found. Please deploy Bicep or create via portal before continuing." -ForegroundColor Yellow
  exit 1
}
$proj | Format-List Name,Location,ResourceGroupName
```

---

## 5) Generate (or retrieve) an Appliance Project Key

The **Azure Migrate appliance** runs in your source environment (in this demo: AWS VPC). You’ll deploy a small Windows or Linux VM and install the appliance software, then **paste a project key** to register it.

**azure/powershell/03-generate-appliance-key.ps1**

```powershell
. "$PSScriptRoot/01-login-and-context.ps1"

# Create a discovery site (logical grouping for discovered servers)
$DiscoverySiteName = "aws-site-01"
$site = New-AzMigrateSite -MigrateProjectName $ProjectName -ResourceGroupName $ResourceGroup -Name $DiscoverySiteName -Location (Get-AzResourceGroup -Name $ResourceGroup).Location
$site | Format-List Name,Id

# Generate a project key to register the Azure Migrate appliance
$key = New-AzMigrateProjectKey -ResourceGroupName $ResourceGroup -MigrateProjectName $ProjectName -SiteName $DiscoverySiteName
$keyText = $key.ApplianceName | Out-String

# Display registration details
$key | Format-List *
Write-Host "\n*** Copy the project key/token below to your appliance setup wizard ***\n" -ForegroundColor Cyan
$key.SharedSecret
```

> **Next:** In AWS, launch a small Windows Server (or Linux) VM to act as the **Azure Migrate appliance** (2–4 vCPU, 8–16 GB RAM is common). Download the Azure Migrate appliance installer from the Azure portal (Servers → Discover), then paste the **project key** above to register. Configure discovery to point at your EC2 instances (by IP range, credentials, etc.). Allow required ports (WMI/WinRM/SSH, HTTPS to Azure endpoints).

---

## 6) Create an Assessment from discovered EC2 servers

After the appliance starts discovery (give it some time), you can create groups and assessments:

**azure/powershell/04-create-assessment.ps1**

```powershell
. "$PSScriptRoot/01-login-and-context.ps1"

# Example: create a group and assessment for all discovered servers with a tag/value
$GroupName = "aws-ec2-web"
$AssessmentName = "aws-ec2-web-assessment"

# List discovered servers
$servers = Get-AzMigrateDiscoveredServer -ResourceGroupName $ResourceGroup -ProjectName $ProjectName
$servers | Select-Object DisplayName, Fqdn, IpAddresses, OperatingSystem | Format-Table -AutoSize

# Simple filter example: include all for demo
$serverIds = $servers.Id

# Create group
$group = New-AzMigrateGroup -ResourceGroupName $ResourceGroup -ProjectName $ProjectName -Name $GroupName -MachineId $serverIds

# Create assessment (as-is sizing). You can tweak properties via -AssessmentProperties
$assessment = New-AzMigrateAssessment -ResourceGroupName $ResourceGroup -ProjectName $ProjectName -GroupName $GroupName -Name $AssessmentName
$assessment | Format-List Name, Id, Properties
```

---

## 7) Initialize replication infra & enable replication (agent-based)

Treat AWS EC2 like “physical servers” for **agent-based** migration. You’ll deploy the **Mobility service** (the appliance guides this) and enable replication.

**azure/powershell/05-init-replication.ps1**

```powershell
. "$PSScriptRoot/01-login-and-context.ps1"

# Initialize target replication infrastructure (creates cache storage, vault, etc.)
Initialize-AzMigrateReplicationInfrastructure -ResourceGroupName $ResourceGroup -ProjectName $ProjectName -TargetRegion $TargetRegion

# Map discovered servers to replication settings
$servers = Get-AzMigrateDiscoveredServer -ResourceGroupName $ResourceGroup -ProjectName $ProjectName
$targetResourceGroupId = (Get-AzResourceGroup -Name $ResourceGroup).ResourceId
$targetVnetId = (Get-AzVirtualNetwork -ResourceGroupName $ResourceGroup | Select-Object -First 1).Id

foreach ($s in $servers) {
  Enable-AzMigrateServerReplication \
    -ResourceGroupName $ResourceGroup \
    -ProjectName $ProjectName \
    -DiscoveredMachineId $s.Id \
    -TargetResourceGroupId $targetResourceGroupId \
    -TargetNetworkId $targetVnetId \
    -TargetSubnetName (Get-AzVirtualNetwork -ResourceGroupName $ResourceGroup | Select-Object -First 1).Subnets[0].Name \
    -TargetLocation $TargetRegion \
    -LicenseType "NoLicenseType"    # adjust for Windows Hybrid Benefit if applicable
}

# Monitor jobs
Get-AzMigrateJob -ProjectName $ProjectName -ResourceGroupName $ResourceGroup | Select-Object Name,State,Task | Format-Table
```

> 📝 Ensure a target VNet/subnet already exists in your RG. If not, create one (e.g., `az network vnet create -g rg-azmigrate-demo -n vnet-demo --address-prefix 10.50.0.0/16 --subnet-name default --subnet-prefix 10.50.0.0/24`).

---

## 8) Test migrate, validate, and cut over

**azure/powershell/06-test-and-cutover.ps1**

```powershell
. "$PSScriptRoot/01-login-and-context.ps1"

$replicated = Get-AzMigrateServerReplication -ResourceGroupName $ResourceGroup -ProjectName $ProjectName

# Start a test migration (creates an isolated test VM)
foreach ($r in $replicated) {
  Start-AzMigrateTestMigration -InputObject $r -TestNetworkId (Get-AzVirtualNetwork -ResourceGroupName $ResourceGroup | Select-Object -First 1).Id
}

Write-Host "Validate the test VMs, then perform cleanup of test failover in the portal or via: Stop-AzMigrateTestMigration"

# When ready for cutover:
foreach ($r in $replicated) {
  Start-AzMigrateMigration -InputObject $r -PerformShutdown $true
}

# Check status
Get-AzMigrateJob -ProjectName $ProjectName -ResourceGroupName $ResourceGroup | Select-Object Name,State,Task | Format-Table
```

---

## 9) Cleanup scripts

**cleanup/destroy_aws.sh**

```bash
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../aws/terraform"
terraform destroy -auto-approve
```

**cleanup/cleanup_azure.ps1**

```powershell
. "$PSScriptRoot/../azure/powershell/01-login-and-context.ps1"

# Stop replication and remove replicated items
$items = Get-AzMigrateServerReplication -ResourceGroupName $ResourceGroup -ProjectName $ProjectName -ErrorAction SilentlyContinue
foreach ($i in $items) {
  try { Stop-AzMigrateServerReplication -InputObject $i -Force } catch { }
}

# Optionally remove test/migrated VMs and the project resource group (DANGEROUS)
# Remove-AzResourceGroup -Name $ResourceGroup -Force -AsJob
Write-Host "Azure cleanup complete (replication stopped). Manually remove RG if desired."
```

---

## 10) End-to-end runbook

1. **Provision AWS EC2**: `terraform apply` in `aws/terraform`.
2. **Deploy Azure Migrate project**: Deploy the Bicep file to `rg-azmigrate-demo`.
3. **Register appliance**: Run `03-generate-appliance-key.ps1`, deploy the appliance VM in AWS, install & register with the key, start discovery.
4. **Assessment**: After discovery populates, `04-create-assessment.ps1` to create a group & assessment.
5. **Replication**: Ensure a target VNet exists; run `05-init-replication.ps1`.
6. **Test & Cutover**: Run `06-test-and-cutover.ps1`.
7. **Cleanup**: `cleanup/destroy_aws.sh` and `cleanup/cleanup_azure.ps1`.

---

## Notes & Tips

- **Costs**: Use small instance types and shut down when idle.
- **IAM**: The appliance needs creds to query your EC2 instances (Linux SSH key/username, Windows admin creds for WMI/WinRM) and outbound HTTPS to Azure.
- **Naming & tags**: The sample tags include `migration_profile=azure-migrate-demo` to help you filter discovered servers.
- **Windows test**: To try Windows, swap the AMI and open RDP in the SG; install IIS via `Install-WindowsFeature -Name Web-Server -IncludeManagementTools`.
- **Private connectivity**: For restricted environments, consider Azure Migrate over Private Link via VPN/ExpressRoute and configure NSGs accordingly.
