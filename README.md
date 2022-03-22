# unifiPS

Manage a unifi controller with powershell 

- [unifiPS](#unifips)
  - [Hints](#hints)
  - [Usage](#usage)
    - [Authentication](#authentication)
    - [Basic information](#basic-information)
    - [Sites](#sites)
    - [Devices](#devices)
    - [Clients](#clients)
    - [Tags](#tags)
    - [Firewall](#firewall)
      - [Firewall Groups](#firewall-groups)
      - [Firewall Rules](#firewall-rules)
  - [TODO](#todo)

## Hints

Almost all functions need the parameter `SiteName`. You can easily pipe the output of `Get-UnifiSite` to any of these functions.

This also applies to other functions which in turn needs information about Devices, Clients, FirewallGroups, FirewallRules and so on

## Usage

### Authentication

Logging into the unifi controller:  

`Invoke-UnifiLogin -Uri <URI of the controller> [-Credential <PSCredential>]` 

For example:

`Invoke-UnifiLogin -Uri https://127.0.0.1:8443`

Logging out of the unifi controller:

`Invoke-UnifiLogout`

### Basic information

Retrieve basic information about the UniFi server:  

`Get-UnifiServerInfo`

Currently logged on user details:  

`Get-UnifiLogin`

List Admins:  

`Get-UnifiAdmin`

Show events:  

`Get-UnifiEvent -SiteName <SiteName>`

Or alarms:

`Get-UnifiAlarm -SiteName <SiteName>`

### Sites  

`Get-UnifiSite -SiteID <Site ID>`  or  
`Get-UnifiSite -SiteName <Internal Site Name` or  
`Get-UnifiSite -SiteDisplayName <Name of the site visible in the controller>`

To list all sites use a wildcard like `Get-UnifiSite -SiteName "*"`

You can also specify more than one site like `Get-UnifiSite -DisplayName "Default","Test","Site1"`

Retrieve extended information for a site

`Get-UnifiSiteInfo -SiteName <SiteName>`

For example:

`Get-UnifiSite "*" | Get-UnifiSiteInfo | Format-Table`

### Devices

*Devices are Access-Points, Switches, Gateways, etc.*

List devices:  

`Get-UnifiDevice -SiteName <SiteName>`

Restart devices:

`Restart-UnifiDevice -SiteName <SiteName> -MAC <Device MAC>`

Force-Provision a device:  

`Sync-UnifiDevice -SiteName <SiteName> -MAC <Device MAC>`

### Clients

*Clients are devices which are or were connected to a UniFi device, like a wifi client*

List all clients, connected now or connected in the past:  

`Get-UnifiClient -SiteName <SiteName>`

Only list active clients:  

`Get-UnifiClient -SiteName <SiteName> -Active`

Reconnect a client:  

`Disconnect-UnifiClient -SiteName <SiteName> -MAC <Client MAC>`

### Tags

List all tags:  

`Get-UnifiTag -SiteName <SiteName>`

Create new tag:  

`New-UnifiTag -SiteName <SiteName> -TagName <TagName> [-TagMembers <Array of Device MACs>]`

Edit tag:  

`Edit-UnifiTag -SiteName <SiteName> -TagID <TagID> [-TagName <TagName>] [-TagMembers <Array of Device MACs> -Mode Add|Replace]`

Delete tag:  

`Remove-UnifiTag -SiteName <SiteName> -TagID <TagID>`

### Firewall

#### Firewall Groups

List all firewall groups:  

`Get-UnifiFirewallGroup -SiteName <SiteName>`

Create new firewall group:  

`New-UnifiFirewallGroup -SiteName <SiteName> -GroupName <GroupName> -GroupType port-group|address-group|ipv6-address-group [-GroupMembers <Array of Port-Numbers/Ranges or IP-Addresses/Ranges depending on Group-Type>]`

Edit firewall group:  

`Edit-UnifiFirewallGroup -SiteName <SiteName> -GroupID <GroupID> [-GroupName <GroupName>] [-GroupMembers <Array of Port-Numbers/Ranges or IP-Addresses/Ranges depending on Group-Type>]`

Delete firewall group:  

`Remove-UnifiFirewallGroup -SiteName <SiteName> -GroupID <GroupID>`

#### Firewall Rules

List all firewall rules:  

`Get-UnifiFirewallRule -SiteName <SiteName>`

Create new firewall rule:  

`New-UnifiFirewallRule -SiteName <SiteName> -RuleName <GroupName> [...]]`  
This function has way too many parameters to list them here. Have a look at the help of this function to see some descriptive information

Edit firewall rule (does not work yet):  

`New-UnifiFirewallRule -SiteName <SiteName> -GroupID <GroupID> [...]]`  
This function has way too many parameters to list them here. Have a look at the help of this function to see some descriptive information

Delete firewall rule:  

`Remove-UnifiFirewallRule -SiteName <SiteName> -GroupID <GroupID>`

## TODO

* [ ] Add more help descriptions
* [ ] Add more filters to Get-Unifi*-Functions, so `Where-Object`-Piping is not necessary anymore
* [ ] Review error-messages

More functions will follow, for example:
* [ ] creating sites
* [ ] removing sites
* [ ] blocking clients
* [ ] update firmware for access-points
* [ ] forget (remove) access-points
* ...