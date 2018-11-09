# azure_cli_appgw_vm_azuredatabaseformysql
Automation Script

# Resources
* Application Gateway(L7 Load Balancer)  
* Virtual Machine(Single)  
* Azure Database for MySQL  

# Software
* Virtual Machine(Single)  
Centos7.5 Publisher Rogue Wave Software  
apache 2.4  
php 5.4

* Azure Database for MySQL  
MySQL 5.6 or 5.7

# Others  
* Application Gateway(L7 Load Balancer)  
With Multiple site hosting   (Production Env, Test Env)  
With SSL termination  (Both Production Env, Test Env)  
With Redirect http to https (Both Production Env, Test Env)  
With Web Application Firewall  
SSL is Self signed certificate (Both Production Env, Test Env) 

# How to Provisioning  
1. common.azcli  
1. virtualmachine_single.azcli  
1. azuredbmysql.azcli  
1. applicationgateway.azcli

# ToDo
* [Connecting and Mounting](https://docs.microsoft.com/ja-jp/azure/virtual-machines/linux/add-disk) Data Disk
* Copy Project Directory to Data Disk  
* Comeercial SSL import to Production Env
* DNS Settings  
* Create SSH keys for Developers, Server administrator
* Create Database Account and Authorization
