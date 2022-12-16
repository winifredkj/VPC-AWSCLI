# Create a Custom VPC Using the AWS CLI

[![image](https://www.linkpicture.com/q/awsclivpc.png)](https://www.linkpicture.com/view.php?img=LPic639b38566a3011070310356)

As you may already know, we usually manage AWS infrastructure via Terraform in the modern era. In this repo, I am trying to create and set up a VPC and host a WordPress website using AWS CLI instead of Terraform.

I created this setup so that you can compare and check the entire procedure to create a VPC through AWS CLI instead of Terraform is a painless process. Also, I wanted to familiarize myself with the detailed configuration steps required to create a custom VPC using AWS CLI. Administrators are shielded from some of these details when using the AWS Console and I desired a better understanding.

---------------------------------------------------------------
### _Resources we will be using in this setup:_
- Public subnets - 2
- Private subnet - 1
- Public route table - 1
- Private route table - 1
- NAT Gateway - 1
- Internet Gateway - 1
- Elastic IP - 1
- Bastion instance - 1
- Frontend instance for the webserver - 1
- Backend instance for the DB - 1
- Key Pair - 1
- Security Groups - 3

---------------------------------------------------------------
## Table of Contents



- [Prequisites](https://github.com/winifredkj/VPC-AWSCLI/edit/main/README.md#prerequisites)
- [Installing or updating AWS CLI](https://github.com/winifredkj/VPC-AWSCLI/edit/main/README.md#installing-or-updating-aws-cli)
- [Configuring the AWS CLI](https://github.com/winifredkj/VPC-AWSCLI/edit/main/README.md#configuring-the-aws-cli)
- [Create AWS VPC (Virtual Private Cloud)](https://github.com/winifredkj/VPC-AWSCLI/edit/main/README.md#create-aws-vpc-virtual-private-cloud)
- [Create Public and Private Subnets](https://github.com/winifredkj/VPC-AWSCLI/edit/main/README.md#create-public-and-private-subnets)
- [Create Internet Gateway (IGW)](https://github.com/winifredkj/VPC-AWSCLI/edit/main/README.md#create-internet-gateway-igw)
- [Create NAT Gateway](https://github.com/winifredkj/VPC-AWSCLI/edit/main/README.md#create-nat-gateway)
- [Configure Route Tables](https://github.com/winifredkj/VPC-AWSCLI/edit/main/README.md#configure-route-tables)
- [Launching all three instances into the three subnets that were created before.](https://github.com/winifredkj/VPC-AWSCLI/edit/main/README.md#launching-all-three-instances-into-the-three-subnets-that-were-created-before)


----------------------------------------------------------     
## Prerequisites

- AWSCLI must be installed on your local machine.
- AWSCLI must be configured with an IAM user and the output format should be "json"
--------------------------------------------------------
## Installing or Updating AWS CLI

The AWS Command Line Interface (AWS CLI) is an open source tool that enables you to interact with AWS services using commands in your command-line shell. 

For more info on AWS CLI see: https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-welcome.html

Here, I am installing the AWS CLI on a Linux machine (64-Bit).

    $ curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip awscliv2.zip
    sudo ./aws/install

 > **NOTE**: _To update your current installation of the AWS CLI, add your existing symlink and installer information to construct the install command with the --update parameter._
 
    sudo ./aws/install --bin-dir /usr/local/bin --install-dir /usr/local/aws-cli --update
---------------------------------------------------------------
> ```Attention!``` 
>I recommend that all customers regularly monitor the [Amazon Web Services Security Bulletins website](https://aws.amazon.com/security/security-bulletins/?card-body.sort-by=item.additionalFields.bulletinId&card-body.sort-order=desc&awsf.bulletins-flag=*all&awsf.bulletins-year=*all) for any important security bulletins related to aws-cli.
---------------------------------------------------
## Configuring the AWS CLI

To do the same we need to create an IAM user with programmatic access. While creating user it will generate Access key and Secret key. Save the keys at your end and by using the below command we can configure AWSCLI. Here, I am configuring AWSCLI in the region us-east-2.

    $ aws configure
    AWS Access Key ID [None]:XXXXXXXXXXXX 
    AWS Secret Access Key [None]: XXXXXXXXXXXXXXXX
    Default region name [None]: us-east-2
    Default output format [None]: json
--------------------------------------------------
## Create AWS VPC (Virtual Private Cloud)

An AWS VPC is a virtual private network in the AWS Cloud where you can provision and run different AWS resources (e.g. ECS container instances, Lambda functions, RDS database instances etc).

For more info on AWS VPC see https://docs.aws.amazon.com/vpc/latest/userguide/what-is-amazon-vpc.html.

Here we are going to create VPC in the region us-east-2 with name "peoplesVPC" using the block 172.16.0.0/16. 

    [root@ip-172-31-36-30 ~]# aws ec2 create-vpc --cidr-block 172.16.0.0/16 --region us-east-2 --query Vpc.VpcId --output text
    vpc-04c7baf32fb3a31b4
    [root@ip-172-31-36-30 ~]#

Next, adding Name tag for VPC as "peoplesVPC"

    [root@ip-172-31-36-30 ~]# aws ec2 create-tags --resources "vpc-04c7baf32fb3a31b4" --tags Key=Name,Value="peoplesVPC"
    [root@ip-172-31-36-30 ~]#

Now, we enable the  "DNS Hostnames" in the VPC:

    [root@ip-172-31-36-30 ~]# aws ec2 modify-vpc-attribute --vpc-id "vpc-04c7baf32fb3a31b4" --enable-dns-hostnames
    [root@ip-172-31-36-30 ~]#
--------------------------------------------------------    
## Create Public and Private Subnets

Subnets can be public (accessible from the internet) or private (not accessible from the internet), a subnet is public when it routes traffic through an Internet Gateway (IGW) attached the VPC. A subnet is private when it doesn't route traffic through an IGW, however outbound internet access can be enabled from a private subnet by routing traffic through a Network Address Translation (NAT) Gateway located in a public subnet.

For more info on AWS Subnets see https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Subnets.html.

Next we'll create the subnets inside our VPC that will hold our AWS resources. I am going to create 3 subntes in the region us-east-2a, us-east-2b and us-east-2c respectively. Two of them will be public subnets and the other one will be a private subnet. 

Follow these steps to create the subnets in your VPC:

------------------------------
    [root@ip-172-31-36-30 ~]# aws ec2 create-subnet --vpc-id vpc-04c7baf32fb3a31b4 --availability-zone "us-east-2a" --cidr-block 172.16.0.0/18
    {
     "Subnet": {
        "AvailabilityZone": "us-east-2a",
        "AvailabilityZoneId": "use2-az1",
        "AvailableIpAddressCount": 16379,
        "CidrBlock": "172.16.0.0/18",
        "DefaultForAz": false,
        "MapPublicIpOnLaunch": false,
        "State": "available",
        "SubnetId": "subnet-0ebe178a62b4c4f56",
        "VpcId": "vpc-04c7baf32fb3a31b4",
        "OwnerId": "887670523072",
        "AssignIpv6AddressOnCreation": false,
        "Ipv6CidrBlockAssociationSet": [],
        "SubnetArn": "arn:aws:ec2:us-east-2:887670523072:subnet/subnet-0ebe178a62b4c4f56",
        "EnableDns64": false,
        "Ipv6Native": false,
        "PrivateDnsNameOptionsOnLaunch": {
            "HostnameType": "ip-name",
            "EnableResourceNameDnsARecord": false,
            "EnableResourceNameDnsAAAARecord": false
                    }
                }
        }
----------------------------------------------------
    [root@ip-172-31-36-30 ~]# aws ec2 create-subnet --vpc-id vpc-04c7baf32fb3a31b4 --availability-zone "us-east-2b" --cidr-block 172.16.64.0/18
    {
    "Subnet": {
        "AvailabilityZone": "us-east-2b",
        "AvailabilityZoneId": "use2-az3",
        "AvailableIpAddressCount": 16379,
        "CidrBlock": "172.16.64.0/18",
        "DefaultForAz": false,
        "MapPublicIpOnLaunch": false,
        "State": "available",
        "SubnetId": "subnet-07782e4e2403a07c0",
        "VpcId": "vpc-04c7baf32fb3a31b4",
        "OwnerId": "887670523072",
        "AssignIpv6AddressOnCreation": false,
        "Ipv6CidrBlockAssociationSet": [],
        "SubnetArn": "arn:aws:ec2:us-east-2:887670523072:subnet/subnet-07782e4e2403a07c0",
        "EnableDns64": false,
        "Ipv6Native": false,
        "PrivateDnsNameOptionsOnLaunch": {
            "HostnameType": "ip-name",
            "EnableResourceNameDnsARecord": false,
            "EnableResourceNameDnsAAAARecord": false
             }
         }
    }
-----------------------------------------------------
    [root@ip-172-31-36-30 ~]# aws ec2 create-subnet --vpc-id vpc-04c7baf32fb3a31b4 --availability-zone "us-east-2c" --cidr-block 172.16.128.0/18
    {
    "Subnet": {
        "AvailabilityZone": "us-east-2c",
        "AvailabilityZoneId": "use2-az2",
        "AvailableIpAddressCount": 16379,
        "CidrBlock": "172.16.128.0/18",
        "DefaultForAz": false,
        "MapPublicIpOnLaunch": false,
        "State": "available",
        "SubnetId": "subnet-0459c429691eec8f8",
        "VpcId": "vpc-04c7baf32fb3a31b4",
        "OwnerId": "887670523072",
        "AssignIpv6AddressOnCreation": false,
        "Ipv6CidrBlockAssociationSet": [],
        "SubnetArn": "arn:aws:ec2:us-east-2:887670523072:subnet/subnet-0459c429691eec8f8",
        "EnableDns64": false,
        "Ipv6Native": false,
        "PrivateDnsNameOptionsOnLaunch": {
            "HostnameType": "ip-name",
            "EnableResourceNameDnsARecord": false,
            "EnableResourceNameDnsAAAARecord": false
            }
         }
    }
    

Now, adding tags for the newly created subnets:
##
I am naming the public and private subnets as "subnet-public-1", "subnet-public-2", and "subnet-private-1" respectively.

    [root@ip-172-31-36-30 ~]# aws ec2 create-tags --resources "subnet-0ebe178a62b4c4f56" --tags Key=Name,Value="subnet-public-1"
    [root@ip-172-31-36-30 ~]#
    [root@ip-172-31-36-30 ~]# aws ec2 create-tags --resources "subnet-07782e4e2403a07c0" --tags Key=Name,Value="subnet-public-2"
    [root@ip-172-31-36-30 ~]#
    [root@ip-172-31-36-30 ~]# aws ec2 create-tags --resources "subnet-0459c429691eec8f8" --tags Key=Name,Value="subnet-private-1"
    [root@ip-172-31-36-30 ~]#
    
Inorder to make two public subnets, it must have public IP addresses. 
###
With the following commands, I am making IPs public on launch for two public subnets.

    [root@ip-172-31-36-30 ~]# aws ec2 modify-subnet-attribute  --subnet-id "subnet-0ebe178a62b4c4f56"  --map-public-ip-on-launch
    [root@ip-172-31-36-30 ~]#
    [root@ip-172-31-36-30 ~]# aws ec2 modify-subnet-attribute  --subnet-id "subnet-07782e4e2403a07c0"  --map-public-ip-on-launch
    [root@ip-172-31-36-30 ~]#

## Create Internet Gateway (IGW)

An AWS internet gateway (IGW) is used to enable internet access to and from subnets in your VPC. A subnet that routes traffic to an IGW is a public subnet, and a subnet that doesn't route traffic to an IGW is a private subnet. Routes are configured in route tables that we'll cover shortly.

For more on internet gateways see https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Internet_Gateway.html.

Follow these steps to create an IGW and attach it to your VPC:

    [root@ip-172-31-36-30 ~]# aws ec2 create-internet-gateway
    {
    "InternetGateway": {
        "Attachments": [],
        "InternetGatewayId": "igw-0eb0b0bd3bb1b496d",
        "OwnerId": "887670523072",
        "Tags": []
                      }
    }
    [root@ip-172-31-36-30 ~]#

Now, I am adding a Name tag to the IGW:

    [root@ip-172-31-36-30 ~]# aws ec2 create-tags --resources "igw-0eb0b0bd3bb1b496d" --tags Key=Name,Value="people-igw"
    [root@ip-172-31-36-30 ~]#


And attaching the IGW to the VPC:

    [root@ip-172-31-36-30 ~]# aws ec2 attach-internet-gateway --internet-gateway-id "igw-0eb0b0bd3bb1b496d" --vpc-id "vpc-04c7baf32fb3a31b4"
    [root@ip-172-31-36-30 ~]#

There will be a default route table assigned to all subnets. Now I am going to create a custom route table for the VPC using the following create-route-table command and create a tag of "people-rt".

    [root@ip-172-31-36-30 ~]# aws ec2 create-route-table --vpc-id "vpc-04c7baf32fb3a31b4"
    {
    "RouteTable": {
        "Associations": [],
        "PropagatingVgws": [],
        "RouteTableId": "rtb-000aae707d2d03ad8",
        "Routes": [
            {
                "DestinationCidrBlock": "172.16.0.0/16",
                "GatewayId": "local",
                "Origin": "CreateRouteTable",
                "State": "active"
            }
        ],
        "Tags": [],
        "VpcId": "vpc-04c7baf32fb3a31b4",
        "OwnerId": "887670523072"
         }
    }
    [root@ip-172-31-36-30 ~]#

Now, I am adding the Name tag for the route table:

    [root@ip-172-31-36-30 ~]# aws ec2 create-tags --resources rtb-000aae707d2d03ad8 --tags Key=Name,Value=people-rt
    [root@ip-172-31-36-30 ~]#

The route table is currently not associated with any subnet. We need to associate it with a subnet in the VPC so that traffic from that subnet is routed to the internet gateway. Use the following describe-subnets command to get the subnet IDs.

    [root@ip-172-31-36-30 ~]# aws ec2 describe-route-tables --route-table-id rtb-000aae707d2d03ad8
    {
    "RouteTables": [
        {
            "Associations": [],
            "PropagatingVgws": [],
            "RouteTableId": "rtb-000aae707d2d03ad8",
            "Routes": [
                {
                    "DestinationCidrBlock": "172.16.0.0/16",
                    "GatewayId": "local",
                    "Origin": "CreateRouteTable",
                    "State": "active"
                },
                {
                    "DestinationCidrBlock": "0.0.0.0/0",
                    "GatewayId": "igw-0eb0b0bd3bb1b496d",
                    "Origin": "CreateRoute",
                    "State": "active"
                }
            ],
            "Tags": [
                {
                    "Key": "Name",
                    "Value": "people-rt"
                }
            ],
            "VpcId": "vpc-04c7baf32fb3a31b4",
            "OwnerId": "887670523072"
                }
            ]
    }
    [root@ip-172-31-36-30 ~]#

To associate the public route table to public subnets I am running the following commands:

    [root@ip-172-31-36-30 ~]# aws ec2 associate-route-table --route-table-id rtb-0ec07251dcc6bcb6b --subnet-id subnet-0ebe178a62b4c4f56
    {
    "AssociationId": "rtbassoc-0ab096abf6c84e126",
    "AssociationState": {
        "State": "associated"
             }
    }
-------------------------------------------------------
    [root@ip-172-31-36-30 ~]# aws ec2 associate-route-table --route-table-id rtb-0ec07251dcc6bcb6b --subnet-id subnet-07782e4e2403a07c0
    {
    "AssociationId": "rtbassoc-03e093e20cc2066b8",
    "AssociationState": {
        "State": "associated"
            }
    }
    [root@ip-172-31-36-30 ~]#


Also, I am Attaching internet gateway to the default route table or the route table assigned to the public subnets:

    [root@ip-172-31-36-30 ~]# aws ec2 create-route --route-table-id rtb-0ec07251dcc6bcb6b --destination-cidr-block 0.0.0.0/0 --gateway-id igw-0eb0b0bd3bb1b496d
    {
    "Return": true
        }
    [root@ip-172-31-36-30 ~]#
##
> **NOTE**: You can find the details of the default public route table on the VPC by running the following command:
>
> #aws ec2 describe-route-tables
 #
 ----------------------------------------------------------
 
 # Create NAT Gateway

A network address translation (NAT) gateway is used to provide outbound internet access to AWS resources running in private subnets. A NAT gateway is located in a public subnet and acts like a proxy for outbound traffic from private subnets that route their traffic to the NAT gateway.

For more info on NAT gateways see https://docs.aws.amazon.com/vpc/latest/userguide/vpc-nat-gateway.html.

I am going to create a NAT Gateway and allocate to the second public subnet "subnet-public-2". For creating a NAT gateway, it will be needed to allocate an elastic ip address first.

    [root@ip-172-31-36-30 ~]# aws ec2 allocate-address --domain vpc
    {
    "PublicIp": "65.2.42.42",
    "AllocationId": "eipalloc-0ddd3bb548bf5532e",
    "PublicIpv4Pool": "amazon",
    "NetworkBorderGroup": "us-east-2",
    "Domain": "vpc"
    }
    [root@ip-172-31-36-30 ~]#

The above command will allocate an elastic IP to the VPC.

Now, I am creating a NAT gateway with the Elastic IP.

    [root@ip-172-31-36-30 ~]# aws ec2 create-nat-gateway --subnet-id "subnet-0ebe178a62b4c4f56" --allocation-id "eipalloc-0ddd3bb548bf5532e"
    {
    "ClientToken": "99203dbd-12ca-4a4f-806a-5d2ddebb0fe1",
    "NatGateway": {
        "CreateTime": "2022-12-09T14:18:13+00:00",
        "NatGatewayAddresses": [
            {
                "AllocationId": "eipalloc-0ddd3bb548bf5532e"
            }
        ],
        "NatGatewayId": "nat-05e76df380ecbda59",
        "State": "pending",
        "SubnetId": "subnet-0ebe178a62b4c4f56",
        "VpcId": "vpc-04c7baf32fb3a31b4",
        "ConnectivityType": "public"
                }
    }
    [root@ip-172-31-36-30 ~]#

Adding tags to the NAT gateway:

    [root@ip-172-31-36-30 ~]# aws ec2 create-tags --resources nat-05e76df380ecbda59 --tags Key=Name,Value=people-nat
    [root@ip-172-31-36-30 ~]#

# Configure Route Tables

Associating the private route table to private subnet and attach NAT gateway to the same:

    [root@ip-172-31-36-30 ~]# aws ec2 associate-route-table --route-table-id rtb-000aae707d2d03ad8 --subnet-id subnet-0459c429691eec8f8
    {
    "AssociationId": "rtbassoc-0d14a5g2g0dbcfadf",
    "AssociationState": {
        "State": "associated"
                        }
    }
    [root@ip-172-31-36-30 ~]#
----------------------------------------------------------------------------
    [root@ip-172-31-36-30 ~]#  aws ec2 create-route --route-table-id rtb-000aae707d2d03ad8 --destination-cidr-block 0.0.0.0/0 --nat-gateway-id nat-05e76df380ecbda59
    {
    "Return": true
    }
    [root@ip-172-31-36-30 ~]#

#### _VPC creation part is completed successfully now. For the same we have created subnets, route tables, internet gateway, NAT gateway and associated with the respective subnets._
#
#
 ---------------------------------------------------------------
# Launching all three instances into the three subnets that were created before:

In our scenario, we are creating 3 instances in 3 subnets and for each instances we are creating 3 different security groups. First, we are going to create Keypair using the create-key-pair command:

Creating a Key pair to access the instances: 

    [root@ip-172-31-36-30 ~]# aws ec2 create-key-pair --key-name "peopleec-key" --query 'KeyMaterial' --output text > peopleec-key.pem
    [root@ip-172-31-36-30 ~]#
 

Changed the Key pair permissions for security purposes:

    [root@ip-172-31-36-30 ~]# chmod 400 peopleec-key.pem
    [root@ip-172-31-36-30 ~]#
    
Creating 3 Security Groups:

Then I am going to create 3 security groups. One security group only have SSH access (For bastion instance) and assigning to one of our public subnet. And the other one which I am going to create with only have httpd access from the public and SSH access from the first instance. Because, I am going to create with only Apache and PHP content installed in that instance (Frontend). After doing the same, I am going to create another instance that will only have the database server and it is going to be set up in a private subnet. So the third security group will have the rule for MySQL access from the first instance and SSH access from the bastion instance. 

Let's continue with the security group creation in this scenario:

    [root@ip-172-31-36-30 ~]# aws ec2 create-security-group  --group-name "bastion-sg"  --description "Bastion-MyIP"  --vpc-id "vpc-04c7baf32fb3a31b4"
    {
    "GroupId": "sg-08bfd82ab279d5c2e"
    }
    [root@ip-172-31-36-30 ~]#
-----------------------------------------------------------
    [root@ip-172-31-36-30 ~]# aws ec2 create-security-group  --group-name "frontend-sg"  --description "Frontend-Allow 80 and BastionIP"  --vpc-id "vpc-04c7baf32fb3a31b4"
    {
    "GroupId": "sg-07fe4a76b36a410d1"
    }
    [root@ip-172-31-36-30 ~]#
----------------------------------------------------------------
    [root@ip-172-31-36-30 ~]# aws ec2 create-security-group  --group-name "dbbackend-sg"  --description "DB-backend-Allow 3306 and BastionIP"  --vpc-id "vpc-04c7baf32fb3a31b4"
    {
    "GroupId": "sg-03ed1026006950c16"
    }
    [root@ip-172-31-36-30 ~]#
--------------------------------------------------------------------------

Here, I am naming the three security group names as _"bastion-sg"_, _"frontend-sg"_, and _"dbbackend-sg"_.

    [root@ip-172-31-36-30 ~]# aws ec2 create-tags --resources "sg-08bfd82ab279d5c2e" --tags Key=Name,Value="bastion-sg"
    [root@ip-172-31-36-30 ~]#
-----------------------------------------------------------------
    [root@ip-172-31-36-30 ~]# aws ec2 create-tags --resources "sg-07fe4a76b36a410d1" --tags Key=Name,Value="frontend-sg"
    [root@ip-172-31-36-30 ~]#
-------------------------------------------------------------------
    [root@ip-172-31-36-30 ~]# aws ec2 create-tags --resources "sg-03ed1026006950c16" --tags Key=Name,Value="dbbackend-sg"
    [root@ip-172-31-36-30 ~]#
---------------------------------------------------------------------

Then, I am going to assign the rules in the respective security groups:

Enabling port 22 to _"bastion-sg"_:

    [root@ip-172-31-36-30 ~]# aws ec2 authorize-security-group-ingress --group-id "sg-08bfd82ab279d5c2e"  --protocol tcp --port 22  --cidr "0.0.0.0/0"
    {
        "Return": true,
        "SecurityGroupRules": [
            {
                "SecurityGroupRuleId": "sgr-06d66e5de9dd3ea91",
                "GroupId": "sg-08bfd82ab279d5c2e",
                "GroupOwnerId": "887670523072",
                "IsEgress": false,
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "CidrIpv4": "0.0.0.0/0"
            }
        ]
    }
    [root@ip-172-31-36-30 ~]#

Enabling port 80 to the public and 443 to _"frontend-sg"_:

    [root@ip-172-31-36-30 ~]# aws ec2 authorize-security-group-ingress --group-id "sg-07fe4a76b36a410d1"  --protocol tcp --port 80  --cidr "0.0.0.0/0"
    {
     "Return": true,
     "SecurityGroupRules": [
        {
            "SecurityGroupRuleId": "sgr-0b62fe0c2a57820fb",
            "GroupId": "sg-07fe4a76b36a410d1",
            "GroupOwnerId": "887670523072",
            "IsEgress": false,
            "IpProtocol": "tcp",
            "FromPort": 80,
            "ToPort": 80,
            "CidrIpv4": "0.0.0.0/0"
        }
            ]
    }
--------------------------------------------------------------
    [root@ip-172-31-36-30 ~]# aws ec2 authorize-security-group-ingress --group-id "sg-07fe4a76b36a410d1"  --protocol tcp --port 443  --cidr "0.0.0.0/0"
    {
        "Return": true,
        "SecurityGroupRules": [
            {
            "SecurityGroupRuleId": "sgr-0bd8cfe6a2dca2476",
            "GroupId": "sg-07fe4a76b36a410d1",
            "GroupOwnerId": "887670523072",
            "IsEgress": false,
            "IpProtocol": "tcp",
            "FromPort": 443,
            "ToPort": 443,
            "CidrIpv4": "0.0.0.0/0"
            }
        ]
    }
    [root@ip-172-31-36-30 ~]#
    
    
Enabling custom ssh access from _"bastion-sg"_ to _"frontend-sg"_:

    [root@ip-172-31-36-30 ~]# aws ec2 authorize-security-group-ingress --group-id "sg-07fe4a76b36a410d1"  --protocol tcp --port 22 --source-group "sg-08bfd82ab279d5c2e"
    {
        "Return": true,
        "SecurityGroupRules": [
            {
                "SecurityGroupRuleId": "sgr-01d661d494e6b8e62",
                "GroupId": "sg-07fe4a76b36a410d1",
                "GroupOwnerId": "887670523072",
                "IsEgress": false,
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "ReferencedGroupInfo": {
                    "GroupId": "sg-08bfd82ab279d5c2e",
                    "UserId": "887670523072"
            }
        }
                    ]
    }
    [root@ip-172-31-36-30 ~]#

Enabling custom ssh from _"bastion-sg"_ to _"dbbackend-sg"_:

    [root@ip-172-31-36-30 ~]# aws ec2 authorize-security-group-ingress --group-id "sg-03ed1026006950c16"  --protocol tcp --port 22 --source-group "sg-08bfd82ab279d5c2e"
    {
        "Return": true,
        "SecurityGroupRules": [
            {
                "SecurityGroupRuleId": "sgr-04980563c6df2e38d",
                "GroupId": "sg-03ed1026006950c16",
                "GroupOwnerId": "887670523072",
                "IsEgress": false,
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "ReferencedGroupInfo": {
                    "GroupId": "sg-08bfd82ab279d5c2e",
                    "UserId": "887670523072"
            }
        }
                        ]
    }
    [root@ip-172-31-36-30 ~]#
    
Enabling 3306 from _"frontend-sg"_ to _"dbbackend-sg"_:

    [root@ip-172-31-36-30 ~]# aws ec2 authorize-security-group-ingress --group-id "sg-03ed1026006950c16"  --protocol tcp --port 3306 --source-group "sg-07fe4a76b36a410d1"
    {
        "Return": true,
        "SecurityGroupRules": [
            {
                "SecurityGroupRuleId": "sgr-0bcb9ea8fa3efc4c2",
                "GroupId": "sg-03ed1026006950c16",
                "GroupOwnerId": "887670523072",
                "IsEgress": false,
                "IpProtocol": "tcp",
                "FromPort": 3306,
                "ToPort": 3306,
                "ReferencedGroupInfo": {
                    "GroupId": "sg-07fe4a76b36a410d1",
                    "UserId": "887670523072"
            }
        }
                                ]
    }
    [root@ip-172-31-36-30 ~]#

Now, I am launching the instances one by one.

*  Launching instance with only SSH access: _'people-bastion'_ (Used the security group _"bastion-sg"_ and subnet id of _"subnet-public-2"_)
--------------------------------------------------------------------
#
    [root@ip-172-31-36-30 ~]# aws ec2 run-instances --image-id ami-074dc0a6f6c764218 --count 1 --instance-type t2.micro --key-name peopleec-key --security-group-ids "sg-08bfd82ab279d5c2e" --subnet-id "subnet-07782e4e2403a07c0" --user-data file://userdata.sh --associate-public-ip-address
    {
        "Groups": [],
        "Instances": [
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-074dc0a6f6c764218",
                "InstanceId": "i-09d5a77e117a4ee5e",
                "InstanceType": "t2.micro",
                "KeyName": "peopleec-key",
                "LaunchTime": "2022-12-09T14:57:57+00:00",
                "Monitoring": {
                    "State": "disabled"
                },
            "Placement": {
                "AvailabilityZone": "us-east-2b",
                "GroupName": "",
                "Tenancy": "default"
            },
            "PrivateDnsName": "ip-172-16-89-180.us-east-2.compute.internal",
            "PrivateIpAddress": "172.16.89.180",
			
		}
	                ]
    }
    [root@ip-172-31-36-30 ~]#

* Launching the second instance as a Webserver frontend: _'people-frontend'_ (Used the security group _"frontend-sg"_ and subnet id of _"subnet-public-1"_)
#
--------------------------------------------------------------------

    [root@ip-172-31-36-30 ~]# aws ec2 run-instances --image-id ami-074dc0a6f6c764218 --count 1 --instance-type t2.micro --key-name peopleec-key --security-group-ids "sg-07fe4a76b36a410d1" --subnet-id "subnet-0ebe178a62b4c4f56" --user-data file://userdata.sh --associate-public-ip-address

    {
        "Groups": [],
        "Instances": [
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-074dc0a6f6c764218",
                "InstanceId": "i-060142ee6d0751f9b",
                "InstanceType": "t2.micro",
                "KeyName": "peopleec-key",
                "LaunchTime": "2022-12-09T14:56:45+00:00",
                "Monitoring": {
                    "State": "disabled"
                },
                "Placement": {
                    "AvailabilityZone": "us-east-2a",
                    "GroupName": "",
                    "Tenancy": "default"
                },
                    "PrivateDnsName": "ip-172-16-59-31.us-east-2.compute.internal",
                    "PrivateIpAddress": "172.16.59.31",
		}
	                ]
    }
    [root@ip-172-31-36-30 ~]#

* Launching the third instance as a database server: _'people-dbbackend'_: (Used the security group _"dbbackend-sg"_ and subnet id of _"subnet-private-1"_)
#
----------------------------------------------------------------------
    [root@ip-172-31-36-30 ~]# aws ec2 run-instances --image-id ami-074dc0a6f6c764218 --count 1 --instance-type t2.micro --key-name peopleec-key --security-group-ids "sg-03ed1026006950c16" --subnet-id "subnet-0459c429691eec8f8" --user-data file://userdata.sh --associate-public-ip-address

    {
        "Groups": [],
        "Instances": [
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-074dc0a6f6c764218",
                "InstanceId": "i-065ca84cb43a24236",
                "InstanceType": "t2.micro",
                "KeyName": "peopleec-key",
                "LaunchTime": "2022-12-09T14:59:02+00:00",
                "Monitoring": {
                    "State": "disabled"
                },
                "Placement": {
                    "AvailabilityZone": "us-east-2c",
                    "GroupName": "",
                    "Tenancy": "default"
                },
                "PrivateDnsName": "ip-172-16-120-135.us-east-2.compute.internal",
                "PrivateIpAddress": "172.16.120.135",
		    }
	    ]
    }
    [root@ip-172-31-36-30 ~]#

Here, I have used a _"userdata.sh"_ file which contains some bash commands to setup a stable SSH connection when launching the instances.

    [root@ip-172-31-36-30 ~]# cat userdata.sh
    #!/bin/bash

    echo "ClientAliveInterval 60" >> /etc/ssh/sshd_config
    echo "LANG=en_US.utf-8" >> /etc/environment
    echo "LC_ALL=en_US.utf-8" >> /etc/environment
    service sshd restart
    [root@ip-172-31-36-30 ~]#
    
Now we can try describing the instances in a table format to display the instance ID, availability zone, and the value of the Name tag of instances that have a tag with the name tag-key:
    
    [root@ip-172-31-36-30 ~]# aws ec2 describe-instances  --filters Name=tag-key,Values=Name --query 'Reservations[*].Instances[*].{Instance:InstanceId,AZ:Placement.AvailabilityZone,Name:Tags[?Key==`Name`]|[0].Value}' --output table
    -------------+-----------------------+---------------------
    |                    DescribeInstances                    |
    +------------+-----------------------+--------------------+
    |     AZ     |       Instance        |       Name         |
    +------------+-----------------------+--------------------+
    |  us-east-2a|  i-060142ee6d0751f9b  |  people-frontend   |
    |  us-east-2b|  i-09d5a77e117a4ee5e  |  people-bastion    |
    |  us-east-2c|  i-065ca84cb43a24236  |  people-dbbackend  |
    +------------+-----------------------+--------------------+
    [root@ip-172-31-36-30 ~]#  

### Now, we can SSH into _"people-bastion"_ server and try accessing the _"people-frontend"_ and _"people-dbbackend"_ servers from it. 

You must install the _'httpd'_ service and _PHP_ on the _'people-frontend'_ server so that you can set up a WordPress Website on it. Also, database software like _'MariaDB'_ must be installed and configured on the _"people-dbbackend"_ server so that you can create the WordPress database and database user on it and use the same for your WordPress website.

> **NOTE**: Don't forget to add the private IP of the _"people-dbbackend"_ server in the _"DB_HOST"_ section of the _"wp-config.php"_ of the website on the _"people-frontend"_ server.

Once you set up the website, try accessing the public DNS name or public IP of the _"people-frontend"_ server and it will display your WordPress website content.

> Refer:
https://httpd.apache.org/docs/2.4/install.html
https://www.tutorialswebsite.com/how-to-install-php-on-aws-ec2-instance/
https://mariadb.com/kb/en/yum/#installing-mariadb-server-with-yum
https://linuxhint.com/create-mariadb-user/
