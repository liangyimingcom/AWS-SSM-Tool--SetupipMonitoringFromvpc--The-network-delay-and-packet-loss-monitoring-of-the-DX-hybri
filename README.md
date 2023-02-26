## SetupIPMonitoringFromVPC - 通过SSM实现DX混合网络的网络延时与丢包监控(AWS原生方法且不限制主机数量)

### 第一章节：原生Global Porting（有IP数量限制的）的 SetupIPMonitoringFromVPC使用教程（@glei gulei老师撰写）

使用教程如下：
1）	Amazon Systems Manager---Documents 网络监控的使用如下

2）	 ![image-20230226123229079](https://raw.githubusercontent.com/liangyimingcom/storage/master/PicGo/image-20230226123229079.png)

3）	All documents 搜索 “SetupIPMonitoringFromVPC”

4）	 ![image-20230226123240929](https://raw.githubusercontent.com/liangyimingcom/storage/master/PicGo/image-20230226123240929.png)


5）	![image-20230226123304470](https://raw.githubusercontent.com/liangyimingcom/storage/master/PicGo/image-20230226123304470.png)

6）	点击执行

7）	输入 子网id和要ip地址，其他默认就可。

8）	![image-20230226123310195](https://raw.githubusercontent.com/liangyimingcom/storage/master/PicGo/image-20230226123310195.png)

9）	开始执行后，在exccuted steps处观察执行结果，在29步执行完成后，就会在cloudwatch中生成监控面板![image-20230226123321025](https://raw.githubusercontent.com/liangyimingcom/storage/master/PicGo/image-20230226123321025.png)


10）	结果展示如下，目前每个ip显示两个指标，一个丢包，一个延迟![image-20230226123346070](https://raw.githubusercontent.com/liangyimingcom/storage/master/PicGo/image-20230226123346070.png)


11）	结束



### 第二章节：魔改后的（无IP数量限制的）的 SetupIPMonitoringFromVPC使用教程

简述：在@glei gulei老师的基础上，liangym@修改TargetIPs输入框为9999个字符串，大约可以输入500个IP地址；在输入100个IP地址的环境下测试通过；同时修改了其他因为字符串数量超出导致的报错（如tag）确保可用；

使用方法：输入“SetupIPMonitoringFromVPC-nolimitips”后直接运行。可以参考上面的教程；

![image-20230226123408790](https://raw.githubusercontent.com/liangyimingcom/storage/master/PicGo/image-20230226123408790.png) 

![image-20230226123451608](https://raw.githubusercontent.com/liangyimingcom/storage/master/PicGo/image-20230226123451608.png)

测试环境：提供100不重复的公网IP作为测试环境搭建尝试
43.192.49.104,69.231.137.15,68.79.60.136,43.192.32.183,69.230.233.13,114.55.70.62,47.91.13.31,47.89.61.33,47.88.147.22,114.215.161.36,47.89.224.28,47.89.170.0,47.89.61.59,47.91.103.0,47.88.98.20,47.91.13.0,149.129.164.77,114.55.70.35,47.91.102.19,47.91.112.0,47.91.83.0,47.91.49.169,47.92.22.68,47.89.61.0,47.89.224.0,120.76.91.0,120.76.91.7,47.91.83.56,47.88.147.36,47.91.103.51,39.104.29.35,121.43.18.66,47.91.102.0,120.76.91.29,114.215.161.0,47.91.84.0,149.129.228.88,47.254.212.25,60.205.89.31,60.205.89.0,101.37.74.0,47.88.147.0,121.43.18.68,47.91.12.0,139.224.4.0,47.91.49.175,112.124.140.0,8.208.17.76,60.205.89.21,139.224.4.79,47.91.83.15,47.91.49.0,114.215.161.28,47.88.98.24,47.91.13.77,47.89.224.56,47.91.9.0,139.224.4.85,47.108.22.35,8.213.162.192,8.213.162.64,8.213.163.0,47.92.185.0,47.92.185.128,47.92.185.192,47.92.185.64,8.213.0.128,8.213.0.192,8.213.5.0,8.213.5.64,39.107.7.0,39.107.7.64,182.92.32.128,182.92.32.192,8.134.21.0,8.134.21.64,8.134.21.128,8.134.21.192,8.134.22.128,8.134.22.192,8.134.224.0,8.134.224.64,8.134.0.64,8.134.0.128,8.134.0.192,8.134.5.0,47.106.63.0,47.106.63.64,47.106.63.128,47.106.63.192

请注意：超过100个IP输入，EC2实例建议用最大的(t3 large)。因为实测 t3.medium 100个IP就能到80%cpu占用率了


 

 全剧终。

 

 

### 附录：liangym@魔改后的（无IP数量限制的）的 SetupIPMonitoringFromVPC的原始yaml代码

```json
{
  "schemaVersion": "0.3",
  "description": "AWSSupport-SetupIPMonitoringFromVPC creates an EC2 instance in the specified subnet and monitors selected target IPs by continuously running ping, MTR, traceroute and tracetcp tests. The results are stored in CloudWatch logs, and metric filters are applied to quickly visualize latency and packet loss statistics in a CloudWatch dashboard. The latest version of the runbook uses Amazon Cloudwatch Agent to send the metrics.",
  "assumeRole": "{{ AutomationAssumeRole }}",
  "parameters": {
    "SubnetId": {
      "type": "String",
      "description": "(Required) The subnet ID for the monitor instance. NOTE: If you specify a private subnet, make sure there is Internet access to allow the monitor instance to setup the test (i.e. install the CloudWatch Logs agent, interact with AWS Systems Manager and Amazon CloudWatch).",
      "allowedPattern": "^subnet-[a-z0-9]{8,17}$"
    },
    "TargetIPs": {
      "type": "String",
      "description": "(Required) Comma separated list of IPv4s and/or IPv6s to monitor. No spaces allowed. Maximum size is 9999 characters. NOTE: If you provide an invalid IP, the automation will fail and rollback the test setup.",
      "allowedPattern": "^[0-9a-fA-F.:,]{6,9999}$"
    },
    "CloudWatchLogGroupNamePrefix": {
      "description": "(Optional) Prefix used for each CloudWatch log group created for the test results.",
      "type": "String",
      "default": "/AWSSupport-SetupIPMonitoringFromVPC",
      "allowedPattern": "^[0-9a-zA-Z_.#/\\-]{1,512}$"
    },
    "CloudWatchLogGroupRetentionInDays": {
      "description": "(Optional) Number of days you want to keep the network monitoring results for.",
      "type": "String",
      "allowedValues": [
        "1",
        "3",
        "5",
        "7",
        "14",
        "30",
        "60",
        "90",
        "120",
        "150",
        "180",
        "365",
        "400",
        "545",
        "731",
        "1827",
        "3653"
      ],
      "default": "7"
    },
    "InstanceType": {
      "type": "String",
      "description": "(Optional) The EC2 instance type for the test instance. Recommended size: t3.micro.",
      "default": "t3.micro",
      "allowedValues": [
        "t3.micro",
        "t3.small",
        "t3.medium",
        "t3.large"
      ]
    },
    "AutomationAssumeRole": {
      "type": "String",
      "description": "(Optional) The IAM role for this execution. If no role is specified, AWS Systems Manager Automation will use the permissions of the user that executes this document.",
      "default": ""
    }
  },
  "mainSteps": [
    {
      "name": "describeSubnet",
      "action": "aws:executeAwsApi",
      "onFailure": "Abort",
      "inputs": {
        "Service": "ec2",
        "Api": "DescribeSubnets",
        "SubnetIds": [
          "{{ SubnetId }}"
        ]
      },
      "outputs": [
        {
          "Name": "VpcId",
          "Selector": "$.Subnets[0].VpcId"
        }
      ],
      "isCritical": "true",
      "nextStep": "branchOnTargetIPs"
    },
    {
      "name": "branchOnTargetIPs",
      "action": "aws:branch",
      "onFailure": "Abort",
      "inputs": {
        "Choices": [
          {
            "NextStep": "assertSubnetHasIPv6CidrBlock",
            "Variable": "{{ TargetIPs }}",
            "Contains": ":"
          }
        ],
        "Default": "getLatestLinuxAMI"
      },
      "isCritical": "true"
    },
    {
      "name": "assertSubnetHasIPv6CidrBlock",
      "action": "aws:assertAwsResourceProperty",
      "onFailure": "Abort",
      "inputs": {
        "Service": "ec2",
        "Api": "DescribeSubnets",
        "SubnetIds": [
          "{{ SubnetId }}"
        ],
        "PropertySelector": "$.Subnets[0].Ipv6CidrBlockAssociationSet[0].Ipv6CidrBlockState.State",
        "DesiredValues": [
          "associated"
        ]
      },
      "isCritical": "true",
      "nextStep": "getLatestLinuxAMI"
    },
    {
      "name": "getLatestLinuxAMI",
      "action": "aws:executeAwsApi",
      "onFailure": "Abort",
      "inputs": {
        "Service": "ssm",
        "Api": "GetParameter",
        "Name": "/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
      },
      "outputs": [
        {
          "Name": "ImageId",
          "Selector": "$.Parameter.Value",
          "Type": "String"
        }
      ],
      "isCritical": "true",
      "nextStep": "createSecurityGroup"
    },
    {
      "name": "createSecurityGroup",
      "action": "aws:executeAwsApi",
      "onFailure": "step:deleteSecurityGroup",
      "inputs": {
        "Service": "ec2",
        "Api": "CreateSecurityGroup",
        "VpcId": "{{ describeSubnet.VpcId }}",
        "GroupName": "SetupIPMonitoringFromVPC_{{ automation:EXECUTION_ID }}",
        "Description": "Security group used by the test instance created by AWSSupport-SetupIPMonitoringFromVPC Automation execution {{ automation:EXECUTION_ID }}."
      },
      "outputs": [
        {
          "Name": "GroupId",
          "Selector": "$.GroupId"
        }
      ],
      "isCritical": "true",
      "nextStep": "allowAllOutboundTrafficInSecurityGroup"
    },
    {
      "name": "allowAllOutboundTrafficInSecurityGroup",
      "action": "aws:executeAwsApi",
      "onFailure": "step:deleteSecurityGroup",
      "inputs": {
        "Service": "ec2",
        "Api": "AuthorizeSecurityGroupEgress",
        "GroupId": "{{ createSecurityGroup.GroupId }}",
        "IpPermissions": [
          {
            "IpProtocol": "-1"
          }
        ]
      },
      "isCritical": "true",
      "nextStep": "createEC2Role"
    },
    {
      "name": "createEC2Role",
      "action": "aws:executeAwsApi",
      "onFailure": "step:deleteEC2Role",
      "inputs": {
        "Service": "iam",
        "Api": "CreateRole",
        "RoleName": "SetupIPMonitoringFromVPC_{{ automation:EXECUTION_ID }}",
        "Path": "/AWSSupport/",
        "Description": "Role used by the test instance created by AWSSupport-SetupIPMonitoringFromVPC Automation execution {{ automation:EXECUTION_ID }}.",
        "AssumeRolePolicyDocument": "{\"Version\": \"2012-10-17\",\"Statement\": [ { \"Effect\": \"Allow\", \"Principal\": { \"Service\": \"ec2.amazonaws.com\" }, \"Action\": \"sts:AssumeRole\" } ] }"
      },
      "outputs": [
        {
          "Name": "Name",
          "Selector": "$.Role.RoleName"
        }
      ],
      "isCritical": "true",
      "nextStep": "attachSSMManagedPolicyToEC2Role"
    },
    {
      "name": "attachSSMManagedPolicyToEC2Role",
      "action": "aws:executeAwsApi",
      "onFailure": "step:detachSSMManagedPolicyFromEC2Role",
      "inputs": {
        "Service": "iam",
        "Api": "AttachRolePolicy",
        "PolicyArn": "arn:aws-cn:iam::aws:policy/AmazonSSMManagedInstanceCore",
        "RoleName": "SetupIPMonitoringFromVPC_{{ automation:EXECUTION_ID }}"
      },
      "isCritical": "true",
      "nextStep": "addCloudWatchInlinePolicyToEC2Role"
    },
    {
      "name": "addCloudWatchInlinePolicyToEC2Role",
      "action": "aws:executeAwsApi",
      "onFailure": "step:removeCloudWatchInlinePolicyFromEC2Role",
      "inputs": {
        "Service": "iam",
        "Api": "PutRolePolicy",
        "RoleName": "SetupIPMonitoringFromVPC_{{ automation:EXECUTION_ID }}",
        "PolicyName": "SetupIPMonitoringFromVPC_CWPermissions",
        "PolicyDocument": "{    \"Version\": \"2012-10-17\",    \"Statement\": [        {            \"Effect\": \"Allow\",            \"Action\": [                \"logs:PutMetricFilter\",                \"logs:PutRetentionPolicy\",                \"logs:CreateLogGroup\",                \"logs:CreateLogStream\",                \"logs:DescribeLogGroups\",                \"logs:DescribeLogStreams\",                \"logs:PutLogEvents\"            ],            \"Resource\": \"arn:aws-cn:logs:{{ global:REGION }}:{{ global:ACCOUNT_ID }}:log-group:/AWSSupport-SetupIPMonitoringFromVPC/*\"        },        {            \"Effect\": \"Allow\",            \"Action\": \"cloudwatch:PutDashboard\",            \"Resource\": \"*\"        }    ]}"
      },
      "isCritical": "true",
      "nextStep": "createIAMInstanceProfile"
    },
    {
      "name": "createIAMInstanceProfile",
      "action": "aws:executeAwsApi",
      "onFailure": "step:deleteIAMInstanceProfile",
      "inputs": {
        "Service": "iam",
        "Api": "CreateInstanceProfile",
        "InstanceProfileName": "SetupIPMonitoringFromVPC_{{ automation:EXECUTION_ID }}",
        "Path": "/AWSSupport/"
      },
      "outputs": [
        {
          "Name": "Name",
          "Selector": "$.InstanceProfile.InstanceProfileName"
        },
        {
          "Name": "Arn",
          "Selector": "$.InstanceProfile.Arn"
        }
      ],
      "isCritical": "true",
      "nextStep": "addIAMRoleToInstanceProfile"
    },
    {
      "name": "addIAMRoleToInstanceProfile",
      "action": "aws:executeAwsApi",
      "onFailure": "step:removeIAMRoleFromInstanceProfile",
      "inputs": {
        "Service": "iam",
        "Api": "AddRoleToInstanceProfile",
        "RoleName": "{{ createEC2Role.Name }}",
        "InstanceProfileName": "{{ createIAMInstanceProfile.Name }}"
      },
      "isCritical": "true",
      "nextStep": "waitForInstanceProfileToBeAvailable"
    },
    {
      "name": "waitForInstanceProfileToBeAvailable",
      "action": "aws:sleep",
      "onFailure": "Continue",
      "inputs": {
        "Duration": "PT60S"
      },
      "isCritical": "false",
      "nextStep": "createManagedInstance"
    },
    {
      "name": "createManagedInstance",
      "action": "aws:executeAwsApi",
      "onFailure": "step:terminateInstance",
      "inputs": {
        "Service": "ec2",
        "Api": "RunInstances",
        "ImageId": "{{ getLatestLinuxAMI.ImageId }}",
        "InstanceType": "{{ InstanceType }}",
        "MinCount": 1,
        "MaxCount": 1,
        "IamInstanceProfile": {
          "Arn": "{{ createIAMInstanceProfile.Arn }}"
        },
        "NetworkInterfaces": [
          {
            "AssociatePublicIpAddress": true,
            "DeleteOnTermination": true,
            "DeviceIndex": 0,
            "SubnetId": "{{ SubnetId }}",
            "Groups": [
              "{{ createSecurityGroup.GroupId }}"
            ]
          }
        ],
        "TagSpecifications": [
          {
            "ResourceType": "instance",
            "Tags": [
              {
                "Key": "Name",
                "Value": "AWSSupport-SetupIPMonitoringFromVPC - {{ SubnetId }}"
              },
              {
                "Key": "AutomationExecutionId",
                "Value": "{{ automation:EXECUTION_ID }}"
              },
              {
                "Key": "TargetIPs",
                "Value": "noiplimits"
              }
            ]
          }
        ]
      },
      "outputs": [
        {
          "Name": "InstanceId",
          "Selector": "$.Instances[0].InstanceId",
          "Type": "String"
        },
        {
          "Name": "NetworkInterfaceId",
          "Selector": "$.Instances[0].NetworkInterfaces[0].NetworkInterfaceId",
          "Type": "String"
        }
      ],
      "isCritical": "true",
      "nextStep": "branchOnTargetIPsToAssignIPv6ToInstance"
    },
    {
      "name": "branchOnTargetIPsToAssignIPv6ToInstance",
      "action": "aws:branch",
      "onFailure": "Abort",
      "inputs": {
        "Choices": [
          {
            "NextStep": "assignIPv6ToInstance",
            "Variable": "{{ TargetIPs }}",
            "Contains": ":"
          }
        ],
        "Default": "waitForInstanceToBeManaged"
      },
      "isCritical": "true"
    },
    {
      "name": "assignIPv6ToInstance",
      "action": "aws:executeAwsApi",
      "onFailure": "step:terminateInstance",
      "inputs": {
        "Service": "ec2",
        "Api": "AssignIpv6Addresses",
        "NetworkInterfaceId": "{{ createManagedInstance.NetworkInterfaceId }}",
        "Ipv6AddressCount": 1
      },
      "isCritical": "true",
      "nextStep": "waitForInstanceToBeManaged"
    },
    {
      "name": "waitForInstanceToBeManaged",
      "action": "aws:waitForAwsResourceProperty",
      "timeoutSeconds": 600,
      "onFailure": "step:terminateInstance",
      "inputs": {
        "Service": "ssm",
        "Api": "DescribeInstanceInformation",
        "InstanceInformationFilterList": [
          {
            "key": "InstanceIds",
            "valueSet": [
              "{{ createManagedInstance.InstanceId }}"
            ]
          }
        ],
        "PropertySelector": "$.InstanceInformationList[0].PingStatus",
        "DesiredValues": [
          "Online"
        ]
      },
      "isCritical": "true",
      "nextStep": "installPrerequisites"
    },
    {
      "name": "installPrerequisites",
      "action": "aws:runCommand",
      "onFailure": "step:terminateInstance",
      "inputs": {
        "DocumentName": "AWS-RunShellScript",
        "InstanceIds": [
          "{{ createManagedInstance.InstanceId }}"
        ],
        "Parameters": {
          "commands": [
            "#!/bin/bash",
            "",
            "sudo yum update -y &> /dev/null",
            "sudo yum install -y python3 &> /dev/null",
            "sudo yum install -y amazon-cloudwatch-agent &> /dev/null"
          ]
        }
      },
      "isCritical": "true",
      "nextStep": "validateIPs"
    },
    {
      "name": "validateIPs",
      "action": "aws:runCommand",
      "onFailure": "step:terminateInstance",
      "inputs": {
        "DocumentName": "AWS-RunShellScript",
        "InstanceIds": [
          "{{ createManagedInstance.InstanceId }}"
        ],
        "Parameters": {
          "commands": [
            "#!/bin/bash",
            "",
            "error_trap()",
            "{",
            "    if test -n \"$1\" ; then",
            "        printf \"%s\\\\n\" \"$1\"",
            "    fi",
            "",
            "    printf \"%.s=\" $(seq 1 80)",
            "    printf \"\\\\nThe input parameter TargetIPs contains one or more invalid IPs. Please review your input and run this automation again.\\\\n\"",
            "",
            "    exit 1",
            "}",
            "",
            "# Check that Python3 interpreter is available in the host environment",
            "if command -v python3 > /dev/null; then",
            "    PYTHON=python3",
            "else",
            "    error_trap \"Python3 is not installed!\"",
            "fi",
            "",
            "printf \"Target IPs: {{ TargetIPs }}\\\\n\"",
            "",
            "# Verify all IPs are syntactically correct",
            "printf \"Verifying IP addresses\\\\n\"",
            "OUTPUT=\"$(${PYTHON} -c \"",
            "import ipaddress",
            "import sys",
            "",
            "def run():",
            "    target_ips_input = '{{ TargetIPs }}'",
            "    ip_addresses = target_ips_input.split(',')",
            "    invalid_ip_addresses = []",
            "    duplicate_ip_addresses = []",
            "    error_message = ''",
            "    for ip_address in ip_addresses:",
            "        try:",
            "            if ip_addresses.count(ip_address) > 1:",
            "                if not ip_address in duplicate_ip_addresses:",
            "                    duplicate_ip_addresses.append(ip_address)",
            "            ipaddress.ip_address(ip_address)",
            "        except ValueError as error:",
            "            invalid_ip_addresses.append(ip_address)",
            "    ",
            "    if invalid_ip_addresses:",
            "        error_message = 'The following IP addresses are invalid: {}\\n'.format(','.join(invalid_ip_addresses))",
            "",
            "    if duplicate_ip_addresses:",
            "        error_message += 'The following IP addresses have been provided more than once: {}'.format(','.join(duplicate_ip_addresses))",
            "    ",
            "    if error_message:",
            "        raise ValueError(error_message)",
            "",
            "if __name__ == '__main__':",
            "    sys.exit(run())",
            "\")\" || error_trap",
            "printf \"All IPs passed validation\\\\n\""
          ]
        }
      },
      "isCritical": "true",
      "nextStep": "defineMTRTest"
    },
    {
      "name": "defineMTRTest",
      "action": "aws:runCommand",
      "onFailure": "step:terminateInstance",
      "inputs": {
        "DocumentName": "AWS-RunShellScript",
        "InstanceIds": [
          "{{ createManagedInstance.InstanceId }}"
        ],
        "Parameters": {
          "commands": [
            "#!/bin/bash",
            "",
            "IFS=', ' read -r -a ipList <<< \"{{ TargetIPs }}\"",
            "logPath='/home/ec2-user/logs'",
            "",
            "for ip in ${ipList[@]}; do",
            "    touch /home/ec2-user/mtr_${ip}.sh",
            "    if [[ ! $ip = *\":\"* ]]; then",
            "        # MTR IPv4 Test",
            "        cat <<EOT >> /home/ec2-user/mtr_${ip}.sh",
            "#!/bin/bash",
            "sudo /sbin/mtr -rn -c 30 $ip | sed 's/Start: //g' |  sed -e \"2,\\$ s/^/     /\" >> $logPath/mtr-to-$ip.txt",
            "EOT",
            "    else",
            "        # MTR IPv6 Test",
            "        cat <<EOT >> /home/ec2-user/mtr_${ip}.sh",
            "#!/bin/bash",
            "sudo /sbin/mtr -6 -rn -c 30 $ip | sed 's/Start: //g' |  sed -e \"2,\\$ s/^/     /\" >> $logPath/mtr-to-$ip.txt",
            "EOT",
            "    fi",
            "    chmod u+x /home/ec2-user/mtr_${ip}.sh && chown ec2-user:ec2-user /home/ec2-user/mtr_${ip}.sh",
            "done"
          ]
        }
      },
      "isCritical": "true",
      "nextStep": "definePing64Test"
    },
    {
      "name": "definePing64Test",
      "action": "aws:runCommand",
      "onFailure": "step:terminateInstance",
      "inputs": {
        "DocumentName": "AWS-RunShellScript",
        "InstanceIds": [
          "{{ createManagedInstance.InstanceId }}"
        ],
        "Parameters": {
          "commands": [
            "#!/bin/bash",
            "",
            "IFS=', ' read -r -a ipList <<< \"{{ TargetIPs }}\"",
            "logPath='/home/ec2-user/logs'",
            "",
            "for ip in ${ipList[@]}; do",
            "    touch /home/ec2-user/ping64_${ip}.sh",
            "    if [[ ! $ip = *\":\"* ]]; then",
            "        # Ping IPv4 Test",
            "        cat <<EOT >> /home/ec2-user/ping64_${ip}.sh",
            "#!/bin/bash",
            "ping -s 56 -c 30 $ip | sed -e \"1,$ s/^/     /\" | sed \"s/%//g\" | tail -n 3 | sed \"s#/# #g\"  >> $logPath/ping64-to-$ip.txt",
            "EOT",
            "    else",
            "        # Ping IPv6 Test",
            "        cat <<EOT >> /home/ec2-user/ping64_${ip}.sh",
            "#!/bin/bash",
            "ping6 -s 56 -c 30 $ip | sed -e \"1,$ s/^/     /\" | sed \"s/%//g\" | tail -n 3 | sed \"s#/# #g\"  >> $logPath/ping64-to-$ip.txt",
            "EOT",
            "    fi",
            "    chmod u+x /home/ec2-user/ping64_${ip}.sh && chown ec2-user:ec2-user /home/ec2-user/ping64_${ip}.sh",
            "done"
          ]
        }
      },
      "isCritical": "true",
      "nextStep": "definePing1500Test"
    },
    {
      "name": "definePing1500Test",
      "action": "aws:runCommand",
      "onFailure": "step:terminateInstance",
      "inputs": {
        "DocumentName": "AWS-RunShellScript",
        "InstanceIds": [
          "{{ createManagedInstance.InstanceId }}"
        ],
        "Parameters": {
          "commands": [
            "#!/bin/bash",
            "",
            "IFS=', ' read -r -a ipList <<< \"{{ TargetIPs }}\"",
            "logPath='/home/ec2-user/logs'",
            "",
            "for ip in ${ipList[@]}; do",
            "    touch /home/ec2-user/ping1500_${ip}.sh",
            "    if [[ ! $ip = *\":\"* ]]; then",
            "        # Ping IPv4 Test",
            "        cat <<EOT >> /home/ec2-user/ping1500_${ip}.sh",
            "#!/bin/bash",
            "ping -s 1492 -c 30 $ip | sed -e \"1,$ s/^/     /\" | sed \"s/%//g\" | tail -n 3 | sed \"s#/# #g\"  >> $logPath/ping1500-to-$ip.txt",
            "EOT",
            "    else",
            "        # Ping IPv6 Test",
            "        cat <<EOT >> /home/ec2-user/ping1500_${ip}.sh",
            "#!/bin/bash",
            "ping6 -s 1492 -c 30 $ip | sed -e \"1,$ s/^/     /\" | sed \"s/%//g\" | tail -n 3 | sed \"s#/# #g\"  >> $logPath/ping1500-to-$ip.txt",
            "EOT",
            "    fi",
            "    chmod u+x /home/ec2-user/ping1500_${ip}.sh && chown ec2-user:ec2-user /home/ec2-user/ping1500_${ip}.sh",
            "done"
          ]
        }
      },
      "isCritical": "true",
      "nextStep": "defineTracepathTest"
    },
    {
      "name": "defineTracepathTest",
      "action": "aws:runCommand",
      "onFailure": "step:terminateInstance",
      "inputs": {
        "DocumentName": "AWS-RunShellScript",
        "InstanceIds": [
          "{{ createManagedInstance.InstanceId }}"
        ],
        "Parameters": {
          "commands": [
            "#!/bin/bash",
            "",
            "IFS=', ' read -r -a ipList <<< \"{{ TargetIPs }}\"",
            "logPath='/home/ec2-user/logs'",
            "",
            "for ip in ${ipList[@]}; do",
            "    touch /home/ec2-user/tracepath_${ip}.sh",
            "    if [[ ! $ip = *\":\"* ]]; then",
            "        # Tracepath IPv4 Test",
            "        cat <<EOT >> /home/ec2-user/tracepath_${ip}.sh",
            "#!/bin/bash",
            "tracepath -n $ip | grep -v \"Too many hops\" | sed -e \"$ ! s/^/     /\" >> $logPath/tracepath-to-$ip.txt",
            "EOT",
            "    else",
            "        # Tracepath IPv6 Test",
            "        cat <<EOT >> /home/ec2-user/ping64_${ip}.sh",
            "#!/bin/bash",
            "tracepath6 -n $ip | grep -v \"Too many hops\" | sed -e \"$ ! s/^/     /\" >> $logPath/tracepath-to-$ip.txt",
            "EOT",
            "    fi",
            "    chmod u+x /home/ec2-user/tracepath_${ip}.sh && chown ec2-user:ec2-user /home/ec2-user/tracepath_${ip}.sh",
            "done"
          ]
        }
      },
      "isCritical": "true",
      "nextStep": "defineTracerouteTCPTest"
    },
    {
      "name": "defineTracerouteTCPTest",
      "action": "aws:runCommand",
      "onFailure": "step:terminateInstance",
      "inputs": {
        "DocumentName": "AWS-RunShellScript",
        "InstanceIds": [
          "{{ createManagedInstance.InstanceId }}"
        ],
        "Parameters": {
          "commands": [
            "#!/bin/bash",
            "",
            "IFS=', ' read -r -a ipList <<< \"{{ TargetIPs }}\"",
            "logPath='/home/ec2-user/logs'",
            "",
            "for ip in ${ipList[@]}; do",
            "    touch /home/ec2-user/ping1500_${ip}.sh",
            "    cat <<EOT >> /home/ec2-user/traceroutetcp_${ip}.sh",
            "#!/bin/bash",
            "sudo traceroute -n $ip -q 2 -A -T -p 80 | sed -e \"s/^/     /\" >> $logPath/traceroutetcp-to-$ip.txt",
            "EOT",
            "    chmod u+x /home/ec2-user/traceroutetcp_${ip}.sh && chown ec2-user:ec2-user /home/ec2-user/traceroutetcp_${ip}.sh",
            "done"
          ]
        }
      },
      "isCritical": "true",
      "nextStep": "configureCloudWatchLogsForTestResults"
    },
    {
      "name": "configureCloudWatchLogsForTestResults",
      "action": "aws:runCommand",
      "onFailure": "step:terminateInstance",
      "inputs": {
        "DocumentName": "AWS-RunShellScript",
        "InstanceIds": [
          "{{ createManagedInstance.InstanceId }}"
        ],
        "Parameters": {
          "commands": [
            "#!/bin/bash",
            "",
            "error_trap()",
            "{",
            "    if test -n \"$1\" ; then",
            "        printf \"%s\\\\n\" \"$1\"",
            "    fi",
            "",
            "    printf \"%.s=\" $(seq 1 80)",
            "    printf \"\\\\nThe CloudWatch logs agent configuration failed. Please try to run this automation again.\\\\n\"",
            "",
            "    exit 1",
            "}",
            "",
            "IFS=', ' read -r -a ipList <<< \"{{ TargetIPs }}\"",
            "",
            "# Creating logs folder",
            "mkdir /home/ec2-user/logs || error_trap",
            "chown ec2-user:ec2-user /home/ec2-user/logs || error_trap",
            "",
            "# For each IP in the list, create corresponding configuration",
            "# in Amazon CloudWatch Agent Configuration file",
            "# IPv4 Tests - MTR, 1500-byte Ping, 64-byte Ping, Tracepath, TCP Traceroute",
            "# IPv6 Tests - MTR, 1500-byte Ping, 64-byte Ping, TCP Traceroute",
            "",
            "retentionInDays=\"{{ CloudWatchLogGroupRetentionInDays }}\"",
            "",
            "for ip in ${ipList[@]}; do",
            "    # CloudWatch log group doesn't support \":\" in the name, which is typical of IPv6.",
            "    # Replacing any occurrence of \":\" with \".\"",
            "    ipmod=`echo $ip | sed 's/:/./g'`",
            "    touch /home/ec2-user/cloudwatchagent-$ipmod.json",
            "    cat <<EOT >> /home/ec2-user/cloudwatchagent-$ipmod.json",
            "    {",
            "      \"logs\": {",
            "        \"logs_collected\": {",
            "          \"files\": {",
            "            \"collect_list\": [",
            "              {",
            "                \"file_path\": \"/home/ec2-user/logs/mtr-to-$ip.txt\",",
            "                \"log_group_name\": \"{{ CloudWatchLogGroupNamePrefix }}/mtr-from-{{ SubnetId }}-to-$ipmod\",",
            "                \"log_stream_name\": \"{{ automation:EXECUTION_ID }}\",",
            "                \"timezone\": \"UTC\",",
            "                \"retention_in_days\": $retentionInDays",
            "              },",
            "              {",
            "                \"file_path\": \"/home/ec2-user/logs/ping1500-to-$ip.txt\",",
            "                \"log_group_name\": \"{{ CloudWatchLogGroupNamePrefix }}/ping1500-from-{{ SubnetId }}-to-$ipmod\",",
            "                \"log_stream_name\": \"{{ automation:EXECUTION_ID }}\",",
            "                \"timezone\": \"UTC\",",
            "                \"multi_line_start_pattern\": \"---.*\",",
            "                \"retention_in_days\": $retentionInDays",
            "              },",
            "              {",
            "                \"file_path\": \"/home/ec2-user/logs/ping64-to-$ip.txt\",",
            "                \"log_group_name\": \"{{ CloudWatchLogGroupNamePrefix }}/ping64-from-{{ SubnetId }}-to-$ipmod\",",
            "                \"log_stream_name\": \"{{ automation:EXECUTION_ID }}\",",
            "                \"timezone\": \"UTC\",",
            "                \"multi_line_start_pattern\": \"---.*\",",
            "                \"retention_in_days\": $retentionInDays",
            "              },",
            "              {",
            "                \"file_path\": \"/home/ec2-user/logs/tracepath-to-$ip.txt\",",
            "                \"log_group_name\": \"{{ CloudWatchLogGroupNamePrefix }}/tracepath-from-{{ SubnetId }}-to-$ipmod\",",
            "                \"log_stream_name\": \"{{ automation:EXECUTION_ID }}\",",
            "                \"timezone\": \"UTC\",",
            "                \"multi_line_start_pattern\": \"1?:.*\",",
            "                \"retention_in_days\": $retentionInDays",
            "              },",
            "              {",
            "                \"file_path\": \"/home/ec2-user/logs/traceroutetcp-to-$ip.txt\",",
            "                \"log_group_name\": \"{{ CloudWatchLogGroupNamePrefix }}/traceroutetcp-from-{{ SubnetId }}-to-$ipmod\",",
            "                \"log_stream_name\": \"{{ automation:EXECUTION_ID }}\",",
            "                \"timezone\": \"UTC\",",
            "                \"multi_line_start_pattern\": \"traceroute\",",
            "                \"retention_in_days\": $retentionInDays",
            "              }",
            "            ]",
            "          }",
            "        }",
            "      }",
            "    }",
            "EOT",
            "    # Starting Amazon CloudWatch Agent",
            "   if [[ \"$ipmod\" = \"${ipList[0]}\" ]]; then",
            "    sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c file:/home/ec2-user/cloudwatchagent-$ipmod.json",
            "   else",
            "    sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a append-config -m ec2 -s -c file:/home/ec2-user/cloudwatchagent-$ipmod.json",
            "   fi",
            "done"
          ]
        }
      },
      "isCritical": "true",
      "nextStep": "startNetworkTests"
    },
    {
      "name": "startNetworkTests",
      "action": "aws:runCommand",
      "onFailure": "step:terminateInstance",
      "inputs": {
        "DocumentName": "AWS-RunShellScript",
        "InstanceIds": [
          "{{ createManagedInstance.InstanceId }}"
        ],
        "Parameters": {
          "commands": [
            "#!/bin/bash",
            "",
            "error_trap()",
            "{",
            "    if test -n \"$1\" ; then",
            "        printf \"%s\\\\n\" \"$1\"",
            "    fi",
            "",
            "    printf \"%.s=\" $(seq 1 80)",
            "    printf \"\\\\nThe crontab configuration failed. Please try to run this automation again.\\\\n\"",
            "",
            "    exit 1",
            "}",
            "",
            "IFS=', ' read -r -a ipList <<< \"{{ TargetIPs }}\"",
            "touch /home/ec2-user/cronConf.txt || error_trap",
            "",
            "for ip in ${ipList[@]}; do",
            "    echo \"* * * * * /home/ec2-user/mtr_${ip}.sh\" >> /home/ec2-user/cronConf.txt",
            "    echo \"* * * * * /home/ec2-user/ping1500_${ip}.sh\" >> /home/ec2-user/cronConf.txt",
            "    echo \"* * * * * /home/ec2-user/ping64_${ip}.sh\" >> /home/ec2-user/cronConf.txt",
            "    echo \"* * * * * /home/ec2-user/traceroutetcp_${ip}.sh\" >> /home/ec2-user/cronConf.txt",
            "    echo \"* * * * * /home/ec2-user/tracepath_${ip}.sh\" >> /home/ec2-user/cronConf.txt",
            "done",
            "crontab -u ec2-user /home/ec2-user/cronConf.txt || error_trap",
            ""
          ]
        }
      },
      "isCritical": "true",
      "nextStep": "sleepBeforeSettingRetentions"
    },
    {
      "name": "sleepBeforeSettingRetentions",
      "action": "aws:sleep",
      "onFailure": "Continue",
      "inputs": {
        "Duration": "PT240S"
      },
      "isCritical": "false",
      "nextStep": "configureLocalLogRotation"
    },
    {
      "name": "configureLocalLogRotation",
      "action": "aws:runCommand",
      "onFailure": "step:terminateInstance",
      "inputs": {
        "DocumentName": "AWS-RunShellScript",
        "InstanceIds": [
          "{{ createManagedInstance.InstanceId }}"
        ],
        "Parameters": {
          "commands": [
            "#!/bin/bash",
            "",
            "error_trap()",
            "{",
            "    if test -n \"$1\" ; then",
            "        printf \"%s\\\\n\" \"$1\"",
            "    fi",
            "",
            "    printf \"%.s=\" $(seq 1 80)",
            "    printf \"\\\\nThe logrotate configuration failed. Please try to run this automation again.\\\\n\"",
            "",
            "    exit 1",
            "}",
            "",
            "touch /etc/logrotate.d/logrotateConfig.conf || error_trap",
            "",
            "# Disabling dateext feature from default logrotate config file",
            "sed -i 's/dateext/#dateext/g' /etc/logrotate.conf",
            "",
            "cat << EOF >> /etc/logrotate.d/logrotateConfig.conf",
            "/home/ec2-user/logs/*.txt {",
            "    daily",
            "    missingok",
            "    size 5M",
            "    start 1",
            "    rotate 4",
            "}",
            "EOF",
            "",
            "#logrotate -vf /etc/logrotate.d/logrotateConfig.conf || error_trap"
          ]
        }
      },
      "isCritical": "true",
      "nextStep": "setCloudWatchLogsMetricFilters"
    },
    {
      "name": "setCloudWatchLogsMetricFilters",
      "action": "aws:runCommand",
      "onFailure": "step:terminateInstance",
      "inputs": {
        "DocumentName": "AWS-RunShellScript",
        "InstanceIds": [
          "{{ createManagedInstance.InstanceId }}"
        ],
        "Parameters": {
          "commands": [
            "#!/bin/bash",
            "",
            "error_trap()",
            "{",
            "    if test -n \"$1\" ; then",
            "        printf \"%s\\\\n\" \"$1\"",
            "    fi",
            "",
            "    printf \"%.s=\" $(seq 1 80)",
            "    printf \"\\\\nThe CloudWatch logs metric filters configuration failed. Please try to run this automation again.\\\\n\"",
            "",
            "    exit 1",
            "}",
            "",
            "IFS=', ' read -r -a ipList <<< \"{{ TargetIPs }}\"",
            "test_instance=\"{{ createManagedInstance.InstanceId }}\"",
            "",
            "# For each IP in the list, create corresponding metric filters",
            "for ip in ${ipList[@]}; do",
            "    # CloudWatch log group doesn't support \":\" in the name, which is typical of IPv6.",
            "    # Replacing any occurrence of \":\" with \".\"",
            "    ipmod=`echo $ip | sed 's/:/./g'`",
            "    touch packet_loss_metric_filter-$ipmod.json || error_trap",
            "    touch latency_metric_filter-$ipmod.json || error_trap",
            "    log_group_name=\"{{ CloudWatchLogGroupNamePrefix }}/ping64-from-{{ SubnetId }}-to-$ipmod\"",
            "    cat <<EOT >> packet_loss_metric_filter-$ipmod.json",
            "    [",
            "        {",
            "            \"metricName\": \"$ipmod Packet Loss\",",
            "            \"metricNamespace\": \"AWSSupport-SetupIPMonitoringFromVPC/{{ SubnetId }}/$test_instance\",",
            "            \"metricValue\": \"\\$LOSS\",",
            "            \"defaultValue\": 100",
            "        }",
            "    ]",
            "EOT",
            "    aws logs put-metric-filter --log-group-name $log_group_name \\",
            "        --filter-name \"packet_loss\"  \\",
            "        --filter-pattern \"[r1,r2,r3,,r4,r5,r6,r7,r8,r9,LOSS,r11,r12,r13,r14,r15,r16,r17,r18,r19,r20,r21,r22,AVG,r24]\" \\",
            "        --metric-transformations file://packet_loss_metric_filter-$ipmod.json \\",
            "        --region \"{{ global:REGION }}\" || error_trap",
            "",
            "    cat <<EOT >> latency_metric_filter-$ipmod.json",
            "    [",
            "    {",
            "        \"metricName\": \"$ipmod Latency\",",
            "        \"metricNamespace\": \"AWSSupport-SetupIPMonitoringFromVPC/{{ SubnetId }}/$test_instance\",",
            "        \"metricValue\": \"\\$AVG\",",
            "        \"defaultValue\": 0",
            "    }",
            "    ]",
            "EOT",
            "    aws logs put-metric-filter --log-group-name $log_group_name \\",
            "        --filter-name \"latency\"  \\",
            "        --filter-pattern \"[r1,r2,r3,,r4,r5,r6,r7,r8,r9,LOSS,r11,r12,r13,r14,r15,r16,r17,r18,r19,r20,r21,r22,AVG,r24]\" \\",
            "        --metric-transformations file://latency_metric_filter-$ipmod.json \\",
            "        --region \"{{ global:REGION }}\" || error_trap",
            "done"
          ]
        }
      },
      "isCritical": "true",
      "nextStep": "createCloudWatchDashboard"
    },
    {
      "name": "createCloudWatchDashboard",
      "action": "aws:runCommand",
      "onFailure": "step:deleteDashboard",
      "inputs": {
        "DocumentName": "AWS-RunShellScript",
        "InstanceIds": [
          "{{ createManagedInstance.InstanceId }}"
        ],
        "Parameters": {
          "commands": [
            "#!/bin/bash",
            "",
            "error_trap()",
            "{",
            "    if test -n \"$1\" ; then",
            "        printf \"%s\\\\n\" \"$1\"",
            "    fi",
            "",
            "    printf \"%.s=\" $(seq 1 80)",
            "    printf \"\\\\nThe dashboard creation failed. Please try to run this automation again.\\\\n\"",
            "",
            "    exit 1",
            "}",
            "",
            "IFS=', ' read -r -a ipList <<< \"{{ TargetIPs }}\"",
            "dashboard_name=\"{{ SubnetId }}_{{ createManagedInstance.InstanceId }}\"",
            "touch /home/ec2-user/dashboard.json || error_trap",
            "cat <<EOT >> /home/ec2-user/dashboard.json",
            "    {",
            "        \"widgets\": [",
            "            {",
            "                \"type\": \"text\",",
            "                \"x\": 0,",
            "                \"y\": 0,",
            "                \"width\": 24,",
            "                \"height\": 6,",
            "                \"properties\": {",
            "                    \"markdown\": \"\\n# AWSSupport-SetupIPMonitoringFromVPC\\n[button:Pause test](https://{{ global:REGION }}.console.aws.amazon.com.cn/systems-manager/automation/execute/AWS-StopEC2Instance?region={{ global:REGION }}#documentVersion=%24LATEST&InstanceId={{ createManagedInstance.InstanceId }}) \\n[button:Resume test](https://{{ global:REGION }}.console.aws.amazon.com.cn/systems-manager/automation/execute/AWS-StartEC2Instance?region={{ global:REGION }}#documentVersion=%24LATEST&InstanceId={{ createManagedInstance.InstanceId }}) \\n[button:Terminate test](https://{{ global:REGION }}.console.aws.amazon.com.cn/systems-manager/automation/execute/AWSSupport-TerminateIPMonitoringFromVPC?region={{ global:REGION }}#documentVersion=%24LATEST&AutomationExecutionId={{ automation:EXECUTION_ID }}&SubnetId={{ SubnetId }}&InstanceId={{ createManagedInstance.InstanceId }}) \\n[button:primary:Start a new test](https://{{ global:REGION }}.console.aws.amazon.com.cn/systems-manager/automation/execute/AWSSupport-SetupIPMonitoringFromVPC?region={{ global:REGION }})\\n\\nThis dashboard was generated by the [AWSSupport-SetupIPMonitoringFromVPC](https://{{ global:REGION }}.console.aws.amazon.com.cn/systems-manager/documents/AWSSupport-SetupIPMonitoringFromVPC/description?region={{ global:REGION }}) Automation document (execution ID: [{{ automation:EXECUTION_ID }}](https://{{ global:REGION }}.console.aws.amazon.com.cn/systems-manager/automation/execution/277cab73-7484-4566-a63a-b54e74261960?region={{ global:REGION }})).\\n\\n## Pause/Resume the test\\nYou can pause and resume the test by using the buttons above. These actions will stop or start the underlying test [EC2 instance](https://{{ global:REGION }}.console.aws.amazon.com.cn/ec2/v2/home?region={{ global:REGION }}#Instances:instanceId={{ createManagedInstance.InstanceId }};sort=desc:tag:Name) that runs the tests against the provided IPs ({{ TargetIPs }}).\\n\\n## Terminate the test\\nIf you decide to terminate the test, this dashboard, the EC2 instance and the associated IAM resources created by the Automation will be permanently terminated. CloudWatch logs will be retained for the number of days you specified during the test setup ({{ CloudWatchLogGroupRetentionInDays }} days).\\n\"",
            "                }",
            "            },",
            "EOT",
            "count=0",
            "",
            "# For each IP in the list, create corresponding CloudWatch widgets in the dashboard",
            "for ip in ${ipList[@]}; do",
            "    ipmod=`echo $ip | sed 's/:/./g'`",
            "    y1=$(($count * 8))",
            "    y2=$(($y1 + 6))",
            "",
            "    cat <<EOT >> /home/ec2-user/dashboard.json",
            "            {",
            "                \"type\": \"metric\",",
            "                \"x\": 0,",
            "                \"y\": $y1,",
            "                \"width\": 12,",
            "                \"height\": 6,",
            "                \"properties\": {",
            "                    \"metrics\": [",
            "                        [ \"AWSSupport-SetupIPMonitoringFromVPC/{{ SubnetId }}/{{ createManagedInstance.InstanceId }}\", \"$ipmod Packet Loss\", { \"color\": \"#d62728\", \"yAxis\": \"left\" } ]",
            "                    ],",
            "                    \"view\": \"timeSeries\",",
            "                    \"stacked\": true,",
            "                    \"region\": \"{{ global:REGION }}\",",
            "                    \"start\": \"-PT5M\",",
            "                    \"end\": \"P0D\",",
            "                    \"stat\": \"Maximum\",",
            "                    \"period\": 60,",
            "                    \"title\": \"{{ SubnetId }} {{ createManagedInstance.InstanceId }} - $ip Loss (%)\",",
            "                    \"legend\": {",
            "                        \"position\": \"bottom\"",
            "                    },",
            "                    \"yAxis\": {",
            "                        \"left\": {",
            "                            \"label\": \"%\",",
            "                            \"showUnits\": false",
            "                        }",
            "                    }",
            "                }",
            "            },",
            "            {",
            "                \"type\": \"metric\",",
            "                \"x\": 12,",
            "                \"y\": $y1,",
            "                \"width\": 12,",
            "                \"height\": 6,",
            "                \"properties\": {",
            "                    \"metrics\": [",
            "                        [ \"AWSSupport-SetupIPMonitoringFromVPC/{{ SubnetId }}/{{ createManagedInstance.InstanceId }}\", \"$ipmod Latency\" ]",
            "                    ],",
            "                    \"view\": \"timeSeries\",",
            "                    \"stacked\": true,",
            "                    \"region\": \"{{ global:REGION }}\",",
            "                    \"stat\": \"Maximum\",",
            "                    \"period\": 60,",
            "                    \"title\": \"{{ SubnetId }} {{ createManagedInstance.InstanceId }} - $ip Latency (ms)\",",
            "                    \"yAxis\": {",
            "                        \"left\": {",
            "                            \"label\": \"ms\",",
            "                            \"showUnits\": false",
            "                        }",
            "                    }",
            "                }",
            "            },",
            "            {",
            "                \"type\": \"text\",",
            "                \"x\": 0,",
            "                \"y\": $y2,",
            "                \"width\": 24,",
            "                \"height\": 2,",
            "                \"properties\": {",
            "                    \"markdown\": \"\\nTarget IP | MTR | ping64 | ping1500 | traceroute (TCP) | tracepath\\n----|-----|-----|-----|-----|-----\\n$ip | [1h](https://{{ global:REGION }}.console.aws.amazon.com.cn/cloudwatch/home?region={{ global:REGION }}#logEventViewer:group={{ CloudWatchLogGroupNamePrefix }}/mtr-from-{{ SubnetId }}-to-$ipmod;stream={{ automation:EXECUTION_ID }};start=PT1H) [3h](https://{{ global:REGION }}.console.aws.amazon.com.cn/cloudwatch/home?region={{ global:REGION }}#logEventViewer:group={{ CloudWatchLogGroupNamePrefix }}/mtr-from-{{ SubnetId }}-to-$ipmod;stream={{ automation:EXECUTION_ID }};start=PT3H) | [1h](https://{{ global:REGION }}.console.aws.amazon.com.cn/cloudwatch/home?region={{ global:REGION }}#logEventViewer:group={{ CloudWatchLogGroupNamePrefix }}/ping64-from-{{ SubnetId }}-to-$ipmod;stream={{ automation:EXECUTION_ID }};start=PT1H) [3h](https://{{ global:REGION }}.console.aws.amazon.com.cn/cloudwatch/home?region={{ global:REGION }}#logEventViewer:group={{ CloudWatchLogGroupNamePrefix }}/ping64-from-{{ SubnetId }}-to-$ipmod;stream={{ automation:EXECUTION_ID }};start=PT3H) | [1h](https://{{ global:REGION }}.console.aws.amazon.com.cn/cloudwatch/home?region={{ global:REGION }}#logEventViewer:group={{ CloudWatchLogGroupNamePrefix }}/ping1500-from-{{ SubnetId }}-to-$ipmod;stream={{ automation:EXECUTION_ID }};start=PT1H) [3h](https://{{ global:REGION }}.console.aws.amazon.com.cn/cloudwatch/home?region={{ global:REGION }}#logEventViewer:group={{ CloudWatchLogGroupNamePrefix }}/ping1500-from-{{ SubnetId }}-to-$ipmod;stream={{ automation:EXECUTION_ID }};start=PT3H) | [1h](https://{{ global:REGION }}.console.aws.amazon.com.cn/cloudwatch/home?region={{ global:REGION }}#logEventViewer:group={{ CloudWatchLogGroupNamePrefix }}/traceroutetcp-from-{{ SubnetId }}-to-$ipmod;stream={{ automation:EXECUTION_ID }};start=PT1H) [3h](https://{{ global:REGION }}.console.aws.amazon.com.cn/cloudwatch/home?region={{ global:REGION }}#logEventViewer:group={{ CloudWatchLogGroupNamePrefix }}/traceroutetcp-from-{{ SubnetId }}-to-$ipmod;stream={{ automation:EXECUTION_ID }};start=PT3H) | [1h](https://{{ global:REGION }}.console.aws.amazon.com.cn/cloudwatch/home?region={{ global:REGION }}#logEventViewer:group={{ CloudWatchLogGroupNamePrefix }}/tracepath-from-{{ SubnetId }}-to-$ipmod;stream={{ automation:EXECUTION_ID }};start=PT1H) [3h](https://{{ global:REGION }}.console.aws.amazon.com.cn/cloudwatch/home?region={{ global:REGION }}#logEventViewer:group={{ CloudWatchLogGroupNamePrefix }}/tracepath-from-{{ SubnetId }}-to-$ipmod;stream={{ automation:EXECUTION_ID }};start=PT3H)\\n\"",
            "                }",
            "            },",
            "EOT",
            "    count=$((count+1))",
            "done",
            "",
            "# Remove the extra comma at the end. To do so, I remove the last two characters",
            "# (trailing new line and the comma), and add the trailing new line back",
            "truncate -s-2 /home/ec2-user/dashboard.json || error_trap",
            "echo \"\" >> /home/ec2-user/dashboard.json",
            "",
            "cat <<EOT >> /home/ec2-user/dashboard.json",
            "        ]",
            "    }",
            "EOT",
            "",
            "chown ec2-user:ec2-user /home/ec2-user/dashboard.json",
            "",
            "dashboard=$(aws cloudwatch put-dashboard --dashboard-name $dashboard_name \\",
            "    --dashboard-body file:///home/ec2-user/dashboard.json \\",
            "    --region \"{{ global:REGION }}\") || error_trap",
            "",
            "echo \"https://{{ global:REGION }}.console.aws.amazon.com.cn/systems-manager/resource-groups/cloudwatch?region={{ global:REGION }}&dashboard=${dashboard_name}\""
          ]
        }
      },
      "isCritical": "true",
      "isEnd": "true"
    },
    {
      "name": "deleteDashboard",
      "action": "aws:executeAwsApi",
      "onFailure": "Continue",
      "inputs": {
        "Service": "cloudwatch",
        "Api": "DeleteDashboards",
        "DashboardNames": [
          "{{ SubnetId }}_{{ createManagedInstance.InstanceId }}"
        ]
      },
      "isCritical": "true",
      "nextStep": "terminateInstance"
    },
    {
      "name": "terminateInstance",
      "action": "aws:changeInstanceState",
      "onFailure": "Continue",
      "inputs": {
        "InstanceIds": [
          "{{ createManagedInstance.InstanceId }}"
        ],
        "CheckStateOnly": false,
        "DesiredState": "terminated"
      },
      "isCritical": "true",
      "nextStep": "removeIAMRoleFromInstanceProfile"
    },
    {
      "name": "removeIAMRoleFromInstanceProfile",
      "action": "aws:executeAwsApi",
      "onFailure": "Continue",
      "inputs": {
        "Service": "iam",
        "Api": "RemoveRoleFromInstanceProfile",
        "RoleName": "SetupIPMonitoringFromVPC_{{ automation:EXECUTION_ID }}",
        "InstanceProfileName": "SetupIPMonitoringFromVPC_{{ automation:EXECUTION_ID }}"
      },
      "isCritical": "true",
      "nextStep": "deleteIAMInstanceProfile"
    },
    {
      "name": "deleteIAMInstanceProfile",
      "action": "aws:executeAwsApi",
      "onFailure": "Continue",
      "inputs": {
        "Service": "iam",
        "Api": "DeleteInstanceProfile",
        "InstanceProfileName": "SetupIPMonitoringFromVPC_{{ automation:EXECUTION_ID }}"
      },
      "isCritical": "true",
      "nextStep": "removeCloudWatchInlinePolicyFromEC2Role"
    },
    {
      "name": "removeCloudWatchInlinePolicyFromEC2Role",
      "action": "aws:executeAwsApi",
      "onFailure": "Continue",
      "inputs": {
        "Service": "iam",
        "Api": "DeleteRolePolicy",
        "RoleName": "SetupIPMonitoringFromVPC_{{ automation:EXECUTION_ID }}",
        "PolicyName": "SetupIPMonitoringFromVPC_CWPermissions"
      },
      "isCritical": "true",
      "nextStep": "detachSSMManagedPolicyFromEC2Role"
    },
    {
      "name": "detachSSMManagedPolicyFromEC2Role",
      "action": "aws:executeAwsApi",
      "onFailure": "Continue",
      "inputs": {
        "Service": "iam",
        "Api": "DetachRolePolicy",
        "PolicyArn": "arn:aws-cn:iam::aws:policy/AmazonSSMManagedInstanceCore",
        "RoleName": "SetupIPMonitoringFromVPC_{{ automation:EXECUTION_ID }}"
      },
      "isCritical": "true",
      "nextStep": "deleteEC2Role"
    },
    {
      "name": "deleteEC2Role",
      "action": "aws:executeAwsApi",
      "onFailure": "Continue",
      "inputs": {
        "Service": "iam",
        "Api": "DeleteRole",
        "RoleName": "SetupIPMonitoringFromVPC_{{ automation:EXECUTION_ID }}"
      },
      "isCritical": "true",
      "nextStep": "deleteSecurityGroup"
    },
    {
      "name": "deleteSecurityGroup",
      "action": "aws:executeAwsApi",
      "onFailure": "Continue",
      "inputs": {
        "Service": "ec2",
        "Api": "DeleteSecurityGroup",
        "GroupId": "{{ createSecurityGroup.GroupId }}"
      },
      "isCritical": "true",
      "isEnd": "true"
    }
  ],
  "outputs": [
    "createCloudWatchDashboard.Output",
    "createManagedInstance.InstanceId"
  ]
}

```



 

 
