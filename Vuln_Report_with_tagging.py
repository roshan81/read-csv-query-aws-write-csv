import csv
import boto3
import datetime

now = datetime.datetime.now().strftime("%Y-%m-%d")

def main():
    with open('/Users/roshan/Documents/Scripts/Qualys/Input/[your aws vulnerability report with instance IDs].csv', 'r') as csv_file:

        csv_reader = csv.DictReader(csv_file, delimiter =',')

        regions_client = boto3.client('ec2', region_name = 'us-east-1')
        ec2_regions = regions_client.describe_regions()

        all_ec2s = {}

        for region in ec2_regions['Regions']:
            regionname = region['RegionName']
            i_ec2 = boto3.client('ec2', region_name = regionname)
            i_response = i_ec2.describe_instances()
            for r in i_response['Reservations']:
                for i in r['Instances']:
                    instace_id = i['InstanceId']
                    Name = ''
                    app_id = ''
                    t_cmdb = ''
                    t_dcl = ''
                    t_pillar = ''
                    t_shut = ''
                    t_role = ''
                    t_awscon = ''
                    t_environment = ''
                    t_responsible_individuals = ''
                    t_owner_individual = ''
                    t_name = ''
                    t_cost_centre = ''

                    if 'Tags' in i:
                        for t in i['Tags']:
                            if t['Key'] == 'Name':
                               Name = t['Value']
                            elif t['Key'] == 'app_id':
                               app_id = t['Value']
                            elif t['Key'] == 't_cmdb':
                                t_cmdb = t['Value']
                            elif t['Key'] == 't_dcl':
                               t_dcl = t['Value']
                            elif t['Key'] == 't_pillar':
                                t_pillar = t['Value']
                            elif t['Key'] == 't_shut':
                                t_shut = t['Value']                        
                            elif t['Key'] == 't_role':
                                t_role = t['Value'] 
                            elif t['Key'] == 't_awscon':
                                t_awscon = t['Value']
                            elif t['Key'] == 't_environment':
                                t_environment = t['Value']
                            elif t['Key'] == 't_responsible_individuals':
                                t_responsible_individuals = t['Value']                        
                            elif t['Key'] == 't_owner_individual':
                                t_owner_individual = t['Value']
                            elif t['Key'] == 't_name':
                                t_name = t['Value']
                            elif t['Key'] == 't_cost_centre':
                                t_cost_centre = t['Value']

                        all_ec2s[instace_id] = { 'InstanceID' : i['InstanceId'], 'InstanceName' : Name, 'App_ID' : app_id, 'RegionName' : regionname, 't_cmdb' : t_cmdb, \
                            't_dcl' : t_dcl, 't_pillar' : t_pillar, 't_shut' : t_shut, 't_role' : t_role, 't_awscon' : t_awscon, 't_environment' : t_environment, 't_responsible_individuals' : t_responsible_individuals, 't_owner_individual' : t_owner_individual, \
                               't_name' : t_name, 't_cost_centre' : t_cost_centre }


        with open('/Users/roshan/Documents/Scripts/Qualys/output/PLA_Vulnerability_Report_{0}.csv'.format(now),'w', newline='') as f_t:
            fieldnames = ['InstanceId', 'ImageId', 'IP', 'DNS', 'RegionName', 'OS', 'InstanceName', 'app_id', 't_cmdb', 't_dcl', 't_pillar', 't_shut', 't_role', 't_awscon', 't_environment', 't_responsible_individuals',
                                           't_owner_individual',
                                           't_name',
                                           't_cost_centre',                                       
                                           'TRACKING_METHOD',
                                           'TITLE',
                                           'CVSS_V2_BASE',
                                           'TYPE',
                                           'Exposure',
                                           'STATUS',
                                           'PATCHABLE',
                                           'PCI_FLAG',
                                           'FIRST_FOUND_DATETIME',
                                           'LAST_FOUND_DATETIME',
                                           'VulnAge',
                                           'DIAGNOSIS',
                                           'SOLUTION',
                                           'RESULTS' ]
            csv_writer = csv.DictWriter(f_t, fieldnames=fieldnames, delimiter=',')

            csv_writer.writeheader()

            def iter_dict(i_id, keyname):
                return(all_ec2s[i_id][keyname])

            def lfdt_strip(lfdt):
                return(lfdt.strip("(),"))
                
            for irows in csv_reader:
                if irows['EC2_instanceId'] in all_ec2s:

                    InstanceId = irows['EC2_instanceId']
                    ImageId = irows['EC2_imageId']
                    app_id = iter_dict(irows['EC2_instanceId'], 'App_ID')
                    IP = irows['IP']
                    DNS = irows['DNS']
                    RegionName = iter_dict(irows['EC2_instanceId'], 'RegionName')
                    OS = irows['OS']
                    InstanceName = iter_dict(irows['EC2_instanceId'], 'InstanceName')
                    t_cmdb = iter_dict(irows['EC2_instanceId'], 't_cmdb')
                    t_dcl = iter_dict(irows['EC2_instanceId'], 't_dcl')
                    t_pillar = iter_dict(irows['EC2_instanceId'], 't_pillar')
                    t_shut = iter_dict(irows['EC2_instanceId'], 't_shut')
                    t_role = iter_dict(irows['EC2_instanceId'], 't_role')
                    t_awscon = iter_dict(irows['EC2_instanceId'], 't_awscon')
                    t_environment = iter_dict(irows['EC2_instanceId'], 't_environment')
                    t_responsible_individuals = iter_dict(irows['EC2_instanceId'], 't_responsible_individuals')
                    t_owner_individual = iter_dict(irows['EC2_instanceId'], 't_owner_individual')
                    t_name = iter_dict(irows['EC2_instanceId'], 't_name')
                    t_cost_centre = iter_dict(irows['EC2_instanceId'], 't_cost_centre')
                    TRACKING_METHOD = irows['TRACKING_METHOD']                  
                    TITLE = irows['TITLE']
                    CVSS_V2_BASE = irows['CVSS_V2_BASE']
                    TYPE = irows['TYPE']
                    Exposure = irows['Exposure']
                    STATUS = irows['STATUS']
                    PATCHABLE = irows['PATCHABLE']
                    PCI_FLAG = irows['PCI_FLAG']
                    FIRST_FOUND_DATETIME = irows['FIRST_FOUND_DATETIME']
                    LAST_FOUND_DATETIME = lfdt_strip(irows['LAST_FOUND_DATETIME'])
                    VulnAge = irows['VulnAge']
                    DIAGNOSIS = irows['DIAGNOSIS']
                    SOLUTION = irows['SOLUTION']
                    RESULTS = irows['RESULTS']

                    csv_writer.writerow({'InstanceId' : InstanceId, 'ImageId' : ImageId , 'IP' : IP, 'DNS' : DNS, 'RegionName' : RegionName, 'OS' : OS, 'InstanceName' : InstanceName, 'app_id' : app_id, 't_cmdb' : t_cmdb, 't_dcl' : t_dcl, \
                        't_pillar' : t_pillar, 't_shut' : t_shut, 't_role' : t_role, 't_awscon' : t_awscon, 't_environment' : t_environment, 't_responsible_individuals' : t_responsible_individuals, 't_owner_individual' : t_owner_individual, \
                            't_name' : t_name, 't_cost_centre' : t_cost_centre, 'TRACKING_METHOD' : TRACKING_METHOD, 'TITLE' : TITLE, 'CVSS_V2_BASE' : CVSS_V2_BASE, 'TYPE' : TYPE, 'Exposure' : Exposure, 'STATUS' : STATUS, 'PATCHABLE' : PATCHABLE, \
                                 'PCI_FLAG' : PCI_FLAG, 'FIRST_FOUND_DATETIME' : FIRST_FOUND_DATETIME, 'LAST_FOUND_DATETIME' : LAST_FOUND_DATETIME, 'VulnAge' : VulnAge, 'DIAGNOSIS' : DIAGNOSIS, 'SOLUTION' : SOLUTION, 'RESULTS' :RESULTS })


        f_t.close()
    csv_file.close()


if __name__ == '__main__':
    main()
