#!/usr/bin/env python

import requests
import argparse


def extract_values(obj, key):
    arr = []

    def extract(obj, arr, key):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    extract(v, arr, key)
                elif k == key:
                    arr.append(v)
        elif isinstance(obj, list):
            for item in obj:
                extract(item, arr, key)
        return arr

    results = extract(obj, arr, key)
    return results


log_info = ''
log_debug = ''

parser = argparse.ArgumentParser(description='Query a New Relic RPM for all alert policy conditions and their entities')
parser.add_argument('apikey', help='New Relic RPM Admin API Key')
parser.add_argument('-o', '--outputfile', help='File name to wrtie report to (default=output.csv)',
                    default='output.csv')
parser.add_argument('-p', '--printoutput', help='Print output file to screen in addition to file', action='store_true')
parser.add_argument('-i', '--includeservers', help='Include results for New Relic Servers (soon to be deprecated)',
                    action='store_true')
parser.add_argument('-lp', '--limitpolicies', help='Limit the number of policies returned', default=5000, type=int)
parser.add_argument('-lc', '--limitconditions', help='Limit the number of conditions returned per policy', default=250,
                    type=int)
parser.add_argument('-id', '--ignoredisabled', help='Do not include disabled conditions in the report',
                    action='store_true')
parser.add_argument('-d', '--debuglevel', help='Set the stdout debug level', choices=['info', 'debug'])
args = parser.parse_args()

api_key = args.apikey
output_file = args.outputfile
print_output = args.printoutput
print_servers = args.includeservers
limit_policies = args.limitpolicies
limit_conditions = args.limitconditions
ignore_disabled = args.ignoredisabled
if args.debuglevel == 'info':
    log_info = True
    log_debug = False
elif args.debuglevel == 'debug':
    log_info = True
    log_debug = True
else:
    log_info = False
    log_debug = False

url_channels = 'https://api.newrelic.com/v2/alerts_channels.json'
url_policies = 'https://api.newrelic.com/v2/alerts_policies.json'
url_conditions = 'https://api.newrelic.com/v2/alerts_conditions.json'
url_servers = 'https://api.newrelic.com/v2/servers/'
url_apm = 'https://api.newrelic.com/v2/applications/'
url_synthetics = 'https://api.newrelic.com/v2/alerts_synthetics_conditions.json'
url_nrql = 'https://api.newrelic.com/v2/alerts_nrql_conditions.json'
url_infra = 'https://infra-api.newrelic.com/v2/alerts/conditions'

headers_channels = {'X-Api-Key': api_key}
headers_policies = {'X-Api-Key': api_key}
headers_conditions = {'X-Api-Key': api_key}
headers_servers = {'X-Api-Key': api_key}
headers_apm = {'X-Api-Key': api_key}
headers_synthetics = {'X-Api-Key': api_key}
headers_nrql = {'X-Api-Key': api_key}
headers_infra = {'X-Api-Key': api_key}

output = 'policyId,policyName,conditionId,conditionName,conditionType,conditionEnabled,entityId,entityServerName,entityAppName,channels (type|name|slackChannel|email),nrqlQuery'

print('Script start')

##Build alert channels lookup json for the RPM
response = requests.get(url_channels, headers=headers_channels)
channels_json = ''
if response.status_code == requests.codes.ok:
    if log_debug: print('Success: Get Channels api call')

    channels_json = response.json()
else:
    print('FAILED: Get Channels api call')
    print(response.status_code)

##Get all alert policies for the RPM
response = requests.get(url_policies, headers=headers_policies)

if response.status_code == requests.codes.ok:
    if log_debug: print('Success: Get Policies api call')

    policies_json = response.json()

    if log_info: print('Number of policies: ' + str(len(policies_json['policies'])))

    policyCounter = 0
    for policy in policies_json['policies']:
        # Lookup policyId and build the alert channels report field for this policy
        channels = ''
        channelName = ''
        channelType = ''
        channelSlackChannel = ''
        channelEmail = ''
        for channel in channels_json['channels']:
            for policyId in channel['links']['policy_ids']:
                if policyId == policy['id']:
                    channelName = channel['name']
                    channelType = channel['type']
                    if channelType == 'slack': channelSlackChannel = channel['configuration']['channel']
                    if channelType == 'email': channelEmail = channel['configuration']['recipients']
                    channels += channelType + '|' + channelName + '|' + channelSlackChannel + '|' + channelEmail + '^'
            channelName = ''
            channelType = ''
            channelSlackChannel = ''
            channelEmail = ''

        ##Get the alert conditions for this policy
        if policyCounter < limit_policies:
            if log_info: print('--Working on policy ' + str(policyCounter + 1) + ' of ' + str(
                len(policies_json['policies'])) + ' with id ' + str(policy['id']) + ' named "' + policy['name'] + '"')

            ##Starting infra conditions
            response = requests.get(url_infra, headers=headers_infra, params='policy_id=' + str(policy['id']))
            if response.status_code == requests.codes.ok:
                if log_debug: print(
                    'Success: Get Infrastructure Conditions api call for policy id ' + str(policy['id']))
                infraConditions_json = response.json()

                if log_info: print('----Number of standard conditions in policy id ' + str(policy['id']) + ': ' + str(
                    len(infraConditions_json['data'])))
                infraConditionsCounter = 0
                for infraCondition in infraConditions_json['data']:
                    if infraConditionsCounter < limit_conditions:
                        if log_info: print(
                            '------Working on condition id ' + str(infraCondition['id']) + ' named "' + infraCondition[
                                'name'] + '" for policyId ' + str(policy['id']) + ' named "' + policy['name'] + '"')
                        infraHostEntities = extract_values(infraCondition, 'entityName')
                        if len(infraHostEntities) > 0:
                            for i in infraHostEntities:
                                lineToAdd = str(policy['id']) + ',' + policy['name'] + ',' + str(infraCondition['id']) + \
                                            ',' + infraCondition['name'] + ',' + infraCondition['type'] + ',' + \
                                            str(infraCondition['enabled']) + ', ,' + i + \
                                            ', ,' + channels
                                if print_servers or infraCondition['type'] != 'servers_metric':
                                    if ignore_disabled:
                                        if infraCondition['enabled']:
                                            if log_debug: print('Adding record: "' + lineToAdd + '"')
                                            output += '\n' + lineToAdd
                                    else:
                                        if log_debug: print('Adding record: "' + lineToAdd + '"')
                                        output += '\n' + lineToAdd

                        infraAppEntities = extract_values(infraCondition, 'nr.apmApplicationNames')
                        if len(infraAppEntities) > 0:
                            for a in infraAppEntities:
                                lineToAdd = str(policy['id']) + ',' + policy['name'] + ',' + str(infraCondition['id']) + \
                                            ',' + infraCondition['name'] + ',' + infraCondition['type'] + ',' + \
                                            str(infraCondition['enabled']) + ', , ,' + \
                                            a + ',' + channels
                                if print_servers or infraCondition['type'] != 'servers_metric':
                                    if ignore_disabled:
                                        if infraCondition['enabled']:
                                            if log_debug: print('Adding record: "' + lineToAdd + '"')
                                            output += '\n' + lineToAdd
                                    else:
                                        if log_debug: print('Adding record: "' + lineToAdd + '"')
                                        output += '\n' + lineToAdd
                    infraConditionsCounter += 1

            ##Starting non-infra conditions
            response = requests.get(url_conditions, headers=headers_conditions, params='policy_id=' + str(policy['id']))

            if response.status_code == requests.codes.ok:
                if log_debug: print('Success: Get Conditions api call for policy id ' + str(policy['id']))
                conditions_json = response.json()

                if log_info: print('----Number of standard conditions in policy id ' + str(policy['id']) + ': ' + str(
                    len(conditions_json['conditions'])))

                ##For each condition in policy, get condition details (APM Application and Key Transaction, Browser and Mobile application metric conditions)
                conditionCounter = 0
                for condition in conditions_json['conditions']:
                    if conditionCounter < limit_conditions:
                        if log_info: print(
                            '------Working on condition id ' + str(condition['id']) + ' named "' + condition[
                                'name'] + '" for policyId ' + str(policy['id']) + ' named "' + policy['name'] + '"')

                        # Add line to output for each entity
                        for entity in condition['entities']:
                            # Get descriptive name for entity
                            entityServerName = ''
                            entityAppName = ''
                            if condition['type'] == 'servers_metric':
                                entityServerName = 'NR_SERVERS'
                            if condition['type'] == 'apm_app_metric':
                                response = requests.get(url_apm + str(entity) + '.json', headers=headers_apm)

                                if response.status_code == requests.codes.ok:
                                    if log_debug: print(
                                        'Success: Get Application api call for entity id ' + str(entity))
                                    servers_json = response.json()
                                    entityAppName = servers_json['application']['name']
                                else:
                                    print('FAILED: Get Application api call for entity id ' + str(entity))
                                    print(response.status_code)

                            lineToAdd = str(policy['id']) + ',' + policy['name'] + ',' + str(condition['id']) + ',' + \
                                        condition['name'] + ',' + condition['type'] + ',' + str(condition['enabled']) + \
                                        ',' + str(
                                entity) + ',' + entityServerName + ',' + entityAppName + ',' + channels

                            if print_servers or condition['type'] != 'servers_metric':
                                if ignore_disabled:
                                    if condition['enabled']:
                                        if log_debug: print('Adding record: "' + lineToAdd + '"')
                                        output += '\n' + lineToAdd
                                else:
                                    if log_debug: print('Adding record: "' + lineToAdd + '"')
                                    output += '\n' + lineToAdd
                    conditionCounter += 1
            else:
                print('FAILED: Get Conditions api call for policy id: ' + str(policy['id']))
                print(response.status_code)

            # Get the synthetic alert conditions for this policy
            if log_debug: print('Working on synthetic condtions for policy ' + str(policy['id']))
            response = requests.get(url_synthetics, headers=headers_synthetics, params='policy_id=' + str(policy['id']))

            if response.status_code == requests.codes.ok:
                if log_debug: print('Success: Get synthetics conditions api call')

                policies_syn = response.json()

                if log_info: print('----Number of synthetics conditions in policy ' + str(policy['id']) + ': ' + str(
                    len(policies_syn['synthetics_conditions'])))

                for synCondition in policies_syn['synthetics_conditions']:
                    lineToAdd = str(policy['id']) + ',' + policy['name'] + ',' + str(synCondition['id']) + ',' + \
                                synCondition['name'] + ',syn_check,' + str(
                        synCondition['enabled']) + ',,,,' + channels + ','
                    if ignore_disabled:
                        if synCondition['enabled']:
                            if log_debug: print('Adding record: "' + lineToAdd + '"')
                            output += '\n' + lineToAdd
                    else:
                        if log_debug: print('Adding record: "' + lineToAdd + '"')
                        output += '\n' + lineToAdd
            else:
                print('FAILED: Get synthetics conditions api call for policy id: ' + str(policy['id']))
                print(response.status_code)

            # Get the NRQL alert conditions for this policy
            if log_debug: print('Working on NRQL condtions for policy ' + str(policy['id']))
            response = requests.get(url_nrql, headers=headers_nrql, params='policy_id=' + str(policy['id']))

            if response.status_code == requests.codes.ok:
                if log_debug: print('Success: Get NRQL conditions api call')

                policies_nrql = response.json()

                if log_info: print('----Number of NRQL conditions in policy ' + str(policy['id']) + ': ' + str(
                    len(policies_nrql['nrql_conditions'])))

                for nrqlCondition in policies_nrql['nrql_conditions']:
                    lineToAdd = str(policy['id']) + ',' + policy['name'] + ',' + str(nrqlCondition['id']) + ',' + \
                                nrqlCondition['name'] + ',nrql,' + str(nrqlCondition['enabled']) + ',,,,' + channels + \
                                ',"' + nrqlCondition['nrql']['query'] + '"'
                    if ignore_disabled:
                        if nrqlCondition['enabled']:
                            if log_debug: print('Adding record: "' + lineToAdd + '"')
                            output += '\n' + lineToAdd
                    else:
                        if log_debug: print('Adding record: "' + lineToAdd + '"')
                        output += '\n' + lineToAdd
            else:
                print('FAILED: Get NRQL conditions api call for policy id: ' + str(policy['id']))
                print(response.status_code)

        policyCounter += 1
else:
    print('FAILED: Get Policies api call')
    print(response.status_code)

if print_output: print('Output file:\n' + output)

file = open(output_file, 'w')
file.write(output)
file.close()

print('CSV report written to ' + output_file)
print('Script complete')
