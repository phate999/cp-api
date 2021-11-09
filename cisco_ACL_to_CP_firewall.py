""" Convert Cisco Extended Access Lists to Cradlepoint ZFW filter_policies
Set config_filename below to your Cisco config
Enter NCM API keys and device and/or group IDs to PATCH configurations (optional)
The script will also output configurations that you can copy and paste to the CLI, useful for initial testing.
"""

import requests
from netaddr import IPAddress


config_filename = 'cisco_config_full.txt'  # Replace with your filename

api_keys = {'X-ECM-API-ID': 'YOUR',  # Replace with your NCM API Keys (optional)
           'X-ECM-API-KEY': 'KEYS',
           'X-CP-API-ID': 'GO',
           'X-CP-API-KEY': 'HERE',
           'Content-Type': 'application/json'}

router_id = '12345'  # Replace with your router ID (optional)

group_id = '12345'  # Replace with your group ID (optional)


def cidr(inverse):
    netmask = []
    inverse = inverse.split('.')
    for octet in inverse:
        netmask.append(str(255 - int(octet)))
    netmask = '.'.join(netmask)
    cidr = IPAddress(netmask).netmask_bits()
    return '/' + str(cidr)


def translate_port(port):
    try:
        port = int(port)
    except:
        pass
    if type(port) == int:
        return str(port)
    else:
        try:
            port_map = {
                'aol': '5120',
                'bgp': '179',
                'chargen': '19',
                'cifs': '3020',
                'citrix': '1494',
                'cmd': '514',
                'ctiqbe': '2748',
                'daytime': '13',
                'discard': '9',
                'domain': '53',
                'echo': '7',
                'exec': '512',
                'finger': '79',
                'ftp': '21',
                'ftp-data': '20',
                'gopher': '70',
                'h323': '1720',
                'hostname': '101',
                'http': '80',
                'https': '443',
                'ident': '113',
                'imap4': '143',
                'irc': '194',
                'kerberos': '88',
                'klogin': '543',
                'kshell': '544',
                'ldap': '389',
                'ldaps': '636',
                'login': '513',
                'lotusnotes': '1352',
                'lpd': '515',
                'netbios-ns': '137',
                'netbios-dgm': '138',
                'netbios-ssn': '139',
                'nfs': '2049',
                'nntp': '119',
                'pcanywhere-data': '5631',
                'pim-auto-rp': '496',
                'pop2': '109',
                'pop3': '110',
                'pptp': '1723',
                'rsh': '514',
                'rtsp': '554',
                'sip': '5060',
                'smtp': '25',
                'sqlnet': '1522',
                'ssh': '22',
                'sunrpc': '111',
                'tacacs': '49',
                'talk': '517',
                'telnet': '23',
                'tftp': '69',
                'uucp': '540',
                'whois': '43',
                'www': '80',
                'bootpc': '67',
                'ntp': '123',
                'time': '123',
                'netbios-ss': '139',
                'snmp': '161',
                'snmptrap': '162',
                'isakmp': '500',
                'syslog': '514',
                }
            ret = port_map[port]
        except KeyError:
            print(f'Missing Port in translate_port: {port}')
            ret = ''
        return ret


def translate_protocol(proto):
    protocol_map = {
        'icmp': [{'identity': 1}],
        'tcp': [{'identity': 6}],
        'udp': [{'identity': 17}],
        'gre': [{'identity': 47}],
        'esp': [{'identity': 50}]
        }
    return protocol_map.get(proto, [])


def translate_ip_mask(index):
    if newline[index] == 'any':
        return [], index + 1
    elif newline[index] == 'host':
        return [{'identity': newline[index + 1] + '/32'}], index + 2
    else:
        return [{'identity': newline[index] + cidr(newline[index + 1])}], index + 2


def translate_dst_ports(index):
    try:
        if newline[index] == 'gt':
            return [{'identity': str(int(newline[index + 1]) + 1) + ':65535'}]
        elif newline[index] == 'eq':
            index += 1
            ports = [{'identity': translate_port(newline[index])}]
            return ports
        elif newline[index] == 'range':
            index += 1
            port1 = newline[index]
            index += 1
            port2 = newline[index]
            return [{'identity': f'{translate_port(port1)}:{translate_port(port2)}'}]
        elif newline[index] in ['echo', 'echo-reply', 'unreachable', 'time-range']:
            return []
        else:
            print(f'Unidentified word in translate_dst_ports: {newline} {newline[index]}')
            return []
    except Exception:
        return []


def get_config_section(filename, start_text):
    try:
        config_file = open(filename, 'rt')
        config_lines = config_file.readlines()
        config_file.close()
    except Exception as e:
        print(f'Exception while reading config file: {filename} {e}')
        return []
    section_lines = []
    found_section_in_config = False
    try:
        for line in config_lines:
            if line.startswith(start_text):
                found_section_in_config = True
            if found_section_in_config:
                if line.startswith('!'):
                    break
                section_lines.append(line)
        return section_lines
    except Exception as e:
        print(f'Exception while parsing config file {filename} {e}')
        return []


# Script starts here
print(f'Converting Cisco config {config_filename} to Cradlepoint ZFW Filter Policies...')

# Get all ACLs:
acl_lines = get_config_section(config_filename, 'ip access-list extended')

# Get all class-maps:
class_map_lines = get_config_section(config_filename, 'class-map')

# Parse all ACLs into individuals
name = 'ACL'
priority = 0
all_acls = []
acl_index = 0
in_list = False
for acl_line in acl_lines:
    if not acl_line == '\n':
        if in_list:
            if acl_line[0] == 'i':
                acl_index += 1
                all_acls.append([acl_line])
            else:
                all_acls[acl_index].append(acl_line)
        else:
            if acl_line[0] == 'i':
                in_list = True
                all_acls = [[acl_line]]

# Parse each ACL into a "ruleset" for combining into a larger class-map
rulesets = {}
for acl in all_acls:
    i = 1
    rule_list = []
    for line in acl:
        line = line.strip('\n').split(' ')
        newline = []
        for item in line:
            if item != '':
                newline.append(item)
        if newline[0] != 'remark':
            if newline[0] == 'ip':  # Begin policy
                priority = 0
                name = newline[3]
            else:
                priority += 10
                ruleaction = newline[0]
                if ruleaction == 'permit':
                    ruleaction = 'allow'
                protocol = translate_protocol(newline[1])
                src, index = translate_ip_mask(2)
                if newline[index] == 'gt':
                    srcport = [{'identity': newline[index + 1] + ':65535'}]
                    index += 2
                else:
                    srcport = []
                dst, index = translate_ip_mask(index)
                dstports = translate_dst_ports(index)
                rule = \
                    {
                        "action": ruleaction,
                        "dst": {
                            "ip": dst,
                            "port": dstports
                        },
                        "ip_version": "ip4",
                        "name": f'{name} {i}',
                        "priority": priority,
                        "protocols": protocol,
                        "src": {
                            "ip": src,
                            "mac": [],
                            "port": srcport
                        }
                    }
                i += 1
                rule_list.append(rule)
    rulesets[name] = rule_list

# If no class-maps exist, create "filter_policy_rules" from ACLs
# If class-maps exist, parse class-maps and combine rulesets to create "filter_policy_rules"
filter_policy_rules = {}
if not class_map_lines:
    print('\nNo class-maps found.  Converting individual ACLs to filter policies...')
    for rule_name, rules in rulesets.items():
        filter_policy_rules[rule_name] = rules
else:
    print('\nClass-maps found.  Combining multiple ACLs into filter-policies...')
    mapname = 'Class_Map'
    for mapline in class_map_lines:
        if not mapline == '\n':
            try:
                if mapline[0] == 'c':
                    map_type = mapline.split(' ')[1]
                    if map_type == 'type':
                        mapname = mapline.split(' ')[4].strip('\n')
                        filter_policy_rules[mapname] = []
                    elif map_type == 'match-any':
                        mapname = mapline.split(' ')[2].strip('\n')
                        filter_policy_rules[mapname] = []
                else:
                    rulename = mapline.split(' ')[4].strip('\n')
                    filter_policy_rules[mapname] = filter_policy_rules[mapname] + rulesets[rulename]
            except Exception as e:
                pass


print('\nDone!')
# Print CLI commands to add to router config
all_filter_policies = {}
print('\nCLI - copy and paste the following post commands:\n')
for i, maprule in enumerate(filter_policy_rules):
    filter_id = f'{i+1:04}0000-0000-0000-0000-abcdef123456'
    filter_policy = {"_id_": filter_id, "default_action": "deny",
                     "rules": filter_policy_rules[maprule], 'name': maprule}
    all_filter_policies[filter_id] = filter_policy
    print(f'post /config/security/zfw/filter_policies/ {filter_policy}')

if api_keys['X-ECM-API-ID'] == 'YOUR':
    print('\nNo API Keys defined, skipping NCM API configuration PATCH.')
else:
    ncm_config_patch = {'configuration': [{'security': {'zfw': {'filter_policies': all_filter_policies}}}, []]}
    if router_id != '12345':
        print(f'\nPatching configuration to router ID {router_id}...')
        try:
            cfg_man_req = requests.get(f'https://www.cradlepointecm.com/api/v2/configuration_managers/?router={router_id}', headers=api_keys).json()
            cfg_man_id = cfg_man_req['data'][0]['id']
            patch_req = requests.patch(f'https://www.cradlepointecm.com/api/v2/configuration_managers/{cfg_man_id}/', headers=api_keys, json=ncm_config_patch)
            if patch_req.status_code < 300:
                print('Success!')
        except Exception as e:
            print(f'Exception patching router config.  Router ID: {router_id} - Exception: {e}')
    if group_id != '12345':
        print(f'\nPatching configuration to group ID {group_id}...')
        try:
            patch_req = requests.patch(f'https://www.cradlepointecm.com/api/v2/groups/{group_id}/', headers=api_keys, json=ncm_config_patch)
            if patch_req.status_code < 300:
                print('Success!')
        except Exception as e:
            print(f'Exception patching group config.  Group ID: {group_id} - Exception: {e}')
