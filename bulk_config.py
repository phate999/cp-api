''' bulk_config.py - bulk configure devices in NCM from .csv file

1. Create routers.csv with router IDs listed in column A
2. Put other device-specific values in subsequent columns (B, C, D, etc)
3. Use NCM Config Editor to build a config template
4. Click "View Pending Changes" and copy the config
5. Paste your config below in the build_config() function where indicated.
6. Replace config values with corresponding csv column letters
    Example, csv file has router name column B:

    config = [{
        "system": {
            "system_id": column["B"]
        }
    },
        []
    ]

7. Enter API Keys below where indicated
8. Run script and watch output

'''
import requests
import csv

api_keys = {
    'X-ECM-API-ID': 'YOUR',
    'X-ECM-API-KEY': 'KEYS',
    'X-CP-API-ID': 'GO',
    'X-CP-API-KEY': 'HERE'
}


def build_config(column):
    # Paste your configuration BELOW THE NEXT LINE:
    config = \
        [{
            "system": {
                "system_id": column["B"]
            },
            "wlan": {
                "radio": {
                    "0": {
                        "bss": {
                            "0": {
                                "ssid": column["C"]
                            }
                        }
                    },
                    "1": {
                        "bss": {
                            "0": {
                                "ssid": column["C"]
                            }
                        }
                    }
                }
            }
        },
            []
        ]
    # Paste configuration ABOVE HERE ^

    return {"configuration": config}


def load_csv(filename):
    router_configs = {}
    try:
        with open(filename, 'rt') as f:
            rows = csv.reader(f)
            for row in rows:
                column = {"A": row[0]}
                i = 1
                while True:
                    try:
                        column[chr(i+97).upper()] = row[i]
                        i += i
                    except:
                        break
                router_configs[column["A"]] = column
    except Exception as e:
        print(f'Exception reading csv file: {e}')
    return router_configs


csv_file = 'routers.csv'
server = 'https://www.cradlepointecm.com/api/v2'
rows = load_csv(csv_file)
for router_id in rows:
    config_url = f'{server}/configuration_managers/?router={router_id}'
    get_config = requests.get(config_url, headers=api_keys)
    if get_config.status_code < 300:
        get_config = get_config.json()
        config_data = get_config["data"]
        config_id = config_data[0]["id"]
        config_patch = build_config(rows[router_id])
        patch_config = requests.patch(f'{server}/configuration_managers/{config_id}/', headers=api_keys, json=config_patch)
        if patch_config.status_code < 300:
            print(f'Sucessfully patched config to router: {router_id}')
        else:
            print(f'Error patching config for {router_id}: {patch_config.text}')
    else:
        print(f'Error getting configuration_managers/ ID for {router_id}: {get_config.text}')
print('Done!')
