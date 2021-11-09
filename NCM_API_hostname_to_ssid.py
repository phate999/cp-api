import requests

api_keys = {
    'X-ECM-API-ID': 'YOUR',
    'X-ECM-API-KEY': 'KEYS',
    'X-CP-API-ID': 'GO',
    'X-CP-API-KEY': 'HERE'
}


def build_config(ssid):
    return {
            "configuration": [{
                    "wlan": {
                        "radio": {
                            "0": {
                                "bss": {
                                    "0": {
                                        "ssid": ssid
                                    }
                                }
                            },
                            "1": {
                                "bss": {
                                    "0": {
                                        "ssid": ssid
                                    }
                                }
                            }
                        }
                    }
                },
                []
            ]
        }


# Script Starts Here
server = 'https://www.cradlepointecm.com/api/v2'
routers_url = f'{server}/routers/?limit=500'
while routers_url:
    get_routers = requests.get(routers_url, headers=api_keys)
    if get_routers.status_code < 300:
        get_routers = get_routers.json()
        routers = get_routers["data"]
        for router in routers:
            config_url = f'{server}/configuration_managers/?router={router["id"]}'
            get_config = requests.get(config_url, headers=api_keys)
            if get_config.status_code < 300:
                get_config = get_config.json()
                config = get_config["data"]
                config_id = config[0]["id"]
                config_patch = build_config(router["name"])
                patch_config = requests.patch(f'{server}/configuration_managers/{config_id}/', headers=api_keys, json=config_patch)
                if patch_config.status_code < 300:
                    print(f'Sucessfully patched config to router: {router["name"]}')
                else:
                    print(f'Error patching config for {router["name"]}: {patch_config.text}')
            else:
                print(f'Error getting configuration_managers/ ID for {router["name"]}: {get_config.text}')
    else:
        print(f'Error getting routers: {get_routers.text}')
    routers_url = get_routers["meta"]["next"]
print('Done!')
