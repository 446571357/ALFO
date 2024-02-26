# 从YAML文件获取参数

import yaml

def get_config(file):
    with open(file, 'r', encoding='utf8') as file:
        config = yaml.safe_load(file)
    # print(config)
    return config