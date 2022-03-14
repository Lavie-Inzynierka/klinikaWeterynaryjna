import json
import jsonschema
import os

dirname = os.path.dirname(os.path.realpath(__file__))
schema_path = os.path.join(dirname, '..', '..', 'static', 'json', 'addpresc.schema.json')
with open(schema_path, 'r', encoding='utf-8') as fp:
    schema = json.load(fp)


def validate(data):
    try:
        jsonschema.validate(data, schema)
        return True
    except:
        return False
