import json
import jsonschema
import os

dirname = os.path.dirname(os.path.realpath(__file__))
schema_path = os.path.join(dirname, '..', '..', 'static', 'json', 'addpresc.schema.json')
with open(schema_path, 'r') as fp:
    schema = json.load(fp)


# noinspection PyArgumentList
# resolver = RefResolver(schema_path='file:{}'.format(schema_path), schema=schema)
# validator = Draft7Validator(schema=schema,  format_checker=None)


def validate(data):
    try:
        # validator.validate(data)
        jsonschema.validate(data, schema)
        return True
    except:
        return False
