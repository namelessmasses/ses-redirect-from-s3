import json

with open('test_event.json', 'r') as f:
    data = json.load(f)

s = json.dumps(data, indent=None, separators=(',', ':'))
print(s)