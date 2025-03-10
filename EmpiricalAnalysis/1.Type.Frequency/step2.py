import json

with open("result.json") as fp:
    result = json.load(fp)

for one in result[:50]:
    print(one[0], one[1])