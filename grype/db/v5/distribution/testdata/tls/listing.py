import urllib.request
import json
import os

with open('listing.json', 'r') as fh:
    data = json.loads(fh.read())

entry = data["available"]["3"][-1]

hostname = os.popen('hostname').read().strip()

with open('www/listing.json', 'w') as fh:
    json.dump(
        {
            "available": {
                entry["version"]: [
                    {
                        "built": entry["built"],
                        "version": entry["version"],
                        "url": f"https://{hostname}.local/db.tar.gz",
                        "checksum": entry["checksum"]
                    }
                ]
            }
        }, fh)

print(entry["url"])
