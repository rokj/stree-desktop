INFO

POC tool for two way synchronization of files with s3 endpoint.

It uses s3 tag capabilities to store version of a file on particular client.

INSTALL/USAGE

1. install requirements with `pip install -r requirements.txt`
2. set configuration in config.json based on config.dist.json
3. `python main.py`

REFERENCES
- https://aykevl.nl/2017/04/concise-version-vectors
- https://stackoverflow.com/a/75347123/1107750
- https://owncloud.dev/architecture/efficient-stat-polling/
