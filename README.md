# Shared
Shared tools and utilities from the team at FalconOps

## Nessus to JSON (for use in Sysreptor)
[nessus-to-json.py](https://github.com/FalconOps-Cybersecurity/Shared/blob/main/nessus-to-json.py)

Convert a .nessus file into the JSON format required for sysreptor. Then upload using the following:
```
cat .\output.json | reptor -s https://sysreptor-server.local -t <token> -p <project_guid> --debug finding
```
