# Shared
Shared tools and utilities from the team at FalconOps

## Nessus to JSON (for use in Sysreptor)
Convert a .nessus file into the JSON format required for sysreptor. Then upload using the following:
```
cat .\output.json | reptor -s https://sysreptor-server.local -t <token> -p <project_guid> --debug finding
```
