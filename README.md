# gatech-slack-account-fixer
[![GitHub license](https://img.shields.io/github/license/RoboJackets/gatech-slack-account-fixer)](https://github.com/RoboJackets/gatech-slack-account-fixer/blob/main/LICENSE)

Corrects Slack account information, for use with Enterprise Grid migrations

## What

This tool will check each account in a Slack workspace and determine what Georgia Tech identity owns it.

If the email address associated to the account is not the primary email address for the Georgia Tech person (i.e. the one listed in the directory), the email will be updated.

If you provide the `--fix-names` flag and the existing Slack name does not appear to be a real name based on some heuristics, the name will be updated to match the directory. Additionally, the "display name" field will be set to a blank string, if it is not already.

You can provide the `--dry-run` flag to not make any changes in Slack.

## Prerequisites

- Network connectivity to Georgia Tech Whitepages (either eduroam or a wired connection on campus, or VPN)
- A [Slack App](https://api.slack.com/apps/) installed to your workspace with at least `users:read`, `users.profile:read`, and `users:read.email` scopes for `--dry-run`s, and `users.profile:write` scope for making changes
- The pre-migration report provided by Alana, as a CSV

If you have access to BuzzAPI, you can also provide credentials for that. This will provide more accurate results than Whitepages, however Whitepages will still be checked first for better performance and data quality.

## Install
The recommended install method is using `pipx`.

```shell
pipx install git+https://github.com/RoboJackets/gatech-slack-account-fixer

# Updates are also through pipx
pipx upgrade gatech-slack-account-fixer
```

## Run
```
usage: gatech-slack-account-fixer [-h] --directory {whitepages,buzzapi}
                                  --pre-migration-report PRE_MIGRATION_REPORT
                                  --slack-api-token SLACK_API_TOKEN
                                  [--buzzapi-username BUZZAPI_USERNAME]
                                  [--buzzapi-password BUZZAPI_PASSWORD]
                                  [--fix-names] [--dry-run] [--debug]

Corrects Slack account information, for use with Enterprise Grid migrations

optional arguments:
  -h, --help            show this help message and exit
  --directory {whitepages,buzzapi}
                        which directory service to use
  --pre-migration-report PRE_MIGRATION_REPORT
                        the pre-migration report provided by Alana, in CSV
                        format
  --slack-api-token SLACK_API_TOKEN
                        the OAuth token to authenticate to the Slack API
  --buzzapi-username BUZZAPI_USERNAME
                        the username to use when connecting to BuzzAPI
  --buzzapi-password BUZZAPI_PASSWORD
                        the password to use when connecting to BuzzAPI
  --fix-names           update names to match the directory
  --dry-run             do not make any changes
  --debug               print debug information
```

Note that this script will necessarily take a long time! There are many external service calls, the Slack API is heavily rate-limited, and most workspaces that need this have many accounts to check. If you are not getting any output, that means that your accounts are OK. You will only get output if:

- the script cannot match a Slack account to a Georgia Tech identity
- the script makes a change (or would make a change, if you have `--dry-run` enabled)
- the script tried to make a change but failed (usually Slack API issues, a few cases are specifically handled and explained)

For reference, running on the SCC workspace (around 800 accounts) against Whitepages with no changes needed takes about a minute, and with BuzzAPI enabled it takes about three minutes.

## Develop

This project uses [Poetry](https://python-poetry.org/) for dependency management and `pipx` integration. You can run the tool with `poetry run gatech-slack-account-fixer` during development.

Please ensure that contributions pass `black`, `flake8`, `pylint`, and `mypy`.
