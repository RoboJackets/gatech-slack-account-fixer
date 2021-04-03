"""
Corrects Slack account information, for use with Enterprise Grid migrations
"""

import logging
import sys
from argparse import ArgumentParser, FileType
from csv import DictReader
from re import fullmatch, search
from typing import Dict, Optional, TextIO

from ldap3 import ALL_ATTRIBUTES, Connection, Server  # type: ignore

from requests import post

from slack_sdk import WebClient  # type: ignore

CHANGING_EMAIL = "Changing email from {old} to {new}"
CHANGING_NAME = 'Changing name for {email} from "{old}" to "{new}"'


def parse_email_map(pre_migration_report: TextIO) -> Dict[str, str]:
    """
    Parses the pre-migration report from a file into a map of old emails to new emails

    :param pre_migration_report: the pre-migration report
    :return: map of old emails to new emails
    """
    email_map = {}

    reader = DictReader(pre_migration_report)
    for row in reader:
        match_parts = search(r"(?P<new_email>[a-z0-9._-]+@(?:[a-z]+.)?gatech.edu)", row["Action"])
        if match_parts is not None:
            email_map[row["Email"]] = match_parts.group("new_email")

    return email_map


def build_ldap_filter(kwargs: Dict[str, str]) -> str:
    """
    Builds up an LDAP filter from kwargs

    :param kwargs: Dict of attribute name, value pairs
    :return: LDAP search filter representation of the dict
    """
    search_filter = ""
    for arg in kwargs:
        search_filter = f"{search_filter}({arg}={kwargs[arg]})"
    return f"(&{search_filter})"


def find_user_in_whitepages(ldap: Connection, **kwargs: str) -> Optional[Dict[str, str]]:
    """
    Looks up a user in Whitepages

    :param ldap: Connection object to use for search
    :param kwargs: Filters to apply
    :return: None if no results, or a dict with the email and name for the account
    """
    search_filter = build_ldap_filter(kwargs)
    logger = logging.getLogger()
    logger.debug("Querying Whitepages with filter " + search_filter)
    result = ldap.search(
        search_base="dc=whitepages,dc=gatech,dc=edu",
        search_filter=search_filter,
        attributes=ALL_ATTRIBUTES,
    )

    if result is not True:
        return None

    if len(ldap.entries) == 0:
        return None

    if len(ldap.entries) > 1:
        print(ldap.entries)
        raise Exception("More than one directory entry matched filter " + search_filter)

    entry = ldap.entries[0]

    display_name_parts = str(entry["displayName"]).split(",")
    first_name_parts = display_name_parts[1].split()
    name = first_name_parts[0] + " " + display_name_parts[0]

    return {
        "email": str(entry["mail"]),
        "name": name,
    }


def find_user_in_buzzapi(username: str, password: str, **kwargs: str) -> Optional[Dict[str, str]]:
    """
    Looks up a user in BuzzAPI

    :param username: the username to use for authentication
    :param password: the password to use for authentication
    :param kwargs: Filters to apply
    :return: None if no results, or a dict with the email and name for the account
    """
    search_filter = build_ldap_filter(kwargs)
    logger = logging.getLogger()
    logger.debug("Querying BuzzAPI with filter " + search_filter)

    response = post(
        "https://api.gatech.edu/apiv3/central.iam.gted.accounts/search",
        json={
            "api_app_id": username,
            "api_app_password": password,
            "api_request_mode": "sync",
            "api_log_level": "error",
            "requested_attributes": [
                "givenName",
                "sn",
                "mail",
            ],
            "filter": search_filter,
        },
    )

    if response.status_code != 200:
        raise Exception("BuzzAPI returned " + str(response.status_code))

    json = response.json()

    if "api_result_data" not in json:
        return None

    if len(json["api_result_data"]) == 0:
        return None

    if len(json["api_result_data"]) > 1:
        print(json["api_result_data"])
        raise Exception("More than one directory entry matched filter " + search_filter)

    result = json["api_result_data"][0]

    return {
        "email": result["mail"],
        "name": result["givenName"].split()[0] + " " + result["sn"],
    }


def main() -> None:  # pylint: disable=too-many-locals,too-many-branches,too-many-statements,unused-variable
    """
    Parses command-line arguments and calls out to helper functions.

    :return: None
    """
    parser = ArgumentParser(
        description="Corrects Slack account information, for use with Enterprise Grid migrations",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--directory",
        choices=["whitepages", "buzzapi"],
        help="which directory service to use",
        required=True,
    )
    parser.add_argument(
        "--pre-migration-report",
        help="the pre-migration report provided by Alana, in CSV format",
        type=FileType("r"),
        required=True,
    )
    parser.add_argument("--debug", help="print debug information", action="store_true")
    parser.add_argument("--dry-run", help="do not make any changes", action="store_true")
    parser.add_argument("--fix-names", help="update names to match the directory", action="store_true")
    parser.add_argument(
        "--buzzapi-username",
        help="the username to use when connecting to BuzzAPI",
        required="buzzapi" in sys.argv,
    )
    parser.add_argument(
        "--buzzapi-password",
        help="the password to use when connecting to BuzzAPI",
        required="buzzapi" in sys.argv,
    )
    parser.add_argument("--slack-api-token", help="the OAuth token to authenticate to the Slack API", required=True)
    args = parser.parse_args()

    formatter = logging.Formatter("%(levelname)s: %(message)s")

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    logger = logging.getLogger()
    logger.addHandler(handler)

    if args.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    email_map = parse_email_map(args.pre_migration_report)

    slack = WebClient(
        token=args.slack_api_token,
        logger=logger,
    )

    if args.directory == "whitepages":
        ldap = Connection(Server("whitepages.gatech.edu"), auto_bind=True)

        def find_user(**kwargs: str) -> Optional[Dict[str, str]]:
            return find_user_in_whitepages(ldap, **kwargs)

    else:

        def find_user(**kwargs: str) -> Optional[Dict[str, str]]:
            return find_user_in_buzzapi(args.buzzapi_username, args.buzzapi_password, **kwargs)

    update_email = 0
    update_name = 0
    no_match = 0

    for response in slack.users_list():  # pylint: disable=too-many-nested-blocks
        for member in response.get("members"):
            profile = member["profile"]
            if profile["email"].endswith("gatech.edu"):
                search_results = find_user(mail=profile["email"])
                if search_results is None:
                    mailbox = profile["email"].split("@")[0]
                    if fullmatch(r"[a-z][a-z]+[0-9]+", mailbox):
                        search_results = find_user(uid=mailbox)
                        if search_results is None:
                            if profile["email"] in email_map:
                                search_results = find_user(mail=email_map[profile["email"]])
                                if search_results is None:
                                    no_match += 1
                                    logger.warning(
                                        "Could not find match for "
                                        + email_map[profile["email"]]
                                        + " found in pre-migration report, this is suspicious. Skipping account."
                                    )
                                    continue
                            else:
                                no_match += 1
                                logger.warning(
                                    "Could not find match for "
                                    + profile["email"]
                                    + " in directory or pre-migration report, this is suspicious. Skipping account."
                                )
                                continue
                    else:
                        if profile["email"] in email_map:
                            search_results = find_user(mail=email_map[profile["email"]])
                            if search_results is None:
                                no_match += 1
                                logger.warning(
                                    "Could not find match for "
                                    + email_map[profile["email"]]
                                    + " found in pre-migration report, this is suspicious. Skipping account."
                                )
                                continue
                        else:
                            no_match += 1
                            logger.warning(
                                "Could not find match for "
                                + profile["email"]
                                + " in directory or pre-migration report, this is suspicious. Skipping account."
                            )
                            continue

                if search_results is None:
                    raise Exception("Missing a case somewhere! Email: " + profile["email"])

                new_profile = {}

                if profile["email"] != search_results["email"]:
                    update_email += 1
                    logger.info(CHANGING_EMAIL.format(old=profile["email"], new=search_results["email"]))
                    new_profile["email"] = search_results["email"]

                if args.fix_names and (search_results["name"] != profile["real_name"] or profile["display_name"] != ""):
                    update_name += 1
                    logger.info(
                        CHANGING_NAME.format(
                            email=profile["email"], old=profile["real_name"], new=search_results["name"]
                        )
                    )

                if len(new_profile) > 0 and not args.dry_run:
                    slack.users_profile_set(profile=new_profile)
            else:
                if len(profile["real_name"].split()) == 2 or len(profile["display_name"].split()) == 2:
                    real_name_parts = profile["real_name"].split()
                    display_name_parts = profile["display_name"].split()

                    search_results = None

                    if len(real_name_parts) == 2:
                        search_results = find_user(givenName=real_name_parts[0] + "*", sn=real_name_parts[1])
                        if search_results is None:
                            if len(display_name_parts) == 2:
                                search_results = find_user(
                                    givenName=display_name_parts[0] + "*", sn=display_name_parts[1]
                                )
                                if search_results is None:
                                    no_match += 1
                                    logger.warning(
                                        "No matches for "
                                        + profile["email"]
                                        + ' - name fields are "'
                                        + profile["real_name"]
                                        + '" and "'
                                        + profile["display_name"]
                                        + '". Skipping account.'
                                    )
                                    continue

                    if len(display_name_parts) == 2:
                        search_results = find_user(givenName=display_name_parts[0] + "*", sn=display_name_parts[1])
                        if search_results is None:
                            no_match += 1
                            logger.warning(
                                "No matches for "
                                + profile["email"]
                                + ' - name fields are "'
                                + profile["real_name"]
                                + '" and "'
                                + profile["display_name"]
                                + '". Skipping account.'
                            )
                            continue

                    if search_results is None:
                        raise Exception("Missing a case somewhere! Email: " + profile["email"])

                    new_profile = {}

                    if profile["email"] != search_results["email"]:
                        update_email += 1
                        logger.info(CHANGING_EMAIL.format(old=profile["email"], new=search_results["email"]))
                        new_profile["email"] = search_results["email"]

                    if args.fix_names and (
                        search_results["name"] != profile["real_name"] or profile["display_name"] != ""
                    ):
                        update_name += 1
                        logger.info(
                            CHANGING_NAME.format(
                                email=profile["email"], old=profile["real_name"], new=search_results["name"]
                            )
                        )

                    if len(new_profile) > 0 and not args.dry_run:
                        slack.users_profile_set(profile=new_profile)
                else:
                    no_match += 1
                    logger.warning(
                        "Not enough information to match "
                        + profile["email"]
                        + ' - name fields are "'
                        + profile["real_name"]
                        + '" and "'
                        + profile["display_name"]
                        + '". Skipping account.'
                    )
                    continue

    logger.info(f"Total emails updated: {update_email}")
    logger.info(f"Total names updated: {update_name}")
    logger.info(f"Total unmatched accounts: {no_match}")
