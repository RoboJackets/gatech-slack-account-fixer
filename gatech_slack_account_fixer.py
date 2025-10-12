"""
Corrects Slack account information, for use with Enterprise Grid migrations
"""

import datetime
import logging
import sys
from argparse import ArgumentParser
from csv import DictWriter
from email.headerregistry import Address
from json import dumps
from re import fullmatch
from typing import Dict, Optional

import cachier

from ldap3 import Connection, Entry, Server  # type: ignore

from requests import post

from slack_sdk import WebClient

NO_MATCH_FOR_EMAIL_IN_DIRECTORY = "Could not find match for {email} in directory or pre-migration report"
DIRECTORY_NO_EMAIL = "{directory}: No entries had email for {search_filter}"
DIRECTORY_MORE_THAN_ONE_EMAIL = "{directory}: More than one email listed for {search_filter}"
DIRECTORY_ONE_RECORD_NO_EMAIL = "{directory}: Only one record returned but no email for {search_filter}"


cachier.set_global_params(
    cache_dir="_cache/",  # type: ignore
    pickle_reload=False,  # type: ignore
    allow_none=True,  # type: ignore
)


def is_georgia_tech_email_address(email_address: str) -> bool:
    """
    Check if the provided email address is a Georgia Tech email address
    """
    return Address(addr_spec=email_address.strip()).domain.split(".")[-2:] in [
        ["gatech", "edu"],
        ["atdc", "org"],
    ]


def build_ldap_filter(kwargs: Dict[str, str]) -> str:
    """
    Builds up an LDAP filter from kwargs

    :param kwargs: Dict of attribute name, value pairs
    :return: LDAP search filter representation of the dict
    """
    search_filter = ""
    for arg in kwargs:
        search_filter = f"{search_filter}({arg}={kwargs[arg]})"
    if len(kwargs) > 1:
        search_filter = f"(&{search_filter})"
    return search_filter


def find_user_in_whitepages(ldap: Connection, kwargs: Dict[str, str]) -> Optional[Dict[str, str]]:
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
        attributes=["mail", "primaryUid", "givenName", "sn"],
    )

    if result is not True:
        return None

    if len(ldap.entries) == 0:
        return None

    if len(ldap.entries) > 1:
        entries_with_email = 0
        entry_with_email = None
        emails = set()
        for entry_in_loop in ldap.entries:
            if (
                "mail" in entry_in_loop
                and entry_in_loop["mail"] is not None
                and entry_in_loop["mail"].value is not None
            ):
                entries_with_email += 1
                emails.add(entry_in_loop["mail"].value.lower())
                entry_with_email = entry_in_loop

        if entries_with_email == 0:
            print(ldap.entries)
            logger.warning(DIRECTORY_NO_EMAIL.format(directory="Whitepages", search_filter=search_filter))
            return None
        if entries_with_email > 1 and len(emails) > 1:
            print(ldap.entries)
            logger.warning(DIRECTORY_MORE_THAN_ONE_EMAIL.format(directory="Whitepages", search_filter=search_filter))
            return None

        entry: Entry = entry_with_email
    else:
        entry = ldap.entries[0]

    if "mail" not in entry:
        print(ldap.entries)
        logger.warning(DIRECTORY_ONE_RECORD_NO_EMAIL.format(directory="Whitepages", search_filter=search_filter))
        return None

    if entry["mail"].value is None:
        print(ldap.entries)
        logger.warning(
            "Whitepages: Matched record has no email for {search_filter}".format(search_filter=search_filter)
        )
        return None

    if not is_georgia_tech_email_address(entry["mail"].value):
        print(ldap.entries)
        logger.warning(
            "Whitepages: Matched record has non-GT email for {search_filter}".format(search_filter=search_filter)
        )
        return None

    return {
        "username": entry["primaryUid"].value.lower(),
        "email": entry["mail"].value.lower(),
        "name": entry["givenName"].value.split()[0] + " " + entry["sn"].value,
        "match_reason": "whitepages_" + list(kwargs.keys())[0],
    }


def find_user_in_buzzapi(username: str, password: str, kwargs: Dict[str, str]) -> Optional[Dict[str, str]]:
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

    request = {
        "api_app_id": username,
        "api_app_password": password,
        "api_request_mode": "sync",
        "api_log_level": "error",
        "requested_attributes": [
            "givenName",
            "sn",
            "mail",
            "gtPrimaryGTAccountUsername",
        ],
        "filter": search_filter,
    }

    response = post("https://api.gatech.edu/apiv3/central.iam.gted.accounts/search", json=request, timeout=(1, 30))
    response.raise_for_status()

    json = response.json()

    if "api_result_data" not in json:
        print(dumps(request))
        print(dumps(json))
        raise Exception("BuzzAPI had an error")

    results = json["api_result_data"]

    if len(results) == 0:
        return None

    if len(results) > 1:
        entries_with_email = 0
        entry_with_email = {}
        emails = set()
        for entry_in_loop in results:
            if "mail" in entry_in_loop and "givenName" in entry_in_loop:
                entries_with_email += 1
                emails.add(entry_in_loop["mail"].lower())
                entry_with_email = entry_in_loop

        if entries_with_email == 0:
            print(results)
            logger.warning(DIRECTORY_NO_EMAIL.format(directory="BuzzAPI", search_filter=search_filter))
            return None
        if entries_with_email > 1 and len(emails) > 1:
            print(results)
            logger.warning(DIRECTORY_MORE_THAN_ONE_EMAIL.format(directory="BuzzAPI", search_filter=search_filter))
            return None

        result: Dict[str, str] = entry_with_email
    else:
        result = results[0]

    if "mail" not in result:
        print(results)
        logger.warning(DIRECTORY_ONE_RECORD_NO_EMAIL.format(directory="BuzzAPI", search_filter=search_filter))
        return None

    if "givenName" not in result:
        print(results)
        logger.warning(
            "BuzzAPI: Only one record returned but no givenName for {search_filter}".format(search_filter=search_filter)
        )
        return None

    if not is_georgia_tech_email_address(result["mail"]):
        print(results)
        logger.warning(
            "BuzzAPI: Matched record has non-GT email for {search_filter}".format(search_filter=search_filter)
        )
        return None

    return {
        "username": result["gtPrimaryGTAccountUsername"],
        "email": result["mail"].lower(),
        "name": result["givenName"].split()[0] + " " + result["sn"],
        "match_reason": "buzzapi_" + list(kwargs.keys())[0],
    }


def find_user_in_apiary(token: str, kwargs: Dict[str, str]) -> Optional[Dict[str, str]]:
    """
    Looks up a user in Apiary

    :param token: the token to use for authentication
    :param kwargs: Filters to apply
    :return: None if no results, or a dict with the email and name for the account
    """
    if "mail" not in kwargs:
        return None

    logger = logging.getLogger()
    logger.debug("Querying Apiary with email " + kwargs["mail"])

    response = post(
        "https://my.robojackets.org/api/v1/users/searchByEmail",
        json={
            "email": kwargs["mail"],
        },
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        },
        timeout=(1, 30),
    )

    if response.status_code in [404, 422]:
        return None

    response.raise_for_status()

    json = response.json()

    if "user" not in json:
        print(dumps(json))
        raise Exception("Apiary had an error")

    result = json["user"]

    if not is_georgia_tech_email_address(result["gt_email"]):
        print(result)
        logger.warning(
            "Apiary: Matched record has non-GT email for {search_filter}".format(search_filter=kwargs["mail"])
        )
        return None

    return {
        "username": result["uid"],
        "email": result["gt_email"].lower(),
        "name": result["first_name"] + " " + result["last_name"],
        "match_reason": "apiary",
    }


def main() -> None:  # pylint: disable=unused-variable
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
    parser.add_argument("--slack-token", help="the token to authenticate to the Slack API", required=True)
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
    parser.add_argument("--apiary-token", help="the token to authenticate to the Apiary API")
    parser.add_argument("--debug", help="print debug information", action="store_true")
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

    slack = WebClient(
        token=args.slack_token,
        logger=logger,
    )

    ldap = Connection(Server("whitepages.gatech.edu"), auto_bind=True)

    if args.directory == "whitepages":

        @cachier.cachier()  # type: ignore
        def find_user(**kwargs: str) -> Optional[Dict[str, str]]:
            return find_user_in_whitepages(ldap, kwargs)

    else:

        if args.apiary_token is None:

            @cachier.cachier()  # type: ignore
            def find_user(**kwargs: str) -> Optional[Dict[str, str]]:
                whitepages_result = find_user_in_whitepages(ldap, kwargs)
                if whitepages_result is not None:
                    return whitepages_result
                return find_user_in_buzzapi(args.buzzapi_username, args.buzzapi_password, kwargs)

        else:

            @cachier.cachier()  # type: ignore
            def find_user(**kwargs: str) -> Optional[Dict[str, str]]:
                whitepages_result = find_user_in_whitepages(ldap, kwargs)
                if whitepages_result is not None:
                    return whitepages_result

                buzzapi_result = find_user_in_buzzapi(args.buzzapi_username, args.buzzapi_password, kwargs)
                if buzzapi_result is not None:
                    return buzzapi_result

                return find_user_in_apiary(args.apiary_token, kwargs)

    update_email = 0
    no_match = 0
    duplicates = 0
    total_accounts = 0

    gt_user_to_slack_user: dict[str, str] = {}
    user_details = []

    for page in slack.users_list():
        for member in page.get("members"):
            this_user = {
                "Workspace user id": member["id"],
                "Workspace full name": member["profile"]["real_name"],
                "Workspace display name": member["profile"]["display_name"],
                "Workspace username": member["name"],
                "Workspace email address": member["profile"]["email"] if "email" in member["profile"] else None,
                "Workspace account type": "member",
                "Workspace account status": "deactivated" if member["deleted"] else "active",
                "Georgia Tech username": None,
                "Georgia Tech full name": None,
                "Match reason": None,
                "Recommended email address": None,
                "Notes": None,
                "Action taken": None,
            }
            if member["id"] == "USLACKBOT":  # slackbot does not have is_bot set for whatever reason
                this_user["Workspace account type"] = "slackbot"
                user_details.append(this_user)
                continue
            if member["is_bot"] is True:
                this_user["Workspace account type"] = "bot"
                user_details.append(this_user)
                continue
            if "is_ultra_restricted" in member and member["is_ultra_restricted"] is True:
                this_user["Workspace account type"] = "ultra_restricted"
            if "is_restricted" in member and member["is_restricted"] is True:
                this_user["Workspace account type"] = "restricted"
            if "is_admin" in member and member["is_admin"] is True:
                this_user["Workspace account type"] = "admin"
            if "is_owner" in member and member["is_owner"] is True:
                this_user["Workspace account type"] = "owner"
            if "is_primary_owner" in member and member["is_primary_owner"] is True:
                this_user["Workspace account type"] = "primary_owner"
            total_accounts += 1
            profile = member["profile"]
            if "email" not in profile:
                print(member)
                raise Exception("Missing email in profile - does this token have access to read emails?")
            if is_georgia_tech_email_address(profile["email"]) or args.apiary_token is not None:
                search_results = find_user(mail=profile["email"])
                if search_results is None:
                    mailbox = Address(addr_spec=profile["email"]).username
                    if is_georgia_tech_email_address(profile["email"]) and fullmatch(r"[a-z][a-z]+[0-9]+", mailbox):
                        search_results = find_user(uid=mailbox)
                        if search_results is None:
                            search_results = find_user(gtSecondaryMailAddress=profile["email"])
                            if search_results is None:
                                no_match += 1
                                logger.warning(NO_MATCH_FOR_EMAIL_IN_DIRECTORY.format(email=profile["email"]))
                                this_user["Notes"] = "Unable to locate GT user"
                                user_details.append(this_user)
                                continue
                    else:
                        parsed_email_address = Address(addr_spec=profile["email"])

                        if parsed_email_address.domain == "robojackets.org":
                            username_parts = parsed_email_address.username.split("+")

                            if len(username_parts) == 2 and username_parts[0] == "support":
                                search_results = find_user(uid=username_parts[1])
                                if search_results is None:
                                    no_match += 1
                                    this_user["Notes"] = "Unable to locate GT user"
                                    user_details.append(this_user)
                                    continue
                            else:
                                no_match += 1
                                this_user["Notes"] = "Unable to locate GT user"
                                user_details.append(this_user)
                                continue
                        else:
                            no_match += 1
                            this_user["Notes"] = "Unable to locate GT user"
                            user_details.append(this_user)
                            continue

                if search_results is None:
                    raise Exception("Missing a case somewhere! Email: " + profile["email"])

                this_user["Georgia Tech username"] = search_results["username"]
                this_user["Georgia Tech full name"] = search_results["name"]
                this_user["Match reason"] = search_results["match_reason"]

                if search_results["username"] in gt_user_to_slack_user:
                    this_user["Notes"] = (
                        "Duplicate Slack account detected - other account is "
                        + gt_user_to_slack_user[search_results["username"]]
                    )
                    user_details.append(this_user)
                    duplicates += 1
                    continue

                gt_user_to_slack_user[search_results["username"]] = profile["email"]

                if profile["email"] != search_results["email"]:
                    update_email += 1
                    this_user["Recommended email address"] = search_results["email"]

                user_details.append(this_user)

    with open(
        slack.team_info()["team"]["name"]
        + " - User Accounts - "
        + datetime.datetime.now().strftime("%B %d, %Y")
        + ".csv",
        "w",
        encoding="utf-8",
        newline="",
    ) as csvfile:
        writer = DictWriter(
            csvfile,
            fieldnames=[
                "Workspace user id",
                "Workspace full name",
                "Workspace display name",
                "Workspace username",
                "Workspace email address",
                "Workspace account type",
                "Workspace account status",
                "Georgia Tech username",
                "Georgia Tech full name",
                "Match reason",
                "Recommended email address",
                "Notes",
                "Action taken",
            ],
        )

        writer.writeheader()
        for user in user_details:
            writer.writerow(user)

    logger.info(f"Total emails updated: {update_email}")
    logger.info(f"Total unmatched accounts: {no_match}")
    logger.info(f"Total duplicate accounts: {duplicates}")
    logger.info(f"Total accounts: {total_accounts}")


if __name__ == "__main__":
    main()
