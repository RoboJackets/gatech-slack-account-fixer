"""
Corrects Slack account information, for use with Enterprise Grid migrations
"""

import logging
import sys
from argparse import ArgumentParser, FileType
from csv import DictReader
from email.headerregistry import Address
from json import dumps
from re import fullmatch, search
from typing import Dict, Optional, TextIO

import cachier

from ldap3 import Connection, Entry, Server  # type: ignore

from requests import post

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

CHANGING_EMAIL = "Changing email from {old} to {new}"
CHANGING_NAME = 'Changing name for {email} from "{old}" to "{new}"'
NO_MATCH_FOR_EMAIL_FROM_PRE_MIGRATION_REPORT = "Could not confirm match for {email} found in pre-migration report"
NO_MATCH_FOR_EMAIL_IN_DIRECTORY = "Could not find match for {email} in directory or pre-migration report"
NO_MATCH_FOR_NAME = 'No matches for {email} - name fields are "{real_name}" and "{display_name}"'
NOT_ENOUGH_INFO_TO_MATCH = (
    'Not enough information to match {email} - name fields are "{real_name}" and "{display_name}"'
)
DIRECTORY_NO_EMAIL = "{directory}: No entries had email for {search_filter}"
DIRECTORY_MORE_THAN_ONE_EMAIL = "{directory}: More than one email listed for {search_filter}"
DIRECTORY_ONE_RECORD_NO_EMAIL = "{directory}: Only one record returned but no email for {search_filter}"


cachier.set_global_params(
    cache_dir="_cache/",  # type: ignore
    pickle_reload=False,  # type: ignore
    allow_none=True,      # type: ignore
)


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
    }


def name_looks_valid(name: str) -> bool:
    """
    Guesses if a name field is valid. Valid is defined as being at least two words, each beginning with a capital
    letter and ending with a lowercase letter.

    :param name: the name to check
    :return: whether this name is considered valid
    """
    existing_parts = name.split()
    parts_that_look_like_names = list(
        filter(lambda part: fullmatch(r"[A-Z](?:[A-Za-z-']+)?[a-z]", part), existing_parts)
    )
    if len(existing_parts) < 2 or len(parts_that_look_like_names) < 2:
        return False
    if len(parts_that_look_like_names) > 2 or len(existing_parts) == len(parts_that_look_like_names):
        return True
    return False


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
    parser.add_argument(
        "--pre-migration-report",
        help="the pre-migration report provided by Alana, in CSV format",
        type=FileType("r"),
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
    parser.add_argument("--fuzzy-match", help="attempt to match users with names", action="store_true")
    parser.add_argument("--fix-names", help="update names to match the directory", action="store_true")
    parser.add_argument("--dry-run", help="do not make any changes", action="store_true")
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

    email_map = parse_email_map(args.pre_migration_report)

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

    def apply_changes(member_arg: Dict[str, str], new_profile_arg: Dict[str, str]) -> None:
        try:
            slack.users_profile_set(user=member_arg["id"], profile=new_profile_arg)
        except SlackApiError as error:
            if error.response["error"] == "cannot_update_admin_user":
                logger.warning(
                    "Could not update user "
                    + member_arg["profile"]["email"]  # type: ignore
                    + " because they are an admin+ and you are not the primary owner"
                )
                logger.warning("Wanted to apply profile values " + dumps(new_profile_arg))
            elif error.response["error"] == "email_taken":
                logger.warning(
                    "Could not update user "
                    + member_arg["profile"]["email"]  # type: ignore
                    + " because the new email is already taken"
                )
                logger.warning("Wanted to apply profile values " + dumps(new_profile_arg))
            else:
                raise

    update_email = 0
    update_name = 0
    no_match = 0
    duplicates = 0
    total_accounts = 0

    gt_user_to_slack_user: dict[str, str] = {}

    for page in slack.users_list():
        for member in page.get("members"):
            if member["id"] == "USLACKBOT":  # slackbot does not have is_bot set for whatever reason
                continue
            if member["is_bot"] is True:
                continue
            if member["deleted"] is True:
                continue
            if member["is_restricted"] is True or member["is_ultra_restricted"] is True:
                logger.info(f"Skipping guest user {member['profile']['email']}")
                continue
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
                            if profile["email"] in email_map:
                                search_results = find_user(mail=email_map[profile["email"]])
                                if search_results is None:
                                    no_match += 1
                                    logger.warning(
                                        NO_MATCH_FOR_EMAIL_FROM_PRE_MIGRATION_REPORT.format(
                                            email=email_map[profile["email"]]
                                        )
                                    )
                                    continue
                            else:  # email not in pre-migration report
                                no_match += 1
                                logger.warning(NO_MATCH_FOR_EMAIL_IN_DIRECTORY.format(email=profile["email"]))
                                continue
                    else:  # mailbox does not look like a GT username
                        if profile["email"] in email_map:
                            search_results = find_user(mail=email_map[profile["email"]])
                            if search_results is None:
                                no_match += 1
                                logger.warning(
                                    NO_MATCH_FOR_EMAIL_FROM_PRE_MIGRATION_REPORT.format(
                                        email=email_map[profile["email"]]
                                    )
                                )
                                continue
                        else:  # email not in pre-migration report
                            no_match += 1
                            logger.warning(NO_MATCH_FOR_EMAIL_IN_DIRECTORY.format(email=profile["email"]))
                            continue

                if search_results is None:
                    raise Exception("Missing a case somewhere! Email: " + profile["email"])

                if search_results["username"] in gt_user_to_slack_user:
                    logger.warning(
                        "Multiple Slack accounts for GT user "
                        + search_results["username"]
                        + " - found "
                        + profile["email"]
                        + " and "
                        + gt_user_to_slack_user[search_results["username"]]
                    )
                    duplicates += 1
                    continue

                gt_user_to_slack_user[search_results["username"]] = profile["email"]

                new_profile = {}

                if profile["email"] != search_results["email"]:
                    update_email += 1
                    logger.info(CHANGING_EMAIL.format(old=profile["email"], new=search_results["email"]))
                    new_profile["email"] = search_results["email"]

                if (
                    args.fix_names
                    and search_results["name"] != profile["real_name"]
                    and not name_looks_valid(profile["real_name"])
                ):
                    update_name += 1
                    logger.info(
                        CHANGING_NAME.format(
                            email=profile["email"], old=profile["real_name"], new=search_results["name"]
                        )
                    )
                    new_profile["real_name"] = search_results["name"]

                if args.fix_names and profile["display_name"] != "":
                    new_profile["display_name"] = ""

                if len(new_profile) > 0 and not args.dry_run:
                    apply_changes(member, new_profile)

            elif args.fuzzy_match and (  # email is non-gatech.edu
                len(profile["real_name"].split()) == 2 or len(profile["display_name"].split()) == 2
            ):
                real_name_parts = profile["real_name"].split()
                display_name_parts = profile["display_name"].split()

                search_results = None

                if len(real_name_parts) == 2:
                    search_results = find_user(givenName=real_name_parts[0] + "*", sn=real_name_parts[1])
                    if search_results is None:
                        if len(display_name_parts) == 2:
                            search_results = find_user(givenName=display_name_parts[0] + "*", sn=display_name_parts[1])
                            if search_results is None:
                                no_match += 1
                                logger.warning(NO_MATCH_FOR_NAME.format(**profile))
                                continue
                        else:  # display_name field is not two words
                            no_match += 1
                            logger.warning(NOT_ENOUGH_INFO_TO_MATCH.format(**profile))
                            continue

                if len(display_name_parts) == 2:
                    search_results = find_user(givenName=display_name_parts[0] + "*", sn=display_name_parts[1])
                    if search_results is None:
                        no_match += 1
                        logger.warning(NO_MATCH_FOR_NAME.format(**profile))
                        continue

                if search_results is None:
                    raise Exception("Missing a case somewhere! Email: " + profile["email"])

                new_profile = {}

                if profile["email"] != search_results["email"]:
                    update_email += 1
                    logger.info(CHANGING_EMAIL.format(old=profile["email"], new=search_results["email"]))
                    new_profile["email"] = search_results["email"]

                if (
                    args.fix_names
                    and search_results["name"] != profile["real_name"]
                    and not name_looks_valid(profile["real_name"])
                ):
                    update_name += 1
                    logger.info(
                        CHANGING_NAME.format(
                            email=profile["email"], old=profile["real_name"], new=search_results["name"]
                        )
                    )
                    new_profile["real_name"] = search_results["name"]

                if args.fix_names and profile["display_name"] != "":
                    new_profile["display_name"] = ""

                if len(new_profile) > 0 and not args.dry_run:
                    apply_changes(member, new_profile)
            else:  # neither name field is two words
                no_match += 1
                logger.warning(NOT_ENOUGH_INFO_TO_MATCH.format(**profile))
                continue

    logger.info(f"Total emails updated: {update_email}")
    if args.fix_names:
        logger.info(f"Total names updated: {update_name}")
    logger.info(f"Total unmatched accounts: {no_match}")
    logger.info(f"Total duplicate accounts: {duplicates}")
    logger.info(f"Total accounts: {total_accounts}")


if __name__ == "__main__":
    main()
