#!/usr/bin/python3


# pylint: disable=line-too-long


"""
Convert MyIP.MS and SpamHaus RBL blacklists to shorewall and shorewall6 blrules files
"""


import logging
import os
import sys
import shutil
import argparse
import zipfile
import io
import datetime
import concurrent.futures
import ipaddress

try:
    import requests
except ImportError:
    print("Please apt install python3-requests")
    sys.exit(1)
try:
    import setproctitle
except ImportError:
    print("Please apt install python3-setproctitle")
    sys.exit(1)


APP_NAME = __file__.split(".")[0]
APP_DESC = __doc__.strip()
APP_VER = "1.0"
PROJECT_ROOT = os.path.abspath(os.path.join(__file__, os.pardir))


def set_process_name():
    """ Set process name """
    setproctitle.setproctitle("%s-%s" % (APP_NAME, APP_VER))  # pylint: disable=no-member,bad-option-value,c-extension-no-member


def set_process_low_prio():
    """ Set process to lower nice level """
    os.nice(39)


def configure_root_logger(level=logging.INFO):
    """ Override root logger to use a better formatter """
    formatter = "%(asctime)s %(levelname)-8s [%(name)s] %(message)s"
    logging.basicConfig(level=level, format=formatter)


def check_filename_writable(path):
    """
    Check if given filename is writable
    https://www.novixys.com/blog/python-check-file-can-read-write/
    """

    if os.path.exists(path):
        if os.path.isfile(path):
            return os.access(path, os.W_OK)
        # directory
        return False

    # target does not exist, check perms on parent dir
    pdir = os.path.dirname(path)
    if not pdir:
        pdir = PROJECT_ROOT
    # target is creatable if parent dir is writable
    return os.access(pdir, os.W_OK)


def get_arguments_from_cmd_line():
    """ Handle command line arguments """
    # Raise terminal size, See https://bugs.python.org/issue13041
    os.environ["COLUMNS"] = str(shutil.get_terminal_size().columns)

    parser = argparse.ArgumentParser(description=APP_DESC, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-4", "--shorewall4-blrules", type=str, default=os.path.join(PROJECT_ROOT, "blrules_4"), help="Shorewall IPv4 blrules file path", metavar="/etc/shorewall/blrules")
    parser.add_argument("-6", "--shorewall6-blrules", type=str, default=os.path.join(PROJECT_ROOT, "blrules_6"), help="Shorewall IPv6 blrules file path", metavar="/etc/shorewall6/blrules")
    parser.add_argument("-z", "--net-zone", type=str, default="net", help="Shorewall public zone name", metavar="ppp")
    parser.add_argument("-f", "--force", action="store_true", help="Overwrite already existing files")
    parsed = parser.parse_args()

    if not parsed.force and (os.path.isfile(parsed.shorewall4_blrules) or os.path.isfile(parsed.shorewall6_blrules)):
        parser.error("At least one destination file already exist, refusing to overwrite without --force")

    if not check_filename_writable(parsed.shorewall4_blrules) or not check_filename_writable(parsed.shorewall6_blrules):
        parser.error("At least one destination file cannot be written (permission issue)")

    return parsed


def validate_addr(payload, ipaddress_type):
    """ Validate IPv4/6 address/subnet """
    try:
        parsed = ipaddress_type(payload)
        return parsed
    except Exception as exc:  # pylint: disable=broad-except
        LOGGER.error("Got invalid address/network: %s: %s: %s", payload, exc.__class__.__name__, exc)


def type_addr(payload):
    """ Guess IPv4/6 address/subnet and return tuple with parsed payload and type """
    try:
        parsed = ipaddress.ip_address(payload)
    except ValueError:
        try:
            parsed = ipaddress.ip_network(payload)
        except Exception as exc:  # pylint: disable=broad-except
            LOGGER.error("Got invalid address/network: %s: %s: %s", payload, exc.__class__.__name__, exc)
            return None, None
        else:
            return parsed, type(parsed)
    except Exception as exc:  # pylint: disable=broad-except
        LOGGER.error("Got invalid address/network: %s: %s: %s", payload, exc.__class__.__name__, exc)
        return None, None
    else:
        return parsed, type(parsed)


def check_addr_in_sub(addr_comment, ipv4_dict, ipv6_dict):  # pylint: disable=too-many-return-statements
    """ Type each address and check if it's member of existing subnets """

    address, address_type = type_addr(addr_comment[0])
    comment = addr_comment[1]

    if address_type == ipaddress.IPv4Address:
        address4_as_sub = ipaddress.IPv4Network(address)
        for ipv4_subnet, ipv4_sub_comment in ipv4_dict.items():
            if address4_as_sub.overlaps(ipv4_subnet):
                comment = "MyIP.MS FullBlacklist adddress %s skipped, already member of %s %s subnet" % (address, ipv4_sub_comment, ipv4_subnet)
                return False, comment
        return address, "MyIP.MS FullBlacklist: %s" % comment

    if address_type == ipaddress.IPv6Address:
        address6_as_sub = ipaddress.IPv6Network(address)
        for ipv6_subnet, ipv6_sub_comment in ipv6_dict.items():
            if address6_as_sub.overlaps(ipv6_subnet):
                comment = "MyIP.MS FullBlacklist adddress %s skipped, already member of %s %s subnet" % (address, ipv6_sub_comment, ipv6_subnet)
                return False, comment
        return address, "MyIP.MS FullBlacklist: %s" % comment

    if address_type == ipaddress.IPv4Network:
        if address and not address in ipv4_dict:
            return address, "MyIP.MS FullBlacklist: %s" % comment

    if address_type == ipaddress.IPv6Network:
        if address and not address in ipv6_dict:
            return address, "MyIP.MS FullBlacklist: %s" % comment

    return False, "Unsupported address: %s" % address


def process_spamhaus_drop(ipv4_dict):
    """
    Process https://www.spamhaus.org/drop/drop.txt
    """

    # SpamHaus DROP
    spamhaus_drop_resp = requests.get("https://www.spamhaus.org/drop/drop.txt", timeout=5)
    spamhaus_drop_resp.raise_for_status()
    for line in spamhaus_drop_resp.text.splitlines():
        if line.strip().startswith(";") or not line.strip():
            continue
        address, comment = line.split(";")
        address = validate_addr(address.strip(), ipaddress.IPv4Network)
        if address and address not in ipv4_dict:
            ipv4_dict[address] = "SpamHaus DROP: %s" % comment.strip()


def process_spamhaus_edrop(ipv4_dict):
    """
    Process https://www.spamhaus.org/drop/edrop.txt
    """

    # SpamHaus EDROP
    spamhaus_edrop_resp = requests.get("https://www.spamhaus.org/drop/edrop.txt", timeout=5)
    spamhaus_edrop_resp.raise_for_status()
    for line in spamhaus_edrop_resp.text.splitlines():
        if line.strip().startswith(";") or not line.strip():
            continue
        address, comment = line.split(";")
        address = validate_addr(address.strip(), ipaddress.IPv4Network)
        if address and address not in ipv4_dict:
            ipv4_dict[address] = "SpamHaus EDROP: %s" % comment.strip()


def process_spamhaus_dropv6(ipv6_dict):
    """
    Process https://www.spamhaus.org/drop/dropv6.txt
    """

    # SpamHaus DROPv6
    spamhaus_dropv6_resp = requests.get("https://www.spamhaus.org/drop/dropv6.txt", timeout=5)
    spamhaus_dropv6_resp.raise_for_status()
    for line in spamhaus_dropv6_resp.text.splitlines():
        if line.strip().startswith(";") or not line.strip():
            continue
        address, comment = line.split(";")
        address = validate_addr(address.strip(), ipaddress.IPv6Network)
        if address and address not in ipv6_dict:
            ipv6_dict[address] = "SpamHaus DROPv6: %s" % comment.strip()


def process_myip_full_resp(ipv4_dict, ipv6_dict):  # pylint: disable=too-many-locals
    """
    Process https://myip.ms/files/blacklist/general/full_blacklist_database.zip
    """

    # MyIP.MS Full Blacklist ZIP
    myip_full_resp = requests.get("https://myip.ms/files/blacklist/general/full_blacklist_database.zip", timeout=30)
    myip_full_resp.raise_for_status()

    path_like = io.BytesIO(myip_full_resp.content)
    with zipfile.ZipFile(path_like) as archive:
        bl_zip_info = archive.infolist()[0]
        with archive.open(bl_zip_info) as bl_file:
            content = str(bl_file.read(), "utf-8")

    addr_comments = []
    # For debugging
    # for line in content.splitlines()[:1000]:
    for line in content.splitlines():
        if line.strip().startswith("#") or not line.strip():
            continue
        address, comment = line.split("#")
        addr_comments.append((address.strip(), comment.strip()))

    futures = {}
    results = []
    with concurrent.futures.ProcessPoolExecutor() as executor:
        for addr_comment in addr_comments:
            futures[executor.submit(check_addr_in_sub, addr_comment, ipv4_dict, ipv6_dict)] = addr_comment

    for future in concurrent.futures.as_completed(futures):
        results.append(future.result())

    for address, comment in results:
        if not address:
            LOGGER.info(comment)
        else:
            if isinstance(address, (ipaddress.IPv4Address, ipaddress.IPv4Network)):
                ipv4_dict[address] = comment
            elif isinstance(address, (ipaddress.IPv6Address, ipaddress.IPv6Network)):
                ipv6_dict[address] = comment


def process(config):
    """ Main processing method """

    ipv4_dict = {}
    ipv6_dict = {}

    process_spamhaus_drop(ipv4_dict)
    process_spamhaus_edrop(ipv4_dict)
    process_spamhaus_dropv6(ipv6_dict)

    process_myip_full_resp(ipv4_dict, ipv6_dict)

    LOGGER.info("Got %d IPv4 subnet/address sanitized", len(ipv4_dict))
    LOGGER.info("Got %d IPv6 subnet/address sanitized", len(ipv6_dict))

    with open(config.shorewall4_blrules, "w") as shorewall4:
        shorewall4.write("#\n")
        shorewall4.write("#\n")
        shorewall4.write("# THIS FILE HAS BEEN GENERATED BY %s %s AT %s\n" % (APP_NAME, APP_VER, datetime.datetime.now(tz=datetime.timezone.utc)))
        shorewall4.write("#\n")
        shorewall4.write("#\n")
        for address, comment in ipv4_dict.items():
            if len(address.compressed) <= 11:
                line = "DROP:info:blk\t%s:%s\t\tall\t# %s\n" % (config.net_zone, address.compressed, comment)
            else:
                line = "DROP:info:blk\t%s:%s\tall\t# %s\n" % (config.net_zone, address.compressed, comment)
            shorewall4.write(line)
    LOGGER.info("%s generated successfully", config.shorewall4_blrules)

    with open(config.shorewall6_blrules, "w") as shorewall6:
        shorewall6.write("#\n")
        shorewall6.write("#\n")
        shorewall6.write("# THIS FILE HAS BEEN GENERATED BY %s %s AT %s" % (APP_NAME, APP_VER, datetime.datetime.now(tz=datetime.timezone.utc)))
        shorewall6.write("#\n")
        shorewall6.write("#\n")
        for address, comment in ipv6_dict.items():
            line = "DROP:info:blk\t%s:%s\tall\t# %s\n" % (config.net_zone, address.compressed, comment)
            shorewall6.write(line)
    LOGGER.info("%s generated successfully", config.shorewall6_blrules)


if __name__ == "__main__":

    set_process_name()
    set_process_low_prio()
    configure_root_logger()

    CONFIG = get_arguments_from_cmd_line()
    LOGGER = logging.getLogger(__name__)

    process(CONFIG)
