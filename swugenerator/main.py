# SWUGenerator, SWU Package Generator for SWUpdate
#
# Copyright (C) 2022 Stefano Babic
#
# SPDX-License-Identifier: GPLv3

import argparse
import codecs
import logging
import os
import sys
import textwrap
from pathlib import Path

import libconf

from swugenerator import __about__, generator
from swugenerator.swu_sign import SWUSignCMS, SWUSignCustom, SWUSignPKCS11, SWUSignRSA


def extract_keys(keyfile):
    try:
        with open(keyfile, "r") as f:
            lines = f.readlines()
    except IOError:
        logging.fatal("Failed to open file with keys %s", keyfile)
        sys.exit(1)

    key, iv = None, None
    for line in lines:
        if "key" in line:
            key = line.split("=")[1].rstrip("\n")
        if "iv" in line:
            iv = line.split("=")[1].rstrip("\n")
    return key, iv


def main() -> None:
    """swugenerator main entry point."""

    # ArgumentParser {{{
    parser = argparse.ArgumentParser(
        prog=__about__.__title__,
        description=__about__.__summary__ + " " + __about__.__version__,
        fromfile_prefix_chars="@",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "-K",
        "--encryption-key-file",
        help="<key,iv> : AES Key to encrypt artifacts",
    )

    parser.add_argument(
        "-n",
        "--no-compress",
        action="store_const",
        const=True,
        default=False,
        help="Do not compress files",
    )

    parser.add_argument(
        "-e",
        "--no-encrypt",
        action="store_const",
        const=True,
        default=False,
        help="Do not encrypt files",
    )

    parser.add_argument(
        "-x",
        "--no-ivt",
        action="store_const",
        const=True,
        default=False,
        help="Do not generate IV when encrypting",
    )

    parser.add_argument(
        "-k",
        "--sign",
        help=textwrap.dedent(
            """\
            RSA key or certificate to sign the SWU
            One of :
            CMS,<private key>,<certificate used to sign>,<file with password if any>
            RSA,<private key>,<file with password if any>
            PKCS11,<pin>
            CUSTOM,<custom command> """
        ),
    )

    parser.add_argument(
        "-s",
        "--sw-description",
        required=True,
        help="sw-description template",
    )

    parser.add_argument(
        "-t",
        "--encrypt-swdesc",
        action="store_const",
        const=True,
        default=False,
        help="Encrypt sw-description",
    )

    parser.add_argument(
        "-a",
        "--artifactory",
        help="list of directories where artifacts are searched",
    )

    parser.add_argument(
        "-o",
        "--swu-file",
        required=True,
        help="SWU output file",
    )

    parser.add_argument(
        "-c",
        "--config",
        help="configuration file",
    )

    parser.add_argument(
        "-l",
        "--loglevel",
        help="set log level, default is WARNING",
    )
    parser.add_argument(
        "command", metavar="command", default=[], help="command to be executed (create)"
    )

    args = parser.parse_args()

    if args.loglevel:
        if args.loglevel == "DEBUG":
            logging.basicConfig(level=logging.DEBUG)
        if args.loglevel == "INFO":
            logging.basicConfig(level=logging.INFO)
        if args.loglevel == "ERROR":
            logging.basicConfig(level=logging.ERROR)
        if args.loglevel == "CRITICAL":
            logging.basicConfig(level=logging.CRITICAL)

    # Read configuration file if any
    config_vars = {}
    if args.config and args.config != "":
        logging.info("Reading configuration file %s", args.config)

        with codecs.open(args.config, "r", "utf-8") as f:
            config = libconf.load(f)
            for key, keydict in config.items():
                if key == "variables":
                    for varname, varvalue in keydict.items():
                        logging.debug("VAR = %s VAL = %s", varname, varvalue)
                        config_vars[varname] = varvalue
            f.close()

    # Signing
    sign_option = None
    if args.sign:
        sign_parms = args.sign.split(",")
        cmd = sign_parms[0]
        if cmd == "CMS":
            if len(sign_parms) < 3:
                logging.critical("CMS requires private key and certificate")
                sys.exit(1)
            # Format : CMS,<private key>,<certificate used to sign>,<file with password>
            if len(sign_parms) == 4:
                sign_option = SWUSignCMS(sign_parms[1], sign_parms[2], sign_parms[3])
            # Format : CMS,<private key>,<certificate used to sign>
            else:
                sign_option = SWUSignCMS(sign_parms[1], sign_parms[2], None)
        if cmd == "RSA":
            if len(sign_parms) < 2:
                logging.critical("RSA requires private key")
                sys.exit(1)
            # Format : RSA,<private key>,<file with password>
            if len(sign_parms) == 3:
                sign_option = SWUSignRSA(sign_parms[1], sign_parms[2])
            # Format : RSA,<private key>
            else:
                sign_option = SWUSignRSA(sign_parms[1], None)
        if cmd == "PKCS11":
            # Format : PKCS11,<pin>>
            if len(sign_parms) < 2:
                logging.critical("PKCS11 requires URI")
                sys.exit(1)
            sign_option = SWUSignPKCS11(sign_parms[1])
        if cmd == "CUSTOM":
            # Format : PKCS11,<custom command>>
            if len(sign_parms) < 2:
                logging.critical("PKCS11 requires URI")
                sys.exit(1)
            sign_option = SWUSignCustom(sign_parms[1])

    key = None
    iv = None
    if args.encryption_key_file:
        key, iv = extract_keys(args.encryption_key_file)

    artidirs = []
    artidirs.append(Path(os.getcwd()))
    if args.artifactory:
        dirs = args.artifactory.split(",")
        for directory in dirs:
            deploy = Path(directory).resolve()
            artidirs.append(deploy)

    if args.command == "create":
        swu = generator.SWUGenerator(
            args.sw_description,
            args.swu_file,
            config_vars,
            artidirs,
            sign_option,
            key,
            iv,
            args.encrypt_swdesc,
            args.no_compress,
            args.no_encrypt,
            args.no_ivt,
        )
        swu.process()
        swu.close()
    else:
        parser.error("no suitable command found: (create)")


if __name__ == "__main__":
    main()
