# Copyright (C) 2022 Stefano Babic
#
# SPDX-License-Identifier: GPLv3
import codecs
import logging
import os
import re
import shutil
import secrets
import subprocess
import sys
from tempfile import TemporaryDirectory

import libconf

from swugenerator.swu_file import SWUFile
from swugenerator.artifact import Artifact


class SWUGenerator:
    def __init__(
        self,
        template,
        out,
        confvars,
        dirs,
        crypt,
        aeskey,
        firstiv,
        encrypt_swdesc=False,
        no_compress=False,
        no_encrypt=False,
        no_ivt=False,
    ):
        self.swdescription = template
        self.artifacts = []
        self.out = open(out, "wb")
        self.artifactory = dirs
        self.cpiofile = SWUFile(self.out)
        self.vars = confvars
        self.lines = []
        self.conf = libconf.AttrDict()
        self.filelist = []
        self.temp = TemporaryDirectory()
        self.signtool = crypt
        self.aeskey = aeskey
        self.aesiv = firstiv
        self.encryptswdesc = encrypt_swdesc
        self.nocompress = no_compress
        self.noencrypt = no_encrypt
        self.noivt = no_ivt

    @staticmethod
    def generate_iv():
        return secrets.token_hex(16)

    def _read_swdesc(self):
        with codecs.open(self.swdescription, "r") as f:
            self.lines = f.readlines()
            f.close()

    def close(self):
        self.temp.cleanup()
        self.cpiofile.close()
        self.out.close()

    def process_entry(self, entry):
        if "filename" not in entry:
            return
        new = None
        for image in self.artifacts:
            if image.filename == entry["filename"]:
                new = image
                break
        if not new:
            logging.debug("New artifact  %s", entry["filename"])
            new = Artifact(entry["filename"], self.artifactory)
            if not new.exists():
                logging.critical("Artifact %s not found", entry["filename"])
                sys.exit(22)

            new.archived_filename = entry["filename"]

            if "compressed" in entry and not self.nocompress:
                cmp = entry["compressed"]
                if cmp:
                    cmp = "zlib"
                if cmp not in ("zlib", "zstd"):
                    logging.critical("Wrong compression algorithm: %s", cmp)
                    sys.exit(1)

                new_path = (
                    os.path.join(self.temp.name, new.archived_filename) + "." + cmp
                )
                new.archived_filename = new.archived_filename + "." + cmp
                if cmp == "zlib":
                    cmd = [
                        "gzip",
                        "-f",
                        "-9",
                        "-n",
                        "-c",
                        "--rsyncable",
                        new.fullfilename,
                        ">",
                        new_path,
                    ]
                else:
                    cmd = [
                        "zstd",
                        "-z",
                        "-k",
                        "-T0",
                        "-c",
                        new.fullfilename,
                        ">",
                        new_path,
                    ]

                try:
                    subprocess.run(" ".join(cmd), shell=True, check=True, text=True)
                except subprocess.CalledProcessError:
                    logging.critical(
                        "Cannot compress %s with %s", entry["filename"], cmd
                    )
                    sys.exit(1)

                new.fullfilename = new_path

            # Encrypt if required
            if "encrypted" in entry and not self.noencrypt:
                if not self.aeskey:
                    logging.critical(
                        "%s must be encrypted, but no encryption key is given",
                        entry["filename"],
                    )
                if self.noivt:
                    iv = self.aesiv
                else:
                    iv = self.generate_iv()

                new.archived_filename = new.archived_filename + "." + "enc"
                new_path = os.path.join(self.temp.name, new.archived_filename)
                if not new.encrypt(new_path, self.aeskey, iv):
                    sys.exit(1)
                new.fullfilename = new_path
                # recompute sha256, now for the encrypted file
                entry["ivt"] = iv
                new.ivt = iv

            self.artifacts.append(new)
        else:
            logging.debug("Artifact  %s already stored", entry["filename"])

        entry["filename"] = new.archived_filename
        entry["sha256"] = new.get_sha256()
        if "encrypted" in entry:
            entry["ivt"] = new.ivt

    def find_files_in_swdesc(self, first):
        for n, val in first.items():
            if isinstance(val, libconf.AttrDict):
                self.find_files_in_swdesc(val)
            elif isinstance(val, tuple):
                for t in val:
                    self.find_files_in_swdesc(t)
            else:
                logging.debug("%s = %s", n, val)
                if n == "filename":
                    self.filelist.append(first)

    def save_swdescription(self, filename, contents):
        with codecs.open(filename, "w", "utf-8") as swd:
            swd.write(contents)

    def process(self):
        self._read_swdesc()
        self._expand_variables()
        self._exec_functions()

        swdesc = ""
        for line in self.lines:
            swdesc = swdesc + line
        self.conf = libconf.loads(swdesc)
        self.find_files_in_swdesc(self.conf.software)

        sw = Artifact("sw-description", self.artifactory)
        sw.archived_filename = os.path.join(self.temp.name, sw.filename)
        self.artifacts.append(sw)
        if self.signtool:
            sig = Artifact("sw-description.sig", self.artifactory)
            sig.archived_filename = os.path.join(self.temp.name, "sw-description.sig")
            self.artifacts.append(sig)

        for entry in self.filelist:
            self.process_entry(entry)

        swdesc = libconf.dumps(self.conf)

        # libconf mishandle special character if they are part
        # of an attribute. This happens to the embedded-script
        # and the script results to be in just one line.
        # Reinsert \n and \t that was removed by libconf
        swdesc = re.sub(r"\\n", "\n", swdesc)
        swdesc = re.sub(r"\\t", "\t", swdesc)

        swdesc_filename = os.path.join(self.temp.name, sw.filename)
        self.save_swdescription(swdesc_filename, swdesc)

        if self.signtool:
            sw_desc_in = swdesc_filename
            sw_desc_out = os.path.join(self.temp.name, "sw-description.sig")
            self.signtool.prepare_cmd(sw_desc_in, sw_desc_out)
            self.signtool.sign()

        # Encrypt sw-description if required
        if self.encryptswdesc:
            if not self.aeskey:
                logging.critical(
                    "sw-description must be encrypted, but no encryption key is given"
                )

            iv = self.aesiv
            sw.fullfilename = swdesc_filename
            swdesc_enc = swdesc_filename + ".enc"
            sw.encrypt(swdesc_enc, self.aeskey, iv)
            shutil.copyfile(swdesc_enc, sw.fullfilename)

        for artifact in self.artifacts:
            self.cpiofile.addartifacttoswu(artifact.fullfilename)

    def _expand_variables(self):
        write_lines = []
        for line in self.lines:
            while True:
                m = re.match(
                    r"^(?P<before_placeholder>.+)@@(?P<variable_name>\w+)@@(?P<after_placeholder>.+)$",
                    line,
                )
                if m:
                    variable_value = self.vars[m.group("variable_name")]
                    line = (
                        m.group("before_placeholder")
                        + variable_value
                        + m.group("after_placeholder")
                    )
                    continue
                else:
                    break
            write_lines.append(line)
        self.lines = write_lines

    def _exec_functions(self):
        for index, line in enumerate(self.lines):
            m = re.match(
                r"^(?P<before_placeholder>.+)\$(?P<function_name>\w+)\((?P<parms>.+)\)(?P<after_placeholder>.+)$",
                line,
            )
            if m:
                fun = (
                    "self." + m.group("function_name") + '("' + m.group("parms") + '")'
                )
                ret = eval(fun)
                line = (
                    m.group("before_placeholder")
                    + ret
                    + m.group("after_placeholder")
                    + "\n"
                )
                self.lines[index] = line

    def setenckey(self, k, iv):
        self.aeskey = k
        self.aesiv = iv

    def swupdate_get_sha256(self, filename: str) -> str:
        a = Artifact(filename, self.artifactory)
        return a.get_sha256()

    def swupdate_get_size(self, filename: str) -> str:
        a = Artifact(filename, self.artifactory)
        return str(a.get_size())
