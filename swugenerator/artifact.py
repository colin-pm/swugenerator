# Copyright (C) 2022 Stefano Babic
#
# SPDX-License-Identifier: GPLv3
import hashlib
import logging
import subprocess
from pathlib import Path
from typing import List, Optional


class Artifact:
    def __init__(self, filename: str, artifact_paths: List[Path]) -> None:
        self.filename = filename
        self.source_path = self._get_artifact_source_path(artifact_paths)
        self.archived_filename = filename
        self.size = 0

    def _get_artifact_source_path(self, artifact_paths: List[Path]) -> Optional[Path]:
        for artifact_dir in artifact_paths:
            tmp_path = artifact_dir / self.filename
            if tmp_path.exists():
                return tmp_path
        return None

    def exists(self):
        return self.source_path and self.source_path.exists()

    def get_sha256(self):
        if not self.exists():
            return None
        sha = hashlib.sha256()
        with self.source_path.open("rb") as artifact:
            while True:
                data = artifact.read(1024)
                if not data:
                    break
                sha.update(data)
        return sha.hexdigest()

    def get_size(self) -> int:
        return self.source_path.stat().st_size if self.exists() else 0

    def encrypt(self, out, key, init_vec):
        if not self.source_path:
            return False
        source = str(self.source_path.resolve())
        enc_cmd = [
            "openssl",
            "enc",
            "-aes-256-cbc",
            "-in",
            source,
            "-out",
            out,
            "-K",
            key,
            "-iv",
            init_vec,
            "-nosalt",
        ]
        try:
            subprocess.run(enc_cmd, check=True)
        except subprocess.CalledProcessError:
            logging.critical("Unable to encrypt %s", source)
            return False
        return True
