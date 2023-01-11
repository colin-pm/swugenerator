# pylint: disable=C0114,C0116,W0621
from pathlib import Path

import pytest

from swugenerator.artifact import Artifact

VALID_TEST_FILE = "valid_artifact"
VALID_TEST_FILE_BYTES = 300
INVALID_TEST_FILE = "invalid_artifact"

KEY = "390ad54490a4a5f53722291023c19e08ffb5c4677a59e958c96ffa6e641df040"
INIT_VEC = "d5d601bacfe13100b149177318ebc7a4"
ENC_TEST_FILE = f"{VALID_TEST_FILE}.enc"


@pytest.fixture(scope="session")
def archive_dir(tmp_path_factory):
    """Creates a directory to test"""
    archive_file = tmp_path_factory.mktemp("archive") / VALID_TEST_FILE

    with archive_file.open("wb") as achive_file_fd:
        achive_file_fd.write(b"\x21" * VALID_TEST_FILE_BYTES)

    return archive_file.parent


def test_valid_artifacts_souce_path_is_valid(archive_dir):
    artifact = Artifact(VALID_TEST_FILE, [Path(archive_dir)])
    assert artifact.source_path == archive_dir / VALID_TEST_FILE


def test_valid_artifact_exists(archive_dir):
    artifact = Artifact(VALID_TEST_FILE, [Path(archive_dir)])
    assert artifact.exists()


def test_invalid_artifact_has_null_source_path(archive_dir):
    artifact = Artifact(INVALID_TEST_FILE, [Path(archive_dir)])
    assert artifact.source_path is None


def test_valid_artifact_has_valid_sha256(archive_dir):
    artifact = Artifact(VALID_TEST_FILE, [Path(archive_dir)])
    assert (
        artifact.get_sha256()
        == "455ffd45b525b321ef1e9ef6db8365bddce07fdfafefd0a0f37516f16d740c24"
    )


def test_invalid_artifact_has_invalid_sha256(archive_dir):
    artifact = Artifact(INVALID_TEST_FILE, [Path(archive_dir)])
    assert artifact.get_sha256() is None


def test_valid_artifact_get_size(archive_dir):
    artifact = Artifact(VALID_TEST_FILE, [Path(archive_dir)])
    assert artifact.get_size() == VALID_TEST_FILE_BYTES


def test_invalid_artifact_get_size(archive_dir):
    artifact = Artifact(INVALID_TEST_FILE, [Path(archive_dir)])
    assert artifact.get_size() == 0


def test_valid_artifact_can_encrypt(archive_dir):
    artifact = Artifact(VALID_TEST_FILE, [Path(archive_dir)])
    assert artifact.encrypt(archive_dir / ENC_TEST_FILE, KEY, INIT_VEC)


def test_encrypting_invalid_artifact_(archive_dir):
    artifact = Artifact(INVALID_TEST_FILE, [Path(archive_dir)])
    assert artifact.encrypt(archive_dir / ENC_TEST_FILE, KEY, INIT_VEC) is False


def test_invalid_params_returns_false(archive_dir):
    artifact = Artifact(VALID_TEST_FILE, [Path(archive_dir)])
    assert artifact.encrypt(archive_dir / ENC_TEST_FILE, "X", "X") is False
