from __future__ import annotations

import os
import re
import json
import shutil
import struct
import hashlib
import pathlib
import pkgutil
import zipfile
import tempfile
from typing import Any
from urllib.request import urlopen
from collections import OrderedDict

import git
from git import Repo
import typing_extensions
import requests  # type: ignore[import-untyped]

from .. import logger
from ..utils import run_proc
from ..disassembler import Disassembler


def gzf_project_name(gzf_path: pathlib.Path) -> str | None:
    if not gzf_path.exists():
        return None

    if not gzf_path.is_file():
        return None

    # Slightly Scuff. Subject to change if serialization format changes
    with open(gzf_path, "rb") as f:
        f.seek(0x12)
        proj_name_len = struct.unpack(">H", f.read(2))[0]
        return str(f.read(proj_name_len), "utf8")


class GhidraBase(Disassembler):
    GIT_REPO = "https://github.com/NationalSecurityAgency/ghidra.git"
    GITHUB_API = "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases"

    @staticmethod
    def DEFAULT_INSTALL():
        """Default Install Location for Ghidra (Within Python Package Installation)"""
        return os.path.join(
            os.path.dirname(pkgutil.get_loader("binocular").path), "data", "ghidra"
        )

    @staticmethod
    def DEFAULT_PROJECT_PATH():
        """Default Ghidra Project Path (Within Python Package Installation)"""
        return os.path.join(
            os.path.dirname(pkgutil.get_loader("binocular").path), "data", "ghidra_proj"
        )

    @staticmethod
    def SCRIPT_PATH():
        return os.path.join(
            os.path.join(os.path.dirname(pkgutil.get_loader("binocular").path)),
            "scripts",
        )

    @classmethod
    def list_versions(cls):
        r = requests.get(cls.GITHUB_API)
        if r.status_code != 200:
            raise Exception(f"Cannot reach {cls.GITHUB_API}")

        release_data = json.loads(r.text)
        versions = list()
        for release in release_data:
            ver = release["name"].rsplit(" ", 1)[1]
            versions.append(ver.strip())

        return versions

    @classmethod
    def _install_prebuilt(
        cls,
        version: str | None,
        install_dir: str,
        local_install_file: str | None = None,
    ) -> str | None:
        if local_install_file is None:
            # Ask Github API for Ghidra Release versions and the
            # prebuilt download link
            try:
                r = requests.get(GhidraBase.GITHUB_API)
            except requests.exceptions.ConnectionError as e:
                logger.error(f"Failed to reach Github: {e}")
                return None

            if not r.ok:
                logger.error(f"Cannot reach {GhidraBase.GITHUB_API}")
                return None

            release_data = json.loads(r.text)
            links = OrderedDict()
            for release in release_data:
                ver = release["name"].rsplit(" ", 1)[1].strip()
                dl_link = release["assets"][0]["browser_download_url"]
                links[ver] = dl_link

            if version is None:
                # Version not specified. getting latest
                version = next(iter(links.keys()))
            elif version not in links:
                logger.error(f"Ghidra version {version} not found")
                return None

            dl_link = links[version]
            logger.info(f"Installing Ghidra {version} to {install_dir}")
            logger.info(f"Downloading {dl_link}...")

            try:
                with tempfile.TemporaryFile() as fp:
                    fp.write(urlopen(dl_link).read())
                    fp.seek(0)
                    logger.info("Extracting Ghidra")
                    with zipfile.ZipFile(fp, "r") as zf:
                        zf.extractall(install_dir)
            except IOError as e:
                logger.error(f"Failed to download or extract Ghidra: {e}")
                return None
        else:
            if not os.path.exists(local_install_file):
                logger.error(f"File Does not Exist: {local_install_file}")
                return None

            # Assume this is a zip of a Ghidra Release
            try:
                with open(local_install_file, "rb") as fp:
                    with zipfile.ZipFile(fp, "r") as zf:
                        zf.extractall(install_dir)
            except IOError as e:
                logger.error(
                    f"{e}: Failed to extract local Ghidra distribution: {local_install_file}"
                )
                return None

        home = os.path.join(install_dir, os.listdir(install_dir)[0])
        if not os.path.exists(home):
            logger.error("Failed to find expected Ghidra installation")
            return None

        return home

    @classmethod
    def _build(cls, version: str, install_dir: str) -> str | None:
        logger.info(f"Building Ghidra @ commit {version}")

        # dependency check
        if shutil.which("java") is None:
            logger.critical(
                "Can't find java. Is JDK 21 installed? Download here: https://adoptium.net/temurin/releases/"
            )
            return None

        if shutil.which("gradle") is None:
            logger.critical(
                "Can't find gradle. Gradle 8.5+ required. Download here: https://gradle.org/releases/"
            )
            return None

        logger.info(f"Cloning Ghidra {version} to: {install_dir}")
        try:
            repo = Repo.clone_from(GhidraBase.GIT_REPO, install_dir)
        except git.GitCommandError:
            logger.info("Ghidra Already Cloned")
            repo = Repo(install_dir)

        repo.git.checkout(version)

        cmds = [
            ["gradle", "-I", "gradle/support/fetchDependencies.gradle", "init"],
            ["gradle", "buildGhidra"],
        ]

        no_init_gradle_commit = repo.commit("30628db2d09d7b4ce46368b7522dc315e7b245c5")
        target_commit = repo.commit(version)

        common_ancestor = repo.merge_base(no_init_gradle_commit, target_commit)
        if target_commit in common_ancestor:
            # do nothing
            pass
        elif no_init_gradle_commit in common_ancestor:
            # remove init in gradle command
            del cmds[0][-1]
        else:
            logger.error(f"Is {version} a valid commit hash?")
            return None

        for cmd in cmds:
            logger.info(f"$ {' '.join(cmd)}")
            out, err = run_proc(cmd=cmd, timeout=None, cwd=install_dir)
            if len(out) > 0:
                logger.info(f"[STDOUT] {out}")
            if len(err) > 0:
                logger.info(f"[STDERR] {err}")

        dist = os.path.join(install_dir, "build", "dist")
        if not os.path.exists(dist):
            logger.error(f"Expected directory to exist. Did Ghidra build fail? {dist}")
            return None

        try:
            zip_file = os.path.join(dist, os.listdir(dist)[0])
            with open(zip_file, "rb") as f:
                with zipfile.ZipFile(f, "r") as zf:
                    zf.extractall(dist)
        except IOError as e:
            logger.error(f"{e}: Failed to extract Ghidra distribution: {zip_file}")
            return None

        home = os.path.join(dist, "_".join(os.path.basename(zip_file).split("_")[:3]))
        if not os.path.exists(home):
            logger.error("Failed to find expected Ghidra installation")
            return None

        return home

    @classmethod
    def install(
        cls,
        version: str | None = None,
        install_dir: str | None = None,
        build: bool | None = False,
        local_install_file: str | None = None,
    ) -> str | None:
        """
        Installs the disassembler to a user specified directory or within the python module if none is specified
        :param version: Release Version Number or Commit Hash
        :param install_dir: the directory to install Ghidra to
        :param build: True if version is a Commit Hash.
        """
        if install_dir is None:
            install_dir = GhidraBase.DEFAULT_INSTALL()

        os.makedirs(install_dir, exist_ok=True)

        if build:
            if version is None:
                logger.error("`version` must be a commmit hash if `build=true`")
                return None

            ghidra_home = GhidraBase._build(version, install_dir)
        else:
            ghidra_home = GhidraBase._install_prebuilt(
                version, install_dir, local_install_file=local_install_file
            )
        if ghidra_home is None:
            logger.error(f"Failed to install Ghidra {version}")
            return None

        logger.info("Ghidra Install Completed")

        # Permission to execute stuff in Ghidra Home
        try:
            os.chmod(os.path.join(ghidra_home, "support", "launch.sh"), 0o775)
            for root, _, files in os.walk(ghidra_home):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    os.chmod(fpath, 0o775)
        except IOError as e:
            logger.warning(
                f"{e}: Failed to set 775 permissions to files in {ghidra_home}"
            )

        return ghidra_home

    @classmethod
    def is_installed(cls, install_dir: str | None = None) -> bool:
        """Returns Boolean on whether or not the dissassembler is installed"""
        os.makedirs(GhidraBase.DEFAULT_INSTALL(), exist_ok=True)

        if install_dir is None:
            install_dir = GhidraBase.DEFAULT_INSTALL()

        if len(os.listdir(install_dir)) == 0:
            return False

        release_install = os.path.join(install_dir, os.listdir(install_dir)[0])
        release_install = os.path.join(release_install, "support", "launch.sh")

        build_install = os.path.join(install_dir, "build", "dist")

        return os.path.exists(release_install) or os.path.exists(build_install)

    def __init__(
        self,
        filepath: pathlib.Path | str,
        verbose: bool = True,
        project_path: str | None = None,
        home: str | None = None,
    ):
        super().__init__(filepath=filepath, verbose=verbose)

        if project_path is None:
            project_path = self.DEFAULT_PROJECT_PATH()
        self.base_project_path = project_path

        self.ghidra_home: str
        if home is None:
            ghidra_release_pattern = re.compile(r"ghidra_(\d+(\.\d+)*)_PUBLIC")
            ghidra_dir = None
            for dir in os.listdir(self.DEFAULT_INSTALL()):
                if ghidra_release_pattern.match(dir):
                    ghidra_dir = dir
                    break

            if ghidra_dir is None:
                raise Exception(
                    f"Unable to find Ghidra install directory inside of {self.DEFAULT_INSTALL()}"
                )

            self.ghidra_home = os.path.join(self.DEFAULT_INSTALL(), ghidra_dir)
        else:
            self.ghidra_home = home

        self._project_name: str | None = None
        self._bin_name: str | None = None
        self.project_location: str = self.base_project_path
        self.bin_size: int = 0

    def _analyze_headless_path(self) -> str:
        return os.path.join(self.ghidra_home, "support", "analyzeHeadless")

    @property
    def project_name(self) -> str:
        if self._project_name is not None:
            return self._project_name
        raise self.NotOpenedError

    @property
    def bin_name(self) -> str:
        if self._bin_name is not None:
            return self._bin_name
        raise self.NotOpenedError

    def open(self) -> typing_extensions.Self:
        super().open()

        self.bin_size = 0
        m = hashlib.md5()
        with open(self.binary_filepath, "rb") as f:
            chunk = f.read(4096)
            while chunk:
                m.update(chunk)
                self.bin_size += len(chunk)
                chunk = f.read(4096)

        md5hash = m.hexdigest()

        # Containing folder of the project is the same name of the project
        # A little cleaner to handle when you can just rm the <md5sum>/ to
        # delete a whole project if need be
        self.project_location = os.path.join(self.base_project_path, md5hash)
        self._project_name = md5hash

        self._bin_name = self.binary_filepath.name

        if self.binary_filepath.suffix == ".gzf":
            self._bin_name = gzf_project_name(self.binary_filepath)

        if self._bin_name is None:
            raise OSError(
                f"Failed to resolve input binary from path: {self.binary_filepath}"
            )

        return self

    def analyze(self) -> None:
        super().analyze()

    def get_func_addr(self, func_ctxt: int) -> int:
        """Returns the address of the function corresponding to the function information returned from `get_func_iterator()`"""
        # Here, func_ctxt is the address
        return func_ctxt

    def get_bb_addr(self, bb_ctxt: Any, func_ctxt: Any) -> int:
        """
        Returns the address of the basic block corresponding to the basic block information returned from `get_func_bb_iterator()`.
        """
        return bb_ctxt
