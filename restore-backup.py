#!/usr/bin/env python3

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request
import zipfile
from fnmatch import fnmatch
from pathlib import Path
from string import Template
from tempfile import TemporaryDirectory


RCLONE_CONFIG = """\
[scaleway]
type = s3
provider = Scaleway
env_auth = false
region = fr-par
endpoint = s3.fr-par.scw.cloud
acl = bucket-owner-full-control
access_key_id = $RCLONE_S3_ACCESS_KEY_ID
secret_access_key = $RCLONE_S3_SECRET_ACCESS_KEY

[inclusion-connect]
type = crypt
remote = $RCLONE_CRYPT_REMOTE
filename_encryption = standard
directory_name_encryption = false
password = $RCLONE_CRYPT_PASSWORD
password2 = $RCLONE_CRYPT_PASSWORD2
"""

pg_internal_id_re = r"[0-9]+; [0-9]+ [0-9]+"
spatial_ref_sys_re = re.compile(rf"{pg_internal_id_re} TABLE DATA public spatial_ref_sys postgres$")


def install_rclone():
    filepath = Path("rclone.zip")
    with urllib.request.urlopen("https://downloads.rclone.org/rclone-current-linux-amd64.zip") as response, open(
        filepath, "wb"
    ) as f:
        f.write(response.read())
    with zipfile.ZipFile(filepath) as zipf:
        for path in zipf.namelist():
            if fnmatch(path, "rclone-v*/rclone"):
                extracted = zipf.extract(path)
                extracted = Path(extracted)
                extracted.chmod(0o755)
                _new_path = extracted.rename("./rclone")
                extracted.parent.rmdir()
                filepath.unlink()
                return


def write_list_without_spatial_sys_ref(backup_file, pg_restore_list):
    restore_list = subprocess.run(["pg_restore", "--list", backup_file], capture_output=True, check=True)
    to_restore = []
    for line in restore_list.stdout.decode().splitlines():
        if not spatial_ref_sys_re.match(line):
            to_restore.append(line)
    pg_restore_list.write_text("\n".join(to_restore))


def main(backup_name):
    with urllib.request.urlopen("https://connect.inclusion.beta.gouv.fr") as response:
        if response.headers.get("X-Scalingo") == "1":
            print("Scalingo is currently serving traffic. Don’t touch its database.")
            return

    print("Installing rclone…", file=sys.stderr)
    install_rclone()

    config = Template(RCLONE_CONFIG).safe_substitute(os.environ)
    backup_prefix = os.environ["BACKUP_BUCKET_PREFIX"]
    remote = "inclusion-connect"
    with TemporaryDirectory() as rclone_config_dir, TemporaryDirectory() as workdir:
        config_file = Path(rclone_config_dir) / "rclone.conf"
        config_file.write_text(config)

        rclone = ["./rclone", "--config", str(config_file), "--quiet"]
        if backup_name is None:
            print("Looking up latest backup…", file=sys.stderr)
            list_cmd = subprocess.run(
                [*rclone, "lsjson", f"{remote}:{backup_prefix}"],
                check=True,
                capture_output=True,
            )
            backups = json.loads(list_cmd.stdout)
            backups.sort(key=lambda obj: obj["ModTime"])
            backup_name = backups[-1]["Name"]

        print(f"Downloading backup {backup_name}…", file=sys.stderr)
        backup_file = Path(workdir) / "backup.dump"
        subprocess.run(
            [*rclone, "copyto", f"{remote}:{backup_prefix}/{backup_name}", backup_file],
            check=True,
        )

        print("Filtering out spatial_sys_ref table…", file=sys.stderr)
        # Fails with:
        # pg_restore: while PROCESSING TOC:
        # pg_restore: from TOC entry 7394; 0 19402 TABLE DATA spatial_ref_sys postgres
        # pg_restore: error: could not execute query: ERROR:  permission denied for table spatial_ref_sys
        # Command was: COPY public.spatial_ref_sys (srid, auth_name, auth_srid, srtext, proj4text) FROM stdin;
        pg_restore_list = Path(workdir) / "db_without_spatial_sys_ref.list"
        write_list_without_spatial_sys_ref(backup_file, pg_restore_list)

        print("Restoring backup file…", file=sys.stderr)
        subprocess.run(
            [
                "pg_restore",
                f"--dbname={os.environ['SCALINGO_POSTGRESQL_URL']}",
                f"--use-list={str(pg_restore_list)}",
                "--schema=public",
                "--clean",
                "--if-exists",
                "--no-owner",
                "--jobs=4",
                backup_file,
            ],
            check=True,
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--backup-name")
    args = parser.parse_args()
    main(args.backup_name)
