#!/usr/bin/env python3

import dkim
import glob
import logging
import os
import pathlib
import shutil
import smtplib
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time

ADDR_FROM = "test.from@example.org"
ADDR_TO = "test@example.com"
DB_NAME = "key-db.sqlite3"
DEFAULT_PORT = 2525

def fail(message):
    print(message, file=sys.stderr)
    sys.exit(1)

def cp_tmp_file(path, executable=False):
    file = tempfile.NamedTemporaryFile(suffix=f"-{path.name}", delete=False)
    with open(path, mode="rb") as f:
        file.write(f.read())
        file.flush()
    flags = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH
    if executable:
        flags = flags | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
    os.chmod(file.name, flags)
    file.close()
    return file


def get_cmd_filter_dkimout(test_dir, algorithm, canonicalization, target):
    filter_path = test_dir.parent / "target" / target / "filter-dkimout"
    filter_path = cp_tmp_file(filter_path, executable=True).name
    db_path = test_dir / DB_NAME
    db_path = cp_tmp_file(db_path).name
    return (
        filter_path,
        db_path,
        f"{filter_path} --algorithm '{algorithm}' --canonicalization '{canonicalization}' --key-data-base '{db_path}' --domain 'example.com' --domain 'example.org' --dns-update-cmd 'builtin:none'",
    )


def get_opensmtpd_config(port, filter_cmd, maildir_path):
    cfg_content = f"""# OpenSMTPD test configuration

# DKIM filter
filter "dkim" proc-exec "{filter_cmd}"

# Users
table vuser {{ "test" = "1000:100:{maildir_path}" }}

# Listening
listen on 127.0.0.1 port {port} hostname localhost filter "dkim"
listen on ::1 port {port} hostname localhost filter "dkim"

# Delivering
action "deliver" maildir userbase <vuser>
match from any for any action "deliver"
"""
    cfg_file = tempfile.NamedTemporaryFile(prefix="smtpd-", suffix=".conf")
    cfg_file.write(cfg_content.encode())
    cfg_file.flush()
    return cfg_file


def get_smtp_session(port):
    return smtplib.SMTP(host="localhost", port=port)


def send_msg(smtp, msg_file):
    with open(msg_file) as f:
        msg = f.read()
        smtp.sendmail(ADDR_FROM, ADDR_TO, msg)
        return 1
    return 0


def custom_get_txt(name, timeout=5):
    db_path = pathlib.Path(__file__).parent.resolve() / DB_NAME
    algs_assoc = {
        "ed25519-sha256": "ed25519",
        "rsa2048-sha256": "rsa",
        "rsa3072-sha256": "rsa",
        "rsa4096-sha256": "rsa",
    }
    name = name.decode("UTF-8")
    selector, domain = name.split("._domainkey.")
    if domain.endswith("."):
        domain = domain[:-1]
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    res = cur.execute(
        "SELECT algorithm, public_key FROM key_db WHERE selector = ? AND sdid = ? LIMIT 1",
        (selector, domain),
    )
    key = res.fetchone()
    if key:
        algorithm = algs_assoc[key[0]]
        key = key[1]
        key = f"v=DKIM1; k={algorithm}; p={key}"
    return key


def test_dkim(message_path):
    with open(message_path, mode="rb") as f:
        msg = f.read()
        d = dkim.DKIM(msg, logger=logging)
        if d.verify(dnsfunc=custom_get_txt):
            return 1
    return 0


def start_opensmtpd(cfg_path):
    args = [
        shutil.which("sudo"),
        shutil.which("smtpd"),
        "-d",
        "-f",
        cfg_path.name,
    ]
    p = subprocess.Popen(args)
    time.sleep(5)
    return p.pid


def kill_opensmtpd(pid):
    if pid is not None:
        subprocess.Popen([shutil.which("sudo"), shutil.which("kill"), f"{pid}"])


def fix_perms(path):
    subprocess.Popen([shutil.which("sudo"), shutil.which("chmod"), "-R", "777", path])


def get_maildir():
    maildir = tempfile.TemporaryDirectory(prefix="Maildir_")
    flags = (
        stat.S_IRUSR
        | stat.S_IWUSR
        | stat.S_IXUSR
        | stat.S_IRGRP
        | stat.S_IWGRP
        | stat.S_IXGRP
        | stat.S_IROTH
        | stat.S_IWOTH
        | stat.S_IXOTH
    )
    os.chmod(maildir.name, flags)
    return maildir

def start_tests(test_dir, smtp_port, canonicalization):
    # Sending emails to OpenSMTPD
    maildir = get_maildir()
    f, d, filter_cmd = get_cmd_filter_dkimout(
        test_dir, "ed25519-sha256", canonicalization, "debug"
    )
    nb = 0
    nb_total = 0
    pid_smtpd = None
    try:
        cfg_path = get_opensmtpd_config(smtp_port, filter_cmd, maildir.name)
        pid_smtpd = start_opensmtpd(cfg_path)
        with get_smtp_session(smtp_port) as smtp_session:
            for test_msg in glob.iglob(f"{test_dir}/*.msg"):
                nb_total += 1
                nb += send_msg(smtp_session, test_msg)
    except e:
        kill_opensmtpd(pid_smtpd)
        raise e
    finally:
        os.remove(f)
        os.remove(d)
    msg = "messages" if nb > 1 else "message"
    print(f"{nb} {msg} delivered")
    nb_failed = nb_total - nb
    if nb_failed > 0:
        msg = "messages" if nb_failed > 1 else "message"
        fail(f"{nb_failed} {msg} could not be delivered")

    # Testing DKIM signatures
    nb_dkim_ok = 0
    nb_dkim_total = 0
    fix_perms(f"{maildir.name}/Maildir")
    maildir_glob = f"{maildir.name}/Maildir/new/*"
    nb_sleep = 0
    while True:
        nb_sleep += 1
        if nb_sleep > 6:
            fail("Some messages have not been received.")
        time.sleep(nb_sleep)
        if len(glob.glob(maildir_glob)) == nb_total:
            break
    kill_opensmtpd(pid_smtpd)
    for test_msg in glob.glob(maildir_glob):
        nb_dkim_total += 1
        nb_dkim_ok += test_dkim(test_msg)
    msg = "messages" if nb_dkim_ok > 1 else "message"
    print(f"{nb_dkim_ok} {msg} passed the DKIM signature test")
    nb_failed = nb_dkim_total - nb_dkim_ok
    if nb_failed > 0:
        msg = "messages" if nb_failed > 1 else "message"
        fail(f"{nb_failed} {msg} failed the DKIM signature test")


def main():
    test_dir = pathlib.Path(__file__).parent.resolve()
    os.chdir(test_dir.parent)
    start_tests(test_dir, DEFAULT_PORT, "relaxed/relaxed")
    start_tests(test_dir, DEFAULT_PORT, "simple/simple")


if __name__ == "__main__":
    main()
