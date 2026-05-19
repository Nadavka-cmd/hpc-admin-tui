#!/usr/bin/env python3
"""
hpc_admin_tui.py — HPC Combined Admin TUI

Three top-level tabs:
  1. Slurm Admin    — Slurm account/QoS/partition/AD user management
  2. Config Sync    — Config file sync matrix across cluster nodes
  3. Scratch Audit  — /scratch cleanup auditor with per-node scanning & deletion

Usage:
  python3 hpc_admin_tui.py           # live mode
  python3 hpc_admin_tui.py --demo    # demo mode (no real commands)
"""

import asyncio
import asyncssh
import collections
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

# ──────────────────────────────────────────────────────────────────────────────
# Shared
# ──────────────────────────────────────────────────────────────────────────────

DEMO_MODE = "--demo" in sys.argv

SSH_USER = "adminuser"


def run(cmd: list[str]) -> tuple[int, str, str]:
    if DEMO_MODE:
        return 0, "", ""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return 1, "", str(e)


def run_local(cmd: list[str], timeout: int = 15) -> tuple[int, str, str]:
    if DEMO_MODE:
        return 0, "", ""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return 1, "", str(e)


def ssh(node: str, cmd: str, timeout: int = 10) -> tuple[int, str, str]:
    """Plain SSH — passes cmd directly to the remote shell. Used by config sync."""
    r = subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
         f"{SSH_USER}@{node}", cmd],
        capture_output=True, text=True, timeout=timeout,
    )
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def ssh_bash(node: str, cmd: str, timeout: int = 30) -> tuple[int, str, str]:
    """SSH with bash -lc wrapper — used by scratch audit for multi-line shell scripts."""
    r = subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
         f"{SSH_USER}@{node}", "bash", "-lc", cmd],
        capture_output=True, text=True, timeout=timeout,
    )
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def scp_to(local_path: str, node: str, remote_path: str) -> tuple[bool, str]:
    import os as _os
    tmp_path = f"/tmp/.hpc_sync_{_os.path.basename(remote_path)}"

    # Ownership/permission rules per destination path
    _FILE_META: dict = {
        "/etc/slurm/slurm.conf":     ("slurm:slurm", "644"),
        "/etc/sssd/sssd.conf":       ("root:root",   "600"),
        "/etc/hosts":                ("root:root",   "644"),
        "/etc/security/limits.conf": ("root:root",   "644"),
        "/etc/sysctl.conf":          ("root:root",   "644"),
        "/etc/environment":          ("root:root",   "644"),
    }
    owner, mode = _FILE_META.get(remote_path, ("root:root", "644"))

    # Step 1: if local file is not readable by admin user, sudo-copy to readable temp first
    readable_src = local_path
    tmp_local = f"/tmp/.hpc_local_{_os.path.basename(local_path)}"
    try:
        open(local_path, "rb").close()
    except PermissionError:
        r2 = subprocess.run(
            ["sudo", "cp", local_path, tmp_local],
            capture_output=True, text=True, timeout=10,
        )
        if r2.returncode != 0:
            return False, f"stat local \"{local_path}\": Permission denied"
        subprocess.run(["sudo", "chmod", "644", tmp_local], capture_output=True, timeout=5)
        readable_src = tmp_local

    # Step 1b: scp to /tmp on remote (no sudo needed)
    r = subprocess.run(
        ["scp", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
         "-o", "BatchMode=yes", readable_src, f"{SSH_USER}@{node}:{tmp_path}"],
        capture_output=True, text=True, timeout=30,
    )
    if readable_src != local_path:
        subprocess.run(["sudo", "rm", "-f", tmp_local], capture_output=True, timeout=5)
    if r.returncode != 0:
        return False, r.stderr.strip()

    # Step 2: sudo mv into place with correct ownership/perms; clean up tmp on failure
    cmd = (
        f"sudo mv {tmp_path} {remote_path} "
        f"&& sudo chown {owner} {remote_path} "
        f"&& sudo chmod {mode} {remote_path} "
        f"|| {{ sudo rm -f {tmp_path}; exit 1; }}"
    )
    rc, _, err = ssh(node, cmd)
    return (True, "") if rc == 0 else (False, err)


def safe_exists(path: str) -> bool:
    try:
        os.stat(path)
        return True
    except PermissionError:
        return True
    except OSError:
        return False


# ──────────────────────────────────────────────────────────────────────────────
# ░░  SLURM ADMIN DATA  ░░
# ──────────────────────────────────────────────────────────────────────────────

QOS_DEFINITIONS = {
    "research": {
        "priority": 1000, "max_gpus_job": None, "max_gpus_user": None,
        "max_jobs": 10, "max_submit": 50, "max_wall": None,
        "color": "bold green",
        "sacctmgr_flags": "Priority=1000 MaxJobsPerUser=10 MaxSubmitJobsPerUser=50",
    },
    "a6000_full": {
        "priority": 600, "max_gpus_job": None, "max_gpus_user": None,
        "max_jobs": None, "max_submit": None, "max_wall": None,
        "color": "bold green",
        "sacctmgr_flags": "Priority=600",
    },
    "normal": {
        "priority": 500, "max_gpus_job": 2, "max_gpus_user": None,
        "max_jobs": 2, "max_submit": 20, "max_wall": "1-00:00:00",
        "color": "bold cyan",
        "sacctmgr_flags": "Priority=500 MaxTRESPerJob=gres/gpu=2 MaxJobsPerUser=2 MaxSubmitJobsPerUser=20 MaxWallDurationPerJob=1-00:00:00",
    },
    "a6000_restricted": {
        "priority": 500, "max_gpus_job": 2, "max_gpus_user": None,
        "max_jobs": None, "max_submit": None, "max_wall": None,
        "color": "bold cyan",
        "sacctmgr_flags": "Priority=500 MaxTRESPerJob=gres/gpu=2",
    },
    "course_batch": {
        "priority": 100, "max_gpus_job": 1, "max_gpus_user": None,
        "max_jobs": 1, "max_submit": 4, "max_wall": "04:00:00",
        "color": "bold yellow",
        "sacctmgr_flags": "Priority=100 MaxJobsPerUser=1 MaxSubmitJobsPerUser=4 MaxWallDurationPerJob=04:00:00",
    },
    "course_interactive": {
        "priority": 150, "max_gpus_job": 1, "max_gpus_user": None,
        "max_jobs": 2, "max_submit": 4, "max_wall": "02:00:00",
        "color": "bold yellow",
        "sacctmgr_flags": "Priority=150 MaxJobsPerUser=2 MaxSubmitJobsPerUser=4 MaxWallDurationPerJob=02:00:00",
    },
}

ACCOUNT_DEFINITIONS = {
    "hpc-admin": {
        "description": "HPC Admins",
        "default_qos": "normal",
        "allowed_qos": ["a6000_full", "normal"],
        "ad_group": "hpc_admins",
        "color": "bold red",
    },
    "research_groupA": {
        "description": "Research Group A",
        "default_qos": "normal",
        "allowed_qos": ["a6000_full", "normal", "research"],
        "ad_group": "hpc_groupA",
        "color": "bold green",
    },
    "general_users": {
        "description": "General Users & Faculty",
        "default_qos": "normal",
        "allowed_qos": ["normal"],
        "ad_group": "hpc_researchers",
        "color": "bold cyan",
    },
    "course_students": {
        "description": "Course Students",
        "default_qos": "course_batch",
        "allowed_qos": ["course_batch", "course_interactive", "normal"],
        "ad_group": "hpc_course_students",
        "color": "bold yellow",
    },
}

PARTITION_DEFINITIONS = {
    "research_groupA": {
        "nodes": "hpc-nodeA1",
        "allow_groups": ["hpc_groupA", "hpc_admins"],
        "deny_groups": [],
        "qos": "research",
        "allow_qos": [],
        "max_time": "UNLIMITED",
        "default": False,
        "description": "Group A exclusive — own hardware, unlimited time",
    },
    "course": {
        "nodes": "hpc-node5, hpc-node7  (1080 Ti)",
        "allow_groups": ["hpc_course_students", "hpc_admins"],
        "deny_groups": [],
        "qos": "course_batch",
        "allow_qos": ["course_batch", "course_interactive"],
        "max_time": "04:00:00",
        "default": True,
        "description": "Students only — 1080 Ti nodes, 4h max",
    },
    "shared_rtx6000": {
        "nodes": "hpc-node8  (Quadro RTX 6000 ×2)",
        "allow_groups": ["hpc_researchers", "hpc_faculty", "hpc_admins"],
        "deny_groups": [],
        "qos": "normal",
        "allow_qos": [],
        "max_time": "1-00:00:00",
        "default": False,
        "description": "Shared — Quadro RTX 6000",
    },
    "shared_a5000": {
        "nodes": "A5000 nodes",
        "allow_groups": ["hpc_researchers", "hpc_faculty", "hpc_admins"],
        "deny_groups": [],
        "qos": "normal",
        "allow_qos": [],
        "max_time": "1-00:00:00",
        "default": False,
        "description": "Shared — A5000 nodes",
    },
    "shared_a6000": {
        "nodes": "hpc-node6  (A6000 ×2)",
        "allow_groups": ["hpc_researchers", "hpc_faculty", "hpc_admins"],
        "deny_groups": [],
        "qos": "N/A",
        "allow_qos": ["a6000_restricted", "a6000_full", "normal"],
        "max_time": "2-00:00:00",
        "default": False,
        "description": "Shared A6000 — tiered: normal/a6000_restricted (2 GPU) or a6000_full (privileged)",
    },
    "shared_3090": {
        "nodes": "RTX 3090 nodes",
        "allow_groups": ["hpc_course_students", "hpc_researchers", "hpc_faculty", "hpc_admins"],
        "deny_groups": [],
        "qos": "normal",
        "allow_qos": [],
        "max_time": "1-00:00:00",
        "default": False,
        "description": "Shared — RTX 3090",
    },
    "shared_1080ti": {
        "nodes": "hpc-node5, hpc-node7",
        "allow_groups": ["hpc_researchers", "hpc_faculty", "hpc_admins"],
        "deny_groups": [],
        "qos": "normal",
        "allow_qos": [],
        "max_time": "1-00:00:00",
        "default": False,
        "description": "Shared — 1080 Ti (researchers/faculty only)",
    },
    "shared": {
        "nodes": "hpc-node6, hpc-nodeA1, hpc-node8",
        "allow_groups": ["hpc_researchers", "hpc_faculty", "hpc_admins"],
        "deny_groups": [],
        "qos": "normal",
        "allow_qos": [],
        "max_time": "1-00:00:00",
        "default": False,
        "description": "Shared — all researcher/faculty GPU nodes",
    },
    "CPUonly": {
        "nodes": "hpc-cpu1",
        "allow_groups": ["hpc_matlab_users", "hpc_admins"],
        "deny_groups": [],
        "qos": "normal",
        "allow_qos": [],
        "max_time": "1-00:00:00",
        "default": False,
        "description": "CPU-only — MATLAB users",
    },
}

AD_GROUPS = [
    "hpc_admins", "hpc_groupA", "hpc_researchers",
    "hpc_faculty", "hpc_course_students", "hpc_matlab_users", "HPC-Users",
]

AD_GROUP_TO_ACCOUNT = {
    "hpc_admins":          "hpc-admin",
    "hpc_groupA":          "research_groupA",
    "hpc_researchers":     "general_users",
    "hpc_faculty":         "general_users",
    "hpc_course_students": "course_students",
    "hpc_matlab_users":    "general_users",
    "HPC-Users":           "general_users",
}


def discover_ad_groups() -> list[str]:
    """Discover HPC AD groups by querying each by name via getent."""
    if DEMO_MODE:
        return AD_GROUPS[:]

    candidates = list(AD_GROUPS)
    try:
        r = subprocess.run(
            ["sacctmgr", "show", "accounts", "-n", "-P", "format=Account"],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0:
            for acc in r.stdout.splitlines():
                acc = acc.strip()
                if not acc:
                    continue
                candidate = f"hpc_{acc}"
                if candidate not in candidates:
                    candidates.append(candidate)
    except Exception:
        pass

    result = []
    for grp in candidates:
        rc, out, _ = run(["getent", "group", grp])
        if rc == 0 and out.strip():
            result.append(grp)
    return result

MOCK_ASSOC = [
    {"User": "admin1",  "Account": "hpc-admin",       "DefQOS": "normal",     "QOS": "a6000_full,course_batch,course_interactive,normal"},
    {"User": "admin2",  "Account": "hpc-admin",        "DefQOS": "normal",     "QOS": "a6000_full,normal"},
    {"User": "researcher1", "Account": "research_groupA", "DefQOS": "a6000_full", "QOS": "a6000_full,normal,research"},
    {"User": "faculty1",    "Account": "general_users",   "DefQOS": "normal",     "QOS": "normal"},
    {"User": "student1",    "Account": "course_students", "DefQOS": "course_batch","QOS": "course_batch,course_interactive"},
]
MOCK_QOS = [
    {"Name": "normal",             "Priority": "500",  "MaxTRES": "gres/gpu=2", "MaxTRESPU": "", "MaxWall": "1-00:00:00", "MaxJobsPU": "2",  "MaxSubmitPU": "20"},
    {"Name": "research",           "Priority": "1000", "MaxTRES": "",           "MaxTRESPU": "", "MaxWall": "",           "MaxJobsPU": "10", "MaxSubmitPU": "50"},
    {"Name": "a6000_full",         "Priority": "600",  "MaxTRES": "",           "MaxTRESPU": "", "MaxWall": "",           "MaxJobsPU": "",   "MaxSubmitPU": ""},
    {"Name": "a6000_restricted",   "Priority": "500",  "MaxTRES": "gres/gpu=2", "MaxTRESPU": "", "MaxWall": "",           "MaxJobsPU": "",   "MaxSubmitPU": ""},
    {"Name": "course_batch",       "Priority": "100",  "MaxTRES": "",           "MaxTRESPU": "", "MaxWall": "04:00:00",   "MaxJobsPU": "1",  "MaxSubmitPU": "4"},
    {"Name": "course_interactive", "Priority": "150",  "MaxTRES": "",           "MaxTRESPU": "", "MaxWall": "02:00:00",   "MaxJobsPU": "2",  "MaxSubmitPU": "4"},
]
MOCK_AD = {
    "hpc_admins":          ["admin1", "admin2"],
    "hpc_groupA":          ["researcher1"],
    "hpc_researchers":     ["faculty1", "faculty2"],
    "hpc_faculty":         ["faculty1", "faculty2", "faculty3"],
    "hpc_course_students": ["student1", "student2"],
    "hpc_matlab_users":    [],
    "HPC-Users":           ["admin1", "admin2", "researcher1", "faculty1", "faculty2", "faculty3", "student1", "student2"],
}


def fetch_slurm_assoc() -> list[dict]:
    if DEMO_MODE:
        return MOCK_ASSOC
    rc, out, _ = run(["sacctmgr", "show", "assoc", "-P",
                      "format=User,Account,DefaultQOS,QOS", "--noheader"])
    result = []
    if rc != 0:
        return result
    for line in out.splitlines():
        p = line.split("|")
        if len(p) < 4:
            continue
        user, account, defqos, qos = p[0].strip(), p[1].strip(), p[2].strip(), p[3].strip()
        if not user:
            if account in ACCOUNT_DEFINITIONS and defqos:
                ACCOUNT_DEFINITIONS[account]["default_qos"] = defqos
        else:
            result.append({"User": user, "Account": account, "DefQOS": defqos, "QOS": qos})
    return result


def fetch_slurm_accounts(assoc: list[dict]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for row in assoc:
        acc  = row["Account"]
        user = row["User"]
        if acc not in result:
            result[acc] = []
        if user:
            result[acc].append(user)
    for acc in ACCOUNT_DEFINITIONS:
        if acc not in result:
            result[acc] = []
    return result


def fetch_slurm_qos() -> list[dict]:
    if DEMO_MODE:
        return MOCK_QOS
    rc, out, _ = run(["sacctmgr", "show", "qos", "-P",
                      "format=Name,Priority,MaxTRESPerJob,MaxTRESPerUser,MaxWall,MaxJobsPerUser,MaxSubmitJobsPerUser",
                      "--noheader"])
    if rc != 0:
        return []
    result = []
    for line in out.splitlines():
        p = line.split("|")
        if len(p) >= 7:
            result.append({"Name": p[0], "Priority": p[1], "MaxTRES": p[2],
                           "MaxTRESPU": p[3], "MaxWall": p[4],
                           "MaxJobsPU": p[5], "MaxSubmitPU": p[6]})
    return result


def fetch_ad_group(group: str) -> list[str]:
    """Fetch direct members of a single AD group via getent."""
    if DEMO_MODE:
        return MOCK_AD.get(group, [])
    rc, out, _ = run(["getent", "group", group])
    if rc != 0 or not out:
        return []
    parts = out.split(":")
    if len(parts) >= 4 and parts[3]:
        return [u.strip() for u in parts[3].split(",") if u.strip()]
    return []


# Module-level AD credentials — set once at startup, never written to disk
_AD_BIND_DN: str = ""
_AD_BIND_PW: str = ""
# Update these to match your AD configuration
LDAP_URI   = "ldap://your.ad.domain"
LDAP_BASE  = "OU=HPC,OU=Dept,DC=your,DC=ad,DC=domain"


def set_ad_credentials(username: str, password: str) -> None:
    """Store AD credentials in memory for the session."""
    global _AD_BIND_DN, _AD_BIND_PW
    _AD_BIND_DN = username if "@" in username else f"{username}@your.ad.domain"
    _AD_BIND_PW = password


def test_ad_credentials() -> tuple[bool, str]:
    """Test AD credentials with a quick ldapsearch. Returns (ok, error_msg)."""
    if DEMO_MODE:
        return True, ""
    rc, out, err = run([
        "ldapsearch", "-H", LDAP_URI, "-x",
        "-D", _AD_BIND_DN, "-w", _AD_BIND_PW,
        "-b", LDAP_BASE, "-s", "base", "(objectClass=*)", "cn"
    ])
    if rc != 0:
        return False, err.strip() or out.strip() or "Unknown LDAP error"
    return True, ""


def fetch_all_ad() -> tuple[dict[str, list[str]], dict[str, str]]:
    """Fetch all HPC groups and their members via a single ldapsearch query."""
    if DEMO_MODE:
        return {g: MOCK_AD.get(g, []) for g in AD_GROUPS}, {}

    if not _AD_BIND_DN or not _AD_BIND_PW:
        return {}, {}

    rc, out, err = run([
        "ldapsearch", "-H", LDAP_URI, "-x",
        "-D", _AD_BIND_DN, "-w", _AD_BIND_PW,
        "-b", LDAP_BASE, "(objectClass=group)", "cn", "member"
    ])
    if rc != 0 or not out:
        return {}, {}

    # Parse LDIF — handle line continuations (continuation lines start with space)
    joined_lines = []
    for line in out.splitlines():
        if line.startswith(" ") and joined_lines:
            joined_lines[-1] = joined_lines[-1] + line[1:]
        else:
            joined_lines.append(line)

    groups_raw: dict[str, list[str]] = {}
    current_cn = None
    current_members: list[str] = []
    for line in joined_lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("dn:"):
            if current_cn is not None:
                groups_raw[current_cn] = current_members
            current_cn = None
            current_members = []
        elif line.startswith("cn:"):
            current_cn = line.split(":", 1)[1].strip()
        elif line.startswith("member:"):
            dn = line.split(":", 1)[1].strip()
            m = re.match(r"CN=([^,]+)", dn, re.IGNORECASE)
            if m:
                current_members.append(m.group(1))
    if current_cn is not None:
        groups_raw[current_cn] = current_members

    all_group_names = set(groups_raw.keys())

    def resolve_members(grp_cn: str, visited: set) -> list[str]:
        if grp_cn in visited:
            return []
        visited.add(grp_cn)
        users = []
        for member in groups_raw.get(grp_cn, []):
            if member in all_group_names:
                users.extend(resolve_members(member, visited))
            else:
                users.append(member)
        return users

    skip = {"HPC-Users"}
    result: dict[str, list[str]] = {}
    for grp_cn in sorted(groups_raw.keys()):
        if grp_cn in skip:
            continue
        resolved = resolve_members(grp_cn, set())
        result[grp_cn] = sorted(set(resolved))

    hpc_users_children: dict[str, str] = {}
    for child_cn in groups_raw.get("HPC-Users", []):
        if child_cn not in all_group_names:
            continue
        for user in result.get(child_cn, []):
            if user not in hpc_users_children:
                hpc_users_children[user] = child_cn

    return result, hpc_users_children


def sacct_add_or_update_user(username: str, account: str, defqos: str, extra_qos: list[str],
                              prev_account: str = "") -> tuple[bool, str]:
    all_qos = ",".join(sorted(set([defqos] + extra_qos)))
    cmd_add = ["sacctmgr", "-i", "add", "user", username,
               f"Account={account}", f"DefaultQOS={defqos}", f"QOS={all_qos}"]
    if DEMO_MODE:
        return True, f"[DEMO] sacctmgr add user {username} Account={account} DefaultQOS={defqos} QOS={all_qos}"
    if prev_account and prev_account != account:
        run(["sacctmgr", "-i", "remove", "user", username, f"Account={prev_account}"])
        rc, out, err = run(cmd_add)
        if rc != 0:
            return False, f"sacctmgr error: {err or out or 'unknown error'}"
        return True, f"Moved {username}: {prev_account} → {account}, defaultqos={defqos}, qos={all_qos}"
    cmd_mod = ["sacctmgr", "-i", "modify", "user", username,
               "where", f"Account={account}",
               "set", f"defaultqos={defqos}", f"qos={all_qos}"]
    rc, out, err = run(cmd_mod)
    if rc == 0:
        return True, f"Modified user {username}: defaultqos={defqos}, qos={all_qos}"
    rc, out, err = run(cmd_add)
    if rc != 0:
        return False, f"sacctmgr error: {err or out or 'unknown error'}"
    return True, f"Added user {username} to account {account}"


def sacct_remove_user(username: str, account: str) -> tuple[bool, str]:
    if DEMO_MODE:
        return True, f"[DEMO] sacctmgr --immediate remove user {username} Account={account}"
    rc, out, err = run(["sacctmgr", "--immediate", "remove", "user", username, f"Account={account}"])
    if rc != 0:
        return False, f"sacctmgr error: {err or out}"
    return True, f"Removed '{username}' from '{account}'"


# ──────────────────────────────────────────────────────────────────────────────
# ░░  CONFIG SYNC DATA  ░░
# ──────────────────────────────────────────────────────────────────────────────

MASTER   = "hpc-master"
SINFO    = "/opt/slurm/bin/sinfo"
SCONTROL = "/opt/slurm/bin/scontrol"

SERVICE_NODES = ["hpc-master", "hpc-ood"]

FALLBACK_NODE_GROUPS = [
    ("SERVICE", SERVICE_NODES),
    ("COMPUTE", ["hpc-node5", "hpc-node6", "hpc-node7", "hpc-node8", "hpc-node10", "hpc-nodeA1"]),
]

TRACKED_FILES = [
    ("/etc/slurm/slurm.conf",     "/etc/slurm/slurm.conf",     "slurm.conf",  "Slurm main config"),
    ("/etc/sssd/sssd.conf",       "/etc/sssd/sssd.conf",       "sssd.conf",   "SSSD / AD auth config"),
    ("/etc/hosts",                "/etc/hosts",                "hosts",       "Hosts file"),
    ("/etc/security/limits.conf", "/etc/security/limits.conf", "limits",      "PAM limits"),
    ("/etc/sysctl.conf",          "/etc/sysctl.conf",          "sysctl",      "Kernel params"),
    ("/etc/environment",          "/etc/environment",          "environ",     "Proxy / env vars"),
]

TRUENAS_MOUNTS = ["/truenas/home", "/truenas/sif_images", "/truenas/projects", "/truenas/datasets", "/truenas/courses"]

HOSTS_BEGIN_MARKER = "# BEGIN ANSIBLE MANAGED CLUSTER HOSTS"
HOSTS_END_MARKER   = "# END ANSIBLE MANAGED CLUSTER HOSTS"
MOUNT_IDX          = len(TRACKED_FILES)

PROXY_ENV_FILE        = "/etc/environment"
PROXY_VARS            = ["http_proxy", "https_proxy", "no_proxy",
                         "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"]
PROXY_TEST_URL        = "http://detectportal.firefox.com"
PROXY_CONNECT_TIMEOUT = 5
_COL_PREFIX           = "f_"

STATUS_COLORS = {
    "OK": "green", "MISMATCH": "red", "MISSING": "yellow",
    "ERROR": "dark_orange", "SKIP": "grey50", "CHECKING": "cyan", "PENDING": "grey54",
}
STATUS_SYMS = {
    "OK": "✓", "MISMATCH": "✗", "MISSING": "?",
    "ERROR": "!", "SKIP": "–", "CHECKING": "…", "PENDING": "·",
}


def _expand_nodelist(nodelist: str) -> list[str]:
    try:
        r = subprocess.run([SCONTROL, "show", "hostnames", nodelist],
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip().splitlines()
    except Exception:
        pass
    return [nodelist]


def discover_node_groups() -> tuple[list[tuple[str, list[str]]], str]:
    try:
        r = subprocess.run([SINFO, "-h", "-o", "%P %N", "--noheader"],
                           capture_output=True, text=True, timeout=8)
        if r.returncode != 0 or not r.stdout.strip():
            return FALLBACK_NODE_GROUPS, "sinfo failed — using fallback"
        seen: set[str] = set()
        compute: list[str] = []
        for line in r.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            for host in _expand_nodelist(parts[1]):
                if host not in seen:
                    compute.append(host)
                    seen.add(host)
        if not compute:
            return FALLBACK_NODE_GROUPS, "sinfo returned no nodes — using fallback"
        return [("SERVICE", SERVICE_NODES), ("COMPUTE", compute)], \
               f"Discovered {len(compute)} compute + {len(SERVICE_NODES)} service nodes via sinfo"
    except FileNotFoundError:
        return FALLBACK_NODE_GROUPS, "sinfo not found — using fallback"
    except Exception as e:
        return FALLBACK_NODE_GROUPS, f"sinfo error: {e} — using fallback"


def local_md5(path: str) -> Optional[str]:
    try:
        h = hashlib.md5()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except PermissionError:
        try:
            r = subprocess.run(["sudo", "md5sum", path], capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                return r.stdout.strip().split()[0]
        except Exception:
            pass
        return None
    except Exception:
        return None


def read_file_text(path: str) -> Optional[str]:
    try:
        return Path(path).read_text()
    except PermissionError:
        try:
            r = subprocess.run(["sudo", "cat", path], capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                return r.stdout
        except Exception:
            pass
        return None
    except Exception:
        return None


def _extract_ansible_block(text: str) -> Optional[str]:
    try:
        start = text.index(HOSTS_BEGIN_MARKER)
        end   = text.index(HOSTS_END_MARKER)
        return text[start + len(HOSTS_BEGIN_MARKER):end].strip()
    except ValueError:
        return None


def _parse_hosts_entries(block: str) -> set[str]:
    entries = set()
    for line in block.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            entries.add(f"{parts[0]} {parts[1]}")
    return entries


def check_hosts_on_node(node: str) -> dict:
    master_hosts = read_file_text("/etc/hosts")
    if not master_hosts:
        return {"status": "ERROR", "detail": "can't read master /etc/hosts"}
    master_block = _extract_ansible_block(master_hosts)
    if master_block is None:
        return {"status": "SKIP", "detail": "no Ansible block on master"}
    ref_entries = _parse_hosts_entries(master_block)
    if not ref_entries:
        return {"status": "SKIP", "detail": "master Ansible block is empty"}
    if node == MASTER:
        return {"status": "OK", "detail": f"{len(ref_entries)} entries"}
    try:
        rc, hosts_content, err = ssh(node, "cat /etc/hosts")
        if rc != 0:
            return {"status": "ERROR", "detail": f"SSH rc={rc} {err[:30]}"}
    except subprocess.TimeoutExpired:
        return {"status": "ERROR", "detail": "SSH timeout"}
    except Exception as e:
        return {"status": "ERROR", "detail": str(e)[:40]}
    if HOSTS_BEGIN_MARKER not in hosts_content:
        return {"status": "MISSING", "detail": "no Ansible block"}
    block = _extract_ansible_block(hosts_content)
    if block is None:
        return {"status": "MISSING", "detail": "malformed Ansible block"}
    node_entries = _parse_hosts_entries(block)
    missing = ref_entries - node_entries
    extra   = node_entries - ref_entries
    if not missing and not extra:
        return {"status": "OK", "detail": f"{len(ref_entries)} entries match"}
    parts = []
    if missing: parts.append(f"missing {len(missing)}")
    if extra:   parts.append(f"extra {len(extra)}")
    return {"status": "MISMATCH", "detail": ", ".join(parts)}


def check_file_on_node(local_path: str, node: str, remote_path: str) -> dict:
    if local_path == "/etc/hosts":
        return check_hosts_on_node(node)
    if not safe_exists(local_path):
        return {"status": "SKIP", "detail": "not on master"}
    master_md5 = local_md5(local_path)
    if master_md5 is None:
        return {"status": "ERROR", "detail": "can't read source on master"}
    if node == MASTER:
        if not safe_exists(remote_path):
            return {"status": "MISSING", "detail": "absent on master"}
        node_md5 = local_md5(remote_path)
        if node_md5 is None:
            return {"status": "ERROR", "detail": "can't read locally"}
        return {"status": "OK" if master_md5 == node_md5 else "MISMATCH",
                "detail": master_md5[:8] if master_md5 == node_md5 else f"master:{master_md5[:8]} node:{node_md5[:8]}"}
    if "sssd" in remote_path:
        cmd = (f"if sudo test -f {remote_path}; then sudo md5sum {remote_path} 2>/dev/null; "
               f"else echo __MISSING__; fi")
    else:
        cmd = (f"test -f {remote_path} && md5sum {remote_path} 2>/dev/null || echo __MISSING__")
    try:
        rc, out, err = ssh(node, cmd)
        if rc != 0:
            return {"status": "ERROR", "detail": f"SSH rc={rc} {err[:30]}"}
        if "__MISSING__" in out:
            return {"status": "MISSING", "detail": "absent on node"}
        m = re.search(r"^([0-9a-f]{32})\s", out, re.MULTILINE)
        if not m:
            return {"status": "ERROR", "detail": f"out={out[:50]!r}"}
        node_md5 = m.group(1)
        return {"status": "OK" if master_md5 == node_md5 else "MISMATCH",
                "detail": master_md5[:8] if master_md5 == node_md5 else f"master:{master_md5[:8]} node:{node_md5[:8]}"}
    except subprocess.TimeoutExpired:
        return {"status": "ERROR", "detail": "SSH timeout"}
    except Exception as e:
        return {"status": "ERROR", "detail": str(e)[:40]}


def check_mounts_on_node(node: str) -> dict:
    try:
        checks = " && ".join(f"mountpoint -q {m}" for m in TRUENAS_MOUNTS)
        if node == MASTER:
            rc, out, err = run(["bash", "-c", f"if {checks}; then echo ALL_OK; else mount | grep truenas; fi"])
        else:
            rc, out, err = ssh(node, f"if {checks}; then echo ALL_OK; else mount | grep truenas; fi")
        if rc != 0:
            return {"status": "ERROR", "detail": f"rc={rc} {err[:30]}"}
        if "ALL_OK" in out:
            return {"status": "OK", "detail": f"all {len(TRUENAS_MOUNTS)} mounted"}
        missing = [m for m in TRUENAS_MOUNTS if m not in out]
        if missing:
            return {"status": "MISSING", "detail": f"not mounted: {', '.join(missing)}"}
        return {"status": "OK", "detail": f"all {len(TRUENAS_MOUNTS)} mounted"}
    except subprocess.TimeoutExpired:
        return {"status": "ERROR", "detail": "SSH timeout"}
    except Exception as e:
        return {"status": "ERROR", "detail": str(e)[:40]}


def _parse_env_content(content: str) -> dict[str, str]:
    result = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        result[key.strip()] = val.strip().strip('"').strip("'")
    return result


def _parse_env_file(path: str) -> dict[str, str]:
    content = read_file_text(path)
    return _parse_env_content(content) if content else {}


def _proxy_vars_match(master: dict, node: dict) -> bool:
    return all(master.get(v, "") == node.get(v, "") for v in PROXY_VARS)


# ──────────────────────────────────────────────────────────────────────────────
# ░░  SCRATCH AUDIT DATA  ░░
# ──────────────────────────────────────────────────────────────────────────────

SCRATCH        = "/scratch"
SINFO_BIN      = "/opt/slurm/bin/sinfo"
SQUEUE_BIN     = "/opt/slurm/bin/squeue"
PROMETHEUS     = "http://your-prometheus-host:9090"  # Update to your Prometheus address
WARN_DAYS      = 7
STALE_DAYS     = 30
SKIP_NAMES     = {"lost+found"}
IGNORE_MOUNTS  = {"/boot/efi", "/boot", "/run", "/opt/sentinelone/rpm_mount"}
IGNORE_FSTYPES = {"tmpfs", "vfat"}
NFS_MOUNTS     = {"/truenas/home", "/truenas/sif_images", "/truenas/datasets", "/truenas/projects"}

DEMO_NODES = ["hpc-node5", "hpc-node6", "hpc-node7", "hpc-node8", "hpc-node10", "hpc-nodeA1"]

DEMO_SCRATCH: dict[str, list[dict]] = {
    "hpc-node5": [], "hpc-node6": [],
    "hpc-node7": [
        {"name": "dataset_old",      "owner": "faculty1",  "size_kb": 141557760, "mtime": "2023-06-18 14:22", "kind": "dir"},
        {"name": "checkpoints_2022", "owner": "student1",  "size_kb": 52121600,  "mtime": "2022-11-12 09:11", "kind": "dir"},
        {"name": "test_output",      "owner": "admin1",    "size_kb": 102400,    "mtime": "2024-11-25 09:43", "kind": "file"},
        {"name": ".Trash-1000",      "owner": "faculty1",  "size_kb": 4096,      "mtime": "2023-01-13 08:00", "kind": "dir"},
    ],
    "hpc-node8": [], "hpc-node10": [], "hpc-nodeA1": [],
}
DEMO_ACTIVE_JOBS: dict[str, set[str]] = {}
DEMO_FS: dict[str, dict[str, tuple[int, int]]] = {
    "hpc-node7":  {"/scratch": (983_360_245_760, 154_000_000_000), "/": (254_232_031_232, 198_000_000_000)},
    "hpc-node5":  {"/scratch": (983_360_245_760, 970_000_000_000), "/": (254_232_031_232, 210_000_000_000)},
    "hpc-node6":  {"/scratch": (983_360_245_760, 960_000_000_000), "/": (254_232_031_232, 205_000_000_000)},
    "hpc-node8":  {"/scratch": (983_360_245_760, 975_000_000_000), "/": (254_232_031_232, 212_000_000_000)},
    "hpc-node10": {"/scratch": (983_360_245_760, 950_000_000_000), "/": (254_232_031_232, 200_000_000_000)},
    "hpc-nodeA1": {"/scratch": (983_360_245_760, 980_000_000_000), "/": (254_232_031_232, 215_000_000_000)},
}


def prom_query(query: str) -> list[dict]:
    try:
        url    = f"{PROMETHEUS}/api/v1/query"
        params = urllib.parse.urlencode({"query": query})
        req    = urllib.request.Request(f"{url}?{params}")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=6) as resp:
            data = json.loads(resp.read())
        if data.get("status") == "success":
            return data["data"]["result"]
    except Exception as e:
        print(f"[WARN] Prometheus query failed: {e}", file=sys.stderr)
    return []


def prom_instance_for_node(node: str) -> Optional[str]:
    if DEMO_MODE:
        return f"{node}:9100"
    res = prom_query(f'node_uname_info{{nodename="{node}"}}')
    if res:
        inst = res[0].get("metric", {}).get("instance")
        if inst:
            return inst
    return f"{node}:9100"


def fetch_fs_metrics(node: str) -> dict[str, tuple[int, int]]:
    if DEMO_MODE:
        return DEMO_FS.get(node, {})
    inst = prom_instance_for_node(node)
    if inst:
        sizes: dict[str, int] = {}
        avails: dict[str, int] = {}
        for result in prom_query(f'node_filesystem_size_bytes{{instance="{inst}"}}'):
            mp = result["metric"].get("mountpoint", "")
            ft = result["metric"].get("fstype", "")
            if mp in IGNORE_MOUNTS or ft in IGNORE_FSTYPES or mp in NFS_MOUNTS:
                continue
            try:
                sizes[mp] = int(float(result["value"][1]))
            except (ValueError, IndexError):
                pass
        for result in prom_query(f'node_filesystem_avail_bytes{{instance="{inst}"}}'):
            mp = result["metric"].get("mountpoint", "")
            if mp in sizes:
                try:
                    avails[mp] = int(float(result["value"][1]))
                except (ValueError, IndexError):
                    pass
        prom_result = {mp: (sizes[mp], avails.get(mp, 0)) for mp in sizes}
        if prom_result:
            return prom_result
    result = {}
    rc, out, _ = ssh(node, "df -B1 /scratch / 2>/dev/null | tail -n +2", timeout=10)
    if rc == 0:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 6:
                try:
                    mp = parts[5]
                    if mp in ["/scratch", "/"]:
                        result[mp] = (int(parts[1]), int(parts[3]))
                except (ValueError, IndexError):
                    pass
    return result


def expand_nodelist(expr: str) -> list[str]:
    if DEMO_MODE:
        return DEMO_NODES[:]
    if not expr.strip():
        return []
    rc, out, _ = run_local(["/opt/slurm/bin/scontrol", "show", "hostnames", expr], timeout=10)
    if rc != 0 or not out:
        return [expr.strip()]
    return [x.strip() for x in out.splitlines() if x.strip()]


def discover_compute_nodes() -> list[str]:
    if DEMO_MODE:
        return DEMO_NODES[:]
    rc, out, err = run_local([SINFO_BIN, "-N", "-h", "-o", "%N"], timeout=10)
    if rc != 0:
        rc2, out2, _ = run_local([SINFO_BIN, "-h", "-o", "%N"], timeout=10)
        if rc2 != 0:
            return []
        out = out2
    nodes: list[str] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        nodes.extend(expand_nodelist(line))
    nodes = sorted(set(nodes))
    nodes = [n for n in nodes if not re.search(r"(master|login|head|apps|ood|monitor)", n, re.I)]
    return nodes


@dataclass
class ScratchEntry:
    node:       str
    name:       str
    owner:      str
    size_kb:    int
    mtime:      datetime
    kind:       str
    selected:   bool = False
    active_job: bool = False

    @property
    def path(self) -> str:
        return f"{SCRATCH}/{self.name}"

    @property
    def age_days(self) -> int:
        return (datetime.now() - self.mtime).days

    @property
    def age_label(self) -> str:
        d = self.age_days
        if d < 1:
            return "today"
        if d < 7:
            return f"{d} days"
        years, rem = divmod(d, 365)
        months     = rem // 30
        if years:
            return f"{years}y {months}m" if months else f"{years}y"
        weeks = d // 7
        return f"{weeks}w" if weeks < 8 else f"{d // 30}m"

    @property
    def size_human(self) -> str:
        kb = self.size_kb
        if kb >= 1_073_741_824:
            return f"{kb/1_073_741_824:.1f} TB"
        if kb >= 1_048_576:
            return f"{kb/1_048_576:.1f} GB"
        if kb >= 1_024:
            return f"{kb/1_024:.1f} MB"
        return f"{kb} KB"

    @property
    def age_style(self) -> str:
        if self.active_job:
            return "bold green"
        if self.age_days >= STALE_DAYS:
            return "bold red"
        if self.age_days >= WARN_DAYS:
            return "bold yellow"
        return "white"

    @property
    def size_style(self) -> str:
        if self.size_kb >= 100 * 1_048_576:
            return "bold red"
        if self.size_kb >= 10 * 1_048_576:
            return "bold yellow"
        return "white"


def scan_node(node: str) -> tuple[list[ScratchEntry], str]:
    if DEMO_MODE:
        entries: list[ScratchEntry] = []
        for r in DEMO_SCRATCH.get(node, []):
            if r["name"] in SKIP_NAMES:
                continue
            entries.append(ScratchEntry(
                node=node, name=r["name"], owner=r["owner"],
                size_kb=r["size_kb"],
                mtime=datetime.strptime(r["mtime"], "%Y-%m-%d %H:%M"),
                kind=r["kind"],
            ))
        return entries, ""

    stat_cmd = r"""
set -o pipefail
find /scratch -mindepth 1 -maxdepth 1 -print0 2>/dev/null | while IFS= read -r -d '' e; do
  n="$(basename -- "$e")"
  [[ "$n" == "lost+found" ]] && continue
  owner="$(stat -c '%U' -- "$e" 2>/dev/null || true)"
  if [[ -z "$owner" ]]; then
    uid="$(stat -c '%u' -- "$e" 2>/dev/null || echo '')"
    owner="uid${uid}"
  fi
  mtime="$(stat -c '%Y' -- "$e" 2>/dev/null || echo 0)"
  if [[ -d "$e" ]]; then kind="dir"; else kind="file"; fi
  printf '%s|%s|%s|%s|%s\n' "$n" "$owner" "$mtime" "$kind" "$e"
done
""".strip()

    du_cmd = r"""
set -o pipefail
find /scratch -mindepth 1 -maxdepth 1 -print0 2>/dev/null \
| du -sk --files0-from=- 2>/dev/null || true
""".strip()

    try:
        rc1, stat_out, err1 = ssh_bash(node, stat_cmd)
        rc2, du_out, _     = ssh_bash(node, du_cmd)
    except subprocess.TimeoutExpired:
        return [], "SSH timeout"
    except Exception as e:
        return [], str(e)[:80]

    if rc1 != 0 and not stat_out:
        return [], f"stat failed: {err1[:120]}"

    sizes: dict[str, int] = {}
    for line in du_out.splitlines():
        parts = line.split("\t", 1)
        if len(parts) != 2:
            continue
        kb_s, path = parts[0].strip(), parts[1].strip()
        name = path.split("/")[-1]
        try:
            sizes[name] = int(kb_s)
        except ValueError:
            pass

    entries: list[ScratchEntry] = []
    for line in stat_out.splitlines():
        parts = line.split("|", 4)
        if len(parts) < 5:
            continue
        name, owner, mtime_s, kind, _fullpath = parts
        if name in SKIP_NAMES:
            continue
        try:
            mtime = datetime.fromtimestamp(int(mtime_s))
        except (ValueError, OSError):
            mtime = datetime.now()
        entries.append(ScratchEntry(
            node=node, name=name, owner=owner,
            size_kb=sizes.get(name, 0), mtime=mtime, kind=kind,
        ))
    return entries, ""


def fetch_active_scratch_paths(node: str) -> set[str]:
    if DEMO_MODE:
        return DEMO_ACTIVE_JOBS.get(node, set())
    try:
        rc, out, _ = run_local(
            [SQUEUE_BIN, "-h", "-w", node, "-o", "%Z"], timeout=10)
        if rc != 0:
            return set()
        return {line.strip() for line in out.splitlines() if line.strip()}
    except Exception:
        return set()


def mark_active_jobs(entries: list[ScratchEntry], active_paths: set[str]):
    for e in entries:
        if e.path in active_paths or any(e.path.startswith(p) for p in active_paths):
            e.active_job = True


def delete_entry(entry: ScratchEntry) -> tuple[bool, str]:
    if DEMO_MODE:
        return True, f"[DEMO] rm -rf {entry.path} on {entry.node}"
    cmd = f"sudo rm -rf {entry.path!r}"
    try:
        rc, _, err = ssh(entry.node, cmd, timeout=180)
        if rc != 0:
            return False, f"rm failed (rc={rc}): {err[:120]}"
        return True, f"Deleted {entry.path} on {entry.node}"
    except subprocess.TimeoutExpired:
        return False, "SSH timeout during delete"
    except Exception as e:
        return False, str(e)[:120]


def fmt_bytes(b: int) -> str:
    if b >= 1_099_511_627_776:
        return f"{b/1_099_511_627_776:.1f} TB"
    if b >= 1_073_741_824:
        return f"{b/1_073_741_824:.1f} GB"
    if b >= 1_048_576:
        return f"{b/1_048_576:.1f} MB"
    return f"{b/1_024:.1f} KB"


def pct(used: int, total: int) -> float:
    return (used / total * 100) if total else 0.0


# ──────────────────────────────────────────────────────────────────────────────
# ░░  NETFREEZE MONITOR DATA  ░░
# ──────────────────────────────────────────────────────────────────────────────

def _nf_setup_logger() -> logging.Logger:
    log_dir = Path("/var/log/netfreeze")
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        log_dir = Path.home() / ".local/log/netfreeze"
        log_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("netfreeze_tui")
    if not logger.handlers:
        logger.setLevel(logging.DEBUG)
        fh = logging.FileHandler(log_dir / "tui_app.log")
        fh.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
        logger.addHandler(fh)
    return logger

nf_applog = _nf_setup_logger()

NF_CONFIG_FILE = Path("~/.config/netfreeze_tui.json").expanduser()

NF_DEFAULT_CONFIG = {
    "ssh_user":          "adminuser",
    "ssh_key":           "~/.ssh/id_rsa",
    "deploy_src":        "./net-freeze-monitor",
    "remote_install_dir":"/tmp/netfreeze_deploy",
    "remote_log_dir":    "/var/log/netfreeze",
    "poll_interval":     3,
    "tail_lines":        80,
    "nodes": [
        {"name": "hpc-master",  "host": "hpc-master",  "has_bond": True},
        {"name": "hpc-node5",   "host": "hpc-node5",   "has_bond": True},
        {"name": "hpc-node6",   "host": "hpc-node6",   "has_bond": True},
        {"name": "hpc-node7",   "host": "hpc-node7",   "has_bond": True},
        {"name": "hpc-node8",   "host": "hpc-node8",   "has_bond": True},
        {"name": "hpc-nodeA1",  "host": "hpc-nodeA1",  "has_bond": False},
    ]
}

NF_FREEZE_PATTERNS = [
    re.compile(r"ARP FAILURE DETECTED"),
    re.compile(r"BOND FAILOVER"),
    re.compile(r"LINK FLAP"),
    re.compile(r"UNREACHABLE"),
    re.compile(r"CRITICAL LATENCY"),
]
NF_WARN_PATTERNS = [
    re.compile(r"WARN.*latency", re.IGNORECASE),
    re.compile(r"high latency",  re.IGNORECASE),
    re.compile(r"MII Status.*down", re.IGNORECASE),
]
NF_RECOVER_PATTERNS = [
    re.compile(r"ARP recovered"),
    re.compile(r"RECOVERED"),
]

def nf_classify_line(line: str) -> str:
    for p in NF_FREEZE_PATTERNS:
        if p.search(line): return "freeze"
    for p in NF_WARN_PATTERNS:
        if p.search(line): return "warn"
    for p in NF_RECOVER_PATTERNS:
        if p.search(line): return "recover"
    return "normal"


class NfNodeState:
    def __init__(self, config: dict):
        self.name           = config["name"]
        self.host           = config["host"]
        self.has_bond       = config.get("has_bond", False)
        self.ssh_status     = "unknown"
        self.deploy_status  = "none"
        self.monitor_status = "off"
        self.freeze_active  = False
        self.freeze_count   = 0
        self.last_event_time: Optional[float] = None
        self.last_event_str:  str             = ""
        self.error_msg      = ""


_NF_TS_RE = re.compile(r"\[?(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]?")

def nf_parse_log_timestamp(line: str) -> Optional[float]:
    m = _NF_TS_RE.search(line)
    if not m:
        return None
    try:
        from datetime import datetime as _dt
        return _dt.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").timestamp()
    except Exception:
        return None


async def nf_ssh_connect(host: str, user: str, key_path: str) -> tuple[Optional[asyncssh.SSHClientConnection], str]:
    try:
        keyfile     = str(Path(key_path).expanduser())
        client_keys = [keyfile] if Path(keyfile).exists() else None
        conn = await asyncio.wait_for(
            asyncssh.connect(
                host, username=user,
                client_keys=client_keys,
                agent_path=os.environ.get("SSH_AUTH_SOCK"),
                known_hosts=None,
                connect_timeout=8,
            ),
            timeout=10
        )
        return conn, ""
    except Exception as e:
        nf_applog.error(f"SSH connect failed host={host} err={e}")
        return None, str(e)


async def nf_ssh_run(conn: asyncssh.SSHClientConnection, cmd: str, timeout: int = 15) -> tuple[str, str, int]:
    try:
        result = await asyncio.wait_for(conn.run(cmd), timeout=timeout)
        return result.stdout or "", result.stderr or "", result.returncode or 0
    except asyncio.TimeoutError:
        return "", "timeout", -1
    except Exception as e:
        return "", str(e), -1


# ──────────────────────────────────────────────────────────────────────────────
# ░░  TUI  ░░
# ──────────────────────────────────────────────────────────────────────────────

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.css.query import NoMatches
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widget import Widget
from textual.widgets import (
    Button, DataTable, Footer, Header, Input, Label,
    ListItem, ListView, ProgressBar, RichLog, Rule, Select, Static,
    TabbedContent, TabPane,
)
from textual import on, work
from rich.text import Text

QOS_COLOR = {
    "research": "bold green", "a6000_full": "bold green",
    "normal": "bold cyan",    "a6000_restricted": "bold cyan",
    "course_batch": "bold yellow", "course_interactive": "bold yellow",
}
ACC_COLOR_FIXED = {
    "hpc-admin":      "bold red",
    "general_users":  "bold cyan",
    "course_students":"bold yellow",
    "root":           "dim",
}
_RESEARCH_COLORS = ["bold green", "bold magenta", "bold blue", "bold orange1", "bold purple"]
_research_color_cache: dict[str, str] = {}

def acc_color(account: str) -> str:
    if account in ACC_COLOR_FIXED:
        return ACC_COLOR_FIXED[account]
    if account not in _research_color_cache:
        idx = len(_research_color_cache) % len(_RESEARCH_COLORS)
        _research_color_cache[account] = _RESEARCH_COLORS[idx]
    return _research_color_cache[account]

ACC_COLOR = ACC_COLOR_FIXED


def gpu_label(cap) -> Text:
    if cap is None:
        return Text("∞ unlimited", style="bold green")
    elif cap == 1:
        return Text("max 1 GPU", style="bold yellow")
    elif cap == 2:
        return Text("max 2 GPUs", style="bold cyan")
    return Text(f"max {cap} GPUs", style="bold cyan")


CSS = """
Screen { background: $surface; }

/* ── Slurm tab ── */
#modal-box {
    background: $panel;
    border: thick $primary;
    padding: 1 2;
    width: 72;
    height: auto;
    max-height: 55;
    margin: 3 12;
}
#modal-title   { color: $accent; text-style: bold; padding-bottom: 1; }
#modal-buttons { margin-top: 1; align: center middle; height: 3; }
#modal-status  { padding-top: 1; height: 2; }
#assoc-list    { height: auto; max-height: 10; border: solid $primary-darken-2; margin-bottom: 1; }
.assoc-row     { height: 3; padding: 0 1; align: left middle; }
.assoc-acc-lbl { width: 22; }
.assoc-qos-lbl { width: 24; }
.assoc-btn     { margin-right: 1; min-width: 10; }

.section-title {
    background: $primary-darken-1;
    color: $text;
    padding: 0 1;
    text-style: bold;
}
#sidebar       { width: 34; border-right: solid $primary-darken-2; }
#main-content  { width: 1fr; }
.action-bar    { height: 3; align: left middle; padding: 0 1; background: $surface-darken-1; }
.panel-row     { height: 1fr; }
#qos-legend    { padding: 1; }
#demo-badge    { background: $warning; color: black; padding: 0 1; }

/* ── Config sync tab ── */
#sync-main { height: 1fr; }

#left-panel {
    width: 22;
    border-right: solid $primary;
    background: $panel;
    overflow-y: auto;
    padding: 0 1 1 1;
}
.group-label {
    background: $panel-darken-2;
    color: $primary;
    text-style: bold;
    padding: 0 1;
    margin-top: 1;
    width: 100%;
}
.node-btn {
    width: 100%;
    background: $surface;
    border: none;
    padding: 0 1;
    height: 1;
    min-height: 1;
    color: $text;
}
.node-btn:hover   { background: $boost; }
.node-btn.-active { background: $primary; color: $background; text-style: bold; }

#right-panel  { width: 1fr; }

#sync-action-bar {
    height: 3;
    background: $panel;
    border-top: solid $primary;
    padding: 0 1;
    align: left middle;
}
#sync-action-bar Button { margin-right: 1; }
#action-hint { color: $text-muted; padding: 0 1; }

#proxy-banner {
    height: 5;
    background: $panel;
    border-bottom: solid $primary;
    padding: 0 2;
}
#proxy-action-bar {
    height: 3;
    background: $panel;
    border-top: solid $primary;
    padding: 0 1;
    align: left middle;
}
#proxy-action-bar Button { margin-right: 1; }
#node-detail-header {
    height: 1;
    background: $primary-darken-2;
    color: $text;
    text-style: bold;
    padding: 0 2;
}
#log-view { height: 1fr; }

/* ── Scratch audit tab ── */
#scratch-main { height: 1fr; }

#scr-node-panel {
    width: 26;
    border-right: solid $primary;
    background: $panel;
    overflow-y: auto;
    padding: 0 1 1 1;
}
.np-header {
    background: $panel-darken-2;
    color: $primary;
    text-style: bold;
    padding: 0 1;
    margin-top: 1;
    width: 100%;
}
.scr-node-btn {
    width: 100%;
    background: $surface;
    border: none;
    padding: 0 1;
    height: 1;
    min-height: 1;
    color: $text;
}
.scr-node-btn:hover   { background: $boost; }
.scr-node-btn.-active { background: $primary; color: $background; text-style: bold; }

#scr-right { width: 1fr; }

#node-title {
    height: 1;
    background: $primary-darken-2;
    color: $text;
    text-style: bold;
    padding: 0 2;
    text-align: center;
}

#info-panel {
    height: 9;
    border-top: solid $primary-darken-2;
    background: $panel;
    padding: 0 1;
}
#info-root   { width: 1fr; border-right: solid $primary-darken-2; padding: 0 1; }
#info-center { width: 2fr; padding: 0 2; }
#info-right  { width: 1fr; border-left: solid $primary-darken-2; padding: 0 1; }
.info-header { color: $accent; text-style: bold; padding: 0 0 1 0; }

#scratch-bar-label  { height: 1; }
#scratch-pct-label  { height: 1; color: $text-muted; text-align: center; }
ProgressBar         { height: 1; }
ProgressBar > .bar--bar { color: $primary; }
ProgressBar.-warn > .bar--bar { color: $warning; }
ProgressBar.-crit > .bar--bar { color: $error; }

#scr-action-bar {
    height: 3;
    background: $panel;
    border-top: solid $primary;
    padding: 0 1;
    align: left middle;
}
#scr-action-bar Button { margin-right: 1; }
#scr-hint { color: $text-muted; padding: 0 1; }

#ad-action-bar {
    height: 3;
    background: $panel;
    border-bottom: solid $primary;
    padding: 0 1;
    align: left middle;
}
#ad-action-bar Label { width: 1fr; }
#ad-action-bar Button { margin-left: 1; width: auto; }

/* ── NetFreeze tab ── */
#nf-top-bar {
    height: 3;
    background: $panel;
    padding: 0 2;
    align: left middle;
}
#nf-top-bar Label { margin-right: 3; }

#nf-global-alert {
    height: 1;
    text-align: center;
    text-style: bold;
    background: $panel-darken-1;
    color: $text-muted;
}
#nf-global-alert.freeze { background: $error;       color: white; }
#nf-global-alert.ok     { background: $success 50%; color: white; }

#nf-nodes-scroll { height: 1fr; padding: 0 1; }

#nf-summary-bar {
    height: 1;
    background: $panel-darken-2;
    padding: 0 2;
    color: $text-muted;
}

#nf-action-bar {
    height: 3;
    background: $panel;
    border-top: solid $primary;
    padding: 0 1;
    align: left middle;
}
#nf-action-bar Button { margin-right: 1; }

/* ── Shared ── */
#status-bar {
    height: 1;
    background: $panel-darken-2;
    padding: 0 2;
}
DataTable { height: 1fr; }
Button    { margin: 0 1; }
TabbedContent { height: 1fr; }
"""

# ──────────────────────────────────────────────────────────────────────────────
# Modals
# ──────────────────────────────────────────────────────────────────────────────

class AddAccountModal(ModalScreen):
    BINDINGS = [Binding("escape", "dismiss", "Cancel")]

    def compose(self) -> ComposeResult:
        with Vertical(id="modal-box"):
            yield Label("── New Slurm Account ──", id="modal-title")
            yield Label("Account name:")
            yield Input(placeholder="e.g. research_smith", id="inp-acc-name")
            yield Label("Description:")
            yield Input(placeholder="e.g. Smith Research Group", id="inp-acc-desc")
            yield Label("Organization:")
            yield Input(value="HPC", id="inp-acc-org")
            with Horizontal(id="modal-buttons"):
                yield Button("Create", variant="primary", id="btn-acc-ok")
                yield Button("Cancel", variant="default", id="btn-acc-cancel")
            yield Label("", id="modal-acc-status")

    @on(Button.Pressed, "#btn-acc-cancel")
    def cancel(self): self.dismiss(None)

    @on(Button.Pressed, "#btn-acc-ok")
    def do_create(self) -> None:
        name   = self.query_one("#inp-acc-name", Input).value.strip()
        desc   = self.query_one("#inp-acc-desc", Input).value.strip()
        org    = self.query_one("#inp-acc-org",  Input).value.strip() or "HPC"
        status = self.query_one("#modal-acc-status", Label)
        if not name:
            status.update("[red]Enter an account name.[/]"); return
        if DEMO_MODE:
            self.dismiss((name, f"[DEMO] sacctmgr add account {name}")); return
        rc, out, err = run([
            "sacctmgr", "-i", "add", "account", name,
            f"Description={desc}", f"Organization={org}"
        ])
        if rc != 0:
            status.update(f"[red]{err or out or 'sacctmgr error'}[/]")
        else:
            self.dismiss((name, f"Created account '{name}'"))


class BulkImportModal(ModalScreen):
    BINDINGS = [Binding("escape", "dismiss", "Cancel")]

    def compose(self) -> ComposeResult:
        live_accounts = AddUserModal._fetch_live_accounts()
        live_qos      = AddUserModal._fetch_live_qos()
        with Vertical(id="modal-box"):
            yield Label("── Bulk Import AD Group → Slurm Account ──", id="modal-title")
            yield Label("AD Group name:")
            yield Input(placeholder="e.g. hpc_course_236781", id="inp-bulk-group")
            yield Label("Slurm Account:")
            yield Select([(a, a) for a in live_accounts], id="sel-bulk-account",
                         prompt="Select account…")
            yield Label("Default QoS:")
            yield Select([(q, q) for q in live_qos], id="sel-bulk-defqos",
                         prompt="Select default QoS…")
            yield Label("Additional QoS (comma-separated, or leave blank):")
            yield Input(placeholder="e.g. normal", id="inp-bulk-extraqos")
            yield Static("[dim]All members of the AD group will be added/updated in sacctmgr.[/]")
            with Horizontal(id="modal-buttons"):
                yield Button("Import", variant="primary",  id="btn-bulk-ok")
                yield Button("Cancel", variant="default",  id="btn-bulk-cancel")
            yield Label("", id="modal-bulk-status")

    @on(Button.Pressed, "#btn-bulk-cancel")
    def cancel(self): self.dismiss(None)

    @on(Button.Pressed, "#btn-bulk-ok")
    def do_import(self) -> None:
        group     = self.query_one("#inp-bulk-group",   Input).value.strip()
        account   = self.query_one("#sel-bulk-account", Select).value
        defqos    = self.query_one("#sel-bulk-defqos",  Select).value
        extra_raw = self.query_one("#inp-bulk-extraqos",Input).value.strip()
        extra_qos = [q.strip() for q in extra_raw.split(",") if q.strip()]
        status    = self.query_one("#modal-bulk-status", Label)

        if not group:
            status.update("[red]Enter an AD group name.[/]"); return
        if account is Select.BLANK or defqos is Select.BLANK:
            status.update("[red]Select account and QoS.[/]"); return

        status.update("[yellow]Looking up AD group members…[/]")
        rc, out, err = run([
            "ldapsearch", "-H", LDAP_URI, "-x",
            "-D", _AD_BIND_DN, "-w", _AD_BIND_PW,
            "-b", LDAP_BASE,
            f"(cn={group})", "member"
        ])
        if rc != 0 or not out:
            status.update(f"[red]ldapsearch failed: {err or 'group not found'}[/]"); return

        members = []
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("member:"):
                dn = line.split(":", 1)[1].strip()
                m = re.match(r"CN=([^,]+)", dn, re.IGNORECASE)
                if m:
                    members.append(m.group(1))

        if not members:
            status.update(f"[red]No members found in group '{group}'.[/]"); return

        status.update(f"[yellow]Adding {len(members)} users…[/]")
        ok_count = 0
        fail_msgs = []
        for user in members:
            ok, msg = sacct_add_or_update_user(user, str(account), str(defqos), extra_qos)
            if ok:
                ok_count += 1
            else:
                fail_msgs.append(f"{user}: {msg}")

        summary = f"Imported {ok_count}/{len(members)} users from {group} → {account}"
        if fail_msgs:
            summary += f" ({len(fail_msgs)} errors)"
        self.dismiss((group, str(account), str(defqos), extra_qos, summary, fail_msgs))


class ADCredentialsModal(ModalScreen):
    BINDINGS = [Binding("escape", "exit_app", "Exit")]

    def compose(self) -> ComposeResult:
        with Vertical(id="modal-box"):
            yield Label("── AD Authentication Required ──", id="modal-title")
            yield Static(
                "[dim]Credentials are stored in memory only, never written to disk.[/]"
            )
            yield Label("AD Username:")
            yield Input(placeholder="AD Username", id="inp-ad-user")
            yield Label("AD Password:")
            yield Input(placeholder="AD Password", password=True, id="inp-ad-pw")
            with Horizontal(id="modal-buttons"):
                yield Button("Connect", variant="primary", id="btn-ad-ok")
                yield Button("Exit",    variant="error",   id="btn-ad-exit")
            yield Label("", id="modal-ad-status")

    def action_exit_app(self) -> None:
        self.app.exit()

    @on(Button.Pressed, "#btn-ad-exit")
    def do_exit(self): self.app.exit()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-ad-ok":
            self._try_connect()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self._try_connect()

    def _try_connect(self) -> None:
        username = self.query_one("#inp-ad-user", Input).value.strip()
        password = self.query_one("#inp-ad-pw",   Input).value
        status   = self.query_one("#modal-ad-status", Label)
        if not username or not password:
            status.update("[red]Please enter both username and password.[/]")
            return
        status.update("[yellow]Testing connection…[/]")
        set_ad_credentials(username, password)
        ok, err = test_ad_credentials()
        if ok:
            self.dismiss(True)
        else:
            status.update(f"[red]Authentication failed: {err}[/]")


class ManageUserModal(ModalScreen):
    BINDINGS = [Binding("escape", "dismiss", "Cancel")]

    def __init__(self, username: str = "", all_assocs: list = None):
        super().__init__()
        self._username  = username
        self._assocs    = all_assocs or []
        self._dirty     = False

    @staticmethod
    def _fetch_live_accounts():
        if DEMO_MODE:
            return list(ACCOUNT_DEFINITIONS.keys())
        try:
            r = subprocess.run(
                ["sacctmgr", "show", "accounts", "-n", "-P", "format=Account"],
                capture_output=True, text=True, timeout=10
            )
            if r.returncode == 0:
                accounts = [l.strip() for l in r.stdout.splitlines() if l.strip()]
                if accounts:
                    return sorted(accounts)
        except Exception:
            pass
        return list(ACCOUNT_DEFINITIONS.keys())

    @staticmethod
    def _fetch_live_qos():
        if DEMO_MODE:
            return list(QOS_DEFINITIONS.keys())
        try:
            r = subprocess.run(
                ["sacctmgr", "show", "qos", "-n", "-P", "format=Name"],
                capture_output=True, text=True, timeout=10
            )
            if r.returncode == 0:
                qos_list = [l.strip() for l in r.stdout.splitlines() if l.strip()]
                if qos_list:
                    return sorted(qos_list)
        except Exception:
            pass
        return list(QOS_DEFINITIONS.keys())

    def compose(self):
        live_accounts = self._fetch_live_accounts()
        live_qos      = self._fetch_live_qos()
        account_opts  = [(a, a) for a in live_accounts]
        qos_opts      = [(q, q) for q in live_qos]
        is_update     = bool(self._username)

        with Vertical(id="modal-box"):
            title = f"── Manage User: {self._username} ──" if is_update else "── Add New User to sacctmgr ──"
            yield Label(title, id="modal-title")
            yield Label("AD Username:")
            yield Input(value=self._username,
                        placeholder="e.g. jsmith",
                        id="inp-user",
                        disabled=is_update)

            if self._assocs:
                yield Label("[bold]Current associations:[/]", id="lbl-assocs")
                with ScrollableContainer(id="assoc-list"):
                    for i, a in enumerate(self._assocs):
                        acc     = a["Account"]
                        defqos  = a.get("DefQOS", "")
                        qos     = a.get("QOS", "")
                        all_qos = [q.strip() for q in qos.split(",") if q.strip()]
                        extra   = ", ".join(q for q in all_qos if q != defqos)
                        with Horizontal(classes="assoc-row"):
                            yield Label(f"[bold]{acc}[/]", classes="assoc-acc-lbl")
                            yield Label(f"defqos=[cyan]{defqos}[/]", classes="assoc-qos-lbl")
                            yield Button("✎ Edit",   id=f"assoc-edit-{i}",   variant="default", classes="assoc-btn")
                            yield Button("✕ Remove", id=f"assoc-remove-{i}", variant="error",   classes="assoc-btn")

            yield Rule()
            add_label = "Add to account:" if self._assocs else "Slurm Account:"
            yield Label(add_label)
            yield Select(account_opts, id="sel-account", prompt="Select account…")
            yield Label("Default QoS:")
            yield Select(qos_opts, id="sel-defqos", prompt="Select default QoS…")
            yield Label("Additional QoS (comma-separated, or leave blank):")
            yield Input(placeholder="e.g. a6000_full,research", id="inp-extraqos")
            yield Static(
                "[dim]Note: partition access is controlled by AllowGroups in slurm.conf,\n"
                "not by sacctmgr. This only sets accounting/QoS limits.[/]"
            )
            with Horizontal(id="modal-buttons"):
                btn_label = "Add to Account" if self._assocs else "Add User"
                yield Button(btn_label, variant="primary", id="btn-ok")
                yield Button("Done",   variant="success", id="btn-done")
            yield Label("", id="modal-status")

    def on_mount(self):
        if self._assocs:
            first = self._assocs[0]
            live_accounts = self._fetch_live_accounts()
            live_qos      = self._fetch_live_qos()
            if first["Account"] in live_accounts:
                self.query_one("#sel-account", Select).value = first["Account"]
            if first.get("DefQOS", "") in live_qos:
                self.query_one("#sel-defqos", Select).value = first["DefQOS"]
            all_qos = [q.strip() for q in first.get("QOS", "").split(",") if q.strip()]
            extra   = ", ".join(q for q in all_qos if q != first.get("DefQOS", ""))
            self.query_one("#inp-extraqos", Input).value = extra

    @on(Button.Pressed)
    def _btn(self, event):
        event.stop()
        bid = event.button.id or ""
        if bid == "btn-done":
            self.dismiss(("__refresh__" if self._dirty else None))
            return
        if bid == "btn-ok":
            try:
                self._do_add()
            except Exception as e:
                self._set_status(f"[red]Error: {e}[/]")
            return
        if bid.startswith("assoc-edit-"):
            try:
                idx = int(bid.split("-")[-1])
                self._do_edit(idx)
            except Exception as e:
                self._set_status(f"[red]Error: {e}[/]")
            return
        if bid.startswith("assoc-remove-"):
            try:
                idx = int(bid.split("-")[-1])
                self._do_remove(idx)
            except Exception as e:
                self._set_status(f"[red]Error: {e}[/]")
            return

    def _set_status(self, msg):
        try:
            self.query_one("#modal-status", Label).update(msg)
        except Exception:
            pass
        clean = msg.replace("[red]", "").replace("[green]", "").replace("[/]", "").replace("[dim]", "")
        self.app.notify(clean, timeout=4)

    def _do_add(self):
        username  = self.query_one("#inp-user",    Input).value.strip()
        account   = self.query_one("#sel-account", Select).value
        defqos    = self.query_one("#sel-defqos",  Select).value
        extra_raw = self.query_one("#inp-extraqos", Input).value.strip()
        extra_qos = [q.strip() for q in extra_raw.split(",") if q.strip()]
        if not username:
            self._set_status("[red]Enter a username.[/]"); return
        if account is Select.BLANK or defqos is Select.BLANK:
            self._set_status("[red]Select account and QoS.[/]"); return
        ok, msg = sacct_add_or_update_user(
            username, str(account), str(defqos), extra_qos, prev_account=""
        )
        if ok:
            self._dirty = True
            self._set_status(f"[green]✓ {msg}[/]")
        else:
            self._set_status(f"[red]✗ {msg}[/]")

    def _do_edit(self, idx):
        if idx >= len(self._assocs):
            return
        a       = self._assocs[idx]
        acc     = a["Account"]
        defqos  = a.get("DefQOS", "")
        all_qos = [q.strip() for q in a.get("QOS", "").split(",") if q.strip()]
        extra   = ", ".join(q for q in all_qos if q != defqos)
        live_accounts = self._fetch_live_accounts()
        live_qos      = self._fetch_live_qos()
        if acc in live_accounts:
            self.query_one("#sel-account", Select).value = acc
        if defqos in live_qos:
            self.query_one("#sel-defqos", Select).value = defqos
        self.query_one("#inp-extraqos", Input).value = extra
        self._set_status(f"[dim]Loaded {acc} — edit values above and click Add to Account to apply.[/]")

    def _do_remove(self, idx):
        if idx >= len(self._assocs):
            return
        a   = self._assocs[idx]
        acc = a["Account"]
        username = self._username
        if len(self._assocs) == 1:
            self._set_status(f"[red]Cannot remove last association. Remove user entirely instead.[/]")
            return
        other_accounts = [x["Account"] for x in self._assocs if x["Account"] != acc]
        if other_accounts:
            run(["sacctmgr", "-i", "modify", "user", username,
                 "set", f"defaultaccount={other_accounts[0]}"])
        ok, msg = sacct_remove_user(username, acc)
        if ok:
            self._dirty = True
            self._assocs.pop(idx)
            self._set_status(f"[green]✓ {msg} — refresh to update list[/]")
        else:
            self._set_status(f"[red]✗ {msg}[/]")


AddUserModal = ManageUserModal


class RemoveUserModal(ModalScreen):
    BINDINGS = [Binding("escape", "dismiss", "Cancel")]

    def __init__(self, username: str, account: str):
        super().__init__()
        self.username = username
        self.account  = account

    def compose(self) -> ComposeResult:
        with Vertical(id="modal-box"):
            yield Label("── Remove User from sacctmgr ──", id="modal-title")
            yield Static(
                f"Remove [bold]{self.username}[/] from account [bold]{self.account}[/]?\n\n"
                f"Command: sacctmgr remove user {self.username} Account={self.account} -i\n\n"
                "[dim]This removes accounting/QoS associations only.\n"
                "Partition access via AllowGroups is unchanged.[/]"
            )
            with Horizontal(id="modal-buttons"):
                yield Button("Remove", variant="error",   id="btn-remove")
                yield Button("Cancel", variant="default", id="btn-cancel")
            yield Label("", id="modal-status")

    @on(Button.Pressed, "#btn-cancel")
    def cancel(self): self.dismiss(None)

    @on(Button.Pressed, "#btn-remove")
    def do_remove(self):
        ok, msg = sacct_remove_user(self.username, self.account)
        self.dismiss((ok, msg))


class PartitionDetailModal(ModalScreen):
    BINDINGS = [Binding("escape", "dismiss", "Close")]

    def __init__(self, pname: str):
        super().__init__()
        self.pname = pname

    def compose(self) -> ComposeResult:
        p = PARTITION_DEFINITIONS.get(self.pname, {})
        allow_grps = ", ".join(p.get("allow_groups", [])) or "ALL"
        allow_qos  = ", ".join(p.get("allow_qos", []))    or "ALL"
        deny_grps  = ", ".join(p.get("deny_groups", []))  or "none"
        with Vertical(id="modal-box"):
            yield Label(f"── {self.pname} ──", id="modal-title")
            yield Static(
                f"[bold]Description:[/]  {p.get('description','')}\n\n"
                f"[bold]Nodes:[/]        {p.get('nodes','')}\n"
                f"[bold]Default QoS:[/]  {p.get('qos','')}\n"
                f"[bold]AllowGroups:[/]  {allow_grps}\n"
                f"[bold]AllowQoS:[/]     {allow_qos}\n"
                f"[bold]DenyGroups:[/]   {deny_grps}\n"
                f"[bold]MaxTime:[/]      {p.get('max_time','')}\n"
                f"[bold]Default:[/]      {'YES' if p.get('default') else 'NO'}\n"
            )
            yield Button("Close [Esc]", variant="default", id="btn-close")

    @on(Button.Pressed, "#btn-close")
    def close(self): self.dismiss(None)


class ConfirmDeleteModal(ModalScreen):
    BINDINGS = [Binding("escape", "dismiss", "Cancel")]

    def __init__(self, entries: list[ScratchEntry]):
        super().__init__()
        self.entries = entries

    def compose(self) -> ComposeResult:
        total_str = fmt_bytes(sum(e.size_kb for e in self.entries) * 1024)
        with Vertical(id="modal-box"):
            yield Label(f"⚠  DELETE {len(self.entries)} item(s)  —  {total_str} total", id="modal-title")
            yield Static("[dim]The following will be permanently deleted:[/]")
            with ScrollableContainer(id="modal-list"):
                for e in self.entries:
                    s = "bold red" if e.age_days >= STALE_DAYS else "yellow"
                    yield Label(f"  [{s}]{e.node}:{e.path}[/{s}]  [dim]{e.size_human}  {e.age_label}  owner={e.owner}[/]")
            yield Static("\n[bold red]This cannot be undone.[/bold red]  Active-job entries are excluded automatically.")
            with Horizontal(id="modal-buttons"):
                yield Button("YES — Delete permanently", variant="error",   id="btn-yes")
                yield Button("Cancel",                   variant="default", id="btn-no")

    @on(Button.Pressed, "#btn-no")
    def cancel(self): self.dismiss(False)

    @on(Button.Pressed, "#btn-yes")
    def confirm(self): self.dismiss(True)


# ──────────────────────────────────────────────────────────────────────────────
# NetFreeze widgets
# ──────────────────────────────────────────────────────────────────────────────

class NfNodePanel(Widget):
    DEFAULT_CSS = """
    NfNodePanel {
        height: 3;
        border: solid $panel-lighten-2;
        margin: 0;
    }
    NfNodePanel.expanded { height: 24; }
    NfNodePanel.freeze   { border: heavy $error; }
    NfNodePanel.warn     { border: solid $warning; }
    NfNodePanel.ok       { border: solid $success; }
    NfNodePanel.off      { border: solid $panel; }

    NfNodePanel .nf-header {
        height: 1;
        padding: 0 1;
        background: $panel-lighten-1;
    }
    NfNodePanel .nf-header.freeze { background: $error;         color: white; text-style: bold; }
    NfNodePanel .nf-header.warn   { background: $warning 70%;   color: white; }
    NfNodePanel .nf-header.ok     { background: $success 40%; }

    NfNodePanel .nf-status { height: 1; padding: 0 1; background: $panel-darken-1; }

    NfNodePanel RichLog {
        height: 1fr;
        scrollbar-size: 1 1;
        display: none;
    }
    NfNodePanel.expanded RichLog { display: block; }
    """

    freeze_state = reactive("off")

    def __init__(self, state: NfNodeState, **kwargs):
        super().__init__(**kwargs)
        self.node_state = state
        self._expanded  = False

    def compose(self) -> ComposeResult:
        ns = self.node_state
        yield Static(f" ◉ {ns.name}  [{ns.host}]", classes="nf-header", id=f"nfhdr-{ns.name}")
        yield Static("", classes="nf-status",                             id=f"nfsts-{ns.name}")
        yield RichLog(highlight=False, markup=True,                       id=f"nflog-{ns.name}", wrap=False)

    def on_click(self) -> None:
        self._expanded = not self._expanded
        self.set_class(self._expanded, "expanded")
        self.update_header()

    def update_header(self):
        ns    = self.node_state
        state = self.freeze_state
        icon  = {"freeze": "!", "warn": "~", "ok": "+", "off": "-"}.get(state, "-")
        freeze_tag  = f"  [bold red]FREEZE ACTIVE ({ns.freeze_count})[/]" if state == "freeze" else ""
        deploy_tag  = f"  [dim]deploy:{ns.deploy_status}[/]"
        monitor_tag = f"  [dim]svc:{ns.monitor_status}[/]"
        bond_tag    = "  [dim cyan]bond[/]" if ns.has_bond else ""
        expand_hint = "  [dim]collapse[/]" if self._expanded else "  [dim]expand[/]"
        try:
            hdr = self.query_one(f"#nfhdr-{ns.name}", Static)
            hdr.update(f" [{icon}] {ns.name}  [{ns.host}]{bond_tag}{deploy_tag}{monitor_tag}{freeze_tag}{expand_hint}")
            hdr.remove_class("freeze", "warn", "ok")
            if state != "off": hdr.add_class(state)
        except NoMatches:
            pass
        try:
            sts = self.query_one(f"#nfsts-{ns.name}", Static)
            ssh_color = {"ok": "green", "error": "red", "connecting": "yellow"}.get(ns.ssh_status, "dim")
            ssh_tag   = f"[{ssh_color}]ssh:{ns.ssh_status}[/]"
            err       = f"  [red dim]{ns.error_msg[:60]}[/]" if ns.error_msg else ""
            ts_tag    = ""
            if ns.last_event_time:
                elapsed = int(time.time() - ns.last_event_time)
                if elapsed < 60:
                    age = f"{elapsed}s ago"
                elif elapsed < 3600:
                    age = f"{elapsed//60}m ago"
                else:
                    age = f"{elapsed//3600}h {(elapsed%3600)//60}m ago"
                ts_tag = f"  [dim]last event: {ns.last_event_str}  ({age})[/]"
            sts.update(f" {ssh_tag}{ts_tag}{err}")
        except NoMatches:
            pass
        self.remove_class("freeze", "warn", "ok", "off")
        self.add_class(state if state != "off" else "off")

    def append_log_line(self, line: str):
        kind      = nf_classify_line(line)
        color_map = {"freeze": "bold red", "warn": "yellow", "recover": "green", "normal": "dim white"}
        style     = color_map.get(kind, "white")
        try:
            self.query_one(f"#nflog-{self.node_state.name}", RichLog).write(f"[{style}]{line}[/]")
        except NoMatches:
            pass
        if kind in ("freeze", "warn", "recover"):
            ts = nf_parse_log_timestamp(line)
            if ts:
                self.node_state.last_event_time = ts
                m = _NF_TS_RE.search(line)
                self.node_state.last_event_str  = m.group(1) if m else ""
        self.update_header()

    def set_state_from_batch(self, lines: list[str]):
        last_kind = None
        last_line = ""
        for line in lines:
            k = nf_classify_line(line)
            if k in ("freeze", "warn", "recover"):
                last_kind = k
                last_line = line
        if last_line:
            ts = nf_parse_log_timestamp(last_line)
            if ts:
                self.node_state.last_event_time = ts
                m = _NF_TS_RE.search(last_line)
                self.node_state.last_event_str  = m.group(1) if m else ""
        if last_kind == "freeze":
            self.node_state.freeze_active = True
            self.node_state.freeze_count += 1
            self.freeze_state = "freeze"
        elif last_kind == "recover":
            self.node_state.freeze_active = False
            self.freeze_state = "ok"
        elif last_kind == "warn":
            if self.freeze_state != "freeze":
                self.freeze_state = "warn"
        self.update_header()

    def watch_freeze_state(self, _state: str):
        self.update_header()

    def clear_log(self):
        try:
            self.query_one(f"#nflog-{self.node_state.name}", RichLog).clear()
        except NoMatches:
            pass


class NfNodeRow(Static):
    def __init__(self, node: NfNodeState, **kwargs):
        self._node = node
        self._sel  = True
        super().__init__(f"[bold green]+[/] [green]{node.name}[/]  [dim]{node.host}[/]", **kwargs)

    @property
    def selected(self): return self._sel

    def on_click(self):
        self._sel = not self._sel
        if self._sel:
            self.update(f"[bold green]+[/] [green]{self._node.name}[/]  [dim]{self._node.host}[/]")
        else:
            self.update(f"[bold red]-[/] [dim]{self._node.name}[/]  [dim]{self._node.host}[/]")


class NfDeployScreen(ModalScreen):
    DEFAULT_CSS = """
    NfDeployScreen { align: center middle; }
    NfDeployScreen > Container {
        width: 80; height: 46;
        border: thick $primary;
        background: $surface;
        padding: 1 2;
    }
    NfDeployScreen .nf-node-list  { height: 13; border: solid $panel; margin: 0 0 1 0; padding: 0 1; }
    NfDeployScreen .nf-node-row   { height: 1; padding: 0 1; }
    NfDeployScreen .nf-node-row:hover { background: $boost; }
    NfDeployScreen .nf-deploy-log { height: 16; border: solid $panel; margin: 0 0 1 0; }
    NfDeployScreen .nf-btn-row    { height: 3; align: center middle; }
    """

    def __init__(self, nodes: list[NfNodeState], config: dict, **kwargs):
        super().__init__(**kwargs)
        self.nodes = nodes
        self.cfg   = config

    def compose(self) -> ComposeResult:
        with Container():
            yield Label("Deploy Network Freeze Monitor Suite")
            yield Rule()
            yield Label("Click nodes to toggle (green=selected):")
            with ScrollableContainer(classes="nf-node-list"):
                for node in self.nodes:
                    yield NfNodeRow(node, id=f"nfnb-{node.name}", classes="nf-node-row")
            yield RichLog(id="nf-deploy-log", classes="nf-deploy-log", highlight=False, markup=True)
            with Horizontal(classes="nf-btn-row"):
                yield Button("Deploy Selected", id="nf-btn-deploy", variant="primary")
                yield Button("Close",           id="nf-btn-close")

    @on(Button.Pressed, "#nf-btn-deploy")
    async def do_deploy(self):
        self.query_one("#nf-btn-deploy", Button).disabled = True
        log      = self.query_one("#nf-deploy-log", RichLog)
        selected = []
        for node in self.nodes:
            try:
                row = self.query_one(f"#nfnb-{node.name}", NfNodeRow)
                if row.selected: selected.append(node)
            except Exception:
                selected.append(node)
        if not selected:
            log.write("[yellow]No nodes selected.[/]")
            self.query_one("#nf-btn-deploy", Button).disabled = False
            return
        src = Path(self.cfg["deploy_src"])
        if not src.exists():
            log.write(f"[red]Deploy source not found: {src.resolve()}[/]")
            self.query_one("#nf-btn-deploy", Button).disabled = False
            return
        for node in selected:
            await self._deploy_node(node, log)
        log.write("\n[bold green]Deployment complete.[/]")
        self.query_one("#nf-btn-deploy", Button).disabled = False

    async def _deploy_node(self, node: NfNodeState, log: RichLog):
        log.write(f"\n[bold cyan]── {node.name} ({node.host}) ──[/]")
        node.deploy_status = "deploying"
        conn, err = await nf_ssh_connect(node.host, self.cfg["ssh_user"], self.cfg["ssh_key"])
        if not conn:
            log.write(f"[red]  SSH failed: {err}[/]")
            node.deploy_status = "failed"
            return
        log.write("[green]  Connected[/]")
        await nf_ssh_run(conn, f"mkdir -p {self.cfg['remote_install_dir']}")
        src = Path(self.cfg["deploy_src"])
        try:
            async with conn.start_sftp_client() as sftp:
                for script in sorted(src.glob("*.sh")):
                    remote = f"{self.cfg['remote_install_dir']}/{script.name}"
                    await sftp.put(str(script), remote)
                    log.write(f"  [dim]-> {script.name}[/]")
        except Exception as e:
            log.write(f"[red]  SFTP failed: {e}[/]")
            node.deploy_status = "failed"
            conn.close()
            return
        stdout, stderr, rc = await nf_ssh_run(
            conn,
            f"chmod +x {self.cfg['remote_install_dir']}/*.sh && "
            f"sudo bash {self.cfg['remote_install_dir']}/install.sh 2>&1",
            timeout=60
        )
        for line in stdout.splitlines():
            log.write(f"  [dim]{line}[/]")
        if rc == 0:
            log.write("[bold green]  Installed & services started[/]")
            node.deploy_status  = "deployed"
            node.monitor_status = "running"
        else:
            log.write(f"[red]  Install failed (rc={rc})[/]")
            if stderr: log.write(f"[red dim]  {stderr[:200]}[/]")
            node.deploy_status = "failed"
        conn.close()

    @on(Button.Pressed, "#nf-btn-close")
    def close_screen(self): self.dismiss()


class NfSettingsScreen(ModalScreen):
    DEFAULT_CSS = """
    NfSettingsScreen { align: center middle; }
    NfSettingsScreen > Container {
        width: 70; height: 26;
        border: thick $accent;
        background: $surface;
        padding: 1 2;
    }
    NfSettingsScreen .nf-field-row { height: 3; }
    NfSettingsScreen .nf-btn-row   { height: 3; align: center middle; margin-top: 1; }
    """

    def __init__(self, config: dict, **kwargs):
        super().__init__(**kwargs)
        self.cfg = config

    def compose(self) -> ComposeResult:
        with Container():
            yield Label("NetFreeze Settings")
            yield Rule()
            with Horizontal(classes="nf-field-row"):
                yield Label("SSH User:   ")
                yield Input(value=self.cfg["ssh_user"],       id="nf-inp-user")
            with Horizontal(classes="nf-field-row"):
                yield Label("SSH Key:    ")
                yield Input(value=self.cfg["ssh_key"],        id="nf-inp-key")
            with Horizontal(classes="nf-field-row"):
                yield Label("Deploy Src: ")
                yield Input(value=self.cfg["deploy_src"],     id="nf-inp-src")
            with Horizontal(classes="nf-field-row"):
                yield Label("Poll (sec): ")
                yield Input(value=str(self.cfg["poll_interval"]), id="nf-inp-poll")
            with Horizontal(classes="nf-field-row"):
                yield Label("Tail lines: ")
                yield Input(value=str(self.cfg["tail_lines"]),    id="nf-inp-tail")
            with Horizontal(classes="nf-btn-row"):
                yield Button("Save",   id="nf-btn-save", variant="primary")
                yield Button("Cancel", id="nf-btn-cancel")

    @on(Button.Pressed, "#nf-btn-save")
    def save(self):
        self.cfg["ssh_user"]   = self.query_one("#nf-inp-user", Input).value
        self.cfg["ssh_key"]    = self.query_one("#nf-inp-key",  Input).value
        self.cfg["deploy_src"] = self.query_one("#nf-inp-src",  Input).value
        try: self.cfg["poll_interval"] = int(self.query_one("#nf-inp-poll", Input).value)
        except ValueError: pass
        try: self.cfg["tail_lines"] = int(self.query_one("#nf-inp-tail", Input).value)
        except ValueError: pass
        NF_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        NF_CONFIG_FILE.write_text(json.dumps(self.cfg, indent=2))
        self.dismiss(True)

    @on(Button.Pressed, "#nf-btn-cancel")
    def cancel(self): self.dismiss(False)


# ──────────────────────────────────────────────────────────────────────────────
# Shared widget
# ──────────────────────────────────────────────────────────────────────────────

class StatusBar(Static):
    message = reactive("")
    def render(self) -> str: return self.message
    def set_msg(self, msg: str, style: str = "bold white"):
        self.message = f"[{style}]{msg}[/{style}]"


# ──────────────────────────────────────────────────────────────────────────────
# ZFS Quota Tab
# ──────────────────────────────────────────────────────────────────────────────

# Update these to match your TrueNAS hosts and datasets
ZFS_QUOTA_DATASETS = [
    ("home  (nas1)",     "nas1-hostname", "tank/home"),
    ("projects (nas2)",  "nas2-hostname", "tank/projects"),
]

QUOTA_PRESETS = ["none", "50G", "100G", "200G", "500G", "1T", "2T", "5T"]


def zfs_resolve_uid(uid):
    try:
        uid_int = int(uid)
    except ValueError:
        return uid
    if uid_int < 1000:
        return uid
    rc, out, _ = run_local(["getent", "passwd", uid], timeout=5)
    if rc == 0 and out:
        return out.split(":")[0]
    return uid


def zfs_fetch_userspace(host, dataset):
    if DEMO_MODE:
        return [
            {"uid": "1001", "username": "researcher1", "used": "47.5G", "quota": "none"},
            {"uid": "1002", "username": "student1",    "used": "11.8G", "quota": "500G"},
            {"uid": "1000", "username": "admin1",      "used": "3.24G", "quota": "none"},
        ]
    cmd = f"sudo zfs userspace -H -o type,name,used,quota {dataset}"
    rc, out, err = ssh(host, cmd, timeout=30)
    if rc != 0 or not out:
        return []
    rows = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) != 4:
            continue
        typ, uid, used, quota = parts
        if typ not in ("POSIX User", "SMB User"):
            continue
        username = zfs_resolve_uid(uid)
        rows.append({"uid": uid, "username": username, "used": used, "quota": quota})
    rows.sort(key=lambda r: r["username"].lower())
    return rows


def zfs_set_quota(host, dataset, username, value):
    if DEMO_MODE:
        return 0, ""
    cmd = f"sudo zfs set userquota@{username}={value} {dataset}"
    rc, _, err = ssh(host, cmd, timeout=15)
    return rc, err


class SetQuotaModal(ModalScreen):

    BINDINGS = [("escape", "dismiss(None)", "Cancel")]

    def __init__(self, username, current_quota, dataset_label):
        super().__init__()
        self._username = username
        self._current = current_quota
        self._dataset_label = dataset_label

    def compose(self):
        with Vertical(id="quota-modal-box"):
            yield Label(f"[bold]Set quota for:[/] {self._username}")
            yield Label(f"[dim]Dataset: {self._dataset_label}[/]")
            yield Label(f"[dim]Current quota: {self._current}[/]")
            yield Rule()
            yield Label("Quick presets:")
            with Horizontal(id="quota-preset-row"):
                for p in QUOTA_PRESETS:
                    yield Button(p, id=f"qpreset-{p}", variant="default")
            yield Rule()
            yield Label("Custom value (e.g. 750G, 1.5T, none):")
            yield Input(placeholder="Enter quota value…", id="quota-custom-input")
            yield Rule()
            with Horizontal(id="quota-modal-btns"):
                yield Button("Apply",  id="quota-apply-btn",  variant="primary")
                yield Button("Cancel", id="quota-cancel-btn", variant="default")

    @on(Button.Pressed)
    def _btn(self, event):
        bid = event.button.id or ""
        if bid == "quota-cancel-btn":
            self.dismiss(None)
        elif bid.startswith("qpreset-"):
            self.query_one("#quota-custom-input", Input).value = bid[len("qpreset-"):]
        elif bid == "quota-apply-btn":
            val = self.query_one("#quota-custom-input", Input).value.strip()
            if val:
                self.dismiss(val)

    @on(Input.Submitted, "#quota-custom-input")
    def _submit(self, event):
        val = event.value.strip()
        if val:
            self.dismiss(val)


class ZfsQuotaTab(Widget):

    DEFAULT_CSS = """
    ZfsQuotaTab { height: 1fr; }
    #quota-dataset-bar { height: 3; padding: 0 1; }
    #quota-dataset-bar Button { margin-right: 1; }
    #quota-table-wrap { height: 1fr; }
    #quota-action-bar { height: 3; padding: 0 1; }
    #quota-status { height: 1; padding: 0 1; }
    """

    def __init__(self):
        super().__init__()
        self._current = ZFS_QUOTA_DATASETS[0]
        self._rows = []

    def compose(self):
        with Horizontal(id="quota-dataset-bar"):
            yield Label("[bold]Dataset:[/] ")
            for label, host, dataset in ZFS_QUOTA_DATASETS:
                safe_id = dataset.replace("/", "-")
                variant = "primary" if (label, host, dataset) == self._current else "default"
                yield Button(label, id=f"quota-ds-{safe_id}", variant=variant)
            yield Button("Refresh", id="quota-refresh-btn", variant="default")
        with ScrollableContainer(id="quota-table-wrap"):
            t = DataTable(id="quota-table", cursor_type="row")
            t.add_columns("Username", "UID", "AD Group", "Used", "Quota")
            yield t
        with Horizontal(id="quota-action-bar"):
            yield Button("Set Quota",   id="quota-set-btn",        variant="primary")
            yield Button("Clear Quota", id="quota-clear-btn",      variant="warning")
            yield Button("Refresh AD",  id="quota-refresh-ad-btn", variant="default")
        yield Static("Press Refresh or switch dataset to load.", id="quota-status")

    @on(Button.Pressed)
    def _btn(self, event):
        bid = event.button.id or ""
        if bid == "quota-refresh-btn":
            self._load_dataset(self._current)
        elif bid == "quota-set-btn":
            self._action_set_quota()
        elif bid == "quota-clear-btn":
            self._action_clear_quota()
        elif bid == "quota-refresh-ad-btn":
            self.app.action_refresh_ad()
            if self._current:
                self._load_dataset(self._current)
        elif bid.startswith("quota-ds-"):
            safe = bid[len("quota-ds-"):]
            for entry in ZFS_QUOTA_DATASETS:
                label, host, dataset = entry
                if dataset.replace("/", "-") == safe:
                    for _l, _h, ds in ZFS_QUOTA_DATASETS:
                        sid = ds.replace("/", "-")
                        try:
                            self.query_one(f"#quota-ds-{sid}", Button).variant = (
                                "primary" if ds == dataset else "default"
                            )
                        except Exception:
                            pass
                    self._load_dataset(entry)
                    return

    def _load_dataset(self, entry):
        self._current = entry
        label, host, dataset = entry
        self._set_status(f"[dim]Loading {dataset} from {host}…[/]")
        self.run_worker(self._worker_load(host, dataset), exclusive=True, thread=True)

    async def _worker_load(self, host, dataset):
        rows = await asyncio.get_event_loop().run_in_executor(
            None, zfs_fetch_userspace, host, dataset
        )
        self.app.call_from_thread(self._populate_table, rows, dataset)

    def _populate_table(self, rows, dataset):
        self._rows = rows
        t = self.query_one("#quota-table", DataTable)
        t.clear()
        hpc_child_map = getattr(self.app, "hpc_child_map", {})
        for r in rows:
            quota_display = (
                f"[yellow]{r['quota']}[/]" if r["quota"] != "none"
                else "[dim]none[/]"
            )
            ad_group = hpc_child_map.get(r["username"], "[dim]—[/]")
            t.add_row(r["username"], r["uid"], ad_group, r["used"], quota_display)
        self._set_status(
            f"[green]{dataset}[/]  —  {len(rows)} users  |  "
            f"Select row then [bold]Set Quota[/] or [bold]Clear Quota[/]"
        )

    def _selected_row(self):
        t = self.query_one("#quota-table", DataTable)
        if t.cursor_row < 0 or t.cursor_row >= len(self._rows):
            return None
        return self._rows[t.cursor_row]

    def _action_set_quota(self):
        row = self._selected_row()
        if not row:
            self._set_status("[red]Select a user row first.[/]")
            return
        label, host, dataset = self._current
        self.app.push_screen(
            SetQuotaModal(row["username"], row["quota"], label),
            lambda val: self._apply_quota(val, row, host, dataset),
        )

    def _action_clear_quota(self):
        row = self._selected_row()
        if not row:
            self._set_status("[red]Select a user row first.[/]")
            return
        label, host, dataset = self._current
        self._apply_quota("none", row, host, dataset)

    def _apply_quota(self, value, row, host, dataset):
        if not value:
            return
        uid = row["uid"]
        self._set_status(f"[dim]Setting quota {value} for {row['username']} (uid {uid}) on {dataset}…[/]")
        self.run_worker(
            self._worker_set(host, dataset, uid, value),
            exclusive=False,
            thread=True,
        )

    async def _worker_set(self, host, dataset, username, value):
        rc, err = await asyncio.get_event_loop().run_in_executor(
            None, zfs_set_quota, host, dataset, username, value
        )
        self.app.call_from_thread(self._after_set, rc, err, username, value, dataset)

    def _after_set(self, rc, err, username, value, dataset):
        if rc == 0:
            self._set_status(f"[green]Quota set to {value} for {username} on {dataset}[/]")
            self._load_dataset(self._current)
        else:
            self._set_status(f"[red]Failed: {err}[/]")

    def _set_status(self, msg):
        try:
            self.query_one("#quota-status", Static).update(msg)
        except Exception:
            pass


class HpcAdminTUI(App):
    CSS   = CSS
    TITLE = "HPC Admin"

    BINDINGS = [
        Binding("q",     "quit",             "Quit"),
        Binding("r",     "refresh_slurm",    "Refresh Slurm",   show=False),
        Binding("a",     "add_user",         "Add/Update User",  show=False),
        Binding("d",     "remove_user",      "Remove User",      show=False),
        Binding("R",     "refresh_sync",     "Check All",        show=False),
        Binding("s",     "sync_selected",    "Sync selected",    show=False),
        Binding("S",     "sync_mismatches",  "Sync mismatches",  show=False),
        Binding("D",     "diff_selected",    "Diff",             show=False),
        Binding("n",     "reload_nodes",     "Reload nodes",     show=False),
        Binding("escape","deselect",         "Deselect",         show=False),
        Binding("ctrl+r","scratch_scan_all", "Scan scratch",     show=False),
        Binding("space", "scratch_toggle",   "Toggle sel.",      show=False),
        Binding("ctrl+a","scratch_sel_stale","Sel stale",        show=False),
        Binding("ctrl+d","scratch_delete",   "Delete sel.",      show=False),
        Binding("f1",    "show_help",        "Help"),
    ]

    def __init__(self):
        super().__init__()
        self.assoc:    list[dict]            = []
        self.accounts: dict[str, list[str]] = {}
        self.ad_users: dict[str, list[str]] = {}
        self.hpc_child_map: dict[str, str]  = {}
        self.qos_data: list[dict]            = []
        self._sel_account: Optional[str] = None
        self._sel_user:    Optional[str] = None
        self._sort_state: dict[str, tuple[str, bool]] = {}
        self.node_groups:        list[tuple[str, list[str]]] = []
        self.sync_nodes:         list[str]                   = []
        self.matrix:             dict[str, dict[int, dict]]  = {}
        self.proxy_data:         dict[str, dict]              = {}
        self._master_proxy_vars: dict[str, str]              = {}
        self._selected_node:     Optional[str]               = None
        self._selected_file_idx: Optional[int]               = None
        self.scratch_nodes:  list[str]                         = []
        self.all_entries:    dict[str, list[ScratchEntry]]     = {}
        self.node_errors:    dict[str, str]                    = {}
        self.node_fs:        dict[str, dict[str, tuple[int,int]]] = {}
        self._active_node:   Optional[str]                    = None
        self.nf_cfg         = self._nf_load_config()
        self.nf_node_states = [NfNodeState(n) for n in self.nf_cfg["nodes"]]
        self._nf_polling    = False
        self._nf_ssh_cache: dict[str, asyncssh.SSHClientConnection] = {}
        self._nf_clear_seen: dict[str, bool] = {}

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent(id="main-tabs"):

            with TabPane("Slurm Admin", id="tab-slurm"):
                with TabbedContent(id="slurm-tabs"):
                    with TabPane("Users & Accounts", id="stab-accounts"):
                        with Horizontal(classes="panel-row"):
                            with Vertical(id="sidebar"):
                                yield Label("Slurm Accounts", classes="section-title")
                                yield ListView(id="account-list")
                            with Vertical(id="main-content"):
                                yield Label("User Associations (sacctmgr)", classes="section-title")
                                yield DataTable(id="users-table", cursor_type="row")
                                with Horizontal(classes="action-bar"):
                                    yield Button("Add / Update User  [A]", variant="primary", id="btn-add")
                                    yield Button("Remove User  [D]",        variant="error",   id="btn-del")
                                    yield Button("New Account",             variant="default", id="btn-add-account")

                    with TabPane("QoS Policy", id="stab-qos"):
                        with Vertical():
                            yield Label("Active QoS (from sacctmgr)", classes="section-title")
                            yield DataTable(id="qos-table", cursor_type="row")
                            yield Label("GPU Tier Summary", classes="section-title")
                            yield Static("", id="qos-legend")

                    with TabPane("Partitions", id="stab-partitions"):
                        with Vertical():
                            yield Label("Partitions — AllowGroups / QoS   (Enter for details)", classes="section-title")
                            yield DataTable(id="partition-table", cursor_type="row")

                    with TabPane("AD Groups", id="stab-ad"):
                        with Horizontal(classes="panel-row"):
                            with Vertical(id="sidebar"):
                                yield Label("AD Groups", classes="section-title")
                                yield ListView(id="ad-group-list")
                            with Vertical(id="main-content"):
                                with Horizontal(id="ad-action-bar"):
                                    yield Label("Members → Slurm Account mapping", classes="section-title")
                                    yield Button("Refresh AD", id="btn-refresh-ad", variant="default")
                                    yield Button("Bulk Import", id="btn-bulk-import", variant="primary")
                                yield DataTable(id="ad-users-table", cursor_type="row")

                    with TabPane("Log", id="stab-slurm-log"):
                        yield RichLog(id="slurm-log", highlight=False, markup=False)

                if DEMO_MODE:
                    yield Label("  DEMO MODE — no real commands run", id="demo-badge")

            with TabPane("Config Sync", id="tab-sync"):
                with Vertical():
                    with Horizontal(id="sync-main"):
                        with Vertical(id="left-panel"):
                            yield Label("loading…", id="node-list-placeholder")
                        with Vertical(id="right-panel"):
                            with TabbedContent(id="sync-tabs"):
                                with TabPane("Matrix", id="stab-matrix"):
                                    yield DataTable(id="matrix-table", cursor_type="cell")
                                with TabPane("Node Detail", id="stab-node"):
                                    yield Static("Select a node from the left panel", id="node-detail-header")
                                    yield DataTable(id="node-detail-table", cursor_type="row")
                                with TabPane("Proxy", id="stab-proxy"):
                                    with Vertical():
                                        yield Static(id="proxy-banner", markup=True)
                                        yield DataTable(id="proxy-table", cursor_type="row")
                                        with Horizontal(id="proxy-action-bar"):
                                            yield Button("Check Proxy",           id="btn-check-proxy", variant="primary")
                                            yield Button("Push /etc/environment", id="btn-push-env",    variant="warning")
                                            yield Button("Test Connectivity",     id="btn-test-proxy")
                                with TabPane("Log", id="stab-log"):
                                    yield RichLog(id="log-view", highlight=False, markup=False)
                    with Horizontal(id="sync-action-bar"):
                        yield Button("Check",             id="btn-check-one")
                        yield Button("Sync → Node",       id="btn-sync-one",  variant="warning")
                        yield Button("Diff",              id="btn-diff")
                        yield Button("Check All",         id="btn-check-all", variant="primary")
                        yield Button("Sync Mismatches",   id="btn-sync-all",  variant="warning")
                        yield Static("Select a matrix cell to act on it.", id="action-hint")
                    yield StatusBar(id="sync-status-bar")

            with TabPane("Scratch Audit", id="tab-scratch"):
                with Horizontal(id="scratch-main"):
                    with Vertical(id="scr-node-panel"):
                        yield Label(" NODES ", classes="np-header")
                        yield Static("", id="scr-node-btn-anchor")
                        yield Label(" ACTIONS ", classes="np-header")
                        yield Button("Refresh Nodes",    id="btn-scr-refresh-nodes")
                        yield Button("Scan All Nodes",   id="btn-scr-scan-all", variant="primary")
                        yield Button("Select All Stale", id="btn-scr-sel-stale")
                        yield Button("Deselect All",     id="btn-scr-desel-all")
                        yield Button("Delete Selected",  id="btn-scr-delete-l", variant="error")
                    with Vertical(id="scr-right"):
                        with TabbedContent(id="scr-tabs"):
                            with TabPane("Cluster Summary", id="scr-tab-summary"):
                                yield DataTable(id="summary-table", cursor_type="row")
                            with TabPane("Node View", id="scr-tab-node"):
                                with Vertical(id="node-view"):
                                    yield Static("  Select a node from the left panel", id="node-title")
                                    yield DataTable(id="node-table", cursor_type="row")
                                    with Horizontal(id="info-panel"):
                                        with Vertical(id="info-root"):
                                            yield Static("  /  (root fs)", classes="info-header")
                                            yield Static("–", id="root-info")
                                        with Vertical(id="info-center"):
                                            yield Static("  /scratch", classes="info-header")
                                            yield Static("", id="scratch-bar-label")
                                            yield ProgressBar(total=100, show_eta=False, show_percentage=False, id="scratch-bar")
                                            yield Static("", id="scratch-pct-label")
                                        with Vertical(id="info-right"):
                                            yield Static("  /scratch stats", classes="info-header")
                                            yield Static("–", id="scratch-info")
                            with TabPane("Log", id="scr-tab-log"):
                                yield RichLog(id="scr-log", highlight=False, markup=False)
                with Horizontal(id="scr-action-bar"):
                    yield Button("Scan Node",         id="btn-scr-scan-one")
                    yield Button("Toggle Sel.",        id="btn-scr-toggle-sel")
                    yield Button("Delete Selected",    id="btn-scr-delete-b", variant="error")
                    yield Static("Select a node from the left panel.", id="scr-hint")
                yield StatusBar(id="scr-status-bar")

            with TabPane("ZFS Quotas", id="tab-quotas"):
                yield ZfsQuotaTab()

            with TabPane("NetFreeze", id="tab-netfreeze"):
                with Vertical():
                    with Horizontal(id="nf-top-bar"):
                        yield Label(f"[bold]Nodes:[/] {len(self.nf_node_states)}", id="nf-lbl-nodes")
                        yield Label("[dim]Monitoring: off[/]",                       id="nf-lbl-monitor")
                        yield Label("[dim]Freezes: 0[/]",                            id="nf-lbl-freezes")
                        yield Label(f"[dim]Poll: {self.nf_cfg['poll_interval']}s[/]",id="nf-lbl-poll")
                    yield Static(
                        "  Monitoring not started  —  press Restart Poll below",
                        id="nf-global-alert"
                    )
                    yield Rule()
                    with ScrollableContainer(id="nf-nodes-scroll"):
                        for state in self.nf_node_states:
                            yield NfNodePanel(state, id=f"nfpanel-{state.name}")
                    yield Static("", id="nf-summary-bar")
                    with Horizontal(id="nf-action-bar"):
                        yield Button("Deploy",        id="nf-btn-action-deploy",   variant="primary")
                        yield Button("Restart Poll",  id="nf-btn-action-refresh",  variant="default")
                        yield Button("Pause Poll",    id="nf-btn-action-pause",    variant="warning")
                        yield Button("Clear Logs",    id="nf-btn-action-clear")
                        yield Button("Settings",      id="nf-btn-action-settings")

        if DEMO_MODE:
            yield Label("  DEMO MODE — no SSH / Prometheus / Slurm commands run", id="demo-badge")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#users-table",     DataTable).add_columns(
            "Username", "Account", "Default QoS", "All QoS", "GPU Tier")
        self.query_one("#qos-table",       DataTable).add_columns(
            "Name", "Priority", "Max GPUs/Job", "Max GPUs/User", "Max Jobs", "Max Wall", "Max Submit")
        self.query_one("#partition-table", DataTable).add_columns(
            "Partition", "Default QoS", "AllowGroups", "AllowQoS", "MaxTime", "Default?")
        self.query_one("#ad-users-table",  DataTable).add_columns(
            "AD User", "AD Group", "→ Slurm Account", "Default QoS", "In sacctmgr?")
        self.query_one("#node-table",   DataTable).add_columns(
            "Sel", "Path", "Owner", "Size", "Age", "Kind", "Status")
        self.query_one("#summary-table", DataTable).add_columns(
            "Node", "/scratch %", "/scratch used", "/scratch free",
            "entries", "stale #", "stale size", "/ % (root)", "error")
        if DEMO_MODE:
            self._finish_startup()
        else:
            self.push_screen(ADCredentialsModal(), self._on_ad_auth)

    def _on_ad_auth(self, success: bool) -> None:
        self._finish_startup()

    def _finish_startup(self) -> None:
        self.action_refresh_slurm()
        self.action_refresh_ad()
        self._log_sync("HPC Config Sync starting…")
        self._set_sync_status("Discovering nodes via sinfo…", "bold cyan")
        self._discover_and_build()
        self._scr_log("Scratch Auditor ready.")
        self._set_scr_status("Ready — press Ctrl+R to scan all nodes.")
        self._scr_refresh_nodes_blocking()

    @on(Button.Pressed, "#btn-refresh-ad")
    def on_refresh_ad_btn(self): self.action_refresh_ad()

    @on(Button.Pressed, "#btn-bulk-import")
    def on_bulk_import_btn(self):
        def done(result):
            if result:
                group, account, defqos, extra_qos, summary, fail_msgs = result
                self.notify(summary, title="Bulk Import")
                self._slurm_log(f"[BULK] {summary}")
                for msg in fail_msgs:
                    self._slurm_log(f"  [BULK ERR] {msg}")
                self.action_refresh_slurm()
        self.push_screen(BulkImportModal(), done)

    def action_refresh_ad(self) -> None:
        self.notify("Refreshing AD groups…", title="HPC Admin")
        self._slurm_log("Refreshing AD groups via ldapsearch…")
        self.ad_users, self.hpc_child_map = fetch_all_ad()
        self._pop_ad_tab()
        self._slurm_log(f"AD: loaded {len(self.ad_users)} groups")

    # ═══════════════════════════════════════════════════════════════════════════
    # SLURM ADMIN METHODS
    # ═══════════════════════════════════════════════════════════════════════════

    def action_refresh_slurm(self) -> None:
        self.notify("Refreshing Slurm data…", title="HPC Admin")
        self._slurm_log("Refreshing Slurm data…")
        self.assoc    = fetch_slurm_assoc()
        self.accounts = fetch_slurm_accounts(self.assoc)
        self.qos_data = fetch_slurm_qos()
        self._pop_account_list()
        self._pop_users_table()
        self._pop_qos_table()
        self._pop_partition_table()
        self._pop_ad_tab()
        total_users = sum(len(v) for v in self.accounts.values())
        self._slurm_log(f"Loaded {total_users} users across {len(self.accounts)} accounts, {len(self.qos_data)} QoS entries")
        for acc, users in self.accounts.items():
            if users:
                self._slurm_log(f"  {acc}: {', '.join(users)}")

    def _pop_account_list(self) -> None:
        import time
        lv = self.query_one("#account-list", ListView)
        for child in list(lv.children):
            child.remove()
        ts = int(time.time() * 1000000)
        acc_defqos: dict[str, str] = {}
        for row in self.assoc:
            acc = row["Account"]
            if acc not in acc_defqos and row.get("DefQOS"):
                acc_defqos[acc] = row["DefQOS"]
        for acc in sorted(self.accounts.keys()):
            count  = len(self.accounts.get(acc, []))
            defqos = acc_defqos.get(acc, ACCOUNT_DEFINITIONS.get(acc, {}).get("default_qos", ""))
            c      = acc_color(acc)
            t = Text()
            t.append(f"{acc}\n", style=c)
            t.append(f"  {count} users  [{defqos}]", style="dim")
            lv.append(ListItem(Label(t), id=f"acc-{acc}-{ts}"))

    def _pop_users_table(self, account: Optional[str] = None) -> None:
        ut = self.query_one("#users-table", DataTable)
        ut.clear()
        assoc_by_user = {r["User"]: r for r in self.assoc}
        accs = [account] if account else sorted(self.accounts.keys())
        for acc in accs:
            users = self.accounts.get(acc, [])
            info  = ACCOUNT_DEFINITIONS.get(acc, {})
            ac    = acc_color(acc)
            for user in users:
                row    = assoc_by_user.get(user, {})
                defqos = row.get("DefQOS") or info.get("default_qos", "")
                allqos = row.get("QOS", defqos)
                qc     = QOS_COLOR.get(defqos, "white")
                cap    = QOS_DEFINITIONS.get(defqos, {}).get("max_gpus_job")
                ut.add_row(
                    Text(user, style="bold"), Text(acc, style=ac),
                    Text(defqos, style=qc), Text(allqos, style="dim"),
                    gpu_label(cap), key=f"{acc}::{user}",
                )
            if not users:
                ut.add_row(
                    Text("(no users)", style="dim italic"), Text(acc, style=f"dim {ac}"),
                    Text(info.get("default_qos", ""), style="dim"), Text(""), Text(""),
                    key=f"{acc}::__empty",
                )

    def _pop_qos_table(self) -> None:
        qt = self.query_one("#qos-table", DataTable)
        qt.clear()
        for q in self.qos_data:
            name   = q["Name"]
            color  = QOS_COLOR.get(name, "white")
            tres   = q.get("MaxTRES",   "")
            tresPU = q.get("MaxTRESPU", "")
            gj = re.search(r"gres/gpu=(\d+)", tres)
            gu = re.search(r"gres/gpu=(\d+)", tresPU)
            gpu_j = f"max {gj.group(1)}" if gj else Text("∞", style="bold green")
            gpu_u = f"max {gu.group(1)}" if gu else Text("∞", style="bold green")
            qt.add_row(
                Text(name, style=color), q.get("Priority", ""),
                gpu_j, gpu_u,
                q.get("MaxJobsPU",   "—") or "—",
                q.get("MaxWall",     "—") or "—",
                q.get("MaxSubmitPU", "—") or "—",
            )
        self._update_qos_legend()

    def _update_qos_legend(self) -> None:
        lines = []
        for q in self.qos_data:
            name   = q["Name"]
            color  = QOS_COLOR.get(name, "white")
            tres   = q.get("MaxTRES",   "")
            tresPU = q.get("MaxTRESPU", "")
            wall   = q.get("MaxWall",   "") or "unlimited"
            jobs   = q.get("MaxJobsPU", "") or "∞"
            subm   = q.get("MaxSubmitPU","") or "∞"
            gj  = re.search(r"gres/gpu=(\d+)", tres)
            gu  = re.search(r"gres/gpu=(\d+)", tresPU)
            gpu_j = f"max {gj.group(1)} GPU/job" if gj else "∞ GPUs/job"
            gpu_u = f"max {gu.group(1)} GPU/user" if gu else "∞ GPUs/user"
            parts = [gpu_j, gpu_u, f"{jobs} job(s)", f"{wall} wall", f"submit≤{subm}"]
            lines.append(f"[{color}]{name}[/]  →  {', '.join(parts)}")
        legend = self.query_one("#qos-legend", Static)
        legend.update("\n".join(lines))

    def _pop_partition_table(self) -> None:
        pt = self.query_one("#partition-table", DataTable)
        pt.clear()
        for pname, p in PARTITION_DEFINITIONS.items():
            allow_grps = ", ".join(p["allow_groups"]) if p["allow_groups"] else "ALL"
            allow_qos  = ", ".join(p["allow_qos"])    if p["allow_qos"]    else "ALL"
            qc = QOS_COLOR.get(p["qos"], "dim")
            pt.add_row(
                Text(pname, style="bold"), Text(p["qos"], style=qc),
                Text(allow_grps, style="dim"), Text(allow_qos, style="dim cyan"),
                p["max_time"],
                Text("YES", style="bold green") if p["default"] else Text("—", style="dim"),
                key=pname,
            )

    def _pop_ad_tab(self) -> None:
        import time
        lv = self.query_one("#ad-group-list", ListView)
        for child in list(lv.children):
            child.remove()
        ts = int(time.time() * 1000000)
        total = sum(len(m) for m in self.ad_users.values())
        lv.append(ListItem(
            Label(f" [bold]All Groups[/bold]  [{total}]"),
            id=f"adg-__all__-{ts}"
        ))
        for grp, members in self.ad_users.items():
            lv.append(ListItem(
                Label(f" {grp}  [{len(members)}]"),
                id=f"adg-{re.sub(r'[^a-z0-9_]', '-', grp.lower())}-{ts}"
            ))
        self._sel_ad_group: Optional[str] = None
        self._pop_ad_users_table(None)

    _GENERIC_AD_GROUPS = {
        "hpc_researchers", "hpc_faculty", "hpc_admins",
        "hpc_course_students", "hpc_matlab_users",
        "HPC-Users", "hpc-users",
    }

    def _canonical_group(self, user: str) -> str:
        if user in self.hpc_child_map:
            return self.hpc_child_map[user]
        user_groups = [g for g, members in self.ad_users.items() if user in members]
        for g in ["hpc_admins", "hpc_faculty", "hpc_course_students", "hpc_matlab_users"]:
            if g in user_groups:
                return g
        return user_groups[0] if user_groups else "unknown"

    def _pop_ad_users_table(self, filter_group: Optional[str]) -> None:
        sacctmgr_users = {r["User"] for r in self.assoc}
        adt = self.query_one("#ad-users-table", DataTable)
        adt.clear()

        if filter_group and filter_group in self.ad_users:
            users_to_show = [(user, filter_group) for user in self.ad_users[filter_group]]
        else:
            seen: set[str] = set()
            users_to_show = []
            all_users: set[str] = set()
            for members in self.ad_users.values():
                all_users.update(members)
            for user in sorted(all_users):
                if user not in seen:
                    seen.add(user)
                    users_to_show.append((user, self._canonical_group(user)))

        for user, grp in users_to_show:
            in_s = user in sacctmgr_users
            if in_s:
                user_row = next((r for r in self.assoc if r["User"] == user), {})
                actual_acc = user_row.get("Account", "—")
                actual_qos = user_row.get("DefQOS", "—")
                ac2 = acc_color(actual_acc)
                qc2 = QOS_COLOR.get(actual_qos, "dim")
                acc_cell = Text(actual_acc, style=ac2)
                qos_cell = Text(actual_qos, style=qc2)
            else:
                mapped_acc = AD_GROUP_TO_ACCOUNT.get(grp, grp)
                mapped_qos = ACCOUNT_DEFINITIONS.get(mapped_acc, {}).get("default_qos", "—")
                ac = acc_color(mapped_acc)
                qc = QOS_COLOR.get(mapped_qos, "dim")
                acc_cell = Text(f"{mapped_acc}  (not in sacctmgr)", style="yellow")
                qos_cell = Text(mapped_qos or "—", style=qc)
            adt.add_row(
                Text(user, style="bold"), Text(grp, style="dim"),
                acc_cell, qos_cell,
                Text("✓", style="bold green") if in_s else Text("✗", style="bold red"),
            )

    @on(ListView.Selected, "#account-list")
    def account_selected(self, event: ListView.Selected) -> None:
        iid = event.item.id or ""
        if iid.startswith("acc-"):
            self._sel_account = iid[4:].rsplit("-", 1)[0]
            self._pop_users_table(self._sel_account)

    @on(ListView.Selected, "#ad-group-list")
    def ad_group_selected(self, event: ListView.Selected) -> None:
        iid = event.item.id or ""
        if not iid.startswith("adg-"):
            return
        inner = iid[4:].rsplit("-", 1)[0]
        if inner == "__all__":
            self._pop_ad_users_table(None)
        else:
            matched = next(
                (g for g in self.ad_users if re.sub(r'[^a-z0-9_]', '-', g.lower()) == inner),
                None
            )
            if matched:
                self._pop_ad_users_table(matched)

    @on(DataTable.RowSelected, "#users-table")
    def user_row_selected(self, event: DataTable.RowSelected) -> None:
        key = str(event.row_key.value or "")
        if "::" in key:
            acc, user = key.split("::", 1)
            if not user.startswith("__"):
                self._sel_user    = user
                self._sel_account = acc

    @on(DataTable.RowSelected, "#partition-table")
    def partition_row_selected(self, event: DataTable.RowSelected) -> None:
        pname = str(event.row_key.value or "")
        if pname in PARTITION_DEFINITIONS:
            self.push_screen(PartitionDetailModal(pname))

    @on(DataTable.HeaderSelected)
    def on_table_header_selected(self, event: DataTable.HeaderSelected) -> None:
        from rich.text import Text as RichText
        table_id = event.data_table.id or ""
        col_key  = event.column_key
        col_str  = str(col_key)
        prev_key, prev_rev = self._sort_state.get(table_id, ("", False))
        reverse = (not prev_rev) if col_str == prev_key else False
        self._sort_state[table_id] = (col_str, reverse)

        def sort_key(cell):
            if isinstance(cell, RichText):
                return cell.plain.lower()
            return str(cell).lower()

        try:
            event.data_table.sort(col_key, key=sort_key, reverse=reverse)
        except Exception as ex:
            self._slurm_log(f"Sort error: {ex}")

    @on(Button.Pressed, "#btn-add")
    def btn_add(self): self.action_add_user()

    @on(Button.Pressed, "#btn-del")
    def btn_del(self): self.action_remove_user()

    @on(Button.Pressed, "#btn-add-account")
    def btn_add_account(self):
        def done(result):
            if result:
                name, msg = result
                self.notify(msg, title="sacctmgr")
                self._slurm_log(f"[ACCOUNT] {msg}")
                self.action_refresh_slurm()
        self.push_screen(AddAccountModal(), done)

    def action_add_user(self) -> None:
        def done(result):
            if result and result != "__refresh__":
                if isinstance(result, tuple) and len(result) == 5:
                    username, account, defqos, extra_qos, msg = result
                    self.notify(msg, title="sacctmgr")
                    self._slurm_log(f"[ADD/MOD] {msg}")
            if result is not None:
                self.action_refresh_slurm()

        if self._sel_user:
            all_assocs = [r for r in self.assoc if r["User"] == self._sel_user]
            self.push_screen(ManageUserModal(self._sel_user, all_assocs), done)
        else:
            self.push_screen(ManageUserModal(), done)

    def action_remove_user(self) -> None:
        if not self._sel_user or not self._sel_account:
            self.notify("Select a user row first.", severity="warning"); return
        def done(result):
            if result:
                ok, msg = result
                self.notify(msg, severity="information" if ok else "error")
                self._slurm_log(f"{'[REMOVE OK]' if ok else '[REMOVE FAIL]'} {msg}")
                if ok:
                    self._sel_user = None
                    self.action_refresh_slurm()
        self.push_screen(RemoveUserModal(self._sel_user, self._sel_account), done)

    # ═══════════════════════════════════════════════════════════════════════════
    # CONFIG SYNC METHODS
    # ═══════════════════════════════════════════════════════════════════════════

    def _init_sync_state(self):
        self.sync_nodes = [n for _, grp in self.node_groups for n in grp]
        self.matrix = {
            node: {i: {"status": "PENDING", "detail": ""}
                   for i in list(range(len(TRACKED_FILES))) + [MOUNT_IDX]}
            for node in self.sync_nodes
        }
        self.proxy_data = {
            node: {"vars": {}, "file_status": "PENDING",
                   "match_status": "PENDING", "connect_status": "PENDING"}
            for node in self.sync_nodes
        }

    def _discover_and_build(self):
        groups, msg = discover_node_groups()
        self.node_groups = groups
        self._init_sync_state()
        self._log_sync(msg)
        self._build_left_panel()
        self._build_matrix_table()
        self._build_node_detail_table()
        self._build_proxy_table()
        n = len(self.sync_nodes)
        self._log_sync(f"Tracking {len(TRACKED_FILES)} files across {n} nodes. Starting initial check…")
        self._set_sync_status(f"Ready — {n} nodes, {len(TRACKED_FILES)} files. Running initial check…")
        self._check_all()

    def _build_left_panel(self):
        import time
        panel = self.query_one("#left-panel", Vertical)
        try:
            panel.remove_children()
        except Exception:
            try:
                for _ in range(len(panel.children)):
                    if panel.children:
                        panel.children[0].remove()
            except Exception:
                pass
        ts = int(time.time() * 1000000)
        for group_label, group_nodes in self.node_groups:
            panel.mount(Label(f" {group_label} ", classes="group-label"))
            for node in group_nodes:
                panel.mount(Button(node, id=f"node-{node}-{ts}", classes="node-btn", name=node))
        panel.mount(Label(" ACTIONS ", classes="group-label"))
        panel.mount(Button("Reload Nodes",               id=f"btn-reload-nodes-{ts}"))
        panel.mount(Button("Sync sssd.conf Cluster-wide",  id=f"btn-sync-sssd-all-{ts}",  variant="warning"))
        panel.mount(Button("Sync slurm.conf Cluster-wide", id=f"btn-sync-slurm-all-{ts}", variant="warning"))
        panel.mount(Button("Sync Proxy Cluster-wide",      id=f"btn-sync-proxy-all-{ts}", variant="warning"))

    def _highlight_node_btn(self, node: Optional[str]):
        for btn in self.query("#left-panel .node-btn"):
            btn.remove_class("-active")
        if node:
            for btn in self.query("#left-panel .node-btn"):
                if btn.label == node:
                    btn.add_class("-active")
                    break

    def _build_matrix_table(self):
        dt: DataTable = self.query_one("#matrix-table")
        dt.clear(columns=True)
        dt.add_column("Node", key="col_node", width=16)
        for i, (_, _, short, _) in enumerate(TRACKED_FILES):
            dt.add_column(short, key=f"{_COL_PREFIX}{i}", width=11)
        dt.add_column("mounts", key=f"{_COL_PREFIX}{MOUNT_IDX}", width=8)
        for group_label, group_nodes in self.node_groups:
            dt.add_row(
                f"[bold cyan]── {group_label} ──[/bold cyan]",
                *["[grey30]·[/grey30]"] * (len(TRACKED_FILES) + 1),
                key=f"__sep_{group_label}__",
            )
            for node in group_nodes:
                dt.add_row(
                    node,
                    *[self._sync_cell(self.matrix[node][i]["status"]) for i in range(len(TRACKED_FILES))],
                    self._sync_cell(self.matrix[node][MOUNT_IDX]["status"]),
                    key=node,
                )

    def _refresh_matrix(self):
        dt: DataTable = self.query_one("#matrix-table")
        for node in self.sync_nodes:
            for i in range(len(TRACKED_FILES)):
                try:
                    dt.update_cell(node, f"{_COL_PREFIX}{i}",
                                   self._sync_cell(self.matrix[node][i]["status"]), update_width=False)
                except Exception:
                    pass
            try:
                dt.update_cell(node, f"{_COL_PREFIX}{MOUNT_IDX}",
                               self._sync_cell(self.matrix[node][MOUNT_IDX]["status"]), update_width=False)
            except Exception:
                pass

    def _build_node_detail_table(self):
        dt: DataTable = self.query_one("#node-detail-table")
        dt.clear(columns=True)
        dt.add_column("Config File",  key="d_path",   width=32)
        dt.add_column("Description",  key="d_desc",   width=26)
        dt.add_column("Status",       key="d_status", width=12)
        dt.add_column("Detail",       key="d_detail", width=28)

    def _refresh_node_detail(self, node: str):
        self.query_one("#node-detail-header", Static).update(f"  Node: {node}")
        dt: DataTable = self.query_one("#node-detail-table")
        dt.clear(columns=False)
        for i, (lp, _rp, _short, desc) in enumerate(TRACKED_FILES):
            info  = self.matrix[node].get(i, {"status": "PENDING", "detail": ""})
            color = STATUS_COLORS.get(info["status"], "white")
            dt.add_row(lp, desc, f"[{color}]{info['status']}[/{color}]", info["detail"], key=str(i))
        minfo  = self.matrix[node].get(MOUNT_IDX, {"status": "PENDING", "detail": ""})
        mcolor = STATUS_COLORS.get(minfo["status"], "white")
        dt.add_row("TrueNAS mounts", "NFS mount check",
                   f"[{mcolor}]{minfo['status']}[/{mcolor}]", minfo["detail"], key=str(MOUNT_IDX))

    def _build_proxy_table(self):
        dt: DataTable = self.query_one("#proxy-table")
        dt.clear(columns=True)
        dt.add_column("Node",        key="p_node",    width=16)
        dt.add_column("File",        key="p_file",    width=8)
        dt.add_column("Match",       key="p_match",   width=10)
        dt.add_column("http_proxy",  key="p_http",    width=38)
        dt.add_column("https_proxy", key="p_https",   width=38)
        dt.add_column("no_proxy",    key="p_noproxy", width=26)
        dt.add_column("Connect",     key="p_conn",    width=10)
        for group_label, group_nodes in self.node_groups:
            dt.add_row(f"[bold cyan]── {group_label} ──[/bold cyan]", "", "", "", "", "", "",
                       key=f"__psep_{group_label}__")
            for node in group_nodes:
                dt.add_row(node, "·", "·", "·", "·", "·", "·", key=f"p_{node}")
        self._refresh_proxy_banner()

    def _refresh_proxy_table(self):
        dt: DataTable = self.query_one("#proxy-table")
        for node in self.sync_nodes:
            d     = self.proxy_data[node]
            http  = d["vars"].get("http_proxy")  or d["vars"].get("HTTP_PROXY",  "")
            https = d["vars"].get("https_proxy") or d["vars"].get("HTTPS_PROXY", "")
            nop   = d["vars"].get("no_proxy")    or d["vars"].get("NO_PROXY",    "")
            http  = (http[:36]  + "…") if len(http)  > 37 else http  or "–"
            https = (https[:36] + "…") if len(https) > 37 else https or "–"
            nop   = (nop[:24]   + "…") if len(nop)   > 25 else nop   or "–"
            try:
                dt.update_cell(f"p_{node}", "p_file",    self._sync_cell(d["file_status"]),    update_width=False)
                dt.update_cell(f"p_{node}", "p_match",   self._sync_cell(d["match_status"]),   update_width=False)
                dt.update_cell(f"p_{node}", "p_http",    http,                                  update_width=False)
                dt.update_cell(f"p_{node}", "p_https",   https,                                 update_width=False)
                dt.update_cell(f"p_{node}", "p_noproxy", nop,                                   update_width=False)
                dt.update_cell(f"p_{node}", "p_conn",    self._sync_cell(d["connect_status"]), update_width=False)
            except Exception:
                pass

    def _refresh_proxy_banner(self):
        banner: Static = self.query_one("#proxy-banner")
        if self._master_proxy_vars:
            http  = self._master_proxy_vars.get("http_proxy")  or self._master_proxy_vars.get("HTTP_PROXY",  "[dim]not set[/dim]")
            https = self._master_proxy_vars.get("https_proxy") or self._master_proxy_vars.get("HTTPS_PROXY", "[dim]not set[/dim]")
            nop   = self._master_proxy_vars.get("no_proxy")    or self._master_proxy_vars.get("NO_PROXY",    "[dim]not set[/dim]")
            banner.update(
                f"[bold cyan]Master ({MASTER}) — {PROXY_ENV_FILE}[/bold cyan]\n"
                f"  [bold]http_proxy :[/bold]  {http}\n"
                f"  [bold]https_proxy:[/bold]  {https}\n"
                f"  [bold]no_proxy   :[/bold]  {nop}"
            )
        else:
            banner.update(f"[bold cyan]Master ({MASTER}) — {PROXY_ENV_FILE}[/bold cyan]\n"
                          f"  [dim]Press Check Proxy to load.[/dim]")

    def _sync_cell(self, status: str) -> str:
        c = STATUS_COLORS.get(status, "white")
        s = STATUS_SYMS.get(status, status)
        return f"[{c}]{s}[/{c}]"

    def _slurm_log(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        try:
            self.query_one("#slurm-log", RichLog).write(f"[{ts}] {msg}")
        except Exception:
            pass

    def _log_sync(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        try:
            self.query_one("#log-view", RichLog).write(f"[{ts}] {msg}")
        except Exception:
            pass

    def _set_sync_status(self, msg: str, style: str = "bold white"):
        try:
            self.query_one("#sync-status-bar", StatusBar).set_msg(msg, style)
        except Exception:
            pass

    def _set_hint(self, msg: str):
        try:
            self.query_one("#action-hint", Static).update(msg)
        except Exception:
            pass

    @work(thread=True)
    def _check_all(self):
        self.call_from_thread(self._set_sync_status, "Checking all nodes…", "bold cyan")
        for node in self.sync_nodes:
            self.call_from_thread(self._set_sync_status, f"Checking {node}…", "bold cyan")
            self._check_node(node)
        ok   = sum(1 for n in self.sync_nodes for i in range(len(TRACKED_FILES)+1) if self.matrix[n][i if i < len(TRACKED_FILES) else MOUNT_IDX]["status"] == "OK")
        bad  = sum(1 for n in self.sync_nodes for i in range(len(TRACKED_FILES)+1) if self.matrix[n][i if i < len(TRACKED_FILES) else MOUNT_IDX]["status"] in ("MISMATCH","MISSING","ERROR"))
        msg  = f"Check done — {ok} OK, {bad} issues"
        self.call_from_thread(self._set_sync_status, msg, "bold red" if bad else "bold green")
        self.call_from_thread(self._log_sync, msg)

    def _check_node(self, node: str):
        for i, (lp, rp, _, _) in enumerate(TRACKED_FILES):
            self.matrix[node][i] = {"status": "CHECKING", "detail": ""}
            self.call_from_thread(self._refresh_matrix)
            result = check_file_on_node(lp, node, rp)
            self.matrix[node][i] = result
            self.call_from_thread(self._refresh_matrix)
        self.matrix[node][MOUNT_IDX] = {"status": "CHECKING", "detail": ""}
        self.call_from_thread(self._refresh_matrix)
        self.matrix[node][MOUNT_IDX] = check_mounts_on_node(node)
        self.call_from_thread(self._refresh_matrix)

    @work(thread=True)
    def _check_single(self, node: str, file_idx: int):
        self.call_from_thread(self._set_sync_status, f"Checking {node}…", "bold cyan")
        if file_idx == MOUNT_IDX:
            result = check_mounts_on_node(node)
        else:
            lp, rp, _, _ = TRACKED_FILES[file_idx]
            result = check_file_on_node(lp, node, rp)
        self.matrix[node][file_idx] = result
        self.call_from_thread(self._refresh_matrix)
        msg = f"{node}: {result['status']} — {result['detail']}"
        self.call_from_thread(self._set_sync_status, msg,
                              "bold green" if result["status"] == "OK" else "bold red")
        self.call_from_thread(self._log_sync, msg)

    @work(thread=True)
    def _sync_file_to_node(self, node: str, file_idx: int):
        if file_idx >= len(TRACKED_FILES):
            self.call_from_thread(self._log_sync, "Mount sync not supported via this button.")
            return
        lp, rp, short, _ = TRACKED_FILES[file_idx]
        self.call_from_thread(self._set_sync_status, f"Syncing {short} → {node}…", "bold yellow")
        ok, err = scp_to(lp, node, rp)
        if ok:
            self.matrix[node][file_idx] = {"status": "OK", "detail": "just synced"}
            msg = f"Synced {short} → {node}"
            if rp == "/etc/slurm/slurm.conf":
                rc, _, rerr = run_local([SCONTROL, "reconfigure"], timeout=15)
                if rc == 0:
                    self.call_from_thread(self._log_sync, "scontrol reconfigure OK")
                else:
                    self.call_from_thread(self._log_sync, f"scontrol reconfigure failed: {rerr}")
            if rp == "/etc/sssd/sssd.conf":
                rc2, _, rerr2 = ssh(node, "sudo systemctl restart sssd")
                if rc2 == 0:
                    self.call_from_thread(self._log_sync, f"sssd restarted on {node}")
                else:
                    self.call_from_thread(self._log_sync, f"sssd restart failed on {node}: {rerr2}")
        else:
            self.matrix[node][file_idx] = {"status": "ERROR", "detail": err[:40]}
            msg = f"Failed {short} → {node}: {err}"
        self.call_from_thread(self._refresh_matrix)
        self.call_from_thread(self._set_sync_status, msg, "bold green" if ok else "bold red")
        self.call_from_thread(self._log_sync, msg)

    @work(thread=True)
    def _sync_all_mismatches(self):
        targets = [(n, i) for n in self.sync_nodes
                   for i in range(len(TRACKED_FILES))
                   if self.matrix[n][i]["status"] in ("MISMATCH", "MISSING") and n != MASTER]
        self.call_from_thread(self._set_sync_status, f"Syncing {len(targets)} mismatches…", "bold yellow")
        slurm_pushed = False
        for node, file_idx in targets:
            lp, rp, short, _ = TRACKED_FILES[file_idx]
            ok, err = scp_to(lp, node, rp)
            self.matrix[node][file_idx] = {"status": "OK" if ok else "ERROR",
                                           "detail": "synced" if ok else err[:40]}
            self.call_from_thread(self._refresh_matrix)
            self.call_from_thread(self._log_sync, f"  {'OK' if ok else 'FAIL'} {short} → {node}")
            if ok and rp == "/etc/slurm/slurm.conf":
                slurm_pushed = True
            if ok and rp == "/etc/sssd/sssd.conf":
                rc2, _, rerr2 = ssh(node, "sudo systemctl restart sssd")
                self.call_from_thread(self._log_sync, f"  sssd {'restarted' if rc2 == 0 else 'restart failed'} on {node}")
        if slurm_pushed:
            rc, _, rerr = run_local([SCONTROL, "reconfigure"], timeout=15)
            self.call_from_thread(self._log_sync, f"scontrol reconfigure {'OK' if rc == 0 else 'failed: ' + rerr}")
        self.call_from_thread(self._set_sync_status, f"Sync done — {len(targets)} files.", "bold green")

    @work(thread=True)
    def _sync_file_cluster_wide(self, file_idx: int):
        if file_idx >= len(TRACKED_FILES):
            return
        lp, rp, short, _ = TRACKED_FILES[file_idx]
        targets = [n for n in self.sync_nodes if n != MASTER]
        self.call_from_thread(self._set_sync_status, f"Pushing {short} to {len(targets)} nodes…", "bold yellow")
        for node in targets:
            ok, err = scp_to(lp, node, rp)
            self.matrix[node][file_idx] = {"status": "OK" if ok else "ERROR",
                                           "detail": "synced" if ok else err[:40]}
            self.call_from_thread(self._refresh_matrix)
            self.call_from_thread(self._log_sync, f"  {'OK' if ok else 'FAIL'} {short} → {node}")
        if rp == "/etc/slurm/slurm.conf":
            rc, _, rerr = run_local([SCONTROL, "reconfigure"], timeout=15)
            self.call_from_thread(self._log_sync, f"scontrol reconfigure {'OK' if rc == 0 else 'failed: ' + rerr}")
        if rp == "/etc/sssd/sssd.conf":
            for node in targets:
                if self.matrix[node][file_idx].get("status") == "OK":
                    rc2, _, rerr2 = ssh(node, "sudo systemctl restart sssd")
                    self.call_from_thread(self._log_sync, f"  sssd {'restarted' if rc2 == 0 else 'restart failed'} on {node}")
        self.call_from_thread(self._set_sync_status, f"{short} pushed cluster-wide.", "bold green")

    @work(thread=True)
    def _diff_file(self, node: str, file_idx: int):
        if file_idx >= len(TRACKED_FILES):
            return
        lp, rp, short, _ = TRACKED_FILES[file_idx]
        if node == MASTER:
            self.call_from_thread(self._log_sync, f"  {short}: same file on master, no diff.")
            return
        try:
            rc, remote_content, err = ssh(node, f"cat {rp} 2>/dev/null || echo __MISSING__")
            if "__MISSING__" in remote_content:
                self.call_from_thread(self._log_sync, f"  {short} on {node}: MISSING")
                return
            with tempfile.NamedTemporaryFile(mode="w", suffix=f".{short}.remote", delete=False) as tf:
                tf.write(remote_content)
                tmp = tf.name
            r = subprocess.run(["diff", "-u", f"--label=master:{lp}", f"--label={node}:{rp}", lp, tmp],
                                capture_output=True, text=True)
            os.unlink(tmp)
            if r.stdout:
                for line in r.stdout.splitlines()[:60]:
                    color = "green" if line.startswith("+") else "red" if line.startswith("-") else "dim"
                    self.call_from_thread(self._log_sync, f"[{color}]{line}[/{color}]")
            else:
                self.call_from_thread(self._log_sync, f"  {short} on {node}: no diff (files match)")
        except Exception as e:
            self.call_from_thread(self._log_sync, f"  diff error: {e}")

    @work(thread=True)
    def _check_proxy(self, test_connectivity: bool = False):
        self.call_from_thread(self._set_sync_status, "Checking proxy config…", "bold cyan")
        master_vars = _parse_env_file(PROXY_ENV_FILE)
        self._master_proxy_vars = master_vars
        self.call_from_thread(self._refresh_proxy_banner)
        for node in self.sync_nodes:
            d = self.proxy_data[node]
            if node == MASTER:
                d.update({"file_status": "OK" if safe_exists(PROXY_ENV_FILE) else "MISSING",
                           "vars": master_vars, "match_status": "OK", "connect_status": "SKIP"})
                self.call_from_thread(self._refresh_proxy_table)
                continue
            try:
                rc, out, _ = ssh(node, f"test -f {PROXY_ENV_FILE} && echo EXISTS || echo MISSING")
                if "MISSING" in out or rc != 0:
                    d.update({"file_status": "MISSING", "match_status": "MISSING",
                               "connect_status": "SKIP", "vars": {}})
                    self.call_from_thread(self._refresh_proxy_table)
                    continue
            except Exception:
                d.update({"file_status": "ERROR", "match_status": "ERROR",
                           "connect_status": "ERROR", "vars": {}})
                self.call_from_thread(self._refresh_proxy_table)
                continue
            d["file_status"] = "OK"
            try:
                _, content, _ = ssh(node, f"cat {PROXY_ENV_FILE}")
                node_vars = _parse_env_content(content)
            except Exception:
                node_vars = {}
            d["vars"]         = node_vars
            d["match_status"] = "OK" if _proxy_vars_match(master_vars, node_vars) else "MISMATCH"
            if test_connectivity:
                proxy_url = (node_vars.get("http_proxy") or node_vars.get("HTTP_PROXY") or
                             master_vars.get("http_proxy") or master_vars.get("HTTP_PROXY", ""))
                if proxy_url:
                    try:
                        rc, out, _ = ssh(
                            node,
                            f"curl -s -o /dev/null -w '%{{http_code}}' "
                            f"--proxy {proxy_url} "
                            f"--connect-timeout {PROXY_CONNECT_TIMEOUT} "
                            f"--max-time {PROXY_CONNECT_TIMEOUT+2} "
                            f"{PROXY_TEST_URL}",
                            timeout=PROXY_CONNECT_TIMEOUT + 5,
                        )
                        code = out.strip()
                        ok   = rc == 0 and code.isdigit() and 100 <= int(code) < 400
                        d["connect_status"] = "OK" if ok else "ERROR"
                    except Exception:
                        d["connect_status"] = "ERROR"
                else:
                    d["connect_status"] = "SKIP"
            else:
                d["connect_status"] = "SKIP"
            self.call_from_thread(self._refresh_proxy_table)
        mm  = sum(1 for n in self.sync_nodes if self.proxy_data[n]["match_status"] == "MISMATCH")
        ms  = sum(1 for n in self.sync_nodes if self.proxy_data[n]["file_status"]  == "MISSING")
        msg = f"Proxy check done — Mismatches: {mm}  Missing: {ms}"
        self.call_from_thread(self._set_sync_status, msg, "bold red" if (mm+ms) else "bold green")

    @work(thread=True)
    def _push_env_to_all(self):
        if not safe_exists(PROXY_ENV_FILE):
            self.call_from_thread(self._log_sync, f"ERROR: {PROXY_ENV_FILE} not on master.")
            return
        self.call_from_thread(self._log_sync, f"Pushing {PROXY_ENV_FILE} to all nodes…")
        for node in self.sync_nodes:
            if node == MASTER:
                continue
            self.call_from_thread(self._set_sync_status, f"Pushing → {node}…", "bold yellow")
            ok, err = scp_to(PROXY_ENV_FILE, node, PROXY_ENV_FILE)
            if ok:
                self.proxy_data[node].update({"file_status": "OK", "match_status": "OK"})
                self.call_from_thread(self._log_sync, f"  OK {node}")
            else:
                self.proxy_data[node]["file_status"] = "ERROR"
                self.call_from_thread(self._log_sync, f"  FAIL {node}: {err}")
            self.call_from_thread(self._refresh_proxy_table)
        self.call_from_thread(self._set_sync_status, "Push /etc/environment complete.", "bold green")

    @on(Button.Pressed, "#btn-check-all")
    def on_check_all(self, _):    self._check_all()

    @on(Button.Pressed, "#btn-sync-all")
    def on_sync_all(self, _):     self._sync_all_mismatches()

    @on(Button.Pressed, "#btn-check-proxy")
    def on_check_proxy_btn(self, _): self._check_proxy(test_connectivity=False)

    @on(Button.Pressed, "#btn-push-env")
    def on_push_env(self, _):     self._push_env_to_all()

    @on(Button.Pressed, "#btn-test-proxy")
    def on_test_proxy(self, _):   self._check_proxy(test_connectivity=True)

    @on(Button.Pressed, "#btn-check-one")
    def on_check_one(self, _):
        if self._selected_node and self._selected_file_idx is not None:
            self._check_single(self._selected_node, self._selected_file_idx)

    @on(Button.Pressed, "#btn-sync-one")
    def on_sync_one(self, _):
        if self._selected_node and self._selected_file_idx is not None:
            self._sync_file_to_node(self._selected_node, self._selected_file_idx)

    @on(Button.Pressed, "#btn-diff")
    def on_diff(self, _):
        if self._selected_node and self._selected_file_idx is not None:
            self._diff_file(self._selected_node, self._selected_file_idx)
            self.query_one("#sync-tabs", TabbedContent).active = "stab-log"

    def on_data_table_cell_selected(self, event: DataTable.CellSelected) -> None:
        if event.control.id != "matrix-table":
            return
        row_key = event.cell_key.row_key.value    or ""
        col_key = event.cell_key.column_key.value or ""
        if row_key.startswith("__sep_") or not col_key.startswith(_COL_PREFIX):
            return
        if row_key not in self.sync_nodes:
            return
        try:
            file_idx = int(col_key[len(_COL_PREFIX):])
            self._selected_node     = row_key
            self._selected_file_idx = file_idx
            _, _, _short, desc      = TRACKED_FILES[file_idx] if file_idx < len(TRACKED_FILES) else ("","","mounts","NFS mounts")
            status = self.matrix[row_key][file_idx]["status"]
            detail = self.matrix[row_key][file_idx]["detail"]
            self._set_hint(f"{desc}  on  {row_key}  │  {status}  {detail}")
            self._highlight_node_btn(row_key)
        except (ValueError, KeyError):
            pass

    def action_refresh_sync(self):      self._check_all()
    def action_sync_selected(self):     self.on_sync_one(None)
    def action_sync_mismatches(self):   self._sync_all_mismatches()
    def action_diff_selected(self):     self.on_diff(None)
    def action_reload_nodes(self):
        self._selected_node     = None
        self._selected_file_idx = None
        try:
            self.query_one("#matrix-table",      DataTable).clear(columns=True)
            self.query_one("#node-detail-table",  DataTable).clear(columns=True)
            self.query_one("#proxy-table",        DataTable).clear(columns=True)
        except Exception:
            pass
        self._discover_and_build()

    def action_deselect(self):
        self._selected_node     = None
        self._selected_file_idx = None
        self._highlight_node_btn(None)
        self._set_hint("Select a matrix cell to act on it.")
        self._set_sync_status("Deselected.")

    # ═══════════════════════════════════════════════════════════════════════════
    # SCRATCH AUDIT METHODS
    # ═══════════════════════════════════════════════════════════════════════════

    def _scr_rebuild_node_buttons(self):
        panel = self.query_one("#scr-node-panel", Vertical)
        to_remove = [child for child in panel.children
                     if getattr(child, "id", None) and child.id.startswith("snb-")]
        for child in to_remove:
            child.remove()
        nodes_snapshot = list(self.scratch_nodes)

        def _mount_buttons() -> None:
            try:
                anchor = self.query_one("#scr-node-btn-anchor", Static)
                for node in reversed(nodes_snapshot):
                    panel.mount(Button(node, id=f"snb-{node}", classes="scr-node-btn"), before=anchor)
            except Exception:
                for node in nodes_snapshot:
                    panel.mount(Button(node, id=f"snb-{node}", classes="scr-node-btn"))

        self.call_after_refresh(_mount_buttons)

    def _scr_refresh_nodes_blocking(self):
        self.scratch_nodes = discover_compute_nodes()
        if not self.scratch_nodes:
            self.scratch_nodes = DEMO_NODES[:] if DEMO_MODE else []
        self.all_entries = {n: [] for n in self.scratch_nodes}
        self.node_errors = {n: "" for n in self.scratch_nodes}
        self.node_fs     = {n: {} for n in self.scratch_nodes}
        self._scr_rebuild_node_buttons()
        self._scr_refresh_summary_table()
        self._set_scr_status(f"Nodes loaded: {len(self.scratch_nodes)}", "bold green")

    def _scr_select_node(self, node: str):
        for n in self.scratch_nodes:
            try:
                self.query_one(f"#snb-{n}", Button).remove_class("-active")
            except Exception:
                pass
        try:
            self.query_one(f"#snb-{node}", Button).add_class("-active")
        except Exception:
            pass
        self._active_node = node
        self._scr_refresh_node_title(node)
        self._scr_refresh_node_table(node)
        self._scr_refresh_info_panel(node)
        self.query_one("#scr-tabs", TabbedContent).active = "scr-tab-node"

    def _scr_refresh_node_title(self, node: str):
        err      = self.node_errors.get(node, "")
        entries  = self.all_entries.get(node, [])
        total_kb = sum(e.size_kb for e in entries)
        stale_n  = sum(1 for e in entries if e.age_days >= STALE_DAYS and not e.active_job)
        parts    = [f"  ── {node} ──"]
        if err:
            parts.append(f"  [red]ERROR: {err}[/red]")
        else:
            parts.append(f"  {len(entries)} entries")
            if total_kb:
                parts.append(f"  {fmt_bytes(total_kb * 1024)} used")
            if stale_n:
                parts.append(f"  [red]{stale_n} stale[/red]")
        self.query_one("#node-title", Static).update("  ".join(parts))

    def _scr_refresh_node_table(self, node: str):
        dt = self.query_one("#node-table", DataTable)
        dt.clear()
        err = self.node_errors.get(node, "")
        if err:
            dt.add_row("", Text(f"Error scanning node: {err}", style="bold red"), "", "", "", "", "", key="__err")
            return
        entries = self.all_entries.get(node, [])
        if not entries:
            dt.add_row("", Text("(nothing in /scratch)", style="dim italic"), "", "", "", "", "", key="__empty")
            return
        for e in entries:
            chk    = Text("*", style="bold cyan") if e.selected else Text("o", style="dim")
            path_t = Text(e.path, style="bold")
            own_t  = Text(e.owner, style="dim")
            sz_t   = Text(e.size_human, style=e.size_style)
            age_t  = Text(e.age_label, style=e.age_style)
            kind_t = Text(e.kind, style="dim")
            if e.active_job:
                st = Text("ACTIVE JOB", style="bold green")
            elif e.selected:
                st = Text("selected", style="bold cyan")
            else:
                st = Text("–", style="dim")
            dt.add_row(chk, path_t, own_t, sz_t, age_t, kind_t, st, key=f"{node}::{e.name}")

    def _scr_refresh_info_panel(self, node: str):
        fs = self.node_fs.get(node, {})

        root_data = fs.get("/", None)
        root_w    = self.query_one("#root-info", Static)
        if root_data:
            sz, av = root_data
            used   = sz - av
            p      = pct(used, sz)
            col    = "red" if p >= 85 else "yellow" if p >= 70 else "green"
            root_w.update(
                f"  [dim]size :[/dim]  {fmt_bytes(sz)}\n"
                f"  [dim]used :[/dim]  [{col}]{fmt_bytes(used)}[/{col}]\n"
                f"  [dim]free :[/dim]  {fmt_bytes(av)}\n"
                f"  [dim]use% :[/dim]  [{col}]{p:.1f}%[/{col}]"
            )
        else:
            root_w.update("  [dim]not available[/dim]")

        scratch_data = fs.get("/scratch", None)
        bar     = self.query_one("#scratch-bar", ProgressBar)
        lbl     = self.query_one("#scratch-bar-label", Static)
        pct_lbl = self.query_one("#scratch-pct-label", Static)
        if scratch_data:
            sz, av = scratch_data
            used   = sz - av
            p      = pct(used, sz)
            bar.remove_class("-warn", "-crit")
            if p >= 85:
                bar.add_class("-crit")
            elif p >= 60:
                bar.add_class("-warn")
            bar.progress = p
            lbl.update(f"  [dim]{fmt_bytes(used)} used of {fmt_bytes(sz)}[/dim]")
            pct_lbl.update(f"  {p:.1f}% full")
        else:
            lbl.update("  [dim]not available[/dim]")
            bar.progress = 0
            pct_lbl.update("")

        scr_w   = self.query_one("#scratch-info", Static)
        entries = self.all_entries.get(node, [])
        if entries or scratch_data:
            total_kb = sum(e.size_kb for e in entries)
            stale_kb = sum(e.size_kb for e in entries if e.age_days >= STALE_DAYS and not e.active_job)
            active_n = sum(1 for e in entries if e.active_job)
            stale_n  = sum(1 for e in entries if e.age_days >= STALE_DAYS and not e.active_job)
            sel_kb   = sum(e.size_kb for e in entries if e.selected)
            col_stale = "red" if stale_n else "green"
            col_sel   = "cyan" if sel_kb else "dim"
            scr_w.update(
                f"  [dim]entries:[/dim]  {len(entries)}"
                + (f"  ([bold green]{active_n} active[/bold green])" if active_n else "")
                + f"\n  [dim]total  :[/dim]  {fmt_bytes(total_kb * 1024)}"
                + f"\n  [dim]stale  :[/dim]  [{col_stale}]{stale_n}  {fmt_bytes(stale_kb * 1024)}[/{col_stale}]"
                + f"\n  [dim]sel.   :[/dim]  [{col_sel}]{fmt_bytes(sel_kb * 1024)}[/{col_sel}]"
            )
        else:
            scr_w.update("  [dim]scan node to populate[/dim]")

    def _scr_refresh_summary_table(self):
        st = self.query_one("#summary-table", DataTable)
        st.clear()
        for node in self.scratch_nodes:
            err     = self.node_errors.get(node, "")
            fs      = self.node_fs.get(node, {})
            entries = self.all_entries.get(node, [])
            s_pct = s_used = s_free = "—"
            if "/scratch" in fs:
                sz, av = fs["/scratch"]
                used   = sz - av
                p      = pct(used, sz)
                col    = "red" if p >= 85 else "yellow" if p >= 60 else "green"
                s_pct  = Text(f"{p:.0f}%", style=f"bold {col}")
                s_used = Text(fmt_bytes(used), style=col)
                s_free = Text(fmt_bytes(av), style="dim")
            r_pct = "—"
            if "/" in fs:
                sz, av = fs["/"]
                used   = sz - av
                p      = pct(used, sz)
                col    = "red" if p >= 85 else "yellow" if p >= 70 else "green"
                r_pct  = Text(f"{p:.0f}%", style=f"bold {col}")
            stale_n  = sum(1 for e in entries if e.age_days >= STALE_DAYS and not e.active_job)
            stale_kb = sum(e.size_kb for e in entries if e.age_days >= STALE_DAYS and not e.active_job)
            st.add_row(
                Text(node, style="bold cyan"), s_pct, s_used, s_free,
                Text(str(len(entries)), style="bold" if entries else "dim green"),
                Text(str(stale_n), style="bold red" if stale_n else "dim green"),
                Text(fmt_bytes(stale_kb * 1024) if stale_kb else "0", style="red" if stale_kb else "dim"),
                r_pct,
                Text(err, style="bold red") if err else Text("", style="dim"),
                key=f"sum::{node}",
            )

    @work(thread=True)
    def _scr_scan_all_worker(self):
        self.call_from_thread(self._set_scr_status, "Scanning all nodes…", "bold cyan")
        self.call_from_thread(self._scr_log, "Starting full scan…")
        for node in self.scratch_nodes:
            self.call_from_thread(self._set_scr_status, f"Scanning {node}…", "bold cyan")
            self._scr_scan_node_blocking(node)
        self.call_from_thread(self._scr_refresh_summary_table)
        if self._active_node:
            self.call_from_thread(self._scr_refresh_node_title, self._active_node)
            self.call_from_thread(self._scr_refresh_node_table, self._active_node)
            self.call_from_thread(self._scr_refresh_info_panel, self._active_node)
        total_kb = sum(e.size_kb for ents in self.all_entries.values() for e in ents)
        stale_n  = sum(1 for ents in self.all_entries.values() for e in ents
                       if e.age_days >= STALE_DAYS and not e.active_job)
        msg = f"Scan complete — {fmt_bytes(total_kb * 1024)} total, {stale_n} stale"
        self.call_from_thread(self._set_scr_status, msg, "bold red" if stale_n else "bold green")
        self.call_from_thread(self._scr_log, msg)

    @work(thread=True)
    def _scr_scan_one_worker(self, node: str):
        self.call_from_thread(self._set_scr_status, f"Scanning {node}…", "bold cyan")
        self._scr_scan_node_blocking(node)
        self.call_from_thread(self._scr_refresh_summary_table)
        self.call_from_thread(self._scr_refresh_node_title, node)
        self.call_from_thread(self._scr_refresh_node_table, node)
        self.call_from_thread(self._scr_refresh_info_panel, node)
        self.call_from_thread(self._set_scr_status, f"{node} scanned.", "bold green")

    def _scr_scan_node_blocking(self, node: str):
        self.node_fs[node] = fetch_fs_metrics(node)
        entries, err       = scan_node(node)
        self.node_errors[node] = err
        if not err:
            active  = fetch_active_scratch_paths(node)
            mark_active_jobs(entries, active)
            old_sel = {e.name for e in self.all_entries.get(node, []) if e.selected}
            for e in entries:
                if e.name in old_sel:
                    e.selected = True
        self.all_entries[node] = entries
        if err:
            self.call_from_thread(self._scr_log, f"  {node}: ERROR — {err}")
        else:
            kb = sum(e.size_kb for e in entries)
            self.call_from_thread(self._scr_log, f"  {node}: {len(entries)} entries, {fmt_bytes(kb * 1024)}")

    def _scr_entry_for_key(self, key: str) -> Optional[ScratchEntry]:
        if "::" not in key:
            return None
        node, name = key.split("::", 1)
        for e in self.all_entries.get(node, []):
            if e.name == name:
                return e
        return None

    def _scr_toggle_row(self):
        dt = self.query_one("#node-table", DataTable)
        try:
            raw = dt.cursor_row_key
            key = str(raw.value if hasattr(raw, "value") else raw or "")
        except Exception:
            return
        self._scr_toggle_row_by_key(key)

    def _scr_toggle_row_by_key(self, key: str):
        e = self._scr_entry_for_key(key)
        if e and not e.active_job:
            e.selected = not e.selected
            if self._active_node:
                self._scr_refresh_node_table(self._active_node)
                self._scr_refresh_info_panel(self._active_node)
            self._scr_refresh_summary_table()
            self._set_scr_status(f"{'Selected' if e.selected else 'Deselected'}  {e.path}  on  {e.node}")

    def _scr_select_stale(self):
        n = 0
        for ents in self.all_entries.values():
            for e in ents:
                if e.age_days >= STALE_DAYS and not e.active_job:
                    e.selected = True
                    n += 1
        if self._active_node:
            self._scr_refresh_node_table(self._active_node)
            self._scr_refresh_info_panel(self._active_node)
        self._scr_refresh_summary_table()
        self._set_scr_status(f"Selected {n} stale item(s).")

    def _scr_deselect_all(self):
        for ents in self.all_entries.values():
            for e in ents:
                e.selected = False
        if self._active_node:
            self._scr_refresh_node_table(self._active_node)
            self._scr_refresh_info_panel(self._active_node)
        self._scr_refresh_summary_table()
        self._set_scr_status("Deselected all.")

    def _scr_start_delete(self):
        targets = [e for ents in self.all_entries.values() for e in ents
                   if e.selected and not e.active_job]
        if not targets:
            self.notify("Nothing selected (or selected items have active jobs).", severity="warning")
            return
        def after_confirm(confirmed: bool):
            if confirmed:
                self._scr_delete_worker(targets)
        self.push_screen(ConfirmDeleteModal(targets), after_confirm)

    @work(thread=True)
    def _scr_delete_worker(self, targets: list[ScratchEntry]):
        self.call_from_thread(self._set_scr_status, f"Deleting {len(targets)} item(s)…", "bold yellow")
        ok_n = fail_n = freed_kb = 0
        for e in targets:
            ok, msg = delete_entry(e)
            self.call_from_thread(self._scr_log, f"  {'OK' if ok else 'FAIL'} {msg}")
            if ok:
                ok_n     += 1
                freed_kb += e.size_kb
                self.all_entries[e.node] = [x for x in self.all_entries[e.node] if x.name != e.name]
            else:
                fail_n += 1
        freed_str = fmt_bytes(freed_kb * 1024)
        msg = f"Done — freed {freed_str}   {ok_n} deleted" + (f"   {fail_n} failed" if fail_n else "")
        self.call_from_thread(self._set_scr_status, msg, "bold red" if fail_n else "bold green")
        self.call_from_thread(self._scr_log, msg)
        for node in sorted({e.node for e in targets}):
            self.node_fs[node] = fetch_fs_metrics(node)
        self.call_from_thread(self._scr_refresh_summary_table)
        if self._active_node:
            self.call_from_thread(self._scr_refresh_node_title, self._active_node)
            self.call_from_thread(self._scr_refresh_node_table, self._active_node)
            self.call_from_thread(self._scr_refresh_info_panel, self._active_node)

    @on(Button.Pressed, "#btn-scr-refresh-nodes")
    def ev_scr_refresh_nodes(self, _): self._scr_refresh_nodes_blocking()

    @on(Button.Pressed, "#btn-scr-scan-all")
    def ev_scr_scan_all(self, _): self._scr_scan_all_worker()

    @on(Button.Pressed, "#btn-scr-scan-one")
    def ev_scr_scan_one(self, _):
        if self._active_node:
            self._scr_scan_one_worker(self._active_node)
        else:
            self.notify("Select a node first.", severity="warning")

    @on(Button.Pressed, "#btn-scr-sel-stale")
    def ev_scr_sel_stale(self, _): self._scr_select_stale()

    @on(Button.Pressed, "#btn-scr-desel-all")
    def ev_scr_desel(self, _): self._scr_deselect_all()

    @on(Button.Pressed, "#btn-scr-delete-l")
    @on(Button.Pressed, "#btn-scr-delete-b")
    def ev_scr_delete(self, _): self._scr_start_delete()

    @on(Button.Pressed, "#btn-scr-toggle-sel")
    def ev_scr_toggle(self, _): self._scr_toggle_row()

    @on(DataTable.RowSelected, "#node-table")
    def ev_scr_row(self, event: DataTable.RowSelected):
        key = str(event.row_key.value or "")
        e   = self._scr_entry_for_key(key)
        if e:
            job_note = "  [bold green][ACTIVE JOB — protected][/bold green]" if e.active_job else ""
            self._set_scr_hint(f"{e.node}:{e.path}  {e.size_human}  {e.age_label}  owner={e.owner}{job_note}")
        self._scr_toggle_row_by_key(key)

    def action_scratch_scan_all(self):   self._scr_scan_all_worker()
    def action_scratch_toggle(self):     self._scr_toggle_row()
    def action_scratch_sel_stale(self):  self._scr_select_stale()
    def action_scratch_delete(self):     self._scr_start_delete()

    # ═══════════════════════════════════════════════════════════════════════════
    # SHARED BUTTON / KEY ROUTING
    # ═══════════════════════════════════════════════════════════════════════════

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id or ""
        if bid.startswith("snb-"):
            self._scr_select_node(bid[4:])
            event.stop()
            return
        if bid.startswith("node-"):
            name_part = bid[5:]
            node      = name_part.rsplit("-", 1)[0]
            if node in self.sync_nodes:
                self._selected_node = node
                self._highlight_node_btn(node)
                self._refresh_node_detail(node)
                self.query_one("#sync-tabs", TabbedContent).active = "stab-node"
                self._check_node_btn(node)
                event.stop()
                return
        for prefix, handler in [
            ("btn-reload-nodes-",    self._reload_nodes_action),
            ("btn-sync-sssd-all-",   lambda: self._sync_file_cluster_wide(1)),
            ("btn-sync-slurm-all-",  lambda: self._sync_file_cluster_wide(0)),
            ("btn-sync-proxy-all-",  lambda: self._sync_file_cluster_wide(5)),
        ]:
            if bid.startswith(prefix):
                handler()
                event.stop()
                return

    def _reload_nodes_action(self):
        self._selected_node     = None
        self._selected_file_idx = None
        try:
            self.query_one("#matrix-table",      DataTable).clear(columns=True)
            self.query_one("#node-detail-table",  DataTable).clear(columns=True)
            self.query_one("#proxy-table",        DataTable).clear(columns=True)
        except Exception:
            pass
        self._discover_and_build()

    @work(thread=True)
    def _check_node_btn(self, node: str):
        self._check_node(node)
        self.call_from_thread(self._refresh_node_detail, node)

    # ═══════════════════════════════════════════════════════════════════════════
    # HELPERS
    # ═══════════════════════════════════════════════════════════════════════════

    def _set_scr_status(self, msg: str, style: str = "bold white"):
        try:
            self.query_one("#scr-status-bar", StatusBar).set_msg(msg, style)
        except Exception:
            pass

    def _scr_log(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        try:
            self.query_one("#scr-log", RichLog).write(f"[{ts}] {msg}")
        except Exception:
            pass

    def _set_scr_hint(self, msg: str):
        try:
            self.query_one("#scr-hint", Static).update(msg)
        except Exception:
            pass

    def _set_status(self, msg: str, style: str = "bold white"):
        try:
            self.query_one("#status-bar", StatusBar).set_msg(msg, style)
        except Exception:
            pass

    def action_show_help(self) -> None:
        self.notify(
            "── Slurm Admin ──\n"
            "r          Refresh Slurm data\n"
            "a          Add or update a user\n"
            "d          Remove selected user\n\n"
            "── Config Sync ──\n"
            "R          Check all nodes\n"
            "s          Sync selected cell to node\n"
            "S          Sync all mismatches\n"
            "D          Diff selected file\n"
            "n          Reload node list\n"
            "Esc        Deselect\n\n"
            "── Scratch Audit ──\n"
            "Ctrl+R     Scan all nodes\n"
            "Space      Toggle select on row\n"
            "Ctrl+A     Select all stale entries\n"
            "Ctrl+D     Delete selected\n\n"
            "q          Quit",
            title="Help", timeout=16,
        )

    # ═══════════════════════════════════════════════════════════════════════════
    # NETFREEZE MONITOR METHODS
    # ═══════════════════════════════════════════════════════════════════════════

    def _nf_load_config(self) -> dict:
        if NF_CONFIG_FILE.exists():
            try:
                saved = json.loads(NF_CONFIG_FILE.read_text())
                return {**NF_DEFAULT_CONFIG, **saved}
            except Exception:
                pass
        return dict(NF_DEFAULT_CONFIG)

    def _nf_get_panel(self, name: str) -> Optional[NfNodePanel]:
        try:
            return self.query_one(f"#nfpanel-{name}", NfNodePanel)
        except NoMatches:
            return None

    def _nf_update_global_status(self):
        active_freezes = [s for s in self.nf_node_states if s.freeze_active]
        total_freezes  = sum(s.freeze_count for s in self.nf_node_states)
        try:
            self.query_one("#nf-lbl-freezes", Label).update(
                f"[{'red' if total_freezes else 'dim'}]Freezes: {total_freezes}[/]"
            )
            alert = self.query_one("#nf-global-alert", Static)
            if active_freezes:
                names = ", ".join(s.name for s in active_freezes)
                alert.update(f"  FREEZE ACTIVE on: {names}")
                alert.remove_class("ok")
                alert.add_class("freeze")
            else:
                alert.update(f"  All nodes normal  |  Total freeze events: {total_freezes}")
                alert.remove_class("freeze")
                if total_freezes > 0: alert.add_class("ok")
            ssh_ok   = sum(1 for s in self.nf_node_states if s.ssh_status in ("ok", "local"))
            mon_ok   = sum(1 for s in self.nf_node_states if s.monitor_status == "running")
            deployed = sum(1 for s in self.nf_node_states if s.deploy_status == "deployed")
            self.query_one("#nf-summary-bar", Static).update(
                f"  SSH: {ssh_ok}/{len(self.nf_node_states)}  "
                f"| Services: {mon_ok}/{len(self.nf_node_states)}  "
                f"| Deployed: {deployed}/{len(self.nf_node_states)}  "
                f"| Total events: {total_freezes}"
            )
        except NoMatches:
            pass

    def nf_action_start_poll(self):
        if not self._nf_polling:
            self._nf_polling = True
            try:
                self.query_one("#nf-lbl-monitor", Label).update("[green]Monitoring: ON[/]")
            except NoMatches:
                pass
            self._nf_start_polling()

    def nf_action_restart_poll(self):
        self._nf_polling = False
        for conn in self._nf_ssh_cache.values():
            try: conn.close()
            except Exception: pass
        self._nf_ssh_cache.clear()
        self._nf_clear_seen = {s.name: True for s in self.nf_node_states}
        self.set_timer(self.nf_cfg["poll_interval"] + 0.5, self._nf_do_restart)
        self.notify("NetFreeze: restarting poll…", severity="information")

    def _nf_do_restart(self):
        self._nf_polling = True
        self._nf_start_polling()
        self.notify("NetFreeze: polling restarted.", severity="information")

    def nf_action_clear(self):
        for state in self.nf_node_states:
            panel = self._nf_get_panel(state.name)
            if panel: panel.clear_log()
            self._nf_clear_seen[state.name] = True
        self.notify("NetFreeze: logs cleared.")

    def nf_action_deploy(self):
        self.push_screen(NfDeployScreen(self.nf_node_states, self.nf_cfg))

    def nf_action_settings(self):
        def on_close(saved):
            if saved:
                self.notify("NetFreeze settings saved.", severity="information")
                try:
                    self.query_one("#nf-lbl-poll", Label).update(
                        f"[dim]Poll: {self.nf_cfg['poll_interval']}s[/]"
                    )
                except NoMatches:
                    pass
        self.push_screen(NfSettingsScreen(self.nf_cfg), callback=on_close)

    @work(exclusive=False, thread=False)
    async def _nf_start_polling(self):
        for state in self.nf_node_states:
            self._nf_poll_node(state)

    @work(exclusive=False, thread=False)
    async def _nf_poll_node(self, state: NfNodeState):
        interval  = self.nf_cfg["poll_interval"]
        tail_n    = self.nf_cfg["tail_lines"]
        user      = self.nf_cfg["ssh_user"]
        key       = self.nf_cfg["ssh_key"]
        log_dir   = self.nf_cfg["remote_log_dir"]
        is_local  = state.host in ("localhost", "127.0.0.1", "hpc-master")

        seen_deque: collections.deque[str] = collections.deque(maxlen=2000)
        seen_set:   set[str]              = set()
        stdout = ""

        while self._nf_polling:
            if self._nf_clear_seen.pop(state.name, False):
                seen_deque.clear()
                seen_set.clear()

            if is_local:
                try:
                    import glob as _glob
                    log_files = sorted(f for f in _glob.glob(f"{log_dir}/*.log") if "tui_app" not in f)
                    if log_files:
                        cat_result = subprocess.run(
                            ["bash", "-c", f"cat {' '.join(log_files)} | tail -n {tail_n}"],
                            capture_output=True, text=True
                        )
                        stdout = cat_result.stdout
                    else:
                        stdout = ""
                    svc_result = subprocess.run(
                        ["systemctl", "is-active", "netfreeze-arp", "netfreeze-bond", "netfreeze-latency"],
                        capture_output=True, text=True
                    )
                    svc_status = svc_result.stdout.strip().replace("\n", "/") or "unknown"
                    state.monitor_status = "running" if "active" in svc_status else svc_status
                    if state.monitor_status == "running": state.deploy_status = "deployed"
                    state.ssh_status = "local"
                    state.error_msg  = ""
                    panel = self._nf_get_panel(state.name)
                    if panel and panel.freeze_state == "off":
                        panel.freeze_state = "ok"
                        panel.update_header()
                except Exception as e:
                    state.ssh_status = "local"
                    state.error_msg  = str(e)
                    nf_applog.error(f"Node {state.name}: local read failed: {e}")
                    await asyncio.sleep(interval)
                    continue
            else:
                conn = self._nf_ssh_cache.get(state.name)
                if conn is not None and conn.is_closed():
                    self._nf_ssh_cache.pop(state.name, None)
                    conn = None
                if conn is None:
                    state.ssh_status = "connecting"
                    panel = self._nf_get_panel(state.name)
                    if panel: panel.update_header()
                    conn, err = await nf_ssh_connect(state.host, user, key)
                    if conn:
                        self._nf_ssh_cache[state.name] = conn
                        state.ssh_status = "ok"
                        state.error_msg  = ""
                    else:
                        state.ssh_status = "error"
                        state.error_msg  = err
                        panel = self._nf_get_panel(state.name)
                        if panel: panel.update_header()
                        await asyncio.sleep(interval * 2)
                        continue

                stdout, stderr, rc = await nf_ssh_run(
                    conn, f"cat {log_dir}/*.log 2>/dev/null | tail -n {tail_n}"
                )
                if rc == -1 or "timeout" in stderr:
                    state.ssh_status = "error"
                    state.error_msg  = "Connection lost"
                    self._nf_ssh_cache.pop(state.name, None)
                    conn.close()
                    panel = self._nf_get_panel(state.name)
                    if panel: panel.update_header()
                    await asyncio.sleep(interval)
                    continue
                state.ssh_status = "ok"

                svc_out, _, _ = await nf_ssh_run(
                    conn,
                    "systemctl is-active netfreeze-arp netfreeze-bond netfreeze-latency "
                    "2>/dev/null | sort -u | tr '\\n' '/'",
                    timeout=5
                )
                svc_status = svc_out.strip().strip("/") or "unknown"
                state.monitor_status = "running" if "active" in svc_status else svc_status
                if state.monitor_status == "running": state.deploy_status = "deployed"

            all_lines = [l for l in stdout.splitlines() if l.strip()]
            new_lines = [l for l in all_lines if l not in seen_set]

            panel = self._nf_get_panel(state.name)
            if panel:
                if new_lines:
                    is_first_load = len(seen_set) == 0 and len(new_lines) > 1
                    for line in new_lines:
                        if len(seen_deque) == seen_deque.maxlen:
                            seen_set.discard(seen_deque[0])
                        seen_deque.append(line)
                        seen_set.add(line)
                    display_lines = new_lines[-40:]
                    if is_first_load:
                        now_str = datetime.now().strftime("%H:%M:%S")
                        try:
                            panel.query_one(
                                f"#nflog-{state.name}", RichLog
                            ).write(f"[dim]─── loaded at {now_str} — showing last {len(display_lines)} of {len(new_lines)} lines ───[/]")
                        except NoMatches:
                            pass
                    for line in display_lines:
                        panel.append_log_line(line)
                panel.set_state_from_batch(all_lines)
                if state.ssh_status in ("ok", "local") and state.monitor_status == "running" \
                        and panel.freeze_state == "off":
                    panel.freeze_state = "ok"
                    panel.update_header()

            self._nf_update_global_status()
            await asyncio.sleep(interval)

    @on(Button.Pressed, "#nf-btn-action-deploy")
    def nf_ev_deploy(self, _):   self.nf_action_deploy()

    @on(Button.Pressed, "#nf-btn-action-refresh")
    def nf_ev_refresh(self, _):
        if not self._nf_polling:
            self.nf_action_start_poll()
        else:
            self.nf_action_restart_poll()

    @on(Button.Pressed, "#nf-btn-action-pause")
    def nf_ev_pause(self, _):
        btn = self.query_one("#nf-btn-action-pause", Button)
        if self._nf_polling:
            self._nf_polling = False
            btn.label = "Resume Poll"
            btn.variant = "success"
            self.notify("NetFreeze: polling paused.", severity="warning")
        else:
            self.nf_action_start_poll()
            btn.label = "Pause Poll"
            btn.variant = "warning"
            self.notify("NetFreeze: polling resumed.", severity="information")

    @on(Button.Pressed, "#nf-btn-action-clear")
    def nf_ev_clear(self, _):    self.nf_action_clear()

    @on(Button.Pressed, "#nf-btn-action-settings")
    def nf_ev_settings(self, _): self.nf_action_settings()


# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if DEMO_MODE:
        print("DEMO MODE — no real commands run.\n")
    HpcAdminTUI().run()
