# HPC Admin TUI

A terminal-based administration tool for managing GPU HPC clusters running Slurm, Open OnDemand, and Active Directory/SSSD on Rocky Linux 9.

Built with [Textual](https://github.com/Textualize/textual).

## Features

- **Slurm Admin** — manage users, accounts, QoS policies, and partitions via sacctmgr; bulk-import AD groups; live AD group membership view
- **Config Sync** — cluster-wide config file sync matrix (slurm.conf, sssd.conf, hosts, limits, sysctl, environment); per-file diff and targeted push; proxy config audit
- **Scratch Audit** — per-node /scratch scanner with age/size highlighting, active-job protection, and bulk delete
- **ZFS Quotas** — view and set per-user ZFS quotas on TrueNAS NAS hosts
- **NetFreeze Monitor** — SSH-based network freeze detection across cluster nodes (ARP failure, bond failover, link flap)

## Requirements

- Python 3.11+
- `pip install textual asyncssh`
- Slurm CLI tools (`sacctmgr`, `sinfo`, `squeue`) in PATH
- `ldapsearch` for AD integration
- SSH key-based access to all cluster nodes

## Usage

    python3 hpc_admin_tui.py           # live mode
    python3 hpc_admin_tui.py --demo    # demo mode (no real commands run)

On first launch you will be prompted for AD credentials. These are held in memory only and never written to disk.

## Configuration

Edit the constants at the top of the file before use:

- `SSH_USER` — admin username for SSH/SCP
- `LDAP_URI` / `LDAP_BASE` — your AD domain and search base
- `PROMETHEUS` — Prometheus host for filesystem metrics
- `ZFS_QUOTA_DATASETS` — TrueNAS hostnames and dataset paths
- `NF_DEFAULT_CONFIG` — node list for NetFreeze monitoring
