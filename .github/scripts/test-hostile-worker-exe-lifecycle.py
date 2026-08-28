#!/usr/bin/env python3
"""Exercise hostile-worker procfs evidence against deterministic fixtures."""

import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile


def fail(message):
    raise SystemExit(f"hostile-worker executable lifecycle tests failed: {message}")


def extract_worker_source(systemd_script):
    source = systemd_script.read_text(encoding="utf-8")
    start = (
        '    "${hostile_worker_identity_arguments[@]}" '
        "<<'HOSTILE_PYTHON'\n"
    )
    end = (
        "\nHOSTILE_PYTHON\n"
        "  then\n"
        '    fail "hostile-storage worker evidence failed"\n'
        "  fi\n"
        "}\n\n"
        "hostile_storage_clients_are_live()"
    )
    if source.count(start) != 1 or source.count(end) != 1:
        fail("hostile-worker evidence sentinels are not unique")
    worker_source = source.split(start, 1)[1].split(end, 1)[0]
    proc_root = 'proc_root = Path("/proc")'
    if worker_source.count(proc_root) != 1:
        fail("hostile-worker proc root is not uniquely pinned")
    test_source = worker_source.replace(
        proc_root,
        'proc_root = Path(os.environ["RECASAOS_TEST_PROC_ROOT"])',
    )
    compile(test_source, "assert_hostile_storage_worker_boundaries.py", "exec")
    return test_source


def find_reviewed_binary():
    for candidate in (Path("/usr/bin/true"), Path("/bin/true")):
        try:
            identity = os.stat(candidate, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if (
            stat.S_ISREG(identity.st_mode)
            and identity.st_uid == 0
            and identity.st_gid == 0
            and stat.S_IMODE(identity.st_mode) == 0o755
            and identity.st_nlink == 1
        ):
            return candidate
    fail("no root-owned 0755 single-link reviewed binary is available")


def write_identity(path, pid, state, parent, start):
    fields = [state, str(parent)] + ["0"] * 17 + [str(start)]
    if len(fields) != 20:
        fail("internal proc stat fixture is malformed")
    path.write_text(
        f"{pid} (recasaos-worker) {' '.join(fields)}\n",
        encoding="ascii",
    )


def write_status(
    path,
    tgid,
    pid,
    uid=2000,
    cap_eff="0000000000000000",
    sig_pnd="0000000000000100",
    shd_pnd="0000000000000000",
):
    path.write_text(
        "\n".join(
            (
                "Name:\trecasaos-worker",
                f"Tgid:\t{tgid}",
                f"Pid:\t{pid}",
                f"Uid:\t{uid}\t{uid}\t{uid}\t{uid}",
                f"CapEff:\t{cap_eff}",
                f"SigPnd:\t{sig_pnd}",
                f"ShdPnd:\t{shd_pnd}",
                "",
            )
        ),
        encoding="ascii",
    )


def replace_executable(path, target):
    path.unlink(missing_ok=True)
    path.symlink_to(target)


def build_fixture(root, reviewed_binary, phase, parent=41, fallback=False):
    proc_root = root / "proc"
    proc_root.mkdir(parents=True)
    cgroup_threads = root / "cgroup.threads"
    fixture = {
        "root": proc_root,
        "threads": cgroup_threads,
        "phase": phase,
        "parent": parent,
        "uid": 2000,
        "binary": reviewed_binary,
        "pairs": [],
        "pids": [],
        "tids": [],
        "starts": [],
        "leader_dirs": [],
        "tid_dirs": [],
    }
    for index in range(4):
        pid = 5101 + index * 100
        tid = pid + 1 if fallback else pid
        start = 9001 + index
        leader = proc_root / str(pid)
        leader.mkdir()
        task_entry = leader / "task" / str(tid)
        task_entry.mkdir(parents=True)
        write_identity(
            leader / "stat",
            pid,
            "Z" if fallback else "D",
            parent,
            start,
        )
        if fallback:
            tid_dir = proc_root / str(tid)
            tid_dir.mkdir()
            write_identity(tid_dir / "stat", tid, "D", parent, start + 100)
            write_status(tid_dir / "status", pid, tid)
            replace_executable(tid_dir / "exe", reviewed_binary)
        else:
            tid_dir = leader
            write_status(
                leader / "status",
                pid,
                pid,
                sig_pnd="0000000000000000",
            )
            replace_executable(leader / "exe", reviewed_binary)
        fixture["pairs"].append(f"{pid}:{start}")
        fixture["pids"].append(pid)
        fixture["tids"].append(tid)
        fixture["starts"].append(start)
        fixture["leader_dirs"].append(leader)
        fixture["tid_dirs"].append(tid_dir)
    cgroup_threads.write_text(
        "".join(f"{tid}\n" for tid in fixture["tids"]),
        encoding="ascii",
    )
    return fixture


def run_fixture(worker_script, fixture, expect_success, label, output_needles=()):
    environment = os.environ.copy()
    environment["RECASAOS_TEST_PROC_ROOT"] = str(fixture["root"])
    result = subprocess.run(
        (
            sys.executable,
            str(worker_script),
            fixture["phase"],
            str(fixture["parent"]),
            str(fixture["uid"]),
            str(fixture["binary"]),
            str(fixture["threads"]),
            *fixture["pairs"],
        ),
        check=False,
        capture_output=True,
        env=environment,
        text=True,
    )
    if (result.returncode == 0) != expect_success:
        fail(
            f"{label}: unexpected exit {result.returncode}; "
            f"stdout={result.stdout!r}; stderr={result.stderr!r}"
        )
    for needle in output_needles:
        if needle not in result.stdout:
            fail(f"{label}: success output omitted {needle!r}")


def rejected_case(
    workspace,
    worker_script,
    reviewed_binary,
    label,
    mutate,
    phase="kill-pending",
    fallback=True,
):
    case_root = workspace / label
    fixture = build_fixture(
        case_root,
        reviewed_binary,
        phase,
        fallback=fallback,
    )
    mutate(fixture)
    run_fixture(worker_script, fixture, False, label)


def main():
    if len(sys.argv) != 2:
        fail("usage: test-hostile-worker-exe-lifecycle.py SYSTEMD_SCRIPT")
    systemd_script = Path(sys.argv[1]).resolve()
    if not systemd_script.is_file():
        fail("systemd test script is unavailable")
    reviewed_binary = find_reviewed_binary()
    worker_source = extract_worker_source(systemd_script)

    with tempfile.TemporaryDirectory(prefix="recasaos-hostile-worker-") as raw:
        workspace = Path(raw)
        worker_script = workspace / "hostile-worker-evidence.py"
        worker_script.write_text(worker_source, encoding="utf-8")

        normal = build_fixture(
            workspace / "normal",
            reviewed_binary,
            "blocked",
        )
        run_fixture(
            worker_script,
            normal,
            True,
            "leader executable",
            ("image-source=5101:leader", "leader-state=5101:D"),
        )

        fallback = build_fixture(
            workspace / "fallback",
            reviewed_binary,
            "kill-pending",
            fallback=True,
        )
        run_fixture(
            worker_script,
            fallback,
            True,
            "surviving task executable",
            (
                "image-source=5101:surviving-tid-5102",
                "leader-state=5101:Z",
            ),
        )

        reparented = build_fixture(
            workspace / "reparented",
            reviewed_binary,
            "kill-pending",
            parent=1,
            fallback=True,
        )
        run_fixture(
            worker_script,
            reparented,
            True,
            "reparented surviving task executable",
            ("phase=kill-pending parent=1",),
        )

        def clear_pending_kill(fixture):
            for index, tid_dir in enumerate(fixture["tid_dirs"]):
                write_status(
                    tid_dir / "status",
                    fixture["pids"][index],
                    fixture["tids"][index],
                    sig_pnd="0000000000000000",
                )

        rejected_case(
            workspace,
            worker_script,
            reviewed_binary,
            "blocked-missing-leader-exe",
            clear_pending_kill,
            phase="blocked",
        )
        rejected_case(
            workspace,
            worker_script,
            reviewed_binary,
            "non-zombie-missing-leader-exe",
            lambda fixture: write_identity(
                fixture["leader_dirs"][0] / "stat",
                fixture["pids"][0],
                "D",
                fixture["parent"],
                fixture["starts"][0],
            ),
        )
        rejected_case(
            workspace,
            worker_script,
            reviewed_binary,
            "changed-parent",
            lambda fixture: write_identity(
                fixture["leader_dirs"][0] / "stat",
                fixture["pids"][0],
                "Z",
                42,
                fixture["starts"][0],
            ),
        )
        rejected_case(
            workspace,
            worker_script,
            reviewed_binary,
            "changed-start",
            lambda fixture: write_identity(
                fixture["leader_dirs"][0] / "stat",
                fixture["pids"][0],
                "Z",
                fixture["parent"],
                fixture["starts"][0] + 1,
            ),
        )
        rejected_case(
            workspace,
            worker_script,
            reviewed_binary,
            "mismatched-tgid",
            lambda fixture: write_status(
                fixture["tid_dirs"][0] / "status",
                9999,
                fixture["tids"][0],
            ),
        )
        rejected_case(
            workspace,
            worker_script,
            reviewed_binary,
            "mismatched-status-pid",
            lambda fixture: write_status(
                fixture["tid_dirs"][0] / "status",
                fixture["pids"][0],
                9999,
            ),
        )
        rejected_case(
            workspace,
            worker_script,
            reviewed_binary,
            "missing-survivor-exe",
            lambda fixture: (fixture["tid_dirs"][0] / "exe").unlink(),
        )

        def mismatch_survivor_image(fixture):
            mismatch = fixture["root"].parent / "different-image"
            mismatch.write_bytes(b"different image\n")
            mismatch.chmod(0o755)
            replace_executable(fixture["tid_dirs"][0] / "exe", mismatch)

        rejected_case(
            workspace,
            worker_script,
            reviewed_binary,
            "mismatched-survivor-image",
            mismatch_survivor_image,
        )
        rejected_case(
            workspace,
            worker_script,
            reviewed_binary,
            "changed-uid",
            lambda fixture: write_status(
                fixture["tid_dirs"][0] / "status",
                fixture["pids"][0],
                fixture["tids"][0],
                uid=2001,
            ),
        )
        rejected_case(
            workspace,
            worker_script,
            reviewed_binary,
            "effective-capability",
            lambda fixture: write_status(
                fixture["tid_dirs"][0] / "status",
                fixture["pids"][0],
                fixture["tids"][0],
                cap_eff="0000000000000001",
            ),
        )
        rejected_case(
            workspace,
            worker_script,
            reviewed_binary,
            "missing-pending-sigkill",
            lambda fixture: write_status(
                fixture["tid_dirs"][0] / "status",
                fixture["pids"][0],
                fixture["tids"][0],
                sig_pnd="0000000000000000",
            ),
        )
        rejected_case(
            workspace,
            worker_script,
            reviewed_binary,
            "non-d-state-survivor",
            lambda fixture: write_identity(
                fixture["tid_dirs"][0] / "stat",
                fixture["tids"][0],
                "S",
                fixture["parent"],
                fixture["starts"][0] + 100,
            ),
        )

        def remove_survivor_from_cgroup(fixture):
            retained_tids = fixture["tids"][1:]
            fixture["threads"].write_text(
                "".join(f"{tid}\n" for tid in retained_tids),
                encoding="ascii",
            )

        rejected_case(
            workspace,
            worker_script,
            reviewed_binary,
            "survivor-left-cgroup",
            remove_survivor_from_cgroup,
        )

        def leader_exe_symlink_loop(fixture):
            executable = fixture["leader_dirs"][0] / "exe"
            executable.unlink()
            executable.symlink_to("exe")

        rejected_case(
            workspace,
            worker_script,
            reviewed_binary,
            "leader-exe-oserror",
            leader_exe_symlink_loop,
            phase="blocked",
            fallback=False,
        )

    print("Hostile-worker executable lifecycle tests passed")


if __name__ == "__main__":
    main()
