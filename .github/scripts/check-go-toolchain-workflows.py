#!/usr/bin/env python3
import pathlib
import re
import sys

SETUP_GO_SHA = "4a3601121dd01d1626a1e23e37211e3254c1c06c"


class PolicyError(Exception):
    pass


def check_workflow(path: pathlib.Path, expected: str) -> int:
    lines = path.read_text(encoding="utf-8").splitlines()
    setup_uses = []
    for index, line in enumerate(lines):
        match = re.match(r"^(\s*)uses:\s*actions/setup-go@([^\s#]+)", line)
        if match is None:
            continue
        if match.group(2) != SETUP_GO_SHA:
            raise PolicyError(
                f"{path}:{index + 1}: setup-go action does not use the reviewed SHA"
            )
        setup_uses.append((index, len(match.group(1))))
    for index, line in enumerate(lines):
        if "GOTOOLCHAIN" in line and line != "  GOTOOLCHAIN: local":
            if re.match(r"^\s*GOTOOLCHAIN=local\s*\\?\s*$", line) is None:
                raise PolicyError(
                    f"{path}:{index + 1}: inline GOTOOLCHAIN override is forbidden"
                )
        if re.search(r"go1\.[0-9]+\.[0-9]+", line):
            raise PolicyError(
                f"{path}:{index + 1}: inline Go toolchain override is forbidden"
            )
        if re.search(r"/opt/hostedtoolcache/go/[0-9]+\.[0-9]+\.[0-9]+", line):
            raise PolicyError(
                f"{path}:{index + 1}: hosted-toolcache path is forbidden in workflows"
            )
    if not setup_uses:
        if any(
            re.match(r"^\s*(?:GOTOOLCHAIN|go-version|go-version-file)\s*:", line)
            for line in lines
        ):
            raise PolicyError(
                f"{path}: partial Go toolchain policy exists without setup-go"
            )
        return 0

    toolchain_lines = [
        (index, line)
        for index, line in enumerate(lines)
        if re.match(r"^\s*GOTOOLCHAIN\s*:", line)
    ]
    if len(toolchain_lines) != 1 or toolchain_lines[0][1] != "  GOTOOLCHAIN: local":
        raise PolicyError(
            f"{path}: workflow must contain exactly one top-level GOTOOLCHAIN: local"
        )

    claimed_go_versions = set()
    for uses_index, uses_indent in setup_uses:
        step_indent = uses_indent - 2
        step_start = None
        step_name = None
        for index in range(uses_index - 1, -1, -1):
            line = lines[index]
            if line.strip() and len(line) - len(line.lstrip()) < step_indent:
                break
            match = re.match(r"^(\s*)-\s+name:\s*(.*?)\s*$", line)
            if match is not None and len(match.group(1)) == step_indent:
                step_start = index
                step_name = match.group(2)
                break
        if step_start is None or step_name is None:
            raise PolicyError(
                f"{path}:{uses_index + 1}: setup-go action has no containing named step"
            )
        expected_name = f"Set up Go {expected}"
        if step_name != expected_name and not step_name.startswith(expected_name + " "):
            raise PolicyError(
                f"{path}:{step_start + 1}: setup-go step name must start with {expected_name!r}"
            )

        step_end = len(lines)
        for index in range(step_start + 1, len(lines)):
            line = lines[index]
            if re.match(rf"^\s{{{step_indent}}}-\s+", line):
                step_end = index
                break
            if line.strip() and len(line) - len(line.lstrip()) < step_indent:
                step_end = index
                break
        with_lines = [
            index
            for index in range(step_start, step_end)
            if re.match(rf"^\s{{{uses_indent}}}with:\s*(?:#.*)?$", lines[index])
        ]
        if len(with_lines) != 1:
            raise PolicyError(
                f"{path}:{step_start + 1}: setup-go step must contain exactly one with mapping"
            )
        with_start = with_lines[0]
        with_end = step_end
        for index in range(with_start + 1, step_end):
            line = lines[index]
            if line.strip() and len(line) - len(line.lstrip()) <= uses_indent:
                with_end = index
                break

        version_lines = []
        for index in range(step_start, step_end):
            line = lines[index]
            version = re.match(
                rf"^\s{{{uses_indent + 2}}}go-version\s*:\s*([^#]+?)\s*$",
                line,
            )
            if version is not None:
                value = version.group(1).strip().strip("\"'")
                if with_start < index < with_end:
                    version_lines.append((index, value))
            if re.match(r"^\s*go-version-file\s*:", line):
                raise PolicyError(
                    f"{path}:{index + 1}: setup-go must not use go-version-file"
                )
        if len(version_lines) != 1 or version_lines[0][1] != expected:
            raise PolicyError(
                f"{path}:{step_start + 1}: setup-go step must pin exactly go-version {expected!r}"
            )
        claimed_go_versions.add(version_lines[0][0])

    for index, line in enumerate(lines):
        if re.match(r"^\s*go-version\s*:", line) and index not in claimed_go_versions:
            raise PolicyError(f"{path}:{index + 1}: orphan go-version key is forbidden")
    return len(setup_uses)


def main() -> int:
    if len(sys.argv) < 3:
        print(
            "usage: check-go-toolchain-workflows.py <version> <workflow>...",
            file=sys.stderr,
        )
        return 64
    expected = sys.argv[1]
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", expected) is None:
        print("invalid expected Go version", file=sys.stderr)
        return 65
    try:
        count = sum(
            check_workflow(pathlib.Path(value), expected) for value in sys.argv[2:]
        )
        if count == 0:
            raise PolicyError("no setup-go steps were found")
    except (OSError, UnicodeError, PolicyError) as error:
        print(f"Go workflow toolchain policy failed: {error}", file=sys.stderr)
        return 1
    print(f"Go workflow toolchain policy passed: {expected} ({count} setup-go steps)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
