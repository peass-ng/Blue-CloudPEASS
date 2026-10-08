"""Install pinned upstream tools and mods at image build time."""

import hashlib
import io
import json
import pathlib
import platform
import sys
import tarfile
import urllib.request


def download(url):
    with urllib.request.urlopen(url, timeout=120) as response:
        return response.read()


def extract(data, destination, strip=False):
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in archive:
            if not member.isfile():
                continue
            parts = pathlib.PurePosixPath(member.name).parts
            if strip:
                parts = parts[1:]
            if not parts or ".." in parts or member.name.startswith("/"):
                continue
            path = destination.joinpath(*parts)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(archive.extractfile(member).read())
            path.chmod(member.mode)


if sys.argv[1] == "mods":
    catalog = json.loads(pathlib.Path("/opt/bluepeass/catalog.json").read_text())
    for entries in catalog.values():
        for entry in entries:
            repo = "steampipe-mod-" + entry["mod"]
            data = download(f"https://codeload.github.com/turbot/{repo}/tar.gz/refs/tags/{entry['version']}")
            extract(data, pathlib.Path("/opt/bluepeass/mods") / entry["mod"], strip=True)
            if entry["mod"] == "kubernetes-compliance":
                # v1.1.0 omits the case where both the Pod and container set a
                # UID >= 10000, returning NULL status for correctly hardened Pods.
                path = pathlib.Path("/opt/bluepeass/mods/kubernetes-compliance/query/pod.pp")
                text = path.read_text()
                status = "        when r.run_as_user < 10000 and (p.security_context ->> 'runAsUser')::int < 10000 then 'alarm'"
                reason = "        when r.run_as_user < 10000 and (p.security_context ->> 'runAsUser')::int < 10000 then p.name || ' run as user set to ' || (r.run_as_user) || '.'"
                if text.count(status) != 1 or text.count(reason) != 1:
                    raise RuntimeError("The pinned Kubernetes UID query changed; review the compatibility patch.")
                text = text.replace(status, status + "\n        when r.run_as_user >= 10000 and (p.security_context ->> 'runAsUser')::int >= 10000 then 'ok'")
                text = text.replace(reason, reason + "\n        when r.run_as_user >= 10000 and (p.security_context ->> 'runAsUser')::int >= 10000 then p.name || ' run as user set to ' || (r.run_as_user) || '.'")
                path.write_text(text)
else:
    arch = sys.argv[1] or {"aarch64": "arm64", "x86_64": "amd64"}[platform.machine()]
    for tool, version in zip(["steampipe", "powerpipe"], sys.argv[2:]):
        filename = f"steampipe_linux_{arch}.tar.gz" if tool == "steampipe" else f"powerpipe.linux.{arch}.tar.gz"
        base = f"https://github.com/turbot/{tool}/releases/download/v{version}/"
        data = download(base + filename)
        checksums = download(base + "checksums.txt").decode().splitlines()
        expected = next(line.split()[0] for line in checksums if line.split()[-1].lstrip("*") == filename)
        if hashlib.sha256(data).hexdigest() != expected:
            raise RuntimeError(f"Checksum mismatch for {tool}")
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            member = next(m for m in archive if pathlib.PurePosixPath(m.name).name == tool and m.isfile())
            path = pathlib.Path("/usr/local/bin") / tool
            path.write_bytes(archive.extractfile(member).read())
            path.chmod(0o755)
