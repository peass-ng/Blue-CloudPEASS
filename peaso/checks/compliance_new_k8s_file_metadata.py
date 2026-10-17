"""Signed Kubernetes file-metadata predicates over attested, metadata-only facts.

No host path is opened. One scope verdict checks every owner-declared applicable
path; attestation is not a runtime stat or proof of managed control-plane files.
"""
from __future__ import annotations

from . import register, result, unknown
from .facts import Unavailable, complete_items, get, memoized
from .fixtures import CASES
from peaso.collectors.k8s import FILE_METADATA_SELECTORS, _file_selector_matches

# Explicitly reviewed selectors and threshold/owner semantics from k8s-cis.json.
# Recursive PKI ownership and dynamic etcd account ownership remain unregistered.
RULES = {
    "k8s.cis.file_admin_conf_mode_600": ("/etc/kubernetes/admin.conf", "600"),
    "k8s.cis.file_admin_conf_owner": ("/etc/kubernetes/admin.conf", "root"),
    "k8s.cis.file_controller_manager_conf_mode_600": ("/etc/kubernetes/controller-manager.conf", "600"),
    "k8s.cis.file_controller_manager_conf_owner": ("/etc/kubernetes/controller-manager.conf", "root"),
    "k8s.cis.file_etc_cni_net_d_mode_600": ("/etc/cni/net.d/*", "600"),
    "k8s.cis.file_etc_cni_net_d_owner": ("/etc/cni/net.d/*", "root"),
    "k8s.cis.file_manifests_etcd_yaml_mode_600": ("/etc/kubernetes/manifests/etcd.yaml", "600"),
    "k8s.cis.file_manifests_etcd_yaml_owner": ("/etc/kubernetes/manifests/etcd.yaml", "root"),
    "k8s.cis.file_manifests_kube_apiserver_yaml_mode_600": ("/etc/kubernetes/manifests/kube-apiserver.yaml", "600"),
    "k8s.cis.file_manifests_kube_apiserver_yaml_owner": ("/etc/kubernetes/manifests/kube-apiserver.yaml", "root"),
    "k8s.cis.file_manifests_kube_controller_manager_yaml_mode_600": ("/etc/kubernetes/manifests/kube-controller-manager.yaml", "600"),
    "k8s.cis.file_manifests_kube_controller_manager_yaml_owner": ("/etc/kubernetes/manifests/kube-controller-manager.yaml", "root"),
    "k8s.cis.file_manifests_kube_scheduler_yaml_mode_600": ("/etc/kubernetes/manifests/kube-scheduler.yaml", "600"),
    "k8s.cis.file_manifests_kube_scheduler_yaml_owner": ("/etc/kubernetes/manifests/kube-scheduler.yaml", "root"),
    "k8s.cis.file_pki_ca_crt_mode_600": ("/etc/kubernetes/pki/ca.crt", "600"),
    "k8s.cis.file_pki_ca_crt_mode_644": ("/etc/kubernetes/pki/ca.crt", "644"),
    "k8s.cis.file_pki_ca_crt_owner": ("/etc/kubernetes/pki/ca.crt", "root"),
    "k8s.cis.file_pki_crt_mode_600": ("/etc/kubernetes/pki/*.crt", "600"),
    "k8s.cis.file_pki_crt_mode_644": ("/etc/kubernetes/pki/*.crt", "644"),
    "k8s.cis.file_pki_key_mode_600": ("/etc/kubernetes/pki/*.key", "600"),
    "k8s.cis.file_proxy_conf_mode_600": ("/etc/kubernetes/proxy.conf", "600"),
    "k8s.cis.file_proxy_conf_owner": ("/etc/kubernetes/proxy.conf", "root"),
    "k8s.cis.file_scheduler_conf_mode_600": ("/etc/kubernetes/scheduler.conf", "600"),
    "k8s.cis.file_scheduler_conf_owner": ("/etc/kubernetes/scheduler.conf", "root"),
    "k8s.cis.file_var_lib_etcd_mode_700": ("/var/lib/etcd", "700"),
}
IDS = tuple(RULES)
assert len(RULES) == 25 and {selector for selector, _ in RULES.values()} == set(FILE_METADATA_SELECTORS)


def _indexed(index):
    nodes = complete_items(index, "node")
    live, seen_uids = {}, set()
    for row in nodes:
        name, uid = get(row, "metadata.name", str), get(row, "metadata.uid", str)
        if not name or not uid or name in live or uid in seen_uids:
            raise Unavailable("Node identity missing or duplicated")
        live[name] = uid
        seen_uids.add(uid)
    files = {}
    for row in complete_items(index, "file_metadata"):
        uid, path = get(row, "node_uid", str), get(row, "path", str)
        name = get(row, "node_name", str)
        if not uid or not path or live.get(name) != uid or (uid, path) in files:
            raise Unavailable("file identity missing, foreign or duplicated")
        files[(uid, path)] = row
    return live, files


def _validated_selector_paths(coverage):
    selectors = get(coverage, "selector_paths", dict)
    if set(selectors) != set(FILE_METADATA_SELECTORS):
        raise Unavailable("attested selector set incomplete or unsupported")
    for selector, entries in selectors.items():
        if not isinstance(entries, list):
            raise Unavailable("attested selector paths malformed")
        seen = set()
        for row in entries:
            name, uid, path = get(row, "node_name", str), get(row, "node_uid", str), get(row, "path", str)
            if not name or not uid or not _file_selector_matches(selector, path) or (uid, path) in seen:
                raise Unavailable("attested selector path or identity malformed")
            seen.add((uid, path))
    return selectors


def _evaluate(item, index, selector, criterion):
    if get(item, "provider", str) != "k8s":
        return unknown("not a Kubernetes scope")
    metadata = get(item, "metadata", dict)
    cluster_id = get(metadata, "cluster_id", str)
    coverage = get(metadata, "file_metadata_coverage", dict)
    if get(coverage, "status", str) != "attested_complete":
        return unknown("file path/node coverage not attested complete", reason=coverage.get("reason"))
    if get(coverage, "cluster_id", str) != cluster_id or get(coverage, "runtime_verified", bool) is not False:
        return unknown("file attestation does not match cluster or has unsupported provenance")
    selector_paths = memoized(index, ("compliance_new_k8s_validated_selectors",),
                              lambda: _validated_selector_paths(coverage))
    paths = selector_paths[selector]
    if not paths:
        return unknown("no applicable host path was attested for this selector", selector=selector)
    live, files = memoized(index, ("compliance_new_k8s_file_metadata_index",), lambda: _indexed(index))
    if len(live) != get(coverage, "node_count", int):
        return unknown("attested Node count differs from current inventory")
    bad, unresolved = [], []
    seen = set()
    for entry in paths:
        node_uid, name, path = get(entry, "node_uid", str), get(entry, "node_name", str), get(entry, "path", str)
        if not _file_selector_matches(selector, path):
            return unknown("attested path does not match fixed reviewed selector", selector=selector, observed_path=path)
        key = (node_uid, path)
        if live.get(name) != node_uid or key in seen or key not in files:
            unresolved.append({"node": name, "path": path, "reason": "path identity unresolved"})
            continue
        seen.add(key)
        row = files[key]
        try:
            if get(row, "symlink_status", str) != "not_symlink":
                raise Unavailable("link target was not attested as a non-symlink")
            if criterion == "root":
                uid, gid = get(row, "uid", int), get(row, "gid", int)
                if uid < 0 or gid < 0:
                    raise Unavailable("negative file owner ID")
                violation = uid != 0 or gid != 0
                observed = {"uid": uid, "gid": gid}
            else:
                mode = get(row, "mode", int)
                if not 0 <= mode <= 0o7777:
                    raise Unavailable("mode not permission bits")
                mask = int(criterion, 8)
                violation = bool(mode & ~mask)
                observed = {"mode_octal": f"{mode:04o}", "allowed_mask_octal": criterion}
        except Unavailable as exc:
            unresolved.append({"node": name, "path": path, "reason": str(exc)})
            continue
        if violation:
            bad.append({"node": name, "path": path, **observed})
    if bad:
        return result(True, selector=selector, failing_count=len(bad), failing_files=bad[:20],
                      hidden_failing_count=max(0, len(bad) - 20), unresolved_count=len(unresolved),
                      attestation="operator-supplied metadata; runtime file state not verified")
    if unresolved:
        return unknown("one or more applicable file facts unresolved", selector=selector,
                       unresolved_count=len(unresolved), unresolved_files=unresolved[:20])
    return result(False, selector=selector, assessed_file_count=len(paths), assessed_node_count=len(live),
                  attestation="operator-supplied metadata; runtime file state not verified")


def _case_index(selector, criterion, bad=False):
    path = selector.replace("*", "sample")
    row = {"path": path, "node_name": "node-a", "node_uid": "uid-a", "symlink_status": "not_symlink",
           "mode": 0o644 if bad and criterion == "600" else 0o755 if bad and criterion == "700" else 0o600,
           "uid": 1000 if bad and criterion == "root" else 0, "gid": 0}
    if criterion == "644" and bad:
        row["mode"] = 0o666
    return {"collections": {"node": [{"status": "collected"}], "file_metadata": [{"status": "collected"}]},
            "node": [{"data": {"metadata": {"name": "node-a", "uid": "uid-a"}}}],
            "file_metadata": [{"data": row}]}


def _case_item(selector):
    path = selector.replace("*", "sample")
    return {"provider": "k8s", "metadata": {"cluster_id": "cluster-a", "file_metadata_coverage": {
        "status": "attested_complete", "cluster_id": "cluster-a", "runtime_verified": False,
        "node_count": 1, "selector_paths": {**{key: [] for key in FILE_METADATA_SELECTORS},
                                           selector: [{"node_name": "node-a", "node_uid": "uid-a", "path": path}]}}}}


for _id, (_selector, _criterion) in RULES.items():
    def _check(item, index, selector=_selector, criterion=_criterion):
        return _evaluate(item, index, selector, criterion)

    if _criterion == "root":
        _title = f"Owner-attested file metadata for {_selector} belongs to root:root"
        _remediation = ("Review the host/image owner and file creation process; on owner-managed nodes, correct the declared UID/GID to root:root in the owned configuration after compatibility review, then verify metadata across every applicable node. Managed control-plane files may be inaccessible.")
    else:
        _title = f"Owner-attested file metadata for {_selector} allows only mode {_criterion} bits"
        _remediation = (f"Review the host/image owner and file readers; on owner-managed nodes, restrict {_selector} permission bits to the signed {_criterion} mask in the owned configuration after compatibility review, then verify every applicable node. Managed control-plane files may be inaccessible.")
    register(_id, "k8s", "hardening", "file_metadata", _title, "medium", "CM-6", _remediation,
             target="scope", dependencies=["file_metadata", "node"])(_check)
    CASES[_id] = {"pass": _case_item(_selector), "fail": _case_item(_selector),
                  "pass_index": _case_index(_selector, _criterion),
                  "fail_index": _case_index(_selector, _criterion, bad=True),
                  "missing": {}, "malformed": None}
