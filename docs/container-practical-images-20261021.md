# File backed container image inspection

`scan_image(identity, manifest_bytes, config_bytes, layers, ...)` accepts an ordered list or tuple of absolute, owned, regular `pathlib.Path` layer files. Existing byte layers remain accepted. The manifest and config stay as bounded bytes because their descriptor limits are 256 KiB and 1 MiB. The native verifier still binds the immutable image before and after the scan. The caller keeps source files alive until `scan_image` returns and removes its own download scratch afterward.

The archive helper checks the manifest and config digests, each compressed descriptor size and SHA-256, every rootfs diff ID, tar headers and members, and virtual link destinations. It expands one layer at a time into private regular scratch files using 64 KiB reads and writes. It never extracts member files or creates layer symlinks on the host. OCI output streams the original compressed paths; Docker output streams the validated expanded paths. The temporary expanded files are deleted before Trivy runs. If archive construction fails, the incomplete archive is deleted.

`visit_files(identity, manifest_bytes, config_bytes, layers, callback, check=..., partial_callback=...)` exposes final regular image files as `(virtual_path, bounded_reader, file_size, layer_index)` after all layers validate. The optional partial callback fires after each complete, validated layer. It supports retaining proven observations with an UNKNOWN coverage result if a later layer fails; successful callers use final observations instead. Virtual hardlinks read their validated target bytes. Symlinks are counted and skipped by the file visitor; `links_seen` and `links_skipped` are in its result. Whiteouts and overwrites remove prior files from the final view. Callback readers are valid only during their callback and are bounded to the file's bytes.

## Finite limits

| Limit | Value | Basis |
| --- | ---: | --- |
| Compressed layer | 512 MiB | Above the measured 408 MB largest layer. |
| Compressed image | 1 GiB | Above the measured 556 MB ten layer image. |
| Expanded image | 4 GiB | Bounds decompression and private scratch use. |
| Layers / tar members | 64 / 200,000 | Finite image graph and virtual path map. |
| Written archive | 5 GiB | Bounds Docker expanded or OCI compressed output. |
| Total scanner scratch / process file | 10 GiB / 6 GiB | Covers expansion plus archive during construction and Trivy output. |
| Scan deadline | 900 seconds | Applies to validation and the pinned Trivy process together. |
| Process stdout / stderr | 64 MiB / 1 MiB | Bounds captured report and diagnostics in memory. |

The peak archive construction disk bound is 4 GiB expanded files plus a 5 GiB archive, within the 10 GiB scratch cap. The scanner removes expanded scratch before invoking Trivy. The per stream buffer is 64 KiB; manifest/config, the bounded Trivy report, and up to 200,000 virtual path records with a 64 MiB aggregate path budget are the main memory consumers. A 256 MiB free disk reserve is checked during expansion, archive writes, and subprocess execution. Compression bombs, oversized descriptors, excessive members, deadline or cancellation, unsafe paths, escaped links, sparse or special tar nodes, mutated sources, and invalid digests fail closed.

## Focused verification

Python 3.12: `python -m pytest -q tests/test_container_practical_archive_20261021.py` passed 14 tests. The synthetic fixture has a layer larger than 8 MiB, regular files, relative and absolute internal symlinks, and hardlinks. The tests cover OCI and Docker output, gzip, byte compatibility, a clean and a finding report, limits, cancellation, tampering, escaped links and paths, special nodes, whiteouts, partial callbacks, and scratch cleanup, including low free disk rejection.

Pinned Trivy 0.68.1 loaded the file backed Docker archive with the fresh local database lease and exited 0. Its intentionally sparse fixture had no installed package database, so coverage stayed UNKNOWN with an analysis warning. This is an offline CLI compatibility proof, not a real AWS image scan or a complete vulnerability result. The collector integration and final combined gate are owned by the coordinator.
