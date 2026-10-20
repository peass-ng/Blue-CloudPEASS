# Native GCR image content inspection

The existing optional Artifact Registry image check now accepts exact immutable images at `gcr.io`, `us.gcr.io`, `eu.gcr.io` and `asia.gcr.io` when the native Artifact Registry DockerImage URI/name and repository/project identities agree. The reader uses the returned GCR URL directly and verifies manifest, config, layer and rootfs identities. It never rewrites an alias to a presumed `pkg.dev` backend.

All four host mappings pass installed collector-to-consumer fixtures. Real pinned Kingfisher and TruffleHog detect one merged, redacted leak in an inert GCR image. The initial affected cohort passed 111 tests with one error-type mismatch; the directed recheck passed 18 tests and resolves that exact failure. Latest outcomes: 112 distinct passing tests, zero unresolved recorded failures. The final combined GCR engine/planner/inventory acceptance passed 63 tests. These are local native-schema HTTP fixtures, not live-cloud certification.

Default-off content permission and exact selection remain required. No mutable tags, arbitrary mirrors, legacy storage reconstruction, daemon, execution or extraction. Redirects/challenges and incomplete, oversized or unsupported images remain UNKNOWN. [Hashes, receipts and scope](gcr-image-review.json).
