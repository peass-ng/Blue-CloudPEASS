# Selected Developer Connect linked repository file

The check `gcp.review.developerconnect.selected_repository_file_secret_indicators` belongs to the existing Secrets group and is default off. Use one exact `projects/PROJECT_ID` scope, explicitly name the check, set `content_secret_scans: true`, and provide one to four closed entries in `selected_developerconnect_files`. Each entry requires `link_name`, `link_uid`, `clone_uri`, `provider`, `commit_sha`, `path`, and `blob_sha`. Use a full 40-character lowercase commit SHA and Git blob SHA; branches and tags return UNKNOWN without a token read. `provider` is `github`, `gitlab`, or `bitbucket` for public GitHub, GitLab.com, or Bitbucket Cloud HTTPS clone URIs, respectively. `enterprise` HTTPS origins return UNKNOWN without sending credentials to that host.

```json
{
  "checks": ["gcp.review.developerconnect.selected_repository_file_secret_indicators"],
  "connector": {
    "provider": "gcp",
    "scopes": ["projects/example-project"],
    "options": {
      "content_secret_scans": true,
      "selected_developerconnect_files": [{
        "link_name": "projects/example-project/locations/us-central1/connections/connection-one/gitRepositoryLinks/link-one",
        "link_uid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "clone_uri": "https://github.com/example-org/example-repo.git",
        "provider": "github",
        "commit_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "path": "config/app.txt",
        "blob_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      }]
    }
  }
}
```

The example IDs and hashes are placeholders; use values recorded on the exact linked repository and file. Only safe repository-relative ASCII paths up to 256 characters and blobs up to 1 MiB are supported. Four targets use at most 32 HTTP requests and a 120-second deadline. The collector fetches the exact GitRepositoryLink and project before and after, obtains a read token through `fetchReadToken` only after native binding, then uses the selected provider's official commit and file endpoints. It requires a token with a known expiration within one hour; unknown or nonexpiring credentials are rejected. It never calls `fetchLinkableGitRepositories`, creates/updates a link, executes Git, clones a repository, reads Secret Manager values, or follows redirects. The Google Cloud token is used only on Google API hosts; the returned read token is used only on the matched provider API host. The read token, raw file and file path are absent from ordinary snapshot receipts; the path is represented by SHA-256. Kingfisher and TruffleHog merge duplicate HMAC findings, and a verified positive remains FAIL if another detector is unavailable. A clean incomplete scan is UNKNOWN.

Required Google IAM permissions are `developerconnect.gitRepositoryLinks.get`, `developerconnect.gitRepositoryLinks.fetchReadToken`, and `resourcemanager.projects.get`. `roles/developerconnect.readTokenAccessor` grants the first two along with connection metadata read, but Developer Connect Viewer alone does not grant token access. The principal also needs appropriate repository read access at the public provider: GitHub installation Contents read, GitLab read API/repository, or Bitbucket repository read. Token issuance does not establish that a particular provider token is valid for its REST API; a denied provider read is UNKNOWN. Google OAuth uses the `cloud-platform` scope. No Secret Manager payload read or write/deploy role is needed.

Official references: [GitRepositoryLink GET](https://docs.cloud.google.com/developer-connect/docs/api/reference/rest/v1/projects.locations.connections.gitRepositoryLinks/get), [read-token RPC and response](https://docs.cloud.google.com/developer-connect/docs/api/reference/rest/v1/projects.locations.connections.gitRepositoryLinks/fetchReadToken), [linkable repository discovery](https://docs.cloud.google.com/developer-connect/docs/api/reference/rest/v1/projects.locations.connections/fetchLinkableGitRepositories), [Developer Connect roles](https://docs.cloud.google.com/iam/docs/roles-permissions/developerconnect), [GitHub contents API](https://docs.github.com/en/rest/repos/contents), [GitLab repository files API](https://docs.gitlab.com/api/repository_files/), [Bitbucket Cloud source API](https://developer.atlassian.com/cloud/bitbucket/rest/api-group-source/).

This narrows existing fixed GCP-5 only. It does not cover unselected files, repository history, LFS/nested archives, enterprise provider hosts, other connection models, or credential validity; the fixed denominator remains 29 technical groups.
