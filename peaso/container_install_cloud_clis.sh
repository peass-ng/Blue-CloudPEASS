#!/bin/sh
# Shared by the Compose runtime and the hosted AWS worker. CLI distributions
# keep their Python dependencies separate from the application's pinned SDKs.
set -eu

export DEBIAN_FRONTEND=noninteractive
cli_arch=$(dpkg --print-architecture)
case "$cli_arch" in
    amd64|arm64) ;;
    *) echo "Unsupported cloud CLI architecture: $cli_arch" >&2; exit 1 ;;
esac

apt-get update
apt-get install -y --no-install-recommends bash ca-certificates curl git gnupg groff-base less unzip

cli_work=$(mktemp -d)
trap 'rm -rf "$cli_work"' EXIT HUP INT TERM
fetch() {
    curl --fail --silent --show-error --location --retry 3 "$1" --output "$2"
}

# Vendor repositories verify both package indexes and downloaded packages.
install -d -m 0755 /etc/apt/keyrings
fetch https://packages.cloud.google.com/apt/doc/apt-key.gpg "$cli_work/google.gpg"
gpg --batch --yes --dearmor -o /etc/apt/keyrings/google-cloud.gpg "$cli_work/google.gpg"
fetch https://packages.microsoft.com/keys/microsoft.asc "$cli_work/microsoft.asc"
gpg --batch --yes --dearmor -o /etc/apt/keyrings/microsoft.gpg "$cli_work/microsoft.asc"
chmod 0644 /etc/apt/keyrings/google-cloud.gpg /etc/apt/keyrings/microsoft.gpg
printf '%s\n' 'deb [signed-by=/etc/apt/keyrings/google-cloud.gpg] https://packages.cloud.google.com/apt cloud-sdk main' \
    > /etc/apt/sources.list.d/google-cloud-sdk.list
printf '%s\n' "deb [arch=$cli_arch signed-by=/etc/apt/keyrings/microsoft.gpg] https://packages.microsoft.com/repos/azure-cli/ bookworm main" \
    > /etc/apt/sources.list.d/azure-cli.list
apt-get update
CLOUDSDK_SKIP_PY_COMPILATION=1 apt-get install -y --no-install-recommends google-cloud-cli azure-cli

# AWS's installer selects amd64/arm64 and verifies the distribution signature.
fetch https://awscli.amazonaws.com/v2/install.sh "$cli_work/install-aws.sh"
bash "$cli_work/install-aws.sh" --system --version "${AWS_CLI_VERSION:?AWS_CLI_VERSION is required}"

kubectl_url="https://dl.k8s.io/release/${KUBECTL_VERSION:?KUBECTL_VERSION is required}/bin/linux/$cli_arch/kubectl"
fetch "$kubectl_url" "$cli_work/kubectl"
fetch "$kubectl_url.sha256" "$cli_work/kubectl.sha256"
printf '%s  %s\n' "$(cat "$cli_work/kubectl.sha256")" "$cli_work/kubectl" | sha256sum --check -
install -m 0755 "$cli_work/kubectl" /usr/local/bin/kubectl

apt-get clean
rm -rf /var/lib/apt/lists/*
