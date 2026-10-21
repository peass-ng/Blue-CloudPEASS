# EC2 user-data content inspection

The EC2 user-data response path supports plain UTF-8 scripts, gzip and MIME text. The existing scanner receives decoded text; no script executes, include URLs are not fetched and attachments are not extracted to disk.

Enable content secret scanning and explicitly select the EC2 user-data secret control to use Kingfisher and TruffleHog. The collector retains one HMAC-based leak identity across both detectors. Raw matched values stay in the existing private-evidence path and are redacted from the ordinary report. Detector matches do not validate credentials.

## Read permissions

The existing instance inventory requires `ec2:DescribeInstances`; user data requires `ec2:DescribeInstanceAttribute`. No write permission or additional action is introduced by decoding. An unreadable response remains unresolved. See the main AWS connector setup for role trust and workspace external IDs.

## Bounds

The native payload remains limited to 16 KiB before decompression. Expanded text is limited to 1 MiB, total decompression work to 4 MiB, gzip members to eight, MIME depth to four and MIME parts to 32. Unsupported archives, binary bodies, malformed encodings and exceeded limits remain unresolved. Ordinary scripts containing a `Content-Type:` line remain ordinary text.

This covers the collected instance user-data attribute. It does not fetch arbitrary referenced files or establish that a script ran. Launch-template/configuration readers retain their separately documented contracts.

## Focused regression tests

```sh
python -m pytest -q tests/test_aws_user_data_payload_20261021.py tests/test_aws_user_data_payload_native_20261021.py
```
