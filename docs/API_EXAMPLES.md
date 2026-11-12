# API examples

The interactive API documentation is available at http://127.0.0.1:8000/docs (8001 on the prepared demonstration). Browser users register and log in; scripts may use the installation's private bearer token. Never commit real tokens.

```sh
export BASE_URL=http://127.0.0.1:8000
# Set FWX_API_TOKEN privately from your own local installation.
curl -H "Authorization: Bearer $FWX_API_TOKEN" "$BASE_URL/api/v1/firmware"
curl -H "Authorization: Bearer $FWX_API_TOKEN" \
  -F file=@openwrt-24.10.4-x86-64-generic-squashfs-rootfs.img.gz.bin \
  -F provenance_kind=public_open_source -F license_id=GPL-2.0 \
  -F display_name='OpenWrt assessment' \
  -F source_url=https://downloads.openwrt.org/releases/24.10.4/targets/x86/64/ \
  "$BASE_URL/api/v1/firmware/upload"
```

Upload returns HTTP 202 with firmware_id, job_id, sha256, status and analysis_scope. Use the returned identifiers:

```sh
curl -H "Authorization: Bearer $FWX_API_TOKEN" "$BASE_URL/api/v1/jobs/$JOB_ID"
curl -H "Authorization: Bearer $FWX_API_TOKEN" "$BASE_URL/api/v1/firmware/$FIRMWARE_ID/report"
curl -X POST -H "Authorization: Bearer $FWX_API_TOKEN" "$BASE_URL/api/v1/firmware/$FIRMWARE_ID/reanalyze"
```

Job status may be queued, running, complete, partial or failed. Inspect the result's stage status and reasons; a successful HTTP response is not evidence that all checks completed. Report output contains jobs, findings and evidence. Reanalysis creates a separate assessment and preserves the original. See the generated /openapi.json for exact current response schemas.
