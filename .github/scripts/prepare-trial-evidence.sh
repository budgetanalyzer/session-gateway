#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -lt 3 ]]; then
  echo "Usage: $0 OUTPUT_ARCHIVE LABEL PATH..." >&2
  exit 2
fi

output_archive="$1"
label="$2"
shift 2

if [[ "${output_archive}" != *.tar.gz ]] \
  || [[ "${output_archive}" == /* ]] \
  || [[ "/${output_archive}/" == *'/../'* ]]; then
  echo "The evidence archive must be a workspace-relative .tar.gz path: ${output_archive}" >&2
  exit 2
fi

# Keep one MiB of headroom beneath the operator-approved 25 MiB artifact cap
# for the upload service's archive wrapper and metadata.
max_bytes=25165824

mkdir -p "$(dirname "${output_archive}")"
rm -f "${output_archive}"

runner_temp="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
path_list="$(mktemp "${runner_temp%/}/dependency-automation-paths.XXXXXX")"
tar_file="$(mktemp "${runner_temp%/}/dependency-automation-evidence.XXXXXX.tar")"
measurement_file="${output_archive%.tar.gz}.measurement.txt"
trap 'rm -f "${path_list}" "${tar_file}"' EXIT

total_source_bytes=0
{
  printf 'label=%s\n' "${label}"
  printf 'cap_bytes=%s\n' "${max_bytes}"
  echo 'allowlisted_paths:'
} > "${measurement_file}"

for candidate in "$@"; do
  if [[ "${candidate}" == /* ]] || [[ "/${candidate}/" == *'/../'* ]]; then
    echo "Evidence paths must stay within the workspace: ${candidate}" >&2
    exit 2
  fi

  if [[ -e "${candidate}" || -L "${candidate}" ]]; then
    candidate_bytes="$(du --bytes --summarize --apparent-size -- "${candidate}" | cut -f1)"
    total_source_bytes=$((total_source_bytes + candidate_bytes))
    printf '%s\n' "${candidate}" >> "${path_list}"
    printf '  - %s (%s bytes)\n' "${candidate}" "${candidate_bytes}" >> "${measurement_file}"
  else
    printf '  - %s (missing)\n' "${candidate}" >> "${measurement_file}"
  fi
done

printf '%s\n' "${measurement_file}" >> "${path_list}"
tar --create --file "${tar_file}" --verbatim-files-from --files-from "${path_list}"
uncompressed_bytes="$(stat --format='%s' "${tar_file}")"
gzip --best --stdout "${tar_file}" > "${output_archive}"
compressed_bytes="$(stat --format='%s' "${output_archive}")"

upload_allowed=false
if [[ "${uncompressed_bytes}" -le "${max_bytes}" && "${compressed_bytes}" -le "${max_bytes}" ]]; then
  upload_allowed=true
fi

{
  echo
  printf 'source_bytes=%s\n' "${total_source_bytes}"
  printf 'uncompressed_tar_bytes=%s\n' "${uncompressed_bytes}"
  printf 'compressed_archive_bytes=%s\n' "${compressed_bytes}"
  printf 'upload_allowed=%s\n' "${upload_allowed}"
} >> "${measurement_file}"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    printf 'archive_path=%s\n' "${output_archive}"
    printf 'source_bytes=%s\n' "${total_source_bytes}"
    printf 'uncompressed_bytes=%s\n' "${uncompressed_bytes}"
    printf 'compressed_bytes=%s\n' "${compressed_bytes}"
    printf 'upload_allowed=%s\n' "${upload_allowed}"
  } >> "${GITHUB_OUTPUT}"
fi

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    printf '## %s evidence measurement\n\n' "${label}"
    echo '| Source bytes | Tar bytes (includes archive overhead) | Compressed bytes | Cap bytes | Upload allowed |'
    echo '| ---: | ---: | ---: | ---: | --- |'
    printf '| %s | %s | %s | %s | %s |\n' \
      "${total_source_bytes}" "${uncompressed_bytes}" "${compressed_bytes}" "${max_bytes}" "${upload_allowed}"
    echo
    printf 'The sealed archive contains only the explicit paths listed in %s.\n' "${measurement_file}"
    if [[ "${upload_allowed}" != true ]]; then
      echo
      echo '**Evidence delivery failure:** the complete bundle exceeds the trial cap; upload is blocked without trimming.'
    fi
  } >> "${GITHUB_STEP_SUMMARY}"
fi
