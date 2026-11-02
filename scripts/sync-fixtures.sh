#!/usr/bin/env bash
set -euo pipefail

UPSTREAM_REPO="CloudburstMC/Network"
UPSTREAM_SHA="${NXS_UPSTREAM_SHA:-35cfff20cc720ebb4f54237b4ab626c727039f10}"
BASE="https://raw.githubusercontent.com/${UPSTREAM_REPO}/${UPSTREAM_SHA}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${ROOT}/vendor/upstream"
MODE="${1:-fetch}"

# path | git blob sha | sha256
MANIFEST='
LICENSE|5e6d1ba954fc4e6ababcec4844d398c9ca79b6a5|11c52cd9427fa5092c35697b54f651f839f9edb010932fc926e5b6bd003192a2
docs/external-signaling/README.md|43af52ad7786b72a9a59297ad47a137f978b80c0|20a813a5c1c3513bd4f48000eb66b4945479279f614605df9d099ebc95cb85ac
docs/external-signaling/wire-reference.md|d46d40738959753971e65b8c6e1b96bd5b0b7fc2|fb8e24e7dd1282d35e3d76008eb054345a6d3c8e7e1fb528cd2b5c4e26ad199b
docs/external-signaling/nxs-v1.schema.json|5706ac1a5c97f56af90d0858ae4a11ce7dedaa97|de18510c7add6432b613b5ffc796988aead523f03687b50dd42592cddbf14b4a
docs/external-signaling/fixtures/origins.fixtures.json|ab4e10bf683c9dfe599f25cfe93237ce73b89a7b|674e7f1fc47cbb1c05d63da1ce15e8744464d2244a415a835c1b6edc4823768c
docs/external-signaling/fixtures/nxs-v1.fixtures.json|b8fffb600004e30e942be9bb0b0cae9bc82104a9|7f05013fea19a4c0229226a58dd4f41203a736c7effc4351eb6b25970707cc39
docs/external-signaling/fixtures/stateless-admission-v1.fixtures.json|57032abfffd5fb6329d073abf7c58e0094079d0c|9eaa8266a7a0455f406a0f72c65f13d9f5d161569dc4577af6fd3a0b6782b4f6
docs/external-signaling/fixtures/cloudburst-protocol-vectors.v1.json|29c10ab4a088542c6a9295c0387c01c516f98c45|2bd4c3305a0911f2d4a1166f1c6760ed6979c5af551cbd9660e9badd1f7fb993
docs/external-signaling/fixtures/provenance.json|d2288c24761721fbe5f2ebe76f1c907f417110fd|d88e1ddf6804abd23581b5d876c9295bed6b2d6fd6bc54a2563a8ca6d55fcf4d
'

if [[ "${MODE}" != "fetch" && "${MODE}" != "--check" ]]; then
    echo "usage: $0 [--check]" >&2
    exit 2
fi

verify_file() {
    local file="$1" path="$2" expected_blob="$3" expected_sha="$4"
    local actual_blob actual_sha
    actual_blob="$(git hash-object "$file")"
    actual_sha="$(sha256sum "$file" | cut -d' ' -f1)"
    if [[ "$actual_blob" != "$expected_blob" ]]; then
        echo "blob mismatch for $path" >&2
        echo "  expected $expected_blob" >&2
        echo "  actual   $actual_blob" >&2
        return 1
    fi
    if [[ "$actual_sha" != "$expected_sha" ]]; then
        echo "sha256 mismatch for $path" >&2
        echo "  expected $expected_sha" >&2
        echo "  actual   $actual_sha" >&2
        return 1
    fi
}

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

while IFS='|' read -r path expected_blob expected_sha; do
    [[ -z "${path}" ]] && continue
    out="${DEST}/${path}"

    if [[ "${MODE}" == "--check" ]]; then
        if [[ ! -f "${out}" ]]; then
            echo "missing ${out}" >&2
            exit 1
        fi
        verify_file "${out}" "${path}" "${expected_blob}" "${expected_sha}"
        continue
    fi

    tmp="${tmpdir}/$(basename "${path}")"
    curl -fsSL "${BASE}/${path}" -o "${tmp}"
    verify_file "${tmp}" "${path}" "${expected_blob}" "${expected_sha}"
    mkdir -p "$(dirname "${out}")"
    mv "${tmp}" "${out}"
done <<< "${MANIFEST}"

if [[ "${MODE}" == "fetch" ]]; then
    (
        cd "${DEST}"
        sha256sum LICENSE docs/external-signaling/README.md \
            docs/external-signaling/wire-reference.md \
            docs/external-signaling/nxs-v1.schema.json \
            docs/external-signaling/fixtures/*.json > "${ROOT}/vendor/SHA256SUMS"
    )
    echo "vendored ${UPSTREAM_REPO}@${UPSTREAM_SHA} into vendor/upstream"
else
    echo "vendor tree matches ${UPSTREAM_REPO}@${UPSTREAM_SHA}"
fi
