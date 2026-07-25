#!/usr/bin/env bash
# Set the package version across all packaging files from a single source
# (typically the git tag). Used by the release workflow so the tag is the
# single source of truth; the committed files carry the current dev version.
#
# Usage: packaging/set-version.sh <version>
#   <version> may include a leading "v" (e.g. v1.1); it is stripped.
set -euo pipefail

version="${1:?usage: set-version.sh <version>}"
version="${version#v}"

# Debian versions may not start with a letter and use "~" for pre-releases;
# we only sanity-check that it starts with a digit.
if [[ ! "${version}" =~ ^[0-9] ]]; then
	echo "error: version '${version}' should start with a digit" >&2
	exit 1
fi

cd "$(dirname "$0")/.."

echo "Setting version to ${version}"

# pyproject.toml
sed -i -E "s/^version = \".*\"/version = \"${version}\"/" pyproject.toml

# Python module
sed -i -E "s/^__version__ = \".*\"/__version__ = \"${version}\"/" pypureomapi.py

# RPM spec
sed -i -E "s/^%define version .*/%define version ${version}/" pypureomapi.spec
sed -i -E "s/^%define release .*/%define release 1/" pypureomapi.spec

# Debian changelog: prepend a new native-package entry unless it already exists.
if ! head -n1 debian/changelog | grep -q "(${version})"; then
	date_rfc="$(date -R)"
	tmp="$(mktemp)"
	cat > "${tmp}" <<EOF
pypureomapi (${version}) unstable; urgency=medium

  * Release ${version}

 -- Dr. Torge Szczepanek <debian@cygnusnetworks.de>  ${date_rfc}

EOF
	cat debian/changelog >> "${tmp}"
	mv "${tmp}" debian/changelog
fi

echo "Done. Current versions:"
grep -m1 '^version = ' pyproject.toml
grep -m1 '^__version__' pypureomapi.py
grep -m1 '^%define version' pypureomapi.spec
head -n1 debian/changelog
