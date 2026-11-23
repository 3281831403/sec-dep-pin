"""Dependency lock auditing primitives.

The lock document is JSON with this shape::

    {
      "packages": [
        {
          "name": "Acme_Utils",
          "version": "1.2.3",
          "source": "https://pypi.org/simple",
          "hashes": {
            "sha256": "lowercase hex digest",
            "sha512": "lowercase hex digest"
          }
        }
      ]
    }

All validation is offline and deterministic. Version matching is exact:
there are no ranges, no wildcard versions, and zero tolerance.
"""

import hashlib
import json
import re
import urllib.parse

_REQUIRED_PACKAGE_FIELDS = ("name", "version", "source", "hashes")
_HEX_RE = re.compile(r"[0-9a-f]+")
_NAME_RUN_RE = re.compile(r"[-_.]+")
_DEFAULT_PORTS = {"http": 80, "https": 443}


def parse_lock(text):
    """Parse a JSON lock document into an ordered list of package entries."""
    if not isinstance(text, str):
        raise ValueError("lock document must be a string")
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("malformed JSON lock document") from exc
    if not isinstance(document, dict):
        raise ValueError("lock document must be a JSON object")
    packages = document.get("packages")
    if not isinstance(packages, list):
        raise ValueError("lock document must contain a packages array")
    parsed = []
    for package in packages:
        if not isinstance(package, dict):
            raise ValueError("package entry must be an object")
        unknown = set(package) - set(_REQUIRED_PACKAGE_FIELDS)
        if unknown:
            raise ValueError("package entry has unknown fields: %s" % sorted(unknown))
        for field in ("name", "version", "source"):
            if not isinstance(package.get(field), str):
                raise ValueError("package entry missing string field %r" % field)
        hashes = package.get("hashes")
        if not isinstance(hashes, dict):
            raise ValueError("package entry missing hashes object")
        for algorithm, digest in hashes.items():
            if not isinstance(algorithm, str) or not isinstance(digest, str):
                raise ValueError("hashes must map strings to strings")
        parsed.append(
            {
                "name": package["name"],
                "version": package["version"],
                "source": package["source"],
                "hashes": dict(hashes),
            }
        )
    return parsed


def normalize_name(name):
    """Return the canonical package name used for identity comparisons."""
    if not isinstance(name, str):
        raise ValueError("package name must be a string")
    if not name.strip():
        raise ValueError("package name must not be empty")
    return _NAME_RUN_RE.sub("-", name).lower()


def _canonical_url(url):
    """Canonicalise a URL to a comparable tuple, or None when invalid."""
    if not isinstance(url, str) or not url:
        return None
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        return None
    if parts.username is not None or parts.password is not None:
        return None
    host = parts.hostname
    if not host:
        return None
    try:
        port = parts.port
    except ValueError:
        return None
    if port == _DEFAULT_PORTS[scheme]:
        port = None
    return (scheme, host.lower(), port, parts.path, parts.query, parts.fragment)


def source_ok(entry, allowed):
    """Return True only when the entry source exactly matches an allowed index."""
    if not allowed:
        return False
    if not isinstance(entry, dict):
        return False
    candidate = _canonical_url(entry.get("source"))
    if candidate is None:
        return False
    for url in allowed:
        if _canonical_url(url) == candidate:
            return True
    return False


def _constant_time_equal(a, b):
    """Compare two strings in constant time without ordinary equality."""
    if len(a) != len(b):
        return False
    result = 0
    for left, right in zip(a, b):
        result |= ord(left) ^ ord(right)
    return result == 0


def hash_ok(artifact, entry):
    """Return True only when every hash declared by the lock matches artifact."""
    try:
        data = bytes(artifact)
    except (TypeError, ValueError):
        return False
    hashes = entry.get("hashes") if isinstance(entry, dict) else None
    if not isinstance(hashes, dict) or not hashes:
        return False
    for algorithm, locked in hashes.items():
        if not isinstance(algorithm, str) or not isinstance(locked, str):
            return False
        if not _HEX_RE.fullmatch(locked) or len(locked) % 2 != 0:
            return False
        try:
            digest = hashlib.new(algorithm, data).hexdigest()
        except (ValueError, TypeError):
            return False
        if not _constant_time_equal(digest, locked):
            return False
    return True


def resolve(entries, constraints):
    """Resolve exact version constraints to a canonical-name to entry mapping."""
    indexed = {}
    for entry in entries:
        key = normalize_name(entry["name"])
        indexed.setdefault(key, []).append(entry)

    resolved = {}
    demanded = {}
    for constraint in constraints:
        name = constraint.get("name")
        version = constraint.get("version")
        if not isinstance(version, str) or not version:
            raise ValueError("constraint for %r is missing an exact version" % (name,))
        key = normalize_name(name)
        source = constraint.get("source")
        if key in demanded:
            previous_version, previous_source = demanded[key]
            if previous_version != version or previous_source != source:
                raise ValueError(
                    "conflicting constraints for package %r" % key
                )
        else:
            demanded[key] = (version, source)

        candidates = [
            entry
            for entry in indexed.get(key, [])
            if entry["version"] == version
            and (source is None or entry["source"] == source)
        ]
        if not candidates:
            raise ValueError(
                "no entry satisfies %r version %r" % (key, version)
            )
        if len(candidates) > 1:
            raise ValueError(
                "ambiguous constraint %r version %r" % (key, version)
            )
        resolved[key] = candidates[0]
    return resolved


def _identity(entry):
    return (normalize_name(entry["name"]), entry["source"])


def diff(expected, actual):
    """Compare locked entries with the entries actually installed or built."""
    expected_by_id = {}
    for entry in expected:
        expected_by_id[_identity(entry)] = entry
    actual_by_id = {}
    for entry in actual:
        actual_by_id[_identity(entry)] = entry

    missing = [
        expected_by_id[key]
        for key in sorted(expected_by_id)
        if key not in actual_by_id
    ]
    extra = [
        actual_by_id[key]
        for key in sorted(actual_by_id)
        if key not in expected_by_id
    ]
    changed = [
        {"expected": expected_by_id[key], "actual": actual_by_id[key]}
        for key in sorted(expected_by_id)
        if key in actual_by_id
        and (
            expected_by_id[key]["version"] != actual_by_id[key]["version"]
            or expected_by_id[key]["hashes"] != actual_by_id[key]["hashes"]
        )
    ]
    return {"missing": missing, "extra": extra, "changed": changed}


def validate_policy(policy):
    """Return issue codes for an insecure dependency policy."""
    issues = []
    sources = policy.get("allowed_sources")
    if (
        not isinstance(sources, (list, tuple))
        or not sources
        or any(
            not isinstance(url, str)
            or not url.strip()
            or "*" in url
            for url in sources
        )
    ):
        issues.append("ANY_SOURCE")
    if policy.get("verify_hashes") is not True:
        issues.append("UNVERIFIED_HASHES")
    if policy.get("require_transitive_pins") is not True:
        issues.append("UNPINNED_TRANSITIVE")
    return issues


def lock_batch(manifests, policy):
    """Validate multiple manifests independently and return per-manifest data."""
    results = {}
    for manifest in manifests:
        if not isinstance(manifest, dict):
            raise ValueError("manifest must be a mapping")
        manifest_id = manifest.get("id")
        if not isinstance(manifest_id, str) or not manifest_id:
            raise ValueError("manifest is missing a string id")
        if manifest_id in results:
            raise ValueError("duplicate manifest id %r" % manifest_id)
        entries = manifest.get("entries")
        constraints = manifest.get("constraints")
        if not isinstance(entries, list) or not isinstance(constraints, list):
            raise ValueError("manifest %r needs entries and constraints lists" % manifest_id)

        # Each manifest is validated from scratch; nothing is shared or
        # reused between manifests.
        report = {
            "issues": validate_policy(policy),
            "resolved": resolve(entries, constraints),
        }
        if "actual" in manifest:
            report["diff"] = diff(entries, manifest["actual"])
        results[manifest_id] = report
    return results
