"""Dependency lock auditing primitives.

This module is the only implementation file in the exercise. Every public
function is a stub: it raises NotImplementedError until the ten defects
described in README.md are fixed in order.

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


def parse_lock(text):
    """Parse a JSON lock document into an ordered list of package entries.

    Contract:
    - ``text`` is UTF-8 JSON whose top-level value is an object containing a
      ``packages`` array. Each package has string ``name``, ``version`` and
      ``source`` fields, plus a ``hashes`` object mapping lowercase algorithm
      names to lowercase hexadecimal digests.
    - Return one new dict per package, in file order, preserving ``name``,
      ``version``, ``source`` and every algorithm in ``hashes`` exactly.
      Losing source or hashes is a defect; do not normalize names here.
    - Do not merge duplicate entries: the list is a faithful record of the
      lock file and duplicates may be evidence of the attack.
    - Raise ValueError for malformed JSON, a missing/non-list ``packages``
      value, or a package missing a required field or containing an invalid
      field type. Never silently drop an unknown or malformed field.
    """
    raise NotImplementedError


def normalize_name(name):
    """Return the canonical package name used for identity comparisons.

    Contract:
    - Lower-case the name and collapse each run of hyphen, underscore or dot
      into a single hyphen (PEP 503 style).
    - Thus ``Acme_Utils``, ``acme-utils``, ``ACME--Utils`` and
      ``acme.utils`` all normalize to ``acme-utils``. Treating an underscore
      and a hyphen as different packages is a defect.
    - Raise ValueError for a non-string or empty/whitespace-only name.
    """
    raise NotImplementedError


def source_ok(entry, allowed):
    """Return True only when the entry source exactly matches an allowed index.

    Contract:
    - ``allowed`` is a sequence of index URLs. ``entry["source"]`` must match
      one of them exactly after URL component canonicalisation: lower-case
      scheme and host, remove a default port, and preserve the path, query and
      fragment exactly. No implicit subpaths and no trailing-slash guesses.
    - Compare complete URLs/components with equality. Never use prefix,
      substring, startswith or host-suffix matching: a mirror such as
      ``https://pypi.org/simple-mirror`` must not be accepted for
      ``https://pypi.org/simple``.
    - Return False for missing/malformed URLs, non-HTTP(S) schemes, empty
      allowed lists, userinfo, or anything that is not an exact match.
    """
    raise NotImplementedError


def hash_ok(artifact, entry):
    """Return True only when every hash declared by the lock matches artifact.

    Contract:
    - ``artifact`` is the raw bytes-like content of the downloaded artifact.
      For every algorithm in ``entry["hashes"]``, compute the digest with
      hashlib and compare it with the locked value.
    - Hash coverage is complete: all declared algorithms must be checked and
      must match. A first-algorithm-only shortcut is a defect. A missing
      artifact digest, an unknown algorithm or malformed hex data returns
      False rather than being skipped.
    - Digest comparison must be constant time and must not use ordinary
      equality on digest strings (no ``==`` or ``!=`` and no short-circuit on
      the first differing character). Length mismatches are False.
    - At least one algorithm is required; an empty hash map is False.
    """
    raise NotImplementedError


def resolve(entries, constraints):
    """Resolve exact version constraints to a canonical-name to entry mapping.

    Contract:
    - ``constraints`` is a sequence of mappings with ``name`` and an exact
      ``version`` string; an optional ``source`` may narrow the entry.
    - Every constraint must select exactly one entry by normalized name, an
      exact version string (no ranges, no prefixes, no semver relaxation and
      zero tolerance) and, when given, an exact source.
    - Return a dict keyed by ``normalize_name(name)`` whose values are the
      selected entry dicts. Do not mutate inputs.
    - Raise ValueError when a version is missing, when two constraints demand
      different exact versions of the same normalized package, when a
      constraint is ambiguous because multiple entries have the same name,
      version and optional source, or when no candidate exists. Never return
      the first convenient match and never hide a conflict.
    """
    raise NotImplementedError


def diff(expected, actual):
    """Compare locked entries with the entries actually installed or built.

    Contract:
    - Match entries on the pair ``(normalize_name(name), exact source)``.
      Version and hashes are compared as payload and are not part of identity.
    - Return exactly three keys:
      ``missing``: expected entries with no matching actual entry (deleted);
      ``extra``: actual entries with no matching expected entry (unexpected);
      ``changed``: list of ``{"expected": entry, "actual": entry}`` mappings
      for matching identities whose version or hashes differ.
    - A changed package is not missing; a deleted package is not changed.
      Extras must be reported, not silently ignored, and an extra package with
      the same normalized name but a different source is still extra.
    - Results are deterministic, sorted by the identity key, and inputs are
      not mutated.
    """
    raise NotImplementedError


def validate_policy(policy):
    """Return issue codes for an insecure dependency policy.

    Contract:
    - ``allowed_sources`` must be a non-empty sequence of exact URL strings
      without wildcards. Missing, empty, blank or wildcard values produce
      ``ANY_SOURCE``.
    - ``verify_hashes`` must be exactly ``True``. Anything else produces
      ``UNVERIFIED_HASHES``.
    - ``require_transitive_pins`` must be exactly ``True``. Anything else
      produces ``UNPINNED_TRANSITIVE``.
    - Return codes in that order with no duplicates; a compliant policy
      returns ``[]``. Missing keys must not raise. Never omit the hash check.
    """
    raise NotImplementedError


def lock_batch(manifests, policy):
    """Validate multiple manifests independently and return per-manifest data.

    Contract:
    - ``manifests`` is a sequence of mappings, each with a unique string
      ``id``, an ``entries`` list and a ``constraints`` list. An optional
      ``actual`` list, when present, is compared with ``entries``.
    - For each manifest, from scratch, call ``validate_policy(policy)`` and
      ``resolve(entries, constraints)``. Return::

          {
            manifest_id: {
              "issues": [...],
              "resolved": {...},
              "diff": {...}   # only when "actual" was supplied
            }
          }

    - Manifests are fully independent: a package resolved for one manifest
      must never satisfy, seed or overwrite a later manifest. The same
      manifest must produce the same result whether run alone or in a batch.
    - Preserve input order in the returned dict. Raise ValueError for a
      duplicate/missing id or a malformed manifest.
    """
    raise NotImplementedError