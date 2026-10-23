"""Select probes without dropping the identities and owner controls they depend on."""

import hashlib
import json

from .config import PolicyError


def select(policy, *, identity_ids=None, resource_ids=None, case_ids=None):
    known_identities = {item["id"] for item in policy["identities"]}
    known_resources = {item["id"] for item in policy["resources"]}
    known_cases = {f"{resource}:{identity}" for resource in known_resources for identity in known_identities}
    for values, known, label in ((identity_ids, known_identities, "identity"),
                                 (resource_ids, known_resources, "resource"), (case_ids, known_cases, "case")):
        if values is not None and (not values or any(not isinstance(value, str) or value not in known for value in values)):
            raise PolicyError(f"selection contains an unknown or empty {label}")
    identities = set(identity_ids) if identity_ids is not None else known_identities
    resources = set(resource_ids) if resource_ids is not None else known_resources
    cases = set(case_ids) if case_ids is not None else known_cases
    result = [f"{resource['id']}:{identity['id']}" for resource in policy["resources"]
              for identity in policy["identities"] if resource["id"] in resources and identity["id"] in identities
              and f"{resource['id']}:{identity['id']}" in cases]
    if not result:
        raise PolicyError("selection matches no access checks")
    return result


def dependencies(policy, selected):
    resources = {case.split(":")[0] for case in selected}
    identities = {case.split(":")[1] for case in selected}
    identities.update(resource["control_identity"] for resource in policy["resources"] if resource["id"] in resources)
    return identities


def case_fingerprint(policy, resource, identity):
    controller = next(item for item in policy["identities"] if item["id"] == resource["control_identity"])
    definition = {"identity_check": policy["identity_check"], "identity": identity,
                  "resource": resource, "control_identity": controller}
    return hashlib.sha256(json.dumps(definition, sort_keys=True, ensure_ascii=True).encode()).hexdigest()
