"""Trusted inputs of a signed intent: configuration, source predicate and authentication evidence.

Used by the capture boundary (M2). Nothing here reads request bodies, headers or alert
attributes as authority: attributes are comparison inputs against the protected binding
revision, and authentication evidence comes from the pinned permission decorator's own
successful verification calls.
"""
from __future__ import annotations

import functools
import inspect
import sys
import weakref
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Mapping

from . import envelope as v2

MAX_CAPTURE_SECONDS = 60
MAX_EXECUTION_SECONDS = 4 * 3600


@dataclass(frozen=True)
class Signing:
    ctx: v2.Context
    keys: v2.KeyRing
    kid: str
    message_policy_revision: int
    capture_window: timedelta
    execution_window: timedelta


def load_signing(config: Mapping[str, Any]) -> Signing | None:
    """Trusted configuration, or None when any part is missing or invalid (bound ACKs are then
    refused; an incomplete deployment is a hold, not a crash)."""
    try:
        deployment = config.get("VOALACK_DEPLOYMENT_ID")
        files = config.get("VOALACK_SIGNING_KEY_FILES")
        kid = config.get("VOALACK_ACTIVE_KID")
        providers = config.get("VOALACK_ALLOWED_AUTH_PROVIDERS") or []
        revision = config.get("VOALACK_MESSAGE_POLICY_REVISION")
        capture = config.get("VOALACK_CAPTURE_WINDOW_SECONDS", MAX_CAPTURE_SECONDS)
        execution = config.get("VOALACK_EXECUTION_WINDOW_SECONDS", MAX_EXECUTION_SECONDS)
        if (not isinstance(deployment, str) or not isinstance(files, Mapping) or not isinstance(kid, str)
                or kid not in files or type(revision) is not int or revision < 1
                or type(capture) is not int or not 1 <= capture <= MAX_CAPTURE_SECONDS
                or type(execution) is not int or not capture <= execution <= MAX_EXECUTION_SECONDS
                or not all(isinstance(p, str) for p in providers)):
            return None
        ctx = v2.Context(deployment_id=deployment, allowed_auth_providers=frozenset(providers))
        keys = {}
        for key_id, path in files.items():
            with open(path, "rb") as handle:
                keys[(deployment, ctx.provider, ctx.purpose, key_id)] = handle.read()
        ring = v2.KeyRing(keys, {(deployment, ctx.provider, ctx.purpose): kid})
        return Signing(ctx, ring, kid, revision, timedelta(seconds=capture), timedelta(seconds=execution))
    except (OSError, TypeError, ValueError):
        return None


# --- Ownership class (coexistence 3a, contract r8 section 1) ---------------------------------------
# The public class of an alert, from its event and resource only: "veeam_one" iff the event is exactly
# "VeeamOneAlarm" and the resource is "veeamone:" followed by at least one character; otherwise "none".
# Case-sensitive, no normalisation; non-strings (None included) are "none". voalack.alert_class() in
# schema.sql implements the same rule; one golden table tests both.

ONE_CLASS = "veeam_one"
NO_CLASS = "none"
_ONE_EVENT = "VeeamOneAlarm"
_ONE_PREFIX = "veeamone:"


def alert_class(event: Any, resource: Any) -> str:
    """Return the public ownership class of an alert (never raises)."""
    if (type(event) is str and event == _ONE_EVENT and type(resource) is str
            and resource.startswith(_ONE_PREFIX) and len(resource) > len(_ONE_PREFIX)):
        return ONE_CLASS
    return NO_CLASS


# --- Source predicate (frozen MVP core.py:153-175, against the locked alert and revision) -----

_SEVERITY = {"Error": "major", "Warning": "warning"}


def source_mismatch(alert, revision: Mapping[str, Any]) -> str | None:
    """Return a stable reason if the locked alert does not match its binding revision."""
    for name in ("resource", "event", "environment", "origin"):
        if getattr(alert, name, None) != revision[name]:
            return f"{name}_differs"
    if alert_class(alert.event, alert.resource) != ONE_CLASS:
        return "not_a_veeam_one_alarm"
    if not isinstance(alert.customer, str) or alert.customer != revision["customer"]:
        return "customer_differs"
    attributes = alert.attributes if isinstance(alert.attributes, dict) else {}
    for key, column in (("veeamAlarmCombinationId", "combination_id"), ("captureId", "capture_id")):
        if not isinstance(attributes.get(key), str) or attributes[key] != revision[column]:
            return f"{column}_differs"
    if alert.value not in _SEVERITY:
        return "state_not_active"
    if alert.severity != _SEVERITY[alert.value]:
        return "severity_differs"
    try:
        digest = v2.snapshot_digest({name: getattr(alert, name, None) for name in v2.SNAPSHOT_FIELDS})
    except v2.EnvelopeError:
        return "snapshot_invalid"
    if digest != revision["snapshot_sha256"]:
        return "snapshot_differs"
    return None


# --- Request-private storage (review R21/R22) -----------------------------------------------
# Evidence and original gate facts live here, keyed by the request context object, not in flask.g
# or any mapping a hook can reach through ordinary request state. (Arbitrary in-process code can
# still introspect; this protects against accidental and untrusted request-state changes.)

_PRIVATE: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()


def private() -> dict:
    from flask.globals import request_ctx
    ctx = request_ctx._get_current_object()
    if ctx not in _PRIVATE:
        _PRIVATE[ctx] = {"records": []}
    return _PRIVATE[ctx]


# --- Authentication evidence (pinned alerta/auth/decorators.py) -------------------------------

_wrapped_code = None
_installed = {}                      # the exact wrapper objects placed on Jwt and User
_qualified = {}                      # the qualified pinned verifiers the wrappers depend on

# SHA-256 of inspect.getsource() of the pinned Alerta 9.1.0 verifiers (review R21: first install
# must qualify the originals, not trust whatever is installed at that moment).
PINNED_VERIFIERS = {
    ("alerta.models.token", "Jwt.parse"): "3e343fa1b964808c82486d1cdb313dd2e26e1adb2ed95f3f9566925a6fa6ac42",
    ("alerta.models.user", "User.check_credentials"): "6f3f5b69265ced224bf9e9c13c4366526c887ec1470778150d48b46a43a23448",
    ("alerta.models.user", "User.verify_password"): "f468f91da07feb1108845482925a9a7bfb9ba6b2e6086ff59745373ff55e5b40",
    ("alerta.auth.utils", "check_password_hash"): "ad8cbb3d5ddbe54e1ebb99884ff589264937f191445b8d4fe4cd1b2e5717282d",
}


def _is_pinned(func, module_name: str, qualname: str) -> bool:
    """A plain function defined in the installed Alerta module, with the pinned source text."""
    import hashlib
    module = sys.modules.get(module_name)
    if module is None or not inspect.isfunction(func):
        return False
    try:
        source = inspect.getsource(func)
    except (OSError, TypeError):
        return False
    return (func.__module__ == module_name and func.__qualname__ == qualname
            and func.__code__.co_filename == module.__file__        # a wrapper's code lives elsewhere
            and hashlib.sha256(source.encode("utf-8")).hexdigest() == PINNED_VERIFIERS[(module_name, qualname)])


# Direct verification dependencies of the supported branches (review R21, 9674120): Basic ends in
# bcrypt.checkpw, Jwt.parse calls PyJWT's jwt.decode. Pinned versions and exact entry points;
# transitive library internals, the interpreter and native code are not attested.
PINNED_DEPENDENCY_VERSIONS = {"bcrypt": "5.0.0", "PyJWT": "2.15.1"}
PYJWT_DECODE_SHA256 = "99b4400c1f41526cc02e5c1eb03a2d460d89727078dbb82d0d248a5d1ca77447"
_qualified_deps = {}


def _current_dependencies() -> dict:
    import alerta.auth.utils as auth_utils
    import alerta.models.token as token_module
    return {"checkpw": getattr(getattr(auth_utils, "bcrypt", None), "checkpw", None),
            "decode": getattr(getattr(token_module, "jwt", None), "decode", None)}


def _dependencies_are_pinned(deps: dict) -> bool:
    import hashlib
    from importlib.metadata import PackageNotFoundError, version
    try:
        if any(version(dist) != want for dist, want in PINNED_DEPENDENCY_VERSIONS.items()):
            return False
    except PackageNotFoundError:
        return False
    import alerta.auth.utils as auth_utils
    import alerta.models.token as token_module
    native = sys.modules.get("bcrypt._bcrypt")
    checkpw = deps["checkpw"]
    if (auth_utils.bcrypt is not sys.modules.get("bcrypt") or native is None
            or not inspect.isbuiltin(checkpw) or checkpw is not getattr(native, "checkpw", None)
            or getattr(checkpw, "__self__", None) is not native):
        return False
    api_jwt = sys.modules.get("jwt.api_jwt")
    decode = deps["decode"]
    if (token_module.jwt is not sys.modules.get("jwt") or api_jwt is None or not inspect.ismethod(decode)
            or decode.__self__ is not getattr(api_jwt, "_jwt_global_obj", None)
            or type(decode.__self__) is not api_jwt.PyJWT
            or decode.__func__ is not api_jwt.PyJWT.__dict__.get("decode")
            or decode.__func__.__code__.co_filename != api_jwt.__file__):
        return False
    try:
        source = inspect.getsource(decode.__func__)
    except (OSError, TypeError):
        return False
    return hashlib.sha256(source.encode("utf-8")).hexdigest() == PYJWT_DECODE_SHA256


def _verification_qualified() -> bool:
    return recorders_in_place() and dependencies_in_place()


def dependencies_in_place() -> bool:
    """bcrypt.checkpw and jwt.decode, as Alerta reaches them, are still the qualified objects."""
    current = _current_dependencies()
    return bool(_qualified_deps) and all(current[k] is _qualified_deps[k] for k in _qualified_deps)


def _current_verifiers() -> dict:
    import alerta.auth.utils as auth_utils
    from alerta.models.token import Jwt
    from alerta.models.user import User
    parse = Jwt.__dict__.get("parse")
    check = User.__dict__.get("check_credentials")
    return {("alerta.models.token", "Jwt.parse"): getattr(parse, "__func__", None),
            ("alerta.models.user", "User.check_credentials"): getattr(check, "__func__", None),
            ("alerta.models.user", "User.verify_password"): User.__dict__.get("verify_password"),
            ("alerta.auth.utils", "check_password_hash"): getattr(auth_utils, "check_password_hash", None)}


def _permission_wrapper_code():
    """The code object of the decorator's inner ``wrapped`` function in the pinned source."""
    from alerta.auth import decorators
    outer = decorators.permission.__code__
    decorated = [c for c in outer.co_consts if inspect.iscode(c) and c.co_name == "decorated"]
    if len(decorated) != 1:
        return None
    wrapped = [c for c in decorated[0].co_consts if inspect.iscode(c) and c.co_name == "wrapped"]
    return wrapped[0] if len(wrapped) == 1 else None


def _caller_is_action_permission() -> bool:
    """True only inside the pinned permission('write:alerts') check of the action route."""
    from flask import g, has_request_context
    if _wrapped_code is None or not has_request_context() or g.get("voalack_candidate") is None:
        return False
    frame = sys._getframe(2)            # 0: this function, 1: the wrapper, 2: the decorator
    if frame.f_code is not _wrapped_code:
        return False
    import alerta.views.alerts as views
    from alerta.models.enums import Scope
    scope, view = frame.f_locals.get("scope"), frame.f_locals.get("f")
    return (scope == Scope.write_alerts and view is not None
            and inspect.unwrap(view) is inspect.unwrap(views.action_alert))


def _record(kind: str, values: tuple) -> None:
    private()["records"].append((kind,) + tuple(values))


def install_auth_recorders() -> None:
    """Wrap the two verification calls the decorator makes; behaviour and results are unchanged."""
    global _wrapped_code
    from alerta.models.token import Jwt
    from alerta.models.user import User
    if _installed:
        if not recorders_in_place() or not dependencies_in_place():
            raise RuntimeError("voalack: Alerta's verification helpers were replaced after installation")
        return
    current = _current_verifiers()
    for (module_name, qualname), func in current.items():
        if not _is_pinned(func, module_name, qualname):
            raise RuntimeError(f"voalack: {module_name}.{qualname} is not the pinned Alerta 9.1.0 verifier")
    deps = _current_dependencies()
    if not _dependencies_are_pinned(deps):
        raise RuntimeError("voalack: bcrypt.checkpw or jwt.decode is not the pinned verifier "
                           f"({', '.join(f'{k} {v}' for k, v in PINNED_DEPENDENCY_VERSIONS.items())})")
    _qualified.update(current)
    _qualified_deps.update(deps)
    _wrapped_code = _permission_wrapper_code()
    original_parse = Jwt.__dict__["parse"].__func__
    original_check = User.__dict__["check_credentials"].__func__

    @functools.wraps(original_parse)
    def parse(cls, token, key=None, verify=True, algorithm="HS256"):
        # The verifiers must be the qualified ones while verification runs, not only later at the
        # gate: checked immediately before and after the call (a self-restoring swap is caught).
        qualified = _verification_qualified()
        result = original_parse(cls, token, key, verify, algorithm)
        # Only the decorator's own default verified call counts: no key/algorithm override,
        # signature verification on, and called from the action route's permission check.
        if (qualified and _verification_qualified() and key is None and verify is True
                and algorithm == "HS256" and _caller_is_action_permission()):
            subject = result.oid or result.subject
            _record("jwt", (str(subject) if subject is not None else None, result.preferred_username,
                            result.provider))
        return result

    @functools.wraps(original_check)
    def check_credentials(username, password):
        qualified = _verification_qualified()
        user = original_check(username, password)
        if user is not None and qualified and _verification_qualified() and _caller_is_action_permission():
            _record("basic", (str(user.id), user.email))
        return user

    _installed["parse"] = classmethod(parse)
    _installed["check_credentials"] = staticmethod(check_credentials)
    Jwt.parse = _installed["parse"]
    User.check_credentials = _installed["check_credentials"]


def recorders_in_place() -> bool:
    """The verification calls the decorator uses are still exactly the installed wrappers."""
    from alerta.models.token import Jwt
    from alerta.models.user import User
    if not (_installed and _wrapped_code is not None
            and Jwt.__dict__.get("parse") is _installed["parse"]
            and User.__dict__.get("check_credentials") is _installed["check_credentials"]):
        return False
    current = _current_verifiers()
    # The wrappers' inner originals and the helpers they call are still the qualified ones.
    return (_installed["parse"].__func__.__wrapped__ is _qualified[("alerta.models.token", "Jwt.parse")]
            and _installed["check_credentials"].__func__.__wrapped__
            is _qualified[("alerta.models.user", "User.check_credentials")]
            and all(current[k] is _qualified[k] for k in (("alerta.models.user", "User.verify_password"),
                                                         ("alerta.auth.utils", "check_password_hash"))))


def verified_auth_type(user_id: str, login: str, ctx: v2.Context) -> str | None:
    """``basic`` or ``bearer:<provider>`` from exactly one matching private record, else None."""
    if not recorders_in_place() or not dependencies_in_place():
        return None
    records = list(private()["records"])
    if len(records) != 1:
        return None                        # none (e.g. AuthProxy), or duplicate/stale records
    kind, subject, name, *rest = records[0]
    if (subject, name) != (user_id, login):
        return None
    try:
        if kind == "jwt":
            return v2.auth_type("bearer", rest[0], ctx)
        if kind == "basic":
            return v2.auth_type("basic", None, ctx)
    except v2.EnvelopeError:
        return None
    return None


def build(signing: Signing, frozen: Mapping[str, Any], revision: Mapping[str, Any], generation: int,
          note: object) -> dict:
    """The complete envelope from the frozen gate facts, the revision and the final note."""
    return v2.build_envelope(
        ctx=signing.ctx, kid=frozen["kid"], customer=frozen["customer"],
        source_namespace=revision["source_namespace"], instance_id=revision["instance_id"],
        alert_id=frozen["alert_id"], action_id=frozen["action_id"], request_id=frozen["request_id"],
        generation=generation, binding_id=frozen["binding_id"], binding_revision=frozen["binding_revision"],
        source={"target_kind": revision["target_kind"], "target_id": revision["target_id"],
                "occurrence_ref": revision["occurrence_ref"],
                "occurrence_evidence_sha256": revision["occurrence_evidence_sha256"],
                "snapshot_sha256": revision["snapshot_sha256"]},
        actor={"user_id": frozen["user_id"], "login": frozen["login"], "auth_type": frozen["auth_type"],
               "authorization_policy_revision": frozen["policy_revision"],
               "authorized_customer": frozen["customer"]},
        note=note, message_policy_revision=frozen["message_policy_revision"],
        issued_at=frozen["issued_at"], capture_expires_at=frozen["capture_expires_at"],
        execution_expires_at=frozen["execution_expires_at"])
