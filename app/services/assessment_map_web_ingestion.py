"""Pure extraction and mapping rules for discovery-oriented web tools."""

from __future__ import annotations

from typing import Any, Protocol
from urllib.parse import urljoin

from app.services.assessment_map_identity import (
    CanonicalIdentity,
    canonical_application_origin,
    canonical_endpoint,
)


STRUCTURED_ARTIFACT_TYPES = {
    # These tools currently persist normalized evidence in findings only.
    "katana": frozenset(),
    "playwright": frozenset(),
    "ffuf": frozenset(),
}


class MappingWriter(Protocol):
    root_path: str

    def entity(self, identity: CanonicalIdentity, evidence_kind: str, path: str) -> Any: ...
    def assertion(
        self,
        subject: Any,
        predicate: str,
        *,
        evidence_kind: str,
        path: str,
        object_entity: Any | None = None,
        value: Any = ...,
    ) -> Any: ...
    def skipped_optional(self, reason: str) -> None: ...


def project_web_source(tool: str, data: dict[str, Any]) -> dict[str, Any]:
    """Return only fields consumed by mapping; this defines digest v1 semantics."""

    if tool == "katana":
        observations = data.get("katana_observations")
        return {"source": data.get("source"), "katana_observations": _project_katana(observations)}
    if tool == "playwright":
        observation = data.get("playwright_observation")
        fields = (
            "requested_url", "final_url", "title", "load_status", "status_code",
            "link_samples", "network_events", "forms_count", "inputs_count", "links_count",
        )
        projected = _project_dict(observation, fields)
        if isinstance(projected, dict) and isinstance(observation, dict):
            base_url = observation.get("final_url") or observation.get("requested_url")
            for field in ("requested_url", "final_url"):
                if field in observation:
                    projected[field] = _canonical_url_key(observation.get(field))
            projected["link_samples"] = [
                _canonical_resolved_url_key(base_url, value) for value in observation.get("link_samples") or []
            ] if isinstance(observation.get("link_samples") or [], list) else {"malformed": True}
            projected["network_events"] = _project_network_events(observation.get("network_events"), base_url)
        return {"source": data.get("source"), "playwright_observation": projected}
    if tool == "ffuf":
        results = data.get("ffuf_results")
        return {
            "source": data.get("source"),
            "ffuf_results": _project_ffuf(results),
            "metadata": web_coverage_metadata("ffuf", data),
        }
    raise ValueError("Unsupported web ingestion tool.")


def web_coverage_metadata(tool: str, data: dict[str, Any]) -> dict[str, Any]:
    """Sanitized run-scope metadata stored on the ingestion ledger."""

    if tool == "playwright":
        observation = data.get("playwright_observation")
        if not isinstance(observation, dict):
            return {}
        return {
            key: value
            for key, value in {
                "forms_count": _nonnegative_int(observation.get("forms_count")),
                "inputs_count": _nonnegative_int(observation.get("inputs_count")),
                "links_count": _nonnegative_int(observation.get("links_count")),
                "network_event_count": len(observation.get("network_events") or [])
                if isinstance(observation.get("network_events") or [], list) else None,
            }.items()
            if value is not None
        }
    if tool == "ffuf":
        results = data.get("ffuf_results")
        metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
        return {
            key: value
            for key, value in {
                "profile": _safe_label(metadata.get("ffuf_profile")),
                "profile_label": _safe_label(metadata.get("ffuf_profile_label")),
                "wordlist_name": _basename(metadata.get("wordlist_path")),
                "wordlist_source": _safe_label(metadata.get("wordlist_source")),
                "wordlist_entry_count": _nonnegative_int(metadata.get("wordlist_count")),
                "timeout_seconds": _nonnegative_int(metadata.get("timeout_seconds")),
                "result_count": len(results) if isinstance(results, list) else None,
            }.items()
            if value not in (None, "")
        }
    if tool == "katana":
        observations = data.get("katana_observations")
        return {"observation_count": len(observations)} if isinstance(observations, list) else {}
    return {}


def map_web_source(tool: str, data: dict[str, Any], writer: MappingWriter) -> None:
    source_tool = str(data.get("source") or "").strip().lower().removesuffix(".sh")
    if source_tool and source_tool != tool:
        raise ValueError("Linked structured evidence does not match the scan tool.")
    if tool == "katana":
        _map_katana(data, writer)
    elif tool == "playwright":
        _map_playwright(data, writer)
    elif tool == "ffuf":
        _map_ffuf(data, writer)
    else:
        raise ValueError("Unsupported web ingestion tool.")


def _map_katana(data: dict[str, Any], writer: MappingWriter) -> None:
    observations = _require_list(data, "katana_observations")
    crawled_endpoints: dict[str, CanonicalIdentity] = {}
    valid_observations: list[tuple[int, dict[str, Any], CanonicalIdentity]] = []
    for index, observation in enumerate(observations):
        if not isinstance(observation, dict):
            writer.skipped_optional("malformed_primary_record")
            continue
        url = observation.get("url")
        if not isinstance(url, str) or not url.strip():
            writer.skipped_optional("malformed_primary_url")
            continue
        try:
            identity = canonical_endpoint(url)
        except ValueError:
            writer.skipped_optional("malformed_primary_url")
            continue
        crawled_endpoints[identity.identity_hash] = identity
        valid_observations.append((index, observation, identity))
    mapped = 0
    for index, observation, _ in valid_observations:
        url = str(observation["url"])
        base = f"{writer.root_path}.katana_observations[{index}]"
        application, endpoint = _web_entities(writer, url, "katana_crawled_url", f"{base}.url")
        writer.assertion(application, "contains_endpoint", object_entity=endpoint,
                         evidence_kind="katana_crawled_url", path=f"{base}.url")
        mapped += 1
        for predicate, field in (
            ("has_crawl_depth", "depth"), ("has_observed_method", "method"),
            ("has_response_status", "status_code"), ("has_endpoint_type", "endpoint_type"),
        ):
            if observation.get(field) not in (None, ""):
                writer.assertion(endpoint, predicate, value=observation[field],
                                 evidence_kind=predicate, path=f"{base}.{field}")
        parameters = observation.get("query_parameters") or []
        if not isinstance(parameters, list):
            writer.skipped_optional("malformed_parameter_names")
            parameters = []
        for parameter_index, parameter in enumerate(parameters):
            name = _parameter_name(parameter)
            if name:
                writer.assertion(endpoint, "has_query_parameter_name", value=name,
                                 evidence_kind="katana_parameter_name",
                                 path=f"{base}.query_parameters[{parameter_index}]")
        if observation.get("source") not in (None, ""):
            try:
                source_identity = canonical_endpoint(str(observation["source"]))
            except ValueError:
                writer.skipped_optional("malformed_source_url")
                source_identity = None
            if source_identity is None:
                pass
            else:
                observed_source = crawled_endpoints.get(source_identity.identity_hash)
                if observed_source is not None:
                    source_endpoint = writer.entity(observed_source, "katana_source_url", f"{base}.source")
                    writer.assertion(endpoint, "discovered_from", object_entity=source_endpoint,
                                     evidence_kind="katana_source_url", path=f"{base}.source")
                else:
                    writer.assertion(endpoint, "discovered_from_reference", value=source_identity.payload,
                                     evidence_kind="katana_source_url", path=f"{base}.source")
        forms = observation.get("forms") or []
        if not isinstance(forms, list):
            writer.skipped_optional("malformed_forms")
            forms = []
        for form_index, form in enumerate(forms):
            if not isinstance(form, dict):
                writer.skipped_optional("malformed_form")
                continue
            action = form.get("action")
            if not isinstance(action, str) or not action.strip():
                continue
            action_url = _resolve_url(url, action)
            if action_url is None:
                writer.skipped_optional("malformed_form_action")
                continue
            try:
                form_identity = canonical_endpoint(action_url)
            except ValueError:
                writer.skipped_optional("malformed_form_action")
                continue
            form_path = f"{base}.forms[{form_index}].action"
            form_endpoint = writer.entity(form_identity, "katana_form_action_reference", form_path)
            writer.assertion(endpoint, "declares_form_action", object_entity=form_endpoint,
                             evidence_kind="katana_form_action", path=form_path)
            if form.get("method") not in (None, ""):
                writer.assertion(form_endpoint, "declares_method", value=str(form["method"]).strip(),
                                 evidence_kind="katana_form_method",
                                 path=f"{base}.forms[{form_index}].method")
            inputs = form.get("inputs") or []
            if not isinstance(inputs, list):
                writer.skipped_optional("malformed_form_inputs")
                inputs = []
            for input_index, input_name in enumerate(inputs):
                name = _parameter_name(input_name)
                if name:
                    writer.assertion(form_endpoint, "has_parameter_name", value=name,
                                     evidence_kind="katana_form_parameter_name",
                                     path=f"{base}.forms[{form_index}].inputs[{input_index}]")
    if not mapped:
        raise ValueError("No explicit Katana crawl observations.")


def _map_playwright(data: dict[str, Any], writer: MappingWriter) -> None:
    observation = data.get("playwright_observation")
    if not isinstance(observation, dict):
        raise ValueError("Missing Playwright observation.")
    final_url = observation.get("final_url")
    status = observation.get("status_code")
    network_events = observation.get("network_events") or []
    if not isinstance(network_events, list):
        writer.skipped_optional("malformed_network_events")
        network_events = []
    valid_status = isinstance(status, int) and not isinstance(status, bool) and 100 <= status <= 599
    requested_url = observation.get("requested_url")
    load_status = str(observation.get("load_status") or "").strip().lower()
    explicit_final = (
        isinstance(final_url, str)
        and bool(final_url.strip())
        and (
            valid_status
            or final_url != requested_url
            or load_status not in {"", "unknown", "failed", "timeout", "navigation_failed"}
        )
    )
    observed = explicit_final
    if not observed and valid_status:
        final_url = observation.get("requested_url")
        observed = isinstance(final_url, str) and bool(final_url.strip())
    primary = None
    if observed:
        base = f"{writer.root_path}.playwright_observation"
        try:
            application, primary = _web_entities(writer, str(final_url), "playwright_final_url", f"{base}.final_url")
        except ValueError:
            writer.skipped_optional("malformed_primary_url")
            observed = False
            primary = None
        if primary is not None:
            writer.assertion(application, "contains_endpoint", object_entity=primary,
                             evidence_kind="playwright_final_url", path=f"{base}.final_url")
        for predicate, field in (
            ("has_response_status", "status_code"), ("has_title", "title"),
            ("has_load_status", "load_status"),
        ):
            if primary is not None and observation.get(field) not in (None, ""):
                writer.assertion(primary, predicate, value=observation[field],
                                 evidence_kind=predicate, path=f"{base}.{field}")
    base = f"{writer.root_path}.playwright_observation"
    mapped_events = 0
    for index, event in enumerate(network_events):
        if not isinstance(event, dict):
            writer.skipped_optional("malformed_network_response")
            continue
        event_url = event.get("url")
        event_status = _status(event.get("status") if "status" in event else event.get("status_code"))
        if not isinstance(event_url, str) or not event_url.strip() or event_status is None:
            if event_url not in (None, ""):
                writer.skipped_optional("malformed_network_response")
            continue
        resolved_event_url = _resolve_url(final_url or requested_url, event_url)
        if resolved_event_url is None:
            writer.skipped_optional("malformed_network_url")
            continue
        event_path = f"{base}.network_events[{index}].url"
        try:
            app, endpoint = _web_entities(writer, resolved_event_url, "playwright_network_response", event_path)
        except ValueError:
            writer.skipped_optional("malformed_network_url")
            continue
        writer.assertion(app, "contains_endpoint", object_entity=endpoint,
                         evidence_kind="playwright_network_response", path=event_path)
        status_field = "status" if "status" in event else "status_code"
        writer.assertion(endpoint, "has_response_status", value=event_status,
                         evidence_kind="playwright_network_status",
                         path=f"{base}.network_events[{index}].{status_field}")
        mapped_events += 1
    links = observation.get("link_samples") or []
    if not isinstance(links, list):
        writer.skipped_optional("malformed_sampled_links")
        links = []
    mapped_links = 0
    for index, link in enumerate(links):
        if not isinstance(link, str) or not link.strip():
            writer.skipped_optional("malformed_sampled_link")
            continue
        resolved_link = _resolve_url(final_url or requested_url, link)
        if resolved_link is None:
            writer.skipped_optional("malformed_sampled_link")
            continue
        link_path = f"{base}.link_samples[{index}]"
        try:
            endpoint = writer.entity(canonical_endpoint(resolved_link), "playwright_sampled_link_reference", link_path)
        except ValueError:
            writer.skipped_optional("malformed_sampled_link")
            continue
        if primary is not None:
            writer.assertion(primary, "links_to", object_entity=endpoint,
                             evidence_kind="playwright_sampled_link", path=link_path)
        mapped_links += 1
    if not observed and not mapped_events and not mapped_links:
        raise ValueError("No explicit observed Playwright URL evidence.")


def _map_ffuf(data: dict[str, Any], writer: MappingWriter) -> None:
    results = _require_list(data, "ffuf_results")
    metadata = data.get("metadata") or {}
    if not isinstance(metadata, dict):
        raise ValueError("Malformed ffuf run metadata.")
    mapped = 0
    for index, result in enumerate(results):
        if not isinstance(result, dict):
            raise ValueError("Malformed ffuf response observation.")
        status = _status(result.get("status_code"))
        url = result.get("url")
        if status is None or not isinstance(url, str) or not url.strip():
            writer.skipped_optional("malformed_response_record")
            continue
        base = f"{writer.root_path}.ffuf_results[{index}]"
        try:
            application, endpoint = _web_entities(writer, url, "ffuf_response", f"{base}.url")
        except ValueError:
            writer.skipped_optional("malformed_response_url")
            continue
        writer.assertion(application, "contains_endpoint", object_entity=endpoint,
                         evidence_kind="ffuf_response", path=f"{base}.url")
        for predicate, field in (
            ("has_response_status", "status_code"), ("has_content_length", "content_length"),
            ("has_word_count", "words"), ("has_line_count", "lines"),
        ):
            if result.get(field) is not None:
                writer.assertion(endpoint, predicate, value=result[field],
                                 evidence_kind=predicate, path=f"{base}.{field}")
        redirect = result.get("redirect_location")
        if redirect not in (None, ""):
            try:
                resolved_redirect = _resolve_url(url, redirect)
                if resolved_redirect is None:
                    raise ValueError("Malformed redirect URL.")
                redirect_identity = canonical_endpoint(resolved_redirect)
            except ValueError:
                writer.skipped_optional("malformed_redirect_url")
            else:
                writer.assertion(endpoint, "redirects_to_reference", value=redirect_identity.payload,
                                 evidence_kind="ffuf_redirect", path=f"{base}.redirect_location")
        for field, predicate in (
            ("ffuf_profile", "has_ffuf_profile"), ("ffuf_profile_label", "has_ffuf_profile_label"),
            ("wordlist_path", "has_wordlist_name"), ("wordlist_source", "has_wordlist_source"),
            ("wordlist_count", "has_wordlist_entry_count"), ("timeout_seconds", "has_scan_timeout_seconds"),
        ):
            value = metadata.get(field)
            if value in (None, ""):
                continue
            if field == "wordlist_path":
                value = str(value).replace("\\", "/").rsplit("/", 1)[-1]
            writer.assertion(application, predicate, value=value, evidence_kind="ffuf_run_scope",
                             path=f"{writer.root_path}.metadata.{field}")
        mapped += 1
    if not mapped and results:
        raise ValueError("No response-backed ffuf observations.")
    # A valid zero-result run is represented by its completed ledger projection only. It
    # deliberately creates no target/application entity and no negative assertion.


def _web_entities(writer: MappingWriter, url: str, kind: str, path: str) -> tuple[Any, Any]:
    application = writer.entity(canonical_application_origin(url), kind, path)
    endpoint = writer.entity(canonical_endpoint(url), kind, path)
    return application, endpoint


def _require_list(data: dict[str, Any], key: str) -> list[Any]:
    value = data.get(key)
    if not isinstance(value, list):
        raise ValueError(f"Missing normalized {key} observations.")
    return value


def _project_list(value: object, fields: tuple[str, ...]) -> object:
    if not isinstance(value, list):
        return {"malformed_type": type(value).__name__}
    return [_project_dict(item, fields) if isinstance(item, dict)
            else {"malformed_type": type(item).__name__} for item in value]


def _project_dict(value: object, fields: tuple[str, ...]) -> object:
    if not isinstance(value, dict):
        return {"malformed_type": type(value).__name__}
    return {field: value.get(field) for field in fields if field in value}


def _project_katana(value: object) -> object:
    if not isinstance(value, list):
        return {"malformed_type": type(value).__name__}
    projected = []
    for item in value:
        if not isinstance(item, dict):
            projected.append({"malformed_type": type(item).__name__})
            continue
        forms = []
        if isinstance(item.get("forms") or [], list):
            for form in item.get("forms") or []:
                if not isinstance(form, dict):
                    forms.append({"malformed": True})
                    continue
                forms.append({
                    "action": _canonical_resolved_url_key(item.get("url"), form.get("action")),
                    "method": form.get("method"),
                    "inputs": [_parameter_name(candidate) for candidate in form.get("inputs") or []]
                    if isinstance(form.get("inputs") or [], list) else {"malformed": True},
                })
        projected.append({
            "url": _canonical_url_key(item.get("url")),
            "source": _canonical_url_key(item.get("source")),
            "method": item.get("method"),
            "status_code": item.get("status_code"),
            "depth": item.get("depth"),
            "endpoint_type": item.get("endpoint_type"),
            "query_parameters": [_parameter_name(candidate) for candidate in item.get("query_parameters") or []]
            if isinstance(item.get("query_parameters") or [], list) else {"malformed": True},
            "forms": forms,
        })
    return projected


def _project_network_events(value: object, base_url: object) -> object:
    if not isinstance(value, list):
        return {"malformed_type": type(value).__name__}
    projected = []
    for event in value:
        if not isinstance(event, dict):
            projected.append({"malformed": True})
            continue
        status_field = "status" if "status" in event else "status_code"
        projected.append({
            "url": _canonical_resolved_url_key(base_url, event.get("url")),
            status_field: event.get(status_field),
        })
    return projected


def _project_ffuf(value: object) -> object:
    if not isinstance(value, list):
        return {"malformed_type": type(value).__name__}
    projected = []
    for result in value:
        if not isinstance(result, dict):
            projected.append({"malformed": True})
            continue
        projected.append({
            "url": _canonical_url_key(result.get("url")),
            "status_code": result.get("status_code"),
            "content_length": result.get("content_length"),
            "words": result.get("words"),
            "lines": result.get("lines"),
            "redirect_location": _canonical_resolved_url_key(result.get("url"), result.get("redirect_location")),
        })
    return projected


def _canonical_url_key(value: object) -> str | None:
    if value in (None, ""):
        return None
    try:
        return canonical_endpoint(str(value)).canonical_key
    except ValueError:
        return "invalid"


def _canonical_resolved_url_key(base: object, value: object) -> str | None:
    if value in (None, ""):
        return None
    resolved = _resolve_url(base, value)
    return _canonical_url_key(resolved) if resolved is not None else "invalid"


def _resolve_url(base: object, value: object) -> str | None:
    try:
        return urljoin(str(base or ""), str(value))
    except (TypeError, ValueError):
        return None


def _status(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        status = int(value)
    except (TypeError, ValueError):
        return None
    return status if 100 <= status <= 599 else None


def _parameter_name(value: object) -> str:
    if isinstance(value, dict):
        value = value.get("name") if value.get("name") not in (None, "") else value.get("key")
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        return ""
    cleaned = str(value).strip()
    if not cleaned or cleaned.startswith(("{", "[")):
        return ""
    for separator in ("=", ":"):
        cleaned = cleaned.split(separator, 1)[0].strip()
    if not cleaned or len(cleaned) > 128:
        return ""
    return cleaned if all(character.isalnum() or character in "_.-[]" for character in cleaned) else ""


def _nonnegative_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        result = int(value)
    except (TypeError, ValueError):
        return None
    return result if result >= 0 else None


def _safe_label(value: object) -> str | None:
    cleaned = " ".join(str(value or "").split())
    if not cleaned or len(cleaned) > 120:
        return None
    return cleaned if all(character.isalnum() or character in " ._-+" for character in cleaned) else None


def _basename(value: object) -> str | None:
    cleaned = str(value or "").replace("\\", "/").rsplit("/", 1)[-1].strip()
    return _safe_label(cleaned)
