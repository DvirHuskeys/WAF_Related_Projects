from fastapi import FastAPI, HTTPException, Query, Request

from backend.services.persona import (
    DomainNotFound,
    PersonaNotFound,
    generate_persona_view,
    list_personas,
)
from backend.services import logging as usage_logging


app = FastAPI(
    title="WAF Security Local Lab",
    description="Local-first APIs for GTM Radar and WAFtotal experiments",
    version="0.1.0",
)


@app.get("/health")
async def healthcheck():
    return {"status": "ok"}


@app.get("/personas")
async def personas():
    return list_personas()


@app.get("/persona/{persona_id}/{domain}")
async def persona_view(
    persona_id: str,
    domain: str,
    request: Request,
    log_usage: bool = Query(True, description="Set false to skip usage logging."),
):
    try:
        payload = generate_persona_view(persona_id, domain)
    except PersonaNotFound as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except DomainNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    include_usage = request.query_params.get("include_usage")
    if include_usage is not None:
        log_usage = include_usage.lower() not in {"false", "0"}

    if log_usage:
        usage_logging.log_persona_usage(
            payload["persona_id"], payload["domain"], "view", "API"
        )
    return payload

