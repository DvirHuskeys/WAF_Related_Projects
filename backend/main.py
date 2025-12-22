from fastapi import FastAPI, HTTPException

from backend.services.persona import generate_persona_view, list_personas


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
async def persona_view(persona_id: str, domain: str):
    try:
        payload = generate_persona_view(persona_id, domain)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return payload

