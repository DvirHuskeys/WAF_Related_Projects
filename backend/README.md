# `backend/`

Supports FastAPI services, persona scoring logic, and storage abstractions.
Modules under `backend/services/` should remain import-safe inside Streamlit so
the UI and CLI tools can share code. Keep public APIs documented here when
adding new service layers.
