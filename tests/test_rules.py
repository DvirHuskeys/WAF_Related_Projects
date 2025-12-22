from backend.services import rules, storage


def _setup(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "WAREHOUSE_PATH", tmp_path / "warehouse.db")
    storage.initialize_schema()


def test_add_and_list_notes(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    monkeypatch.setenv("ANNOTATION_AUTHOR", "alice")
    note_id = rules.add_note("cloudflare", "200", "First note")
    notes = rules.list_notes("cloudflare", "200")
    assert len(notes) == 1
    assert notes[0]["note_id"] == note_id
    assert notes[0]["author"] == "alice"


def test_edit_and_delete_notes_with_roles(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    monkeypatch.setenv("ANNOTATION_AUTHOR", "alice")
    note_id = rules.add_note("cloudflare", "300", "Original")

    # Different author without admin role cannot edit
    monkeypatch.setenv("ANNOTATION_AUTHOR", "bob")
    monkeypatch.setenv("ROLE", "viewer")
    assert rules.update_note(note_id, "Hacked") is False

    # Admin role can edit/delete even if not original author
    monkeypatch.setenv("ROLE", "admin")
    assert rules.update_note(note_id, "Updated by admin") is True
    assert rules.delete_note(note_id) is True
    assert rules.list_notes("cloudflare", "300") == []











