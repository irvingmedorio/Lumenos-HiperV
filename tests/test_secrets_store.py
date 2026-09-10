import tempfile, pathlib, json
from lumenos_sandbox.secrets import SecretManager

def test_secrets_fallback_file(tmp_path, monkeypatch):
    monkeypatch.setattr(pathlib.Path, "home", lambda: tmp_path)
    # Force keyring failure
    monkeypatch.setitem(__import__("sys").modules, "keyring", None)
    # Use fresh manager
    import importlib, sys
    m=SecretManager(service_name="test_lumenos")
    # Monkeypatch to simulate keyring import failure
    orig_import = __import__
    def fake_import(name, *a, **k):
        if name=="keyring": raise ImportError("no keyring")
        return orig_import(name, *a, **k)
    # Instead directly test file fallback
    m._file_store("k","v")
    assert m._file_get("k")=="v"
    assert m._file_delete("k") is True
    assert m._file_get("k") is None
