"""Regression coverage for graph loader boot-memory behavior."""

from pathlib import Path


def test_loader_avoids_intermediate_bytesio_buffer():
    source = Path("src/training/data_loader.py").read_text(encoding="utf-8")

    assert "io.BytesIO" not in source
    assert "torch.load(f, weights_only=False)" in source
