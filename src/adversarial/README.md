# Adversarial Robustness Evaluation Suite

Evaluates the HTGAT fraud detection model against deliberate input perturbations that simulate adversarial behavior. Implements [#139](https://github.com/Puneet04-tech/AegisGraph-Sentinel-2.0/issues/139).

## Quick start

From the repo root, with a checkpoint in `models/htgnn_final.pt`:

```bash
python -m src.adversarial
```

This runs all four attacks at five budget levels over 50 graphs each and writes JSON and Markdown reports to `reports/`.

## Attacks

| Name | Category | Budget meaning | What it does |
|---|---|---|---|
| `edge_addition` | structural | fraction of edges | Appends random edges |
| `edge_deletion` | structural | fraction of edges | Removes random edges (keeps ≥ 1) |
| `node_injection` | structural | fraction of nodes | Adds fake nodes connected to existing ones |
| `feature_perturbation` | feature | noise std | Adds Gaussian noise to node features |

## Usage

```bash
# Run all attacks at default budgets
python -m src.adversarial

# Run a subset
python -m src.adversarial --attacks edge_addition feature_perturbation

# Custom budget sweep, more graphs per evaluation
python -m src.adversarial --budgets 0.05 0.10 0.20 --n-graphs 100

# Different checkpoint
python -m src.adversarial --checkpoint models/htgnn_best.pt
```

See `python -m src.adversarial --help` for all options.

## Output

Two files are written to the output directory (default `reports/`):

- `adversarial_results.json` — full numerical results, machine-readable
- `adversarial_results.md` — human-readable summary grouped by attack

The Markdown is suitable for pasting into PR descriptions or issue comments.

## Extending the suite

To add an attack, subclass `BaseAttack` and implement `perturb`:

```python
from src.adversarial.base import BaseAttack, Graph

class MyAttack(BaseAttack):
    name = "my_attack"

    def perturb(self, graph: Graph) -> Graph:
        # Return a new graph dict; do not mutate the input
        ...
```

Then register it in `src/adversarial/attacks/__init__.py` exports and in the CLI's `ATTACK_REGISTRY` in `__main__.py`.

## Testing

```bash
pytest tests/test_adversarial.py -v --noconftest
```

The `--noconftest` flag bypasses the project's existing `tests/conftest.py`, which has preexisting import issues unrelated to this module.

## Limitations

- Evaluates against synthetic graphs matching the format in `example_training.py`. To evaluate against a real test set, pass a custom `graph_builder` to `evaluate_attack()`.
- Budget semantics differ across attack categories (fraction of edges/nodes vs. noise magnitude). The interpretation is documented per attack class.
- Reports against a model with near-zero predictions (such as one trained on uncorrelated synthetic data) will show no threshold flips. Against a properly trained model, the same attacks should surface meaningful flips at moderate budgets.