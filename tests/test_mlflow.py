import mlflow
import shutil
import os


def test_mlflow_integration():
    print("\n" + "="*60)
    print("  Testing MLflow Integration")
    print("="*60)

    mlflow.set_tracking_uri("test_mlruns")
    mlflow.set_experiment("test-aegis")
    print("Tracking URI and experiment set")

    with mlflow.start_run(run_name="test-run-001"):
        mlflow.log_params({
            "learning_rate": 0.001,
            "batch_size": 16,
            "num_epochs": 2,
            "optimizer": "adam",
            "scheduler": "cosine",
            "loss_type": "focal",
            "early_stopping_patience": 5,
            "device": "cpu",
        })
        print("Hyperparameters logged")

        for epoch in range(2):
            mlflow.log_metrics({
                "train_loss": 0.5 - epoch * 0.1,
                "train_f1": 0.7 + epoch * 0.05,
                "train_precision": 0.75 + epoch * 0.03,
                "train_recall": 0.68 + epoch * 0.04,
                "train_roc_auc": 0.80 + epoch * 0.02,
                "val_loss": 0.55 - epoch * 0.08,
                "val_f1": 0.68 + epoch * 0.06,
                "val_precision": 0.72 + epoch * 0.03,
                "val_recall": 0.65 + epoch * 0.04,
                "val_roc_auc": 0.78 + epoch * 0.03,
            }, step=epoch)
        print("Metrics logged for 2 epochs")

    print("\n" + "="*60)
    print("  Verifying MLflow Logs")
    print("="*60)

    experiment = mlflow.get_experiment_by_name("test-aegis")
    assert experiment is not None, "Experiment was not created"
    print("Experiment created:", experiment.name)

    runs = mlflow.search_runs(experiment_ids=[experiment.experiment_id])
    assert len(runs) > 0, "No runs found"
    print("Run logged successfully")

    run = runs.iloc[0]

    assert run['params.optimizer'] == 'adam', "Optimizer param missing"
    assert run['params.learning_rate'] == '0.001', "LR param missing"
    print("Hyperparameters verified")

    assert 'metrics.val_f1' in run, "val_f1 metric missing"
    assert 'metrics.train_loss' in run, "train_loss metric missing"
    print("Metrics verified")

    print("\n" + "="*60)
    print("  ALL TESTS PASSED")
    print("="*60 + "\n")


def cleanup():
    for folder in ['test_mlruns']:
        if os.path.exists(folder):
            shutil.rmtree(folder)
    print("Cleaned up test artifacts")


if __name__ == '__main__':
    try:
        test_mlflow_integration()
    finally:
        cleanup()