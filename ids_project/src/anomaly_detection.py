from __future__ import annotations

import pickle

import pandas as pd
from sklearn.ensemble import IsolationForest

from src.utils import MODEL_PATH, setup_logging


LOGGER = setup_logging(__name__)


def train_anomaly_model(
    data: pd.DataFrame,
    feature_columns: list[str],
    contamination: float = 0.08,
) -> IsolationForest:
    """Train Isolation Forest on normal traffic only when labels are available."""
    training_data = data[data["label"].str.lower().eq("normal")] if "label" in data else data
    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42,
        n_jobs=1,
    )
    model.fit(training_data[feature_columns])
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    with MODEL_PATH.open("wb") as model_file:
        pickle.dump(model, model_file)
    LOGGER.info("Trained Isolation Forest on %s normal records and saved %s", len(training_data), MODEL_PATH)
    return model


def load_or_train_model(data: pd.DataFrame, feature_columns: list[str], retrain: bool = False) -> IsolationForest:
    """Load a persisted anomaly model or train a fresh one."""
    if MODEL_PATH.exists() and not retrain:
        LOGGER.info("Loaded existing anomaly model from %s", MODEL_PATH)
        with MODEL_PATH.open("rb") as model_file:
            return pickle.load(model_file)
    return train_anomaly_model(data, feature_columns)


def predict_anomalies(
    data: pd.DataFrame,
    feature_columns: list[str],
    model: IsolationForest | None = None,
    retrain: bool = False,
) -> pd.DataFrame:
    """Predict anomalous traffic events using the trained Isolation Forest."""
    detector = model or load_or_train_model(data, feature_columns, retrain=retrain)
    scored = data.copy()
    scored["anomaly_score"] = detector.decision_function(scored[feature_columns])
    scored["ml_prediction"] = detector.predict(scored[feature_columns])
    scored["ml_anomaly"] = scored["ml_prediction"].eq(-1)

    anomalies = scored[scored["ml_anomaly"]].copy()
    anomalies["detection_method"] = "machine_learning"
    LOGGER.info("ML anomaly detection flagged %s events", len(anomalies))
    return anomalies
