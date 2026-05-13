"""
Script training ML model cho document classification
"""
import os
import pickle
from pathlib import Path
from typing import List, Tuple
import re

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib

from loguru import logger

# Setup paths
BASE_DIR = Path(__file__).parent.parent.parent
WORKER_DIR = BASE_DIR / "worker"
DATASET_DIR = WORKER_DIR / "dataset"
SENSITIVE_DIR = DATASET_DIR / "sensitive"
NORMAL_DIR = DATASET_DIR / "normal"
MODELS_DIR = WORKER_DIR / "ml_models"

MODELS_DIR.mkdir(parents=True, exist_ok=True)


def load_dataset() -> Tuple[List[str], List[str]]:
    """Load dataset từ thư mục"""
    texts = []
    labels = []
    
    # Load sensitive documents
    logger.info("Loading sensitive documents...")
    for filepath in SENSITIVE_DIR.glob("*.txt"):
        try:
            content = filepath.read_text(encoding="utf-8")
            texts.append(content)
            labels.append("sensitive")
        except Exception as e:
            logger.warning(f"Error reading {filepath}: {e}")
    
    # Load normal documents
    logger.info("Loading normal documents...")
    for filepath in NORMAL_DIR.glob("*.txt"):
        try:
            content = filepath.read_text(encoding="utf-8")
            texts.append(content)
            labels.append("normal")
        except Exception as e:
            logger.warning(f"Error reading {filepath}: {e}")
    
    logger.info(f"Loaded {len(texts)} documents:")
    logger.info(f"  - Sensitive: {labels.count('sensitive')}")
    logger.info(f"  - Normal: {labels.count('normal')}")
    
    return texts, labels


def preprocess_text(text: str) -> str:
    """Preprocess text"""
    # Remove extra whitespace
    text = re.sub(r'\s+', ' ', text)
    # Remove special characters (keep Vietnamese)
    text = re.sub(r'[^\w\sàáạảãâầấậẩẫăằắặẳẵèéẹẻẽêềếệểễìíịỉĩòóọỏõôồốộổỗơờớợởỡùúụủũưừứựửữỳýỵỷỹđ]', ' ', text, flags=re.UNICODE)
    return text.strip().lower()


def train_model():
    """Train ML model"""
    logger.info("Starting model training...")
    
    # Load dataset
    texts, labels = load_dataset()
    
    if len(texts) < 10:
        logger.error(f"Not enough data! Need at least 10 documents, got {len(texts)}")
        logger.info("Run collect_dataset.py first to generate dataset")
        return
    
    # Preprocess
    logger.info("Preprocessing texts...")
    processed_texts = [preprocess_text(text) for text in texts]
    
    # Split dataset
    logger.info("Splitting dataset...")
    X_train, X_test, y_train, y_test = train_test_split(
        processed_texts, labels, test_size=0.2, random_state=42, stratify=labels
    )
    
    logger.info(f"Train set: {len(X_train)} samples")
    logger.info(f"Test set: {len(X_test)} samples")
    
    # Vectorize
    logger.info("Vectorizing texts...")
    vectorizer = TfidfVectorizer(
        max_features=5000,
        ngram_range=(1, 2),
        min_df=2,
        max_df=0.95
    )
    
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)
    
    logger.info(f"Vectorizer features: {len(vectorizer.vocabulary_)}")
    
    # Train model
    logger.info("Training Random Forest classifier...")
    classifier = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        random_state=42,
        n_jobs=-1
    )
    
    classifier.fit(X_train_vec, y_train)
    
    # Evaluate
    logger.info("Evaluating model...")
    y_pred = classifier.predict(X_test_vec)
    accuracy = accuracy_score(y_test, y_pred)
    
    logger.info(f"Accuracy: {accuracy:.4f}")
    logger.info("\nClassification Report:")
    logger.info(classification_report(y_test, y_pred))
    
    # Save model
    logger.info("Saving model...")
    model_path = MODELS_DIR / "classifier.pkl"
    vectorizer_path = MODELS_DIR / "vectorizer.pkl"
    
    joblib.dump(classifier, model_path)
    joblib.dump(vectorizer, vectorizer_path)
    
    logger.info(f"Model saved to: {model_path}")
    logger.info(f"Vectorizer saved to: {vectorizer_path}")
    logger.info("Training completed!")


if __name__ == "__main__":
    train_model()
