"""System-1 message classifier definition (importable so the pickled artifact loads at inference)."""
from __future__ import annotations

import re

import numpy as np
from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression

URL_RE = re.compile(r"(?i)\b(?:https?://|hxxps?://|www\.)\S+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|in|net|org|co|io|xyz|top|shop|info|link|ly|me|app|site|online|live|click)\b(?:/\S*)?")
NUM_RE = re.compile(r"\d")


def normalize(text: str) -> str:
    t = URL_RE.sub(" URLTOKEN ", text)
    t = NUM_RE.sub("0", t)
    return t.lower()


class MessageModel:
    """Word (1-2) + char (3-5) TF-IDF logistic regression with isotonic calibration."""

    def __init__(self):
        self.word = TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=120_000, sublinear_tf=True)
        self.char = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3, max_features=150_000,
                                    sublinear_tf=True)
        self.lr = LogisticRegression(C=6.0, max_iter=3000, class_weight="balanced")
        self.iso = IsotonicRegression(out_of_bounds="clip")

    def _X(self, texts, fit=False):
        n = [normalize(t[:4000]) for t in texts]
        if fit:
            return hstack([self.word.fit_transform(n), self.char.fit_transform(n)]).tocsr()
        return hstack([self.word.transform(n), self.char.transform(n)]).tocsr()

    def fit(self, texts, y, texts_cal, y_cal, sample_weight=None):
        self.lr.fit(self._X(texts, fit=True), y, sample_weight=sample_weight)
        self.iso.fit(self.lr.predict_proba(self._X(texts_cal))[:, 1], y_cal)
        return self

    def predict_proba(self, texts) -> np.ndarray:
        return self.iso.predict(self.lr.predict_proba(self._X(texts))[:, 1])

    def top_terms(self, text: str, k: int = 6) -> list[tuple[str, float]]:
        """Most influential n-grams pushing this text toward 'scam' (for explanations)."""
        X = self._X([text])
        names = np.concatenate([self.word.get_feature_names_out(), self.char.get_feature_names_out()])
        contrib = X.multiply(self.lr.coef_[0]).toarray()[0]
        idx = np.argsort(contrib)[::-1][:k * 3]
        out, seen = [], set()
        for i in idx:
            if contrib[i] <= 0:
                break
            term = names[i].strip()
            if len(term) < 3 or term in seen or term == "urltoken":
                continue
            seen.add(term)
            out.append((term, float(contrib[i])))
            if len(out) >= k:
                break
        return out
