"""System-1 host classifier definition (importable so the pickled artifact loads at inference)."""
from __future__ import annotations

from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression


class HostModel:
    """HistGradientBoosting on engineered features + char n-gram logistic regression, isotonic-calibrated."""

    def __init__(self):
        self.hgb = HistGradientBoostingClassifier(max_iter=400, learning_rate=0.08, max_leaf_nodes=63,
                                                  l2_regularization=1.0, random_state=0)
        self.tfidf = TfidfVectorizer(analyzer="char", ngram_range=(2, 5), min_df=3, max_features=150_000,
                                     sublinear_tf=True)
        self.lr = LogisticRegression(C=4.0, max_iter=2000)
        self.iso = IsotonicRegression(out_of_bounds="clip")

    def raw(self, hosts, X):
        return 0.5 * self.hgb.predict_proba(X)[:, 1] + 0.5 * self.lr.predict_proba(self.tfidf.transform(hosts))[:, 1]

    def fit(self, hosts, X, y, hosts_cal, X_cal, y_cal):
        self.hgb.fit(X, y)
        self.lr.fit(self.tfidf.fit_transform(hosts), y)
        self.iso.fit(self.raw(hosts_cal, X_cal), y_cal)
        return self

    def predict_proba(self, hosts, X):
        return self.iso.predict(self.raw(hosts, X))
