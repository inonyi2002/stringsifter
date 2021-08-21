# Copyright (C) 2019 FireEye, Inc. All Rights Reserved.
import os
import numpy
import joblib
from typing import Iterable, Iterator, Tuple

if __package__ is None or __package__ == "":
    from lib import util
else:
    from .lib import util


class NoStringsFoundException(Exception):
    pass


class StringsRanker:

    def __init__(self):
        modeldir = os.path.join(util.package_base(), "model")
        self._featurizer = joblib.load(os.path.join(modeldir, "featurizer.pkl"))
        self._ranker = joblib.load(os.path.join(modeldir, "ranker.pkl"))

    def rank_strings(self, input_strings: Iterable[str],
                     cutoff: int = None,
                     cutoff_score: float = numpy.nan) -> Iterator[Tuple[float, str]]:

        strings = numpy.array([s.strip() for s in input_strings], dtype=object)

        if len(strings) == 0:
            raise NoStringsFoundException("No strings found within input.")

        x_test = self._featurizer.transform(strings)
        y_scores = self._ranker.predict(x_test)

        if not numpy.isnan(cutoff_score):
            above_cutoff_indices = numpy.where(y_scores >= cutoff_score)
            y_scores = y_scores[above_cutoff_indices]
            strings = strings[above_cutoff_indices]

        argsorted_y_scores = numpy.argsort(y_scores)[::-1]
        sorted_strings = strings[argsorted_y_scores][:cutoff]

        return zip(y_scores[argsorted_y_scores], sorted_strings)
