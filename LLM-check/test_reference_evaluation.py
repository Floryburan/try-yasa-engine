"""Unknowns, matching identities and conditional classification remain distinct."""

import copy
import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from evaluate_ctfd_reference import analyze, verified_annotation_digest, write_report


def gold(case,decision,types=None,kinds=None):
    return {"case_id":case,"function_id":case,"function":"app."+case,"file":"app.py","start_line":1,
            "is_entrypoint":decision,"formation_types":types or [],"entrypoint_kind":(kinds or [None])[0],
            "entrypoint_kinds":kinds or [],"subtypes":["test"],"reason":"source evidence","evidence":[]}


def prediction(case,decision,types=None,kind=None):
    return {"case_id":case,"function":"app."+case,"status":"success",
            "verdict":{"is_entrypoint":decision,"formation_types":types or [],"entrypoint_kind":kind,
                       "raw_formation_choices":{}}}


class ReferenceEvaluationTests(unittest.TestCase):
    def test_both_verified_hash_formats_and_conflicting_hashes(self):
        self.assertEqual(verified_annotation_digest({"artifact_sha256":{"annotations.json":"abc"}}),"abc")
        self.assertEqual(verified_annotation_digest({"annotation_sha256":"abc"}),"abc")
        for value in ({}, {"annotation_sha256":"abc","artifact_sha256":{"annotations.json":"def"}}):
            with self.assertRaises(ValueError):verified_annotation_digest(value)

    def test_report_uses_dataset_name_and_actual_unknown_count(self):
        m,d=analyze([gold("a",False),gold("unknown",None)],[prediction("a",False)])
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            out=Path(directory)
            write_report(out,m,d,{"dataset_name":"django-helpdesk","annotation_version":"django-helpdesk-application-v1"})
            text=(out/"REPORT.md").read_text()
        self.assertIn("Jev 对 django-helpdesk",text)
        self.assertIn("django-helpdesk-application-v1",text)
        self.assertIn("1 个不确定项",text)
        self.assertNotIn("CTFd",text)
        self.assertNotIn("42 个不确定项",text)

    def test_unknown_gold_is_excluded_and_model_unknown_is_not_a_negative(self):
        gs=[gold("tp",True,["decorator"],["http"]),gold("abstain",True,["callback"],["event"]),
            gold("tn",False),gold("unknown",None)]
        ps=[prediction("tp",True,["decorator"],"http"),prediction("abstain",None),
            prediction("tn",False),prediction("unknown",True,["other"],"cli")]
        m,_=analyze(gs,ps)
        self.assertEqual((m["tp"],m["tn"],m["fp"],m["fn"]),(1,1,0,0))
        self.assertEqual((m["model_unknown"],m["excluded_gold_unknown"]),(1,1))
        self.assertEqual(m["recall_on_decided_positives"],1)
        self.assertEqual(m["recall_on_all_gold_positives"],.5)
        self.assertEqual(m["accuracy_on_decided"],1)
        self.assertAlmostEqual(m["correct_fraction_of_all_binary_gold"],2/3)

    def test_failed_and_missing_results_are_separate_from_false_negatives(self):
        gs=[gold("failed",True,["callback"],["event"]),gold("missing",False)]
        m,rows=analyze(gs,[{"case_id":"failed","function":"app.failed","status":"error","error":"network"}])
        self.assertEqual((m["fn"],m["tn"],m["request_errors"],m["not_attempted"]),(0,0,1,1))
        self.assertEqual(m["recall_on_all_gold_positives"],0)
        self.assertEqual(m["f1_with_all_positive_recall"],0)
        self.assertIsNone(m["precision"])
        self.assertEqual({r["outcome"] for r in rows},{"request_error","not_attempted"})

    def test_multilabel_extras_misses_and_alternate_valid_kind(self):
        gs=[gold("a",True,["decorator"],["lifecycle","other"]),gold("b",True,["callback"],["event"]),gold("fp",False)]
        ps=[prediction("a",True,["decorator","configuration"],"other"),prediction("b",False),prediction("fp",True,["registration"],"http")]
        m,_=analyze(gs,ps)
        c=m["classification"]
        self.assertEqual(c["formation_exact_count"],0)
        self.assertEqual(c["kind_correct_count"],1)
        self.assertEqual(c["kind_accuracy_on_true_positives"],1)
        self.assertEqual(c["formation_conditional_on_true_positives"]["counts"],{"tp":1,"fp":1,"fn":0})
        self.assertEqual(c["formation_end_to_end_on_binary_gold"]["counts"],{"tp":1,"fp":2,"fn":1})
        self.assertEqual(c["formation_end_to_end_on_binary_gold"]["per_label"]["callback"]["f1"],0)

    def test_unknown_formation_choice_cannot_count_as_exact(self):
        g=gold("a",True,["decorator"],["http"])
        p=prediction("a",True,["decorator"],"http")
        p["verdict"]["raw_formation_choices"]={"configuration":"unknown"}
        m,_=analyze([g],[p])
        self.assertEqual(m["classification"]["formation_exact_count"],0)

    def test_duplicate_or_mismatched_identities_are_rejected(self):
        g=gold("a",False)
        p=prediction("a",False)
        for gs,ps in (([g,g],[p]),([g],[p,p]),([g],[prediction("different",False)])):
            with self.assertRaises(ValueError):analyze(gs,ps)
        wrong=copy.deepcopy(p)
        wrong["function"]="app.other"
        with self.assertRaises(ValueError):analyze([g],[wrong])


if __name__=="__main__":
    unittest.main()
