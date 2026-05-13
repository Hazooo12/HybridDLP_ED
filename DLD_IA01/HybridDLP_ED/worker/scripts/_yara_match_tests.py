"""One-off: match all YARA rules against test_files/test-risk*.txt"""
import sys
from pathlib import Path

import yara

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from config import WorkerConfig  # noqa: E402

rules = WorkerConfig.load_yara_rules()
existing = {k: v for k, v in rules.items() if Path(v).exists()}
comp = yara.compile(filepaths=existing)
base = ROOT.parent / "test_files"
for name in [
    "test-risk1.txt",
    "test-risk2.txt",
    "test-risk3.txt",
    "test-risk4.txt",
    "test-risk5.txt",
    "test-risk6.txt",
]:
    p = base / name
    if not p.exists():
        print(name, "-> MISSING")
        continue
    m = comp.match(str(p))
    print(name, "->", [x.rule for x in m] if m else "NO MATCH")
