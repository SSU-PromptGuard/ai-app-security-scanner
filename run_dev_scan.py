import json
from pathlib import Path
from scanner.analyzer import scan_file

results = []

for path in sorted(Path("samples/dev").glob("*.py")):
    result = scan_file(path)
    results.append(result.to_dict())

Path("data").mkdir(exist_ok=True)
Path("data/scan_results.json").write_text(
    json.dumps(results, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

print(f"saved {len(results)} scan results to data/scan_results.json")
