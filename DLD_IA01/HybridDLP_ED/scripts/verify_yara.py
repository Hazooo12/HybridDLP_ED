"""
Verify YARA rules against test files
"""
import yara
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
TEST_FILES_DIR = BASE_DIR / "test_files"
YARA_RULES_DIR = BASE_DIR / "worker" / "yara_rules"


def test_yara_rules():
    """Test YARA rules against test files"""
    print("=" * 60)
    print("YARA Rules Verification")
    print("=" * 60)
    
    # Load all YARA rules
    rule_files = {}
    for rule_file in YARA_RULES_DIR.glob("*.yar"):
        rule_files[rule_file.stem] = str(rule_file)
    
    if not rule_files:
        print("No YARA rules found!")
        return
    
    print(f"\nLoaded {len(rule_files)} YARA rules")
    
    # Compile rules
    try:
        rules = yara.compile(filepaths=rule_files)
        print("YARA rules compiled successfully")
    except Exception as e:
        print(f"Error compiling YARA rules: {e}")
        return
    
    # Test each file
    test_files = {
        "credit_card_info.txt": ["credit_card"],
        "vietnam_id_info.txt": ["vietnam_id", "phone_number", "email"],
        "financial_report.txt": ["financial_data"],
        "hr_employee_list.txt": ["hr_data", "vietnam_id", "email"],
        "normal_document.txt": []
    }
    
    print("\n" + "=" * 60)
    print("Testing Files")
    print("=" * 60)
    
    results = {}
    
    for filename, expected_rules in test_files.items():
        file_path = TEST_FILES_DIR / filename
        
        if not file_path.exists():
            print(f"\n[SKIP] {filename} - File not found")
            continue
        
        print(f"\n[TEST] {filename}")
        print(f"  Expected rules: {', '.join(expected_rules) if expected_rules else 'None'}")
        
        try:
            matches = rules.match(str(file_path))
            matched_rules = [m.rule for m in matches] if matches else []
            
            print(f"  Matched rules: {', '.join(matched_rules) if matched_rules else 'None'}")
            
            # Check if expected rules matched
            if expected_rules:
                matched_expected = [r for r in expected_rules if r in matched_rules]
                if matched_expected:
                    print(f"  [OK] Expected rules matched: {', '.join(matched_expected)}")
                else:
                    print(f"  [WARN] Expected rules not matched")
            else:
                if matched_rules:
                    print(f"  [WARN] Unexpected rules matched: {', '.join(matched_rules)}")
                else:
                    print(f"  [OK] No rules matched (expected)")
            
            results[filename] = {
                "expected": expected_rules,
                "matched": matched_rules,
                "status": "PASS" if (expected_rules and any(r in matched_rules for r in expected_rules)) or (not expected_rules and not matched_rules) else "FAIL"
            }
            
        except Exception as e:
            print(f"  [ERROR] {e}")
            results[filename] = {"status": "ERROR", "error": str(e)}
    
    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    
    passed = sum(1 for r in results.values() if r.get("status") == "PASS")
    total = len(results)
    
    for filename, result in results.items():
        status = result.get("status", "UNKNOWN")
        print(f"{status:6} - {filename}")
    
    print(f"\nResults: {passed}/{total} tests passed")
    
    return results


if __name__ == "__main__":
    test_yara_rules()
