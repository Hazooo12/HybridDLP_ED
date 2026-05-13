"""
setup_config.py — Tự động setup config files từ templates
Chạy lần đầu để khởi tạo runtime config
"""
import shutil
from pathlib import Path

AGENT_DIR = Path(__file__).parent
RUNTIME_CONFIG_DIR = AGENT_DIR / "runtime" / "config"

# Config files cần setup
CONFIG_TEMPLATES = {
    "event_filter.json": "event_filter.template.json",
}

def setup_configs():
    """Copy các files từ template vào runtime/config nếu chưa có."""
    RUNTIME_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    
    for target_file, template_file in CONFIG_TEMPLATES.items():
        template_path = AGENT_DIR / template_file
        target_path = RUNTIME_CONFIG_DIR / target_file
        
        # Nếu target file chưa tồn tại, copy từ template
        if not target_path.exists():
            if template_path.exists():
                shutil.copy2(template_path, target_path)
                print(f"✅ Created: {target_path}")
            else:
                print(f"⚠️ Template not found: {template_path}")
        else:
            print(f"✓ Already exists: {target_path}")

if __name__ == "__main__":
    setup_configs()
    print("✅ Config setup complete!")
