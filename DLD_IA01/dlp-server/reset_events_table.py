"""
reset_events_table.py — Drop events table và tạo lại từ đầu

Sử dụng khi schema cũ gây lỗi hoặc cần reset database
"""

import sqlite3
import os
from pathlib import Path

DB_PATH = "dlp_events.db"

def drop_events_table():
    """Xóa bảng events hiện tại"""
    if not os.path.exists(DB_PATH):
        print(f"❌ Database không tồn tại: {DB_PATH}")
        return False
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Drop table
        cursor.execute("DROP TABLE IF EXISTS events")
        conn.commit()
        
        print(f"✅ Dropped events table from {DB_PATH}")
        print("📝 Run 'init_db()' from database.py để tạo lại table với schema mới")
        
        conn.close()
        return True
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def backup_database():
    """Backup database trước khi xóa (tuỳ chọn)"""
    if not os.path.exists(DB_PATH):
        return False
    
    backup_path = f"{DB_PATH}.backup_{pd.now().strftime('%Y%m%d_%H%M%S')}"
    try:
        import shutil
        shutil.copy(DB_PATH, backup_path)
        print(f"✅ Backed up to: {backup_path}")
        return True
    except Exception as e:
        print(f"⚠️  Backup failed: {e}")
        return False


if __name__ == "__main__":
    import sys
    
    print("=" * 60)
    print("⚠️  DROP EVENTS TABLE - Reset Database")
    print("=" * 60)
    
    confirm = input("\n🔍 Bạn chắc chắn muốn xóa bảng 'events'? (yes/no): ").strip().lower()
    
    if confirm != "yes":
        print("❌ Đã hủy")
        sys.exit(0)
    
    # Optional: backup first
    backup_confirm = input("💾 Tạo backup trước? (yes/no): ").strip().lower()
    if backup_confirm == "yes":
        backup_database()
    
    # Drop
    if drop_events_table():
        print("\n✨ Database đã reset!")
        print("🚀 Khởi động lại server để tạo lại table:")
        print("   python main.py")
    else:
        print("\n❌ Reset thất bại")
        sys.exit(1)
