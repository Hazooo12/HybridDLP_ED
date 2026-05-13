"""
Script thu thập và tạo dataset cho training ML model
"""
import os
import re
import json
from pathlib import Path
from typing import List, Dict, Tuple
import shutil

from loguru import logger

# Setup paths
BASE_DIR = Path(__file__).parent.parent.parent
WORKER_DIR = BASE_DIR / "worker"
DATASET_DIR = WORKER_DIR / "dataset"
SENSITIVE_DIR = DATASET_DIR / "sensitive"
NORMAL_DIR = DATASET_DIR / "normal"

# Keywords để phân loại
SENSITIVE_KEYWORDS = [
    # Contracts
    'hợp đồng', 'contract', 'thỏa thuận', 'điều khoản', 'phụ lục',
    # Financial
    'báo cáo tài chính', 'financial report', 'doanh thu', 'lợi nhuận',
    'ngân sách', 'budget', 'chi phí', 'cost',
    # Customer data
    'khách hàng', 'customer', 'client', 'thông tin khách hàng',
    'danh sách khách hàng', 'customer list',
    # HR
    'nhân sự', 'hr', 'human resources', 'lương', 'salary',
    'thông tin nhân viên', 'employee', 'nhân viên',
    # Confidential
    'bảo mật', 'confidential', 'nội bộ', 'internal',
    'mật', 'secret', 'riêng tư', 'private',
    # Legal
    'pháp lý', 'legal', 'luật', 'quy định', 'regulation',
    # Personal info
    'cmnd', 'cccd', 'chứng minh nhân dân', 'căn cước',
    'số điện thoại', 'phone', 'email', 'địa chỉ', 'address'
]

NORMAL_KEYWORDS = [
    # Public
    'công khai', 'public', 'thông tin công khai',
    # News
    'tin tức', 'news', 'báo chí', 'press',
    # General
    'hướng dẫn', 'guide', 'tutorial', 'hướng dẫn sử dụng',
    'giới thiệu', 'introduction', 'overview',
    # Blog
    'blog', 'bài viết', 'article', 'post'
]


def create_directories():
    """Tạo các thư mục cần thiết"""
    SENSITIVE_DIR.mkdir(parents=True, exist_ok=True)
    NORMAL_DIR.mkdir(parents=True, exist_ok=True)
    logger.info(f"Created dataset directories: {DATASET_DIR}")


def auto_label(text: str) -> str:
    """Tự động label dựa trên keywords"""
    text_lower = text.lower()
    
    sensitive_count = sum(1 for keyword in SENSITIVE_KEYWORDS if keyword in text_lower)
    normal_count = sum(1 for keyword in NORMAL_KEYWORDS if keyword in text_lower)
    
    # Check for patterns
    if re.search(r'\b\d{9,12}\b', text):  # ID numbers
        sensitive_count += 2
    if re.search(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', text):  # Credit card
        sensitive_count += 3
    if '@' in text and re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text):
        sensitive_count += 1
    
    if sensitive_count > normal_count and sensitive_count >= 2:
        return 'sensitive'
    else:
        return 'normal'


def create_synthetic_sensitive_docs(num_docs: int = 50):
    """Tạo synthetic sensitive documents"""
    logger.info(f"Creating {num_docs} synthetic sensitive documents...")
    
    templates = [
        """HỢP ĐỒNG LAO ĐỘNG
Số: HD-{id}
Ngày ký: {date}

Bên A: Công ty ABC
Bên B: Nguyễn Văn A
CMND: {cmnd}
Số điện thoại: {phone}
Email: {email}

Điều 1: Mức lương
- Lương cơ bản: 15.000.000 VND
- Phụ cấp: 2.000.000 VND

Điều 2: Thời hạn hợp đồng
- Từ ngày {date} đến ngày {end_date}

Điều 3: Bảo mật
- Bên B cam kết bảo mật thông tin nội bộ
- Không được tiết lộ thông tin khách hàng

Ký tên
Nguyễn Văn A
""",
        """BÁO CÁO TÀI CHÍNH QUÝ {quarter}
Công ty: ABC Corporation

DOANH THU: {revenue} VND
LỢI NHUẬN: {profit} VND
CHI PHÍ: {cost} VND

Khách hàng chính:
- Khách hàng A: {amount1} VND
- Khách hàng B: {amount2} VND

Thông tin liên hệ:
Email: finance@abc.com
Phone: {phone}
""",
        """DANH SÁCH NHÂN VIÊN
Phòng ban: {dept}

STT | Họ tên | CMND | Email | Lương
1 | Nguyễn Văn A | {cmnd1} | {email1} | 15.000.000
2 | Trần Thị B | {cmnd2} | {email2} | 12.000.000
3 | Lê Văn C | {cmnd3} | {email3} | 18.000.000

Tổng lương: 45.000.000 VND
""",
    ]
    
    import random
    from datetime import datetime, timedelta
    
    for i in range(num_docs):
        template = random.choice(templates)
        
        # Generate fake data
        cmnd = f"{random.randint(100000000, 999999999)}"
        cccd = f"{random.randint(100000000000, 999999999999)}"
        phone = f"0{random.randint(900000000, 999999999)}"
        email = f"user{random.randint(1, 1000)}@example.com"
        date = (datetime.now() - timedelta(days=random.randint(1, 365))).strftime("%d/%m/%Y")
        end_date = (datetime.now() + timedelta(days=random.randint(365, 1095))).strftime("%d/%m/%Y")
        revenue = random.randint(1000000000, 10000000000)
        profit = revenue * random.uniform(0.1, 0.3)
        cost = revenue - profit
        quarter = random.randint(1, 4)
        amount1 = random.randint(100000000, 1000000000)
        amount2 = random.randint(100000000, 1000000000)
        dept = random.choice(["IT", "HR", "Finance", "Sales"])
        cmnd1 = f"{random.randint(100000000, 999999999)}"
        cmnd2 = f"{random.randint(100000000, 999999999)}"
        cmnd3 = f"{random.randint(100000000, 999999999)}"
        email1 = f"user{random.randint(1, 1000)}@company.com"
        email2 = f"user{random.randint(1, 1000)}@company.com"
        email3 = f"user{random.randint(1, 1000)}@company.com"
        
        content = template.format(
            id=i+1,
            cmnd=cmnd,
            cccd=cccd,
            phone=phone,
            email=email,
            date=date,
            end_date=end_date,
            revenue=revenue,
            profit=int(profit),
            cost=int(cost),
            quarter=quarter,
            amount1=amount1,
            amount2=amount2,
            dept=dept,
            cmnd1=cmnd1,
            cmnd2=cmnd2,
            cmnd3=cmnd3,
            email1=email1,
            email2=email2,
            email3=email3,
        )
        
        filename = f"sensitive_{i+1:03d}.txt"
        filepath = SENSITIVE_DIR / filename
        filepath.write_text(content, encoding="utf-8")
    
    logger.info(f"Created {num_docs} synthetic sensitive documents")


def create_synthetic_normal_docs(num_docs: int = 50):
    """Tạo synthetic normal documents"""
    logger.info(f"Creating {num_docs} synthetic normal documents...")
    
    templates = [
        """HƯỚNG DẪN SỬ DỤNG
Đây là hướng dẫn sử dụng phần mềm.

Bước 1: Cài đặt
- Download phần mềm từ website
- Chạy file cài đặt
- Làm theo hướng dẫn

Bước 2: Sử dụng
- Mở phần mềm
- Chọn chức năng cần dùng
- Thực hiện các thao tác

Bước 3: Hỗ trợ
- Xem thêm tại website
- Liên hệ support nếu cần
""",
        """TIN TỨC CÔNG NGHỆ
Ngày: {date}

Tiêu đề: Công nghệ mới trong năm {year}

Nội dung:
Công nghệ đang phát triển nhanh chóng. Các công ty đang đầu tư vào AI và Machine Learning.

Xu hướng:
- Artificial Intelligence
- Cloud Computing
- Internet of Things

Kết luận:
Công nghệ sẽ tiếp tục phát triển trong tương lai.
""",
        """GIỚI THIỆU CÔNG TY
Công ty ABC được thành lập năm {year}.

Sứ mệnh:
- Cung cấp dịch vụ chất lượng cao
- Đáp ứng nhu cầu khách hàng
- Phát triển bền vững

Giá trị cốt lõi:
- Chất lượng
- Đổi mới
- Trách nhiệm

Liên hệ:
Website: www.abc.com
Email: info@abc.com
""",
    ]
    
    import random
    from datetime import datetime
    
    for i in range(num_docs):
        template = random.choice(templates)
        year = random.randint(2020, 2024)
        date = datetime.now().strftime("%d/%m/%Y")
        
        content = template.format(year=year, date=date)
        
        filename = f"normal_{i+1:03d}.txt"
        filepath = NORMAL_DIR / filename
        filepath.write_text(content, encoding="utf-8")
    
    logger.info(f"Created {num_docs} synthetic normal documents")


def main():
    """Main function"""
    logger.info("Starting dataset collection...")
    
    create_directories()
    
    # Create synthetic documents
    create_synthetic_sensitive_docs(num_docs=50)
    create_synthetic_normal_docs(num_docs=50)
    
    # Count files
    sensitive_count = len(list(SENSITIVE_DIR.glob("*.txt")))
    normal_count = len(list(NORMAL_DIR.glob("*.txt")))
    
    logger.info(f"Dataset created:")
    logger.info(f"  - Sensitive: {sensitive_count} files")
    logger.info(f"  - Normal: {normal_count} files")
    logger.info(f"  - Total: {sensitive_count + normal_count} files")
    logger.info(f"Dataset location: {DATASET_DIR}")


if __name__ == "__main__":
    main()
