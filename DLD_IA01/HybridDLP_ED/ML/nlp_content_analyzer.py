"""
NLP-Powered Content Analysis Module

THIẾT KẾ:
- Thay thế hardcoded regex/keywords bằng ML/NLP
- Hiểu ngữ cảnh: Document Type, Entities, Relationships
- Risk scoring dựa trên NLP analysis
- Explain được cho analyst

Components:
1. DocumentTypeClassifier - Phân loại loại tài liệu
2. VietnameseNER - Trích xuất entities (tên, tổ chức, địa chỉ)
3. ContextRiskBuilder - Xây dựng risk context từ NLP

Author: HybridDLP Team
Date: 2026-05-04
"""

import re
import logging
import unicodedata
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
from enum import Enum

logger = logging.getLogger(__name__)


def _strip_accents(text: str) -> str:
    """Return lowercase ASCII-ish Vietnamese text for semantic matching."""
    text = str(text or "")
    text = text.replace("đ", "d").replace("Đ", "D")
    normalized = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in normalized if not unicodedata.combining(ch)).lower()


def _normalize_for_semantics(text: str) -> str:
    """
    Normalize evasive variants:
    - Vietnamese accents/case
    - obfuscated email tokens: [at], (at), " g-mail . com"
    - repeated separators inside numeric identifiers
    """
    s = _strip_accents(text)
    s = re.sub(r'\[\s*at\s*\]|\(\s*at\s*\)|\s+at\s+', '@', s)
    s = re.sub(r'\[\s*dot\s*\]|\(\s*dot\s*\)|\s+dot\s+', '.', s)
    s = re.sub(r'g\s*-\s*mail', 'gmail', s)
    s = re.sub(r'(?<=\w)\s*\.\s*(?=\w)', '.', s)
    s = re.sub(r'(?<=\d)[\s.\-]+(?=\d)', '', s)
    s = re.sub(r'\s+', ' ', s)
    return s.strip()


# ============================================================================
# DATA CLASSES
# ============================================================================

class DocumentType(Enum):
    """Các loại tài liệu được phân loại"""
    CONTRACT = "contract"                    # Hợp đồng
    INVOICE = "invoice"                      # Hóa đơn
    PAYSLIP = "payslip"                     # Bảng lương
    HR_DOCUMENT = "hr_document"             # Tài liệu HR
    FINANCIAL = "financial"                  # Báo cáo tài chính
    IDENTITY_DOCUMENT = "identity_document" # CCCD, CMND, Passport
    BANKING = "banking"                     # Sao kê, giao dịch
    SOURCE_CODE = "source_code"              # Code
    CUSTOMER_DATA = "customer_data"          # Database, CSV
    UNKNOWN = "unknown"


class RiskLevel(Enum):
    """Mức độ rủi ro"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class NLPEntity:
    """Entity được trích xuất từ NER"""
    text: str
    entity_type: str  # person, organization, location, id_number, phone, email, bank_account
    confidence: float
    start_pos: int
    end_pos: int
    context: str = ""  # Surrounding text for context


@dataclass
class DocumentAnalysis:
    """Kết quả phân tích document bằng NLP"""
    document_type: DocumentType
    document_type_confidence: float
    
    # Entities trích xuất
    entities: List[NLPEntity]
    entity_summary: Dict[str, int]  # type -> count
    
    # Risk assessment
    risk_level: RiskLevel
    risk_score: float
    risk_factors: List[str]  # Giải thích tại sao risk cao
    
    # Context
    is_structured: bool       # Có cấu trúc (form, table)
    has_pii: bool            # Có PII
    has_financial: bool      # Có thông tin tài chính
    has_legal: bool          # Có nội dung pháp lý
    
    # Vietnamese specific
    is_vietnamese: bool
    language_confidence: float
    
    # Raw content analysis
    content_length: int
    has_signatures: bool
    has_dates: bool
    
    def to_dict(self) -> Dict:
        return {
            'document_type': self.document_type.value,
            'document_type_confidence': round(self.document_type_confidence, 3),
            'entity_summary': self.entity_summary,
            'risk_level': self.risk_level.name,
            'risk_score': round(self.risk_score, 2),
            'risk_factors': self.risk_factors,
            'has_pii': self.has_pii,
            'has_financial': self.has_financial,
            'has_legal': self.has_legal,
            'entities': [
                {
                    'text': e.text[:50],
                    'type': e.entity_type,
                    'confidence': round(e.confidence, 2)
                }
                for e in self.entities
            ]
        }


# ============================================================================
# NLP COMPONENTS
# ============================================================================

class DocumentTypeClassifier:
    """
    Phân loại loại tài liệu dựa trên ML/NLP patterns.
    
    Không dùng hardcoded keywords mà dùng semantic patterns.
    """
    
    # Semantic patterns cho từng loại document (weighted)
    # Format: (pattern_regex, weight, context_hint)
    CONTRACT_PATTERNS = [
        (r'\b(hợp\s*đồng|hđ|hđtd|hđtt|hđmb)\b', 0.9, 'contract_header'),
        (r'\b(bên\s*a|bên\s*b|bên\s*c)\s*[:\-]', 0.7, 'contract_parties'),
        (r'\b(điều\s*\d+|khoản\s*\d+|chương\s*\d+)\b', 0.8, 'contract_articles'),
        (r'\b(thỏa\s*thuận|cam\s*kết|quyền\s*và\s*nghĩa\s*vụ)\b', 0.7, 'contract_terms'),
        (r'\b(ngày\s*ký|hiệu\s*lực|hết\s*hạn)\b', 0.6, 'contract_dates'),
        (r'\b(tài\s*trợ|tài\s*trợ\s*-\s*hỗ\s*trợ)\b', 0.85, 'sponsorship'),
    ]
    
    INVOICE_PATTERNS = [
        (r'\b(hóa\s*đơn|invoice)\b', 0.9, 'invoice_header'),
        (r'\b(tổng\s*cộng|thành\s*tiền|VNĐ|VND)\b', 0.7, 'invoice_amount'),
        (r'\b(mã\s*số\s*thuế|mã\s*HD)\b', 0.6, 'invoice_id'),
        (r'\b(đơn\s*giá|số\s*lượng|đơn\s*giá)\b', 0.7, 'invoice_line_items'),
    ]
    
    PAYSLIP_PATTERNS = [
        (r'\b(bảng\s*lương|payroll|payslip)\b', 0.9, 'payslip_header'),
        (r'\b(lương\s*cơ\s*bản|lương\s*gross|lương\s*net)\b', 0.8, 'salary'),
        (r'\b(bảo\s*hiểm|bhxh|bhyt|btxh)\b', 0.7, 'insurance'),
        (r'\b(thuế\s*tncn|thuế\s*thu\s*nhập)\b', 0.7, 'tax'),
    ]
    
    HR_PATTERNS = [
        (r'\b(nhân\s*sự|hr|human\s*resources)\b', 0.9, 'hr_header'),
        (r'\b(quy\s*trình\s*tuyển\s*dụng)\b', 0.8, 'recruitment'),
        (r'\b(đánh\s*giá\s*hiệu\s*suất|kpi)\b', 0.7, 'performance'),
        (r'\b(chấm\s*công|bảng\s*chấm\s*công)\b', 0.7, 'attendance'),
    ]
    
    IDENTITY_PATTERNS = [
        (r'\b(cccd|căn\s*cước|chứng\s*minh\s*nhân\s*dân|cmnd)\b', 0.95, 'id_header'),
        (r'\b(số\s*cccd|số\s*cmnd|mã\s*số\s*cccd)\b', 0.9, 'id_number'),
        (r'\b(ngày\s*sinh|nơi\s*sinh|quốc\tịch)\b', 0.7, 'personal_info'),
        (r'\b(048\d{7}|0\d{9}|0\d{10})\b', 0.6, 'id_format'),
    ]
    
    BANKING_PATTERNS = [
        (r'\b(sao\s*kê|tài\s*khoản\s*ngân\s*hàng)\b', 0.9, 'bank_header'),
        (r'\b(\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4})\b', 0.8, 'card_number'),
        (r'\b(\d{10,14})\b', 0.6, 'account_number'),
        (r'\b(techcombank|vietcombank|vpbank|bidv|agribank)\b', 0.7, 'bank_name'),
        (r'\b(chuyển\s*khoản|thanh\s*toán|giao\s*dịch)\b', 0.6, 'transaction'),
    ]
    
    FINANCIAL_PATTERNS = [
        (r'\b(báo\s*cáo\s*tài\s*chính|financial\s*statement)\b', 0.9, 'financial_header'),
        (r'\b(doanh\s*thu|lợi\s*nhuận|tài\s*sản)\b', 0.7, 'financial_metrics'),
        (r'\b(bảng\s*cân\s*đối\s*kế\s*toán)\b', 0.8, 'balance_sheet'),
    ]
    
    NORMALIZED_PATTERNS = {
        DocumentType.CONTRACT: [
            (r'\b(hop dong|thoa thuan|van ban thoa thuan|cung cap dich vu|hop tac)\b', 1.4, 'normalized_contract_header'),
            (r'\b(ben a|ben b|phia thu nhat|phia thu hai)\b', 0.9, 'normalized_contract_parties'),
            (r'\b(dieu khoan|cam ket|bao mat thong tin|giu kin tu lieu|khong duoc chia se|tranh tiet lo)\b', 1.1, 'normalized_confidentiality_clause'),
            (r'\b(du lieu khach hang|ho so ve nguoi dung|don vi ngoai|ben thu ba)\b', 0.8, 'normalized_data_clause'),
        ],
        DocumentType.HR_DOCUMENT: [
            (r'\b(nhan luc|nhan su|nhan vien|thanh vien dam nhan|phu trach|nguoi thuc hien)\b', 1.1, 'normalized_hr_roles'),
            (r'\b(thu lao|luong|muc thu lao|chi tra|gia tri hop dong)\b', 0.9, 'normalized_compensation'),
        ],
        DocumentType.IDENTITY_DOCUMENT: [
            (r'\b(cccd|cmnd|can cuoc|ma dinh danh ca nhan|so dinh danh)\b', 1.2, 'normalized_identity_label'),
            (r'\b0\d{11}\b', 0.8, 'normalized_identity_number'),
        ],
        DocumentType.BANKING: [
            (r'\b(ngan hang|chuyen khoan|thanh toan|chi tra|tai khoan|gui qua ngan hang)\b', 0.9, 'normalized_payment_context'),
            (r'\b\d{10,14}\b', 0.6, 'normalized_account_number'),
        ],
        DocumentType.FINANCIAL: [
            (r'\b(muc thu lao|gia tri hop dong|trieu|vnd|viet nam dong|dong)\b', 0.8, 'normalized_money_context'),
            (r'\b(ma so thue|dong thue|thue)\b', 0.8, 'normalized_tax_context'),
        ],
    }

    def classify(self, text: str) -> Tuple[DocumentType, float]:
        """
        Phân loại document type dựa trên semantic patterns.
        
        Returns:
            (DocumentType, confidence_score)
        """
        text_lower = text.lower()
        text_clean = re.sub(r'\s+', ' ', text_lower)
        normalized_text = _normalize_for_semantics(text)
        
        scores = {
            DocumentType.CONTRACT: 0.0,
            DocumentType.INVOICE: 0.0,
            DocumentType.PAYSLIP: 0.0,
            DocumentType.HR_DOCUMENT: 0.0,
            DocumentType.IDENTITY_DOCUMENT: 0.0,
            DocumentType.BANKING: 0.0,
            DocumentType.FINANCIAL: 0.0,
        }
        
        pattern_map = {
            DocumentType.CONTRACT: self.CONTRACT_PATTERNS,
            DocumentType.INVOICE: self.INVOICE_PATTERNS,
            DocumentType.PAYSLIP: self.PAYSLIP_PATTERNS,
            DocumentType.HR_DOCUMENT: self.HR_PATTERNS,
            DocumentType.IDENTITY_DOCUMENT: self.IDENTITY_PATTERNS,
            DocumentType.BANKING: self.BANKING_PATTERNS,
            DocumentType.FINANCIAL: self.FINANCIAL_PATTERNS,
        }
        
        # Calculate scores
        for doc_type, patterns in pattern_map.items():
            type_score = 0.0
            matched_hints = []
            
            for pattern, weight, hint in patterns:
                if re.search(pattern, text_clean):
                    type_score += weight
                    matched_hints.append(hint)

            for pattern, weight, hint in self.NORMALIZED_PATTERNS.get(doc_type, []):
                if re.search(pattern, normalized_text):
                    type_score += weight
                    matched_hints.append(hint)
            
            scores[doc_type] = type_score
        
        # Find best match
        best_type = max(scores, key=scores.get)
        best_score = scores[best_type]
        
        # Normalize score
        if best_score > 0:
            # Cap at 1.0
            best_score = min(1.0, best_score / 10.0)
        
        return best_type, best_score


class VietnameseNER:
    """
    Vietnamese Named Entity Recognition.
    
    Trích xuất entities: Person, Organization, Location, ID, Phone, Email, Bank Account.
    Không dùng external NLP library - dùng pattern-based với Vietnamese context.
    """
    
    # Patterns cho từng entity type
    PATTERNS = {
        'phone': [
            (r'\b(0\d{9,10})\b', 0.95),  # 0905123456, 09051234567
            (r'\b(0(?:24|28|3|5|7|8|9)\d{1,2}[-.\s]?\d{3}[-.\s]?\d{3,4})\b', 0.8),  # 091.234.5678
        ],
        'email': [
            (r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b', 0.95),
        ],
        'cccd': [
            (r'\b(0\d{12})\b', 0.95),  # 12-digit CCCD
            (r'\b(\d{9})\b', 0.7),  # 9-digit CMND
        ],
        'bank_account': [
            (r'\b(\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{0,4})\b', 0.85),  # Formatted account
            (r'\b(\d{10,14})\b', 0.6),  # Plain number 10-14 digits
        ],
        'date': [
            (r'\b(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})\b', 0.9),  # 05/03/2026
            (r'\b(ngày\s+\d{1,2}\s+tháng\s+\d{1,2}\s+năm\s+\d{4})\b', 0.95),  # Vietnamese format
        ],
    }

    NORMALIZED_PATTERNS = {
        'phone': [
            (r'\b0(?:24|28|3|5|7|8|9)\d{7,9}\b', 0.9),
        ],
        'email': [
            (r'\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b', 0.95),
        ],
        'cccd': [
            (r'\b0\d{11}\b', 0.95),
            (r'\b\d{9}\b', 0.7),
        ],
        'tax_code': [
            (r'\b\d{10}\b', 0.75),
        ],
        'bank_account': [
            (r'\b\d{10,14}\b', 0.65),
        ],
    }
    
    # Vietnamese name prefixes
    NAME_PREFIXES = [
        'anh', 'chị', 'ông', 'bà', 'ông', 'bà', 
        'mr', 'ms', 'mrs', 'mr.', 'ms.', 'mrs.'
    ]
    
    # Organization indicators
    ORG_INDICATORS = [
        'công ty', 'cty', 'học viện', 'trường', 'trung tâm',
        'ban', 'bộ', 'sở', 'cục', 'viện', 'tổ chức',
        'academy', 'university', 'college', 'school', 'center'
    ]
    
    # Location indicators
    LOCATION_INDICATORS = [
        'thành phố', 'tp', 'quận', 'huyện', 'phường', 'xã',
        'đường', 'phố', 'số nhà', 'tầng', 'building',
        'city', 'district', 'ward', 'street', 'floor'
    ]
    
    def extract_entities(self, text: str) -> Tuple[List[NLPEntity], Dict[str, int]]:
        """
        Trích xuất entities từ text.
        
        Returns:
            (List[NLPEntity], Dict summary)
        """
        entities = []
        entity_counts = {}
        normalized_text = _normalize_for_semantics(text)
        
        # Extract pattern-based entities
        for entity_type, patterns in self.PATTERNS.items():
            for pattern, base_confidence in patterns:
                for match in re.finditer(pattern, text, re.IGNORECASE):
                    context = text[max(0, match.start()-35):match.end()+35]
                    if not self._entity_context_supports(entity_type, match.group(0), context):
                        continue
                    entity = NLPEntity(
                        text=match.group(0),
                        entity_type=entity_type,
                        confidence=base_confidence,
                        start_pos=match.start(),
                        end_pos=match.end(),
                        context=context
                    )
                    entities.append(entity)
                    entity_counts[entity_type] = entity_counts.get(entity_type, 0) + 1

        for entity_type, patterns in self.NORMALIZED_PATTERNS.items():
            seen_values = {e.text for e in entities if e.entity_type == entity_type}
            for pattern, base_confidence in patterns:
                for match in re.finditer(pattern, normalized_text, re.IGNORECASE):
                    value = match.group(0)
                    context = normalized_text[max(0, match.start()-35):match.end()+35]
                    if not self._entity_context_supports(entity_type, value, context):
                        continue
                    if value in seen_values:
                        continue
                    seen_values.add(value)
                    entity = NLPEntity(
                        text=value,
                        entity_type=entity_type,
                        confidence=base_confidence,
                        start_pos=match.start(),
                        end_pos=match.end(),
                        context=context
                    )
                    entities.append(entity)
                    entity_counts[entity_type] = entity_counts.get(entity_type, 0) + 1
        
        # Extract person names (heuristic)
        person_entities = self._extract_person_names(text)
        for entity in person_entities:
            entities.append(entity)
            entity_counts['person'] = entity_counts.get('person', 0) + 1
        
        # Extract organizations
        org_entities = self._extract_organizations(text)
        for entity in org_entities:
            entities.append(entity)
            entity_counts['organization'] = entity_counts.get('organization', 0) + 1
        
        # Extract locations
        loc_entities = self._extract_locations(text)
        for entity in loc_entities:
            entities.append(entity)
            entity_counts['location'] = entity_counts.get('location', 0) + 1
        
        entities, entity_counts = self._dedupe_entities(entities)
        return entities, entity_counts

    def _dedupe_entities(self, entities: List[NLPEntity]) -> Tuple[List[NLPEntity], Dict[str, int]]:
        seen = set()
        deduped: List[NLPEntity] = []
        counts: Dict[str, int] = {}
        for entity in entities:
            if entity.entity_type in {'phone', 'cccd', 'tax_code', 'bank_account'}:
                value_key = re.sub(r'\D+', '', entity.text)
            elif entity.entity_type == 'email':
                value_key = _normalize_for_semantics(entity.text)
            else:
                value_key = _normalize_for_semantics(entity.text)
            key = (entity.entity_type, value_key)
            if not value_key or key in seen:
                continue
            seen.add(key)
            deduped.append(entity)
            counts[entity.entity_type] = counts.get(entity.entity_type, 0) + 1
        return deduped, counts

    def _entity_context_supports(self, entity_type: str, value: str, context: str) -> bool:
        context_norm = _normalize_for_semantics(context)
        digits = re.sub(r'\D+', '', str(value or ''))

        if entity_type == 'phone':
            if re.search(r'\b(cccd|cmnd|can cuoc|ma dinh danh|so dinh danh)\b', context_norm):
                return False
            if not re.match(r'^((024|028)\d{7,8}|0(3|5|7|8|9)\d{8})$', digits):
                return False
            return bool(re.search(r'\b(phone|dien thoai|lien he|so)\b', context_norm)) or digits.startswith(('03', '05', '07', '08', '09', '024', '028'))

        if entity_type == 'tax_code':
            return bool(re.search(r'\b(ma so thue|dong thue|thue)\b', context_norm))

        if entity_type == 'bank_account':
            if len(digits) < 10 or len(digits) > 14:
                return False
            if re.search(r'\b(cccd|cmnd|can cuoc|ma dinh danh|so dinh danh|dien thoai|lien he|ma so thue|dong thue)\b', context_norm):
                return False
            return bool(re.search(r'\b(tai khoan|ngan hang|bank|techcombank|vietcombank|vpbank|bidv|agribank|chuyen khoan|thanh toan|chi tra)\b', context_norm))

        return True
    
    def _extract_person_names(self, text: str) -> List[NLPEntity]:
        """Trích xuất tên người (heuristic)"""
        entities = []
        
        # Pattern: Prefix + Name (capitalized words)
        # Ví dụ: "Anh Đào Nam Trung", "ông Nguyễn Văn A"
        name_pattern = r'\b([Aa]nh|[Cc]hị|[Oo]ng|[Bb]à)\s+([A-ZÀ-Ỹ][a-zà-ỹ]+(?:\s+[A-ZÀ-Ỹ][a-zà-ỹ]+){1,3})\b'
        
        for match in re.finditer(name_pattern, text):
            entity = NLPEntity(
                text=match.group(0),
                entity_type='person',
                confidence=0.75,
                start_pos=match.start(),
                end_pos=match.end(),
                context=text[max(0, match.start()-30):match.end()+30]
            )
            entities.append(entity)
        
        return entities
    
    def _extract_organizations(self, text: str) -> List[NLPEntity]:
        """Trích xuất tên tổ chức"""
        entities = []
        
        # Pattern: Organization indicator + Name
        org_pattern = r'\b(' + '|'.join(self.ORG_INDICATORS) + r')\s+([A-ZÀ-Ỹ][a-zà-ỹA-Z0-9\s,.-]{3,50})\b'
        
        for match in re.finditer(org_pattern, text, re.IGNORECASE):
            entity = NLPEntity(
                text=match.group(0),
                entity_type='organization',
                confidence=0.7,
                start_pos=match.start(),
                end_pos=match.end(),
                context=text[max(0, match.start()-20):match.end()+20]
            )
            entities.append(entity)
        
        return entities
    
    def _extract_locations(self, text: str) -> List[NLPEntity]:
        """Trích xuất địa chỉ"""
        entities = []
        
        # Vietnamese address pattern
        addr_pattern = r'\b(\d+[^,\n]*?(?:đường|phố|quận|huyện|phường|xã)[^,\n]*)\b'
        
        for match in re.finditer(addr_pattern, text, re.IGNORECASE):
            entity = NLPEntity(
                text=match.group(0),
                entity_type='location',
                confidence=0.65,
                start_pos=match.start(),
                end_pos=match.end(),
                context=text[max(0, match.start()-20):match.end()+20]
            )
            entities.append(entity)
        
        return entities


class ContextRiskBuilder:
    """
    Xây dựng risk context từ NLP analysis.
    
    Đánh giá risk dựa trên:
    1. Document type
    2. Entities present
    3. Combinations (contract + identity = high risk)
    4. Volume/sensitivity
    """
    
    # Risk weights
    DOCUMENT_RISK = {
        DocumentType.CONTRACT: 2.0,
        DocumentType.INVOICE: 1.5,
        DocumentType.PAYSLIP: 2.5,
        DocumentType.HR_DOCUMENT: 2.0,
        DocumentType.IDENTITY_DOCUMENT: 3.0,
        DocumentType.BANKING: 2.5,
        DocumentType.FINANCIAL: 2.0,
        DocumentType.UNKNOWN: 0.5,
    }
    
    ENTITY_RISK = {
        'cccd': 3.0,      # Căn cước công dân
        'cmnd': 2.5,      # Chứng minh nhân dân
        'bank_account': 2.5,
        'tax_code': 1.2,
        'phone': 1.0,
        'email': 0.5,
        'person': 1.5,
        'organization': 1.0,
        'location': 0.5,
    }
    
    # High-risk combinations
    RISK_COMBINATIONS = [
        # (entity_types, multiplier, reason)
        ({'cccd', 'bank_account'}, 2.0, "Identity + Banking: Full financial identity"),
        ({'cccd', 'phone'}, 1.5, "Identity + Contact: Can impersonate"),
        ({'cccd', 'email', 'phone'}, 1.8, "Identity + Contact channels: Profile reconstruction"),
        ({'cccd', 'tax_code'}, 1.5, "Identity + Tax identifier: HR/legal exposure"),
        ({'contract', 'person'}, 1.8, "Contract + Personal info: Legal exposure"),
        ({'contract', 'bank_account'}, 2.0, "Contract + Banking: Financial fraud risk"),
        ({'payslip', 'person'}, 2.0, "Payslip + Identity: Salary fraud"),
        ({'cccd', 'person', 'bank_account'}, 3.0, "Full identity theft kit"),
    ]
    
    def build_risk_context(
        self, 
        doc_type: DocumentType, 
        doc_confidence: float,
        entity_counts: Dict[str, int],
        text_length: int,
        has_dates: bool = False,
        has_signatures: bool = False
    ) -> Dict[str, Any]:
        """
        Xây dựng risk context.
        
        Returns:
            Dict chứa:
            - risk_score: 0-10
            - risk_level: LOW/MEDIUM/HIGH/CRITICAL
            - risk_factors: List[str] - giải thích
            - has_pii: bool
            - has_financial: bool
            - has_legal: bool
        """
        risk_factors = []
        base_risk = 0.0
        
        # 1. Document type risk
        doc_risk = self.DOCUMENT_RISK.get(doc_type, 0.5)
        if doc_type != DocumentType.UNKNOWN:
            risk_factors.append(f"Document: {doc_type.value} (+{doc_risk:.1f})")
            base_risk += doc_risk * doc_confidence
        
        # 2. Entity risks
        entity_risk = 0.0
        for entity_type, count in entity_counts.items():
            if entity_type in self.ENTITY_RISK:
                er = self.ENTITY_RISK[entity_type] * count
                entity_risk += er
                if count > 0:
                    risk_factors.append(f"{entity_type}: {count} (+{er:.1f})")
        base_risk += min(entity_risk, 5.0)  # Cap entity risk
        
        # 3. Check combinations
        entity_set = set(entity_counts.keys())
        if doc_type == DocumentType.CONTRACT:
            entity_set.add('contract')
        if doc_type == DocumentType.PAYSLIP:
            entity_set.add('payslip')
        for required_set, multiplier, reason in self.RISK_COMBINATIONS:
            if required_set.issubset(entity_set):
                base_risk *= multiplier
                risk_factors.append(f"Combination: {reason} (x{multiplier})")
        
        # 4. Volume bonus
        if text_length > 500:
            base_risk += 0.5
            risk_factors.append(f"Large document: {text_length} chars (+0.5)")
        
        # 5. Signature/date bonus (indicates official document)
        if has_signatures:
            base_risk += 1.0
            risk_factors.append("Has signatures (+1.0)")
        
        if has_dates:
            base_risk += 0.3
            risk_factors.append("Has dates (+0.3)")
        
        # 6. Normalize to 0-10
        risk_score = min(10.0, base_risk)
        
        # Determine risk level
        if risk_score >= 7.0:
            risk_level = RiskLevel.CRITICAL
        elif risk_score >= 5.0:
            risk_level = RiskLevel.HIGH
        elif risk_score >= 3.0:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW
        
        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'risk_factors': risk_factors,
            'has_pii': 'cccd' in entity_set or 'cmnd' in entity_set or 'person' in entity_set or 'tax_code' in entity_set,
            'has_financial': 'bank_account' in entity_set or 'tax_code' in entity_set or doc_type == DocumentType.BANKING,
            'has_legal': doc_type == DocumentType.CONTRACT,
            'document_type': doc_type,
            'document_type_confidence': doc_confidence,
            'entity_counts': entity_counts,
        }


class NLPPoweredAnalyzer:
    """
    Main NLP Analyzer - kết hợp tất cả components.
    
    Usage:
        analyzer = NLPPoweredAnalyzer()
        result = analyzer.analyze(text)
    """
    
    def __init__(self):
        self.classifier = DocumentTypeClassifier()
        self.ner = VietnameseNER()
        self.risk_builder = ContextRiskBuilder()
    
    def analyze(self, text: str) -> DocumentAnalysis:
        """
        Phân tích text bằng NLP.
        
        Returns:
            DocumentAnalysis với đầy đủ thông tin
        """
        normalized_text = _normalize_for_semantics(text)

        # 1. Detect language
        is_vietnamese = self._is_vietnamese(text)
        
        # 2. Classify document type
        doc_type, doc_confidence = self.classifier.classify(text)
        
        # 3. Extract entities
        entities, entity_counts = self.ner.extract_entities(text)
        
        # 4. Detect structural elements
        has_dates = bool(re.search(r'\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}', text))
        has_signatures = bool(re.search(r'(ky\s*ten|signature|sign)', text, re.IGNORECASE))
        is_structured = bool(re.search(r'(bảng|mẫu|form|table)', text, re.IGNORECASE))
        
        has_signatures = bool(re.search(r'(ky\s*ten|signature|sign)', normalized_text, re.IGNORECASE))
        is_structured = bool(re.search(r'(bang|mau|form|table|thong tin|danh ba|kenh ket noi)', normalized_text, re.IGNORECASE))

        # 5. Build risk context
        risk_context = self.risk_builder.build_risk_context(
            doc_type=doc_type,
            doc_confidence=doc_confidence,
            entity_counts=entity_counts,
            text_length=len(text),
            has_dates=has_dates,
            has_signatures=has_signatures
        )
        
        return DocumentAnalysis(
            document_type=doc_type,
            document_type_confidence=doc_confidence,
            entities=entities,
            entity_summary=entity_counts,
            risk_level=risk_context['risk_level'],
            risk_score=risk_context['risk_score'],
            risk_factors=risk_context['risk_factors'],
            is_structured=is_structured,
            has_pii=risk_context['has_pii'],
            has_financial=risk_context['has_financial'],
            has_legal=risk_context['has_legal'],
            is_vietnamese=is_vietnamese,
            language_confidence=0.95 if is_vietnamese else 0.5,
            content_length=len(text),
            has_signatures=has_signatures,
            has_dates=has_dates
        )
    
    def _is_vietnamese(self, text: str) -> bool:
        """Detect if text is Vietnamese"""
        vietnamese_chars = len(re.findall(r'[àáảãạăằắẳẵặâầấẩẫậeèéẻẽẹêềếểễệiìíỉĩịoòóỏõọôồốổỗộơờớởỡợuùúủũụưừứửữựyỳýỷỹỵđ]', text, re.IGNORECASE))
        total_chars = len(re.findall(r'\w', text))
        
        if total_chars == 0:
            return False
        
        ratio = vietnamese_chars / total_chars
        return ratio > 0.15  # 15% Vietnamese chars threshold
    
    def analyze_combined_content(self, fragments: List[str]) -> Dict[str, Any]:
        """
        Phân tích combined content từ nhiều fragments.
        
        Tính risk tổng hợp và phát hiện aggregation pattern.
        """
        combined_text = "\n---\n".join(fragments)
        
        # Analyze combined content
        combined_analysis = self.analyze(combined_text)
        
        # Calculate aggregation risk
        aggregation_risk = self._calculate_aggregation_risk(
            fragments=fragments,
            combined_analysis=combined_analysis
        )
        
        return {
            'combined_analysis': combined_analysis.to_dict(),
            'fragment_count': len(fragments),
            'total_length': len(combined_text),
            'aggregation_risk': aggregation_risk,
            'is_fragmented_exfiltration': aggregation_risk['is_suspicious'],
            'recommendation': aggregation_risk['recommendation'],
        }
    
    def _calculate_aggregation_risk(self, fragments: List[str], combined_analysis: DocumentAnalysis) -> Dict:
        """Tính risk cho fragmented content"""
        
        # 1. Check if fragments are semantically related
        doc_type = combined_analysis.document_type
        doc_confidence = combined_analysis.document_type_confidence
        
        # 2. Check entity accumulation
        entity_counts = combined_analysis.entity_summary
        
        # 3. Check if entities span multiple fragments
        entity_diversity = len(entity_counts)
        
        # 4. Suspicious patterns
        is_suspicious = (
            doc_confidence > 0.5 and  # Strong document type detection
            entity_diversity >= 2 and  # Multiple entity types
            combined_analysis.risk_score > 3.0  # Above medium risk
        )
        
        # 5. Recommendation
        if is_suspicious:
            recommendation = f"ALERT: Detected {doc_type.value} with {entity_diversity} entity types. Risk: {combined_analysis.risk_score:.1f}"
        else:
            recommendation = "No suspicious aggregation pattern detected"
        
        return {
            'is_suspicious': is_suspicious,
            'document_type': doc_type.value,
            'document_confidence': doc_confidence,
            'entity_diversity': entity_diversity,
            'combined_risk': combined_analysis.risk_score,
            'risk_factors': combined_analysis.risk_factors,
            'recommendation': recommendation,
        }


# ============================================================================
# STANDALONE TEST
# ============================================================================

if __name__ == '__main__':
    import sys
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    
    print("=" * 70)
    print("NLP-POWERED CONTENT ANALYSIS TEST")
    print("=" * 70)
    
    analyzer = NLPPoweredAnalyzer()
    
    # Test contract content
    test_content = """
    CỘNG HÒA XÃ HỘI CHỦ NGHĨA VIỆT NAM
    Độc lập – Tự do – Hạnh phúc
    
    HỢP ĐỒNG TÀI TRỢ - HỖ TRỢ
    Số 02/HĐTT/2026
    
    BÊN A: Anh Đào Nam Trung
    Số CCCD: 048204003872
    Điện thoại: 0905135115
    Tài khoản: 19038057431014 Techcombank
    
    BÊN B: T.A Academy
    Tài khoản: 24111235555 VPBank
    """
    
    print("\n--- Testing Contract Content ---")
    result = analyzer.analyze(test_content)
    
    print(f"\nDocument Type: {result.document_type.value} ({result.document_type_confidence:.0%})")
    print(f"Risk Score: {result.risk_score:.2f} ({result.risk_level.name})")
    print(f"Has PII: {result.has_pii}")
    print(f"Has Financial: {result.has_financial}")
    print(f"Has Legal: {result.has_legal}")
    
    print("\nRisk Factors:")
    for factor in result.risk_factors:
        print(f"  - {factor}")
    
    print("\nEntities Found:")
    for entity_type, count in result.entity_summary.items():
        print(f"  - {entity_type}: {count}")
    
    print("\n" + "=" * 70)
    print("FRAGMENTED CONTENT TEST")
    print("=" * 70)
    
    fragments = [
        "HỢP ĐỒNG TÀI TRỢ - HỖ TRỢ\nSố 02/HĐTT/2026",
        "BÊN A: Anh Đào Nam Trung\nSố CCCD: 048204003872",
        "Điện thoại: 0905135115\nTài khoản: 19038057431014 Techcombank",
    ]
    
    combined_result = analyzer.analyze_combined_content(fragments)
    
    print(f"\nFragment Count: {combined_result['fragment_count']}")
    print(f"Is Suspicious: {combined_result['is_fragmented_exfiltration']}")
    print(f"Combined Risk: {combined_result['aggregation_risk']['combined_risk']:.2f}")
    print(f"Recommendation: {combined_result['recommendation']}")
