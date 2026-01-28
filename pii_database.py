
import logging
import psycopg2
from psycopg2.extras import RealDictCursor
from typing import Dict, List

logger = logging.getLogger(__name__)


class PIIRulesManager:
    """Manages loading and caching of PII detection rules from PostgreSQL"""
    
    def __init__(self, conn):
        if conn is None:
            raise ValueError("Database connection is required")
        
        self.conn = conn
        logger.info("Using provided database connection for PII rules")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass
    
    def load_all_rules(self) -> Dict:
        logger.info("Loading PII detection rules from database")
        try:
            rules = {
                'pii_field_patterns': self.load_field_patterns(),
                'non_pii_patterns': self.load_non_pii_patterns(),
                'sensitive_keywords': self.load_sensitive_keywords(),
                'value_patterns': self.load_value_patterns(),
                'datatype_hints': self.load_datatype_hints()
            }
            
            logger.info(f"Loaded {len(rules['pii_field_patterns'])} PII categories, "
                       f"{len(rules['non_pii_patterns'])} non-PII patterns")
            
            return rules
            
        except psycopg2.Error as e:
            logger.error(f"Error loading PII rules from database: {e}")
            raise
    
    def load_field_patterns(self) -> Dict[str, List[str]]:
        """Load field name patterns grouped by category"""
        query = """
        SELECT 
            c.category_name,
            fp.pattern
        FROM map_maestro.pii_rule_categories c
        INNER JOIN map_maestro.pii_rule_field_patterns fp 
            ON c.category_id = fp.category_id
        WHERE c.is_active = TRUE 
            AND fp.is_active = TRUE
        ORDER BY c.category_name, fp.priority DESC, fp.pattern
        """
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(query)
        rows = cursor.fetchall()
        cursor.close()
        
        patterns_dict = {}
        for row in rows:
            category = row['category_name']
            pattern = row['pattern']
            
            if category not in patterns_dict:
                patterns_dict[category] = []
            patterns_dict[category].append(pattern)
        
        return patterns_dict
    
    def load_non_pii_patterns(self) -> List[str]:
        query = """
        SELECT pattern
        FROM map_maestro.pii_rule_non_pii_patterns
        WHERE is_active = TRUE
        ORDER BY priority DESC, pattern
        """
        cursor = self.conn.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        cursor.close()
        
        return [row[0] for row in rows]
    
    def load_sensitive_keywords(self) -> List[str]:
        query = """
        SELECT keyword
        FROM map_maestro.pii_rule_sensitive_keywords
        WHERE is_active = TRUE
        ORDER BY keyword
        """
        cursor = self.conn.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        cursor.close()
        
        return [row[0] for row in rows]
    
    def load_value_patterns(self) -> Dict[str, str]:
        query = """
        SELECT 
            pattern_name,
            regex_pattern
        FROM map_maestro.pii_rule_value_patterns
        WHERE is_active = TRUE
        ORDER BY priority DESC, pattern_name
        """
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(query)
        rows = cursor.fetchall()
        cursor.close()
        
        return {row['pattern_name']: row['regex_pattern'] for row in rows}
    
    def load_datatype_hints(self) -> Dict[str, List[str]]:
        query = """
        SELECT 
            c.category_name,
            dh.datatype_pattern
        FROM map_maestro.pii_rule_categories c
        INNER JOIN map_maestro.pii_rule_datatype_hints dh 
            ON c.category_id = dh.category_id
        WHERE c.is_active = TRUE 
            AND dh.is_active = TRUE
        ORDER BY c.category_name, dh.datatype_pattern
        """
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(query)
        rows = cursor.fetchall()
        cursor.close()
        
        hints_dict = {}
        for row in rows:
            category = row['category_name']
            datatype = row['datatype_pattern']
            
            if category not in hints_dict:
                hints_dict[category] = []
            hints_dict[category].append(datatype)
        
        return hints_dict
    
    def get_active_categories(self) -> List[Dict]:
        query = """
        SELECT 
            category_id,
            category_name,
            description
        FROM map_maestro.pii_rule_categories
        WHERE is_active = TRUE
        ORDER BY category_name
        """
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(query)
        categories = cursor.fetchall()
        cursor.close()
        
        return [dict(cat) for cat in categories]
    
    def get_rules_summary(self) -> List[Dict]:
        query = """
        SELECT * FROM map_maestro.v_pii_rules_summary
        ORDER BY category_name
        """
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(query)
        summary = cursor.fetchall()
        cursor.close()
        
        return [dict(row) for row in summary]


# Convenience function for quick rule loading
def load_pii_rules(conn) -> Dict:
    if conn is None:
        raise ValueError("Database connection is required")
    
    with PIIRulesManager(conn) as manager:
        return manager.load_all_rules()