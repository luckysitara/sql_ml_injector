// SQL error patterns to look for in responses
const SQL_ERROR_PATTERNS = [
  // MySQL errors
  "SQL syntax",
  "mysql_fetch",
  "You have an error in your SQL syntax",
  "MySQL server version",
  "MySQLSyntaxErrorException",
  "valid MySQL result",
  "check the manual that corresponds to your MySQL server version",
  "Unknown column",
  "Column count doesn't match",
  "Table doesn't exist",
  "MySQL Query fail",

  // PostgreSQL errors
  "PostgreSQL",
  "pg_query",
  "PSQLException",
  "PG::SyntaxError",
  "ERROR:  syntax error at or near",
  "ERROR: parser: parse error at or near",
  "invalid input syntax for",

  // SQLite errors
  "SQLite3",
  "SQLite error",
  "SQLiteException",
  "sqlite_query",
  "no such table:",
  "unable to open database file",

  // SQL Server errors
  "Microsoft SQL",
  "ODBC SQL Server Driver",
  "SQLServer JDBC Driver",
  "SqlException",
  "Unclosed quotation mark after",
  "Incorrect syntax near",
  "Syntax error in string in query expression",
  "Procedure or function",
  "Server Error in '/' Application",
  "Microsoft OLE DB Provider for SQL Server",
  "Unclosed quotation mark before the character string",

  // Oracle errors
  "ORA-",
  "Oracle error",
  "Oracle Database",
  "SQLSTATE",
  "quoted string not properly terminated",
  "SQL command not properly ended",

  // Generic SQL errors
  "SQL error",
  "SQLSTATE",
  "syntax error",
  "unclosed quotation mark",
  "unterminated string",
  "expects parameter",
  "Warning: mysql",
  "Warning: pg_",
  "Warning: sqlite",
  "Warning: oci_",
  "SQL statement",
  "DB Error",
  "Database error",
  "query failed",
  "SQL query failed",
  "SQL command",
  "Invalid query",
  "Failed to execute SQL",
  "Error executing query",
  "Error Executing Database Query",
]

// Analyze a response to determine if it indicates a SQL injection vulnerability
export async function analyzeResponse(
  payload: string,
  response: { status: number; body: string; headers: Record<string, string> },
  parameter: string,
): Promise<{
  isVulnerable: boolean
  type: string
  confidence: number
  details: string
  evidence: string
}> {
  // Default result
  const result = {
    isVulnerable: false,
    type: "",
    confidence: 0,
    details: "",
    evidence: "",
  }

  try {
    // Make sure we have a valid response body
    if (!response || !response.body) {
      return result
    }

    // Check for SQL error patterns in the response
    let errorFound = false
    let errorPattern = ""

    for (const pattern of SQL_ERROR_PATTERNS) {
      if (response.body.includes(pattern)) {
        errorFound = true
        errorPattern = pattern
        break
      }
    }

    // Simple heuristic analysis
    let isVulnerable = false
    let confidence = 0

    // If we found an error pattern, it's likely vulnerable
    if (errorFound) {
      isVulnerable = true
      confidence = 85
    }
    // Check for other indicators of vulnerability
    else if (
      // Check for unusual response status
      (response.status >= 500 && response.status < 600) ||
      // Check for significant response size differences
      response.body.length > 10000 ||
      // Check for specific patterns in the response that might indicate successful injection
      (response.body.includes("admin") && payload.includes("admin")) ||
      (response.body.includes("root") && payload.includes("admin")) ||
      (response.body.includes("mysql") && !payload.includes("mysql")) ||
      (response.body.includes("sql") && !payload.includes("sql")) ||
      (response.body.includes("database") && !payload.includes("database")) ||
      (response.body.includes("syntax") && !payload.includes("syntax"))
    ) {
      isVulnerable = true
      confidence = 70
    }

    // If the analysis indicates a vulnerability
    if (isVulnerable) {
      // Determine the type of SQL injection
      let injectionType = "Unknown SQL Injection"

      if (payload.includes("UNION SELECT")) {
        injectionType = "Union-based SQL Injection"
      } else if (
        payload.includes("SLEEP") ||
        payload.includes("WAITFOR DELAY") ||
        payload.includes("pg_sleep") ||
        payload.includes("BENCHMARK")
      ) {
        injectionType = "Time-based Blind SQL Injection"
      } else if (payload.includes("AND 1=1") || payload.includes("AND 1=2")) {
        injectionType = "Boolean-based Blind SQL Injection"
      } else if (
        payload.includes("convert") ||
        payload.includes("cast") ||
        payload.includes("updatexml") ||
        payload.includes("extractvalue")
      ) {
        injectionType = "Error-based SQL Injection"
      } else if (payload.includes("' OR '1'='1") || payload.includes("admin'--")) {
        injectionType = "Authentication Bypass SQL Injection"
      }

      // Extract evidence from the response
      let evidence = ""

      // If we found an error pattern, extract the surrounding context
      if (errorFound) {
        const errorIndex = response.body.indexOf(errorPattern)
        const startIndex = Math.max(0, errorIndex - 50)
        const endIndex = Math.min(response.body.length, errorIndex + errorPattern.length + 150)
        evidence = response.body.substring(startIndex, endIndex)
      } else if (response.body.length > 0) {
        // If no specific error message found, use a portion of the response
        evidence = response.body.substring(0, 200) + (response.body.length > 200 ? "..." : "")
      }

      // Set the result
      result.isVulnerable = true
      result.type = injectionType
      result.confidence = confidence
      result.details = `The parameter '${parameter}' appears to be vulnerable to ${injectionType}. The payload '${payload}' was successful in exploiting this vulnerability.`
      result.evidence = evidence
    }
  } catch (error) {
    console.error("Analysis error:", error)
    // Continue with the default result
  }

  return result
}

// Generate mitigation recommendations based on found vulnerabilities
export function generateMitigations(
  vulnerabilities: Array<{
    type: string
    parameter: string
    payload: string
    confidence: number
    details: string
    evidence: string
  }>,
): Array<{
  title: string
  description: string
  priority: "high" | "medium" | "low"
}> {
  const mitigations: Array<{
    title: string
    description: string
    priority: "high" | "medium" | "low"
  }> = []

  // If no vulnerabilities found, return empty array
  if (vulnerabilities.length === 0) {
    return mitigations
  }

  // Add general mitigation recommendations
  mitigations.push({
    title: "Use Parameterized Queries",
    description:
      "Replace dynamic SQL queries with parameterized prepared statements. This is the most effective way to prevent SQL injection as it ensures that user input is treated as data, not executable code.",
    priority: "high",
  })

  mitigations.push({
    title: "Input Validation",
    description:
      "Implement strict input validation for all user-supplied data. Validate input against a whitelist of allowed characters and patterns, and reject any input that doesn't conform.",
    priority: "high",
  })

  mitigations.push({
    title: "Least Privilege Principle",
    description:
      "Ensure that database accounts used by applications have the minimum privileges necessary. This limits the potential damage if an injection attack succeeds.",
    priority: "medium",
  })

  // Add specific mitigations based on vulnerability types
  const vulnerabilityTypes = new Set(vulnerabilities.map((v) => v.type))

  if (vulnerabilityTypes.has("Union-based SQL Injection")) {
    mitigations.push({
      title: "Prevent Union-based Attacks",
      description:
        "Use an ORM (Object-Relational Mapping) library that automatically escapes user input and prevents UNION attacks. Additionally, implement column and table name escaping.",
      priority: "high",
    })
  }

  if (vulnerabilityTypes.has("Error-based SQL Injection")) {
    mitigations.push({
      title: "Disable Error Messages",
      description:
        "Configure your application to display generic error messages to users and log detailed errors server-side. This prevents attackers from gathering information about your database structure.",
      priority: "medium",
    })
  }

  if (vulnerabilityTypes.has("Time-based Blind SQL Injection")) {
    mitigations.push({
      title: "Implement Query Timeouts",
      description:
        "Set strict timeouts for database queries to limit the effectiveness of time-based attacks. Monitor and alert on queries that take longer than expected.",
      priority: "medium",
    })
  }

  if (vulnerabilityTypes.has("Authentication Bypass SQL Injection")) {
    mitigations.push({
      title: "Strengthen Authentication Logic",
      description:
        "Ensure that authentication logic uses parameterized queries and implement multi-factor authentication where possible. Consider using specialized authentication libraries or frameworks.",
      priority: "high",
    })
  }

  // Add general security recommendations
  mitigations.push({
    title: "Web Application Firewall (WAF)",
    description:
      "Deploy a WAF that can detect and block common SQL injection patterns. While not a replacement for secure coding, it adds an additional layer of protection.",
    priority: "medium",
  })

  mitigations.push({
    title: "Regular Security Testing",
    description:
      "Conduct regular security assessments, including automated scanning and manual penetration testing, to identify and remediate vulnerabilities before they can be exploited.",
    priority: "low",
  })

  return mitigations
}
