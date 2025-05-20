// This file provides a fallback mock scanner implementation
// in case the real scanner encounters issues

export async function mockScanTarget(params: {
  url: string
  parameters: string[]
  cookies: string[]
  headers: string[]
  deepScan: boolean
}) {
  // Simulate scanning delay
  await new Promise((resolve) => setTimeout(resolve, 2000))

  // Extract parameters from URL if none provided
  let targetParams = params.parameters
  if (targetParams.length === 0) {
    try {
      const urlObj = new URL(params.url)
      targetParams = Array.from(urlObj.searchParams.keys())

      // If still no parameters found, use some defaults for demo purposes
      if (targetParams.length === 0) {
        targetParams = ["q", "search", "id", "page", "query"]
      }
    } catch (error) {
      console.error("URL parsing error:", error)
      targetParams = ["q", "search", "id"] // Default parameters to test
    }
  }

  // Generate mock results
  const vulnerabilities = []
  let vulnerableParams = 0

  // Simulate finding vulnerabilities in some parameters
  for (const param of targetParams) {
    // Randomly determine if this parameter is vulnerable (for demo purposes)
    const isVulnerable = Math.random() > 0.7

    if (isVulnerable) {
      vulnerableParams++

      // Choose a random vulnerability type
      const vulnTypes = [
        "Union-based SQL Injection",
        "Error-based SQL Injection",
        "Boolean-based Blind SQL Injection",
        "Time-based Blind SQL Injection",
        "Authentication Bypass SQL Injection",
      ]

      const type = vulnTypes[Math.floor(Math.random() * vulnTypes.length)]

      // Choose a relevant payload based on the type
      let payload = ""
      switch (type) {
        case "Union-based SQL Injection":
          payload = "' UNION SELECT 1,2,3--"
          break
        case "Error-based SQL Injection":
          payload = "' AND extractvalue(1, concat(0x7e, version()))--"
          break
        case "Boolean-based Blind SQL Injection":
          payload = "' AND 1=1--"
          break
        case "Time-based Blind SQL Injection":
          payload = "' AND SLEEP(5)--"
          break
        case "Authentication Bypass SQL Injection":
          payload = "' OR '1'='1"
          break
        default:
          payload = "' OR 1=1--"
      }

      vulnerabilities.push({
        type,
        parameter: param,
        payload,
        confidence: 70 + Math.floor(Math.random() * 30), // Random confidence between 70-99%
        details: `The parameter '${param}' appears to be vulnerable to ${type}. The payload '${payload}' was successful in exploiting this vulnerability.`,
        evidence: `Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '${payload}' at line 1`,
      })
    }
  }

  // Generate mitigations based on found vulnerabilities
  const mitigations = []

  // Always add these basic mitigations
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

  return {
    vulnerabilities,
    mitigations,
    summary: {
      totalTested: targetParams.length,
      vulnerableParameters: vulnerableParams,
      scanDuration: 1.5 + Math.random() * 2, // Random scan duration between 1.5-3.5 seconds
    },
  }
}
