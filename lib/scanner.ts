import fetch from "node-fetch"
import { URL } from "url"
import { generateText } from "ai"
import { openai } from "@ai-sdk/openai"
import { getPayloads } from "./payloads"
import { predictSQLInjection } from "./ml-model"

interface ScanTargetParams {
  url: string
  parameters: string[]
  cookies: string[]
  headers: string[]
  deepScan: boolean
}

interface ScanResult {
  vulnerabilities: Array<{
    type: string
    parameter: string
    payload: string
    confidence: number
    details: string
    evidence: string
  }>
  mitigations: Array<{
    title: string
    description: string
    priority: "high" | "medium" | "low"
  }>
  summary: {
    totalTested: number
    vulnerableParameters: number
    scanDuration: number
  }
}

// Main function to scan a target for SQL injection vulnerabilities
export async function scanTarget(params: ScanTargetParams): Promise<ScanResult> {
  const startTime = Date.now()

  try {
    // Extract parameters from URL if none provided
    let targetParams = params.parameters
    if (targetParams.length === 0) {
      const urlObj = new URL(params.url)
      targetParams = Array.from(urlObj.searchParams.keys())
    }

    // Initialize scan result
    const result: ScanResult = {
      vulnerabilities: [],
      mitigations: [],
      summary: {
        totalTested: 0,
        vulnerableParameters: 0,
        scanDuration: 0,
      },
    }

    // Determine which payloads to use based on scan depth
    const payloads = params.deepScan
      ? getPayloads() // Get all payloads for deep scan
      : getPayloads().slice(0, 50) // Get a subset for quick scan

    // Test each parameter with each payload
    for (const param of targetParams) {
      const vulnerabilities = await testParameter(params.url, param, payloads, {
        cookies: params.cookies,
        headers: params.headers,
      })

      result.vulnerabilities.push(...vulnerabilities)

      if (vulnerabilities.length > 0) {
        result.summary.vulnerableParameters++
      }

      result.summary.totalTested++
    }

    // Generate mitigation recommendations based on found vulnerabilities
    result.mitigations = generateMitigations(result.vulnerabilities)

    // Calculate scan duration
    result.summary.scanDuration = (Date.now() - startTime) / 1000

    return result
  } catch (error) {
    console.error("Scan error:", error)
    throw new Error("Failed to scan target")
  }
}

// Test a single parameter with multiple payloads
async function testParameter(
  baseUrl: string,
  parameter: string,
  payloads: string[],
  options: { cookies: string[]; headers: string[] },
): Promise<ScanResult["vulnerabilities"]> {
  const vulnerabilities: ScanResult["vulnerabilities"] = []
  const urlObj = new URL(baseUrl)

  // Get the original parameter value
  const originalValue = urlObj.searchParams.get(parameter) || ""

  // Test each payload
  for (const payload of payloads) {
    try {
      // Create a new URL object for each test to avoid modifying the original
      const testUrl = new URL(baseUrl)

      // Set the payload as the parameter value
      testUrl.searchParams.set(parameter, payload)

      // Send the request
      const response = await sendRequest(testUrl.toString(), options)

      // Analyze the response
      const analysis = await analyzeResponse(payload, response, parameter)

      if (analysis.isVulnerable) {
        vulnerabilities.push({
          type: analysis.type,
          parameter,
          payload,
          confidence: analysis.confidence,
          details: analysis.details,
          evidence: analysis.evidence,
        })

        // If we found a vulnerability, we can stop testing this parameter
        // unless we're doing a deep scan to find all vulnerabilities
        if (!baseUrl.includes("deepScan=true")) {
          break
        }
      }
    } catch (error) {
      console.error(`Error testing parameter ${parameter} with payload ${payload}:`, error)
      // Continue with the next payload
    }
  }

  return vulnerabilities
}

// Send an HTTP request to the target URL
async function sendRequest(
  url: string,
  options: { cookies: string[]; headers: string[] },
): Promise<{ status: number; body: string; headers: Record<string, string> }> {
  try {
    // Prepare headers
    const headers: Record<string, string> = {
      "User-Agent": "SQLGuardian/1.0",
    }

    // Add custom headers
    for (const header of options.headers) {
      const [name, value] = header.split(":", 2)
      if (name && value) {
        headers[name.trim()] = value.trim()
      }
    }

    // Add cookies
    if (options.cookies.length > 0) {
      headers["Cookie"] = options.cookies.join("; ")
    }

    // Send the request
    const response = await fetch(url, {
      method: "GET",
      headers,
      redirect: "follow",
    })

    // Get the response body
    const body = await response.text()

    // Convert headers to a plain object
    const responseHeaders: Record<string, string> = {}
    response.headers.forEach((value, name) => {
      responseHeaders[name] = value
    })

    return {
      status: response.status,
      body,
      headers: responseHeaders,
    }
  } catch (error) {
    console.error("Request error:", error)
    throw new Error("Failed to send request")
  }
}

// Analyze the response to determine if it indicates a SQL injection vulnerability
async function analyzeResponse(
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

  // Use ML model to predict if the payload and response indicate SQL injection
  try {
    // Combine payload and relevant parts of the response for analysis
    const analysisText = `${payload} | Status: ${response.status} | Body: ${response.body.substring(0, 1000)}`

    // Use the ML model to predict
    const prediction = await predictSQLInjection(analysisText)

    if (prediction.isSQLInjection) {
      // Determine the type of SQL injection
      let injectionType = "Unknown"

      if (payload.includes("UNION SELECT")) {
        injectionType = "Union-based SQL Injection"
      } else if (payload.includes("SLEEP") || payload.includes("WAITFOR DELAY") || payload.includes("pg_sleep")) {
        injectionType = "Time-based Blind SQL Injection"
      } else if (payload.includes("AND 1=1") || payload.includes("AND 1=2")) {
        injectionType = "Boolean-based Blind SQL Injection"
      } else if (payload.includes("convert") || payload.includes("cast") || payload.includes("updatexml")) {
        injectionType = "Error-based SQL Injection"
      } else if (payload.includes("' OR '1'='1") || payload.includes("admin'--")) {
        injectionType = "Authentication Bypass SQL Injection"
      }

      // Extract evidence from the response
      let evidence = ""

      // Look for SQL error messages in the response
      const sqlErrorPatterns = [
        "SQL syntax",
        "mysql_fetch",
        "ORA-",
        "PostgreSQL",
        "SQLite3",
        "SQLSTATE",
        "Microsoft SQL",
        "syntax error",
        "unclosed quotation mark",
        "unterminated string",
        "expects parameter",
        "Warning: mysql",
        "Warning: pg_",
        "Warning: sqlite",
        "Warning: oci_",
      ]

      for (const pattern of sqlErrorPatterns) {
        if (response.body.includes(pattern)) {
          const startIndex = Math.max(0, response.body.indexOf(pattern) - 50)
          const endIndex = Math.min(response.body.length, response.body.indexOf(pattern) + 150)
          evidence = response.body.substring(startIndex, endIndex)
          break
        }
      }

      // If no specific error message found, use a portion of the response
      if (!evidence && response.body.length > 0) {
        evidence = response.body.substring(0, 200) + (response.body.length > 200 ? "..." : "")
      }

      // Set the result
      result.isVulnerable = true
      result.type = injectionType
      result.confidence = prediction.confidence
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
function generateMitigations(vulnerabilities: ScanResult["vulnerabilities"]): ScanResult["mitigations"] {
  const mitigations: ScanResult["mitigations"] = []

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

async function analyzeResponses(url: string, parameters: string[]) {
  // In a real implementation, this would analyze actual HTTP responses
  // For this demo, we'll use the AI model to generate simulated results

  const prompt = `
You are a security expert analyzing SQL injection test results for the URL: ${url}

Parameters tested: ${parameters.join(", ")}

Based on your expertise in SQL injection vulnerabilities, generate a realistic security assessment report with:
1. A list of potential SQL injection vulnerabilities (if any)
2. Recommended mitigations
3. A summary of the scan

Format the response as a JSON object with the following structure:
{
  "vulnerabilities": [
    {
      "type": "SQL Injection type (Error-based, Union-based, etc.)",
      "parameter": "vulnerable parameter name",
      "payload": "example payload that worked",
      "confidence": confidence score (0-100),
      "details": "detailed explanation of the vulnerability",
      "evidence": "evidence from the response indicating vulnerability"
    }
  ],
  "mitigations": [
    {
      "title": "mitigation title",
      "description": "detailed explanation of the mitigation",
      "priority": "high/medium/low"
    }
  ],
  "summary": {
    "totalTested": number of parameters tested,
    "vulnerableParameters": number of vulnerable parameters found,
    "scanDuration": simulated scan duration in seconds
  }
}

If no vulnerabilities are found, return an empty array for "vulnerabilities".
Make the assessment realistic - not all parameters are necessarily vulnerable.
Include specific details about the types of SQL injections found and realistic payloads from common SQL injection techniques.
`

  const { text } = await generateText({
    model: openai("gpt-4o"),
    prompt,
  })

  try {
    return JSON.parse(text)
  } catch (error) {
    console.error("Failed to parse AI response:", error)
    return {
      vulnerabilities: [],
      mitigations: [
        {
          title: "Error analyzing results",
          description: "The AI model failed to properly analyze the scan results. Please try again.",
          priority: "high",
        },
      ],
      summary: {
        totalTested: parameters.length,
        vulnerableParameters: 0,
        scanDuration: 3.5,
      },
    }
  }
}
