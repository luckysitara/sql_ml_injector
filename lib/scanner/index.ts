import fetch from "node-fetch"
import { URL } from "url"
import { getPayloads } from "./payloads"
import { analyzeResponse, generateMitigations } from "./analyzer"

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
    // Validate URL
    let urlObj: URL
    try {
      urlObj = new URL(params.url)
    } catch (error) {
      throw new Error(`Invalid URL: ${error.message}`)
    }

    // Extract parameters from URL if none provided
    let targetParams = params.parameters
    if (targetParams.length === 0) {
      targetParams = Array.from(urlObj.searchParams.keys())

      // If still no parameters found, use some defaults for testing
      if (targetParams.length === 0) {
        console.log("No parameters found in URL, using default test parameters")
        targetParams = ["q", "search", "id", "page", "query"]
      }
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
      : getPayloads(null, null, 20) // Get a subset for quick scan

    console.log(`Testing ${targetParams.length} parameters with ${payloads.length} payloads`)

    // Test each parameter with each payload
    for (const param of targetParams) {
      try {
        const vulnerabilities = await testParameter(params.url, param, payloads, {
          cookies: params.cookies,
          headers: params.headers,
        })

        result.vulnerabilities.push(...vulnerabilities)

        if (vulnerabilities.length > 0) {
          result.summary.vulnerableParameters++
        }

        result.summary.totalTested++
      } catch (paramError) {
        console.error(`Error testing parameter ${param}:`, paramError)
        // Continue with next parameter
      }
    }

    // Generate mitigation recommendations based on found vulnerabilities
    result.mitigations = generateMitigations(result.vulnerabilities)

    // Calculate scan duration
    result.summary.scanDuration = (Date.now() - startTime) / 1000

    return result
  } catch (error) {
    console.error("Scan error:", error)
    throw new Error(`Failed to scan target: ${error.message}`)
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

  try {
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
  } catch (error) {
    console.error(`Error in testParameter for ${parameter}:`, error)
  }

  return vulnerabilities
}

// Improved sendRequest function with better error handling
async function sendRequest(
  url: string,
  options: { cookies: string[]; headers: string[] },
): Promise<{ status: number; body: string; headers: Record<string, string> }> {
  // Create abort controller for timeout
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), 10000) // 10 second timeout

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
      signal: controller.signal,
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
    // Handle specific error types
    if (error.name === "AbortError") {
      throw new Error("Request timed out after 10 seconds")
    } else if (error.code === "ENOTFOUND" || error.code === "ECONNREFUSED") {
      throw new Error(`Could not connect to the target: ${error.message}`)
    } else {
      console.error("Request error:", error)
      throw new Error(`Failed to send request: ${error.message || "Unknown network error"}`)
    }
  } finally {
    clearTimeout(timeoutId)
  }
}
