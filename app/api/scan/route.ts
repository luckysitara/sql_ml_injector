import { type NextRequest, NextResponse } from "next/server"
import { scanTarget } from "@/lib/scanner"
import { mockScanTarget } from "@/lib/mock-scanner"

export async function POST(request: NextRequest) {
  try {
    // Parse the request body
    let body
    try {
      body = await request.json()
    } catch (error) {
      console.error("Failed to parse request body:", error)
      return NextResponse.json(
        {
          error: "Invalid request",
          message: "Failed to parse request body. Please ensure you're sending valid JSON.",
        },
        { status: 400 },
      )
    }

    const { url, parameters, cookies, headers, deepScan } = body

    // Validate required fields
    if (!url) {
      return NextResponse.json(
        {
          error: "URL is required",
          message: "Please provide a valid URL to scan",
        },
        { status: 400 },
      )
    }

    // Validate URL format
    try {
      new URL(url)
    } catch (error) {
      return NextResponse.json(
        {
          error: "Invalid URL format",
          message: "The provided URL is not valid. Please ensure it includes the protocol (http:// or https://)",
        },
        { status: 400 },
      )
    }

    // Prepare scan parameters
    const scanParams = {
      url,
      parameters: Array.isArray(parameters) ? parameters : [],
      cookies: Array.isArray(cookies) ? cookies : [],
      headers: Array.isArray(headers) ? headers : [],
      deepScan: Boolean(deepScan),
    }

    console.log("Starting scan with parameters:", JSON.stringify(scanParams, null, 2))

    // Try the real scanner first
    try {
      console.log("Attempting to use real scanner")
      const results = await scanTarget(scanParams)
      return NextResponse.json(results)
    } catch (scanError) {
      console.error("Real scanner failed:", scanError)

      // Fall back to mock scanner
      try {
        console.log("Falling back to mock scanner")
        const mockResults = await mockScanTarget(scanParams)

        // Add a note that this is a mock scan
        mockResults.mitigations.unshift({
          title: "Note: Simulated Results",
          description:
            "The actual scanner encountered an issue, so these are simulated results for demonstration purposes.",
          priority: "medium",
        })

        return NextResponse.json(mockResults)
      } catch (mockError) {
        console.error("Mock scanner also failed:", mockError)

        // If both scanners fail, return a proper error response
        return NextResponse.json(
          {
            error: "Scan failed",
            message: "Both real and mock scanners failed. Please try again later.",
            vulnerabilities: [],
            mitigations: [
              {
                title: "Error during scan",
                description: `The scan encountered an error. Please try again with a different URL or parameters.`,
                priority: "high",
              },
            ],
            summary: {
              totalTested: 0,
              vulnerableParameters: 0,
              scanDuration: 0,
            },
          },
          { status: 500 },
        )
      }
    }
  } catch (error) {
    console.error("Unhandled error in scan API:", error)

    // Return a generic error response for any unhandled errors
    return NextResponse.json(
      {
        error: "Server error",
        message: "An unexpected error occurred while processing your request.",
        vulnerabilities: [],
        mitigations: [],
        summary: {
          totalTested: 0,
          vulnerableParameters: 0,
          scanDuration: 0,
        },
      },
      { status: 500 },
    )
  }
}
