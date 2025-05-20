import { CheckCircle } from "lucide-react"

export function Features() {
  return (
    <div className="mb-12">
      <h2 className="text-2xl font-bold mb-6">Key Features</h2>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="flex items-start space-x-2">
          <CheckCircle className="h-5 w-5 text-green-500 mt-0.5 flex-shrink-0" />
          <div>
            <h3 className="font-medium">Multiple Database Support</h3>
            <p className="text-muted-foreground text-sm">
              Detects SQL injection vulnerabilities in MySQL, PostgreSQL, MSSQL, Oracle, and SQLite databases.
            </p>
          </div>
        </div>
        <div className="flex items-start space-x-2">
          <CheckCircle className="h-5 w-5 text-green-500 mt-0.5 flex-shrink-0" />
          <div>
            <h3 className="font-medium">Advanced Detection Techniques</h3>
            <p className="text-muted-foreground text-sm">
              Uses pattern matching and heuristic analysis to identify vulnerabilities with high accuracy.
            </p>
          </div>
        </div>
        <div className="flex items-start space-x-2">
          <CheckCircle className="h-5 w-5 text-green-500 mt-0.5 flex-shrink-0" />
          <div>
            <h3 className="font-medium">Comprehensive Payload Library</h3>
            <p className="text-muted-foreground text-sm">
              Includes a wide range of SQL injection payloads for different attack vectors and database types.
            </p>
          </div>
        </div>
        <div className="flex items-start space-x-2">
          <CheckCircle className="h-5 w-5 text-green-500 mt-0.5 flex-shrink-0" />
          <div>
            <h3 className="font-medium">Detailed Reporting</h3>
            <p className="text-muted-foreground text-sm">
              Provides comprehensive reports with vulnerability details, evidence, and mitigation recommendations.
            </p>
          </div>
        </div>
        <div className="flex items-start space-x-2">
          <CheckCircle className="h-5 w-5 text-green-500 mt-0.5 flex-shrink-0" />
          <div>
            <h3 className="font-medium">Custom Scan Options</h3>
            <p className="text-muted-foreground text-sm">
              Configure scan parameters, cookies, headers, and scan depth to tailor the scan to your needs.
            </p>
          </div>
        </div>
        <div className="flex items-start space-x-2">
          <CheckCircle className="h-5 w-5 text-green-500 mt-0.5 flex-shrink-0" />
          <div>
            <h3 className="font-medium">Security Best Practices</h3>
            <p className="text-muted-foreground text-sm">
              Provides actionable recommendations based on industry best practices for securing your applications.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}
