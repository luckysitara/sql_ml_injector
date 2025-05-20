import { ScannerForm } from "@/components/scanner-form"
import { Features } from "@/components/features"

export default function Home() {
  return (
    <main className="container mx-auto px-4 py-8">
      <div className="max-w-4xl mx-auto">
        <div className="text-center mb-12">
          <h1 className="text-4xl font-bold tracking-tight mb-4">SQL Injection Scanner</h1>
          <p className="text-xl text-muted-foreground">
            Detect and analyze SQL injection vulnerabilities in web applications
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-12">
          <div className="bg-muted rounded-lg p-6 text-center">
            <h3 className="text-lg font-semibold mb-2">Comprehensive Detection</h3>
            <p className="text-muted-foreground">
              Identifies various types of SQL injection vulnerabilities including error-based, union-based, and blind
              injection techniques.
            </p>
          </div>
          <div className="bg-muted rounded-lg p-6 text-center">
            <h3 className="text-lg font-semibold mb-2">Detailed Analysis</h3>
            <p className="text-muted-foreground">
              Provides in-depth information about detected vulnerabilities, including evidence and confidence levels.
            </p>
          </div>
          <div className="bg-muted rounded-lg p-6 text-center">
            <h3 className="text-lg font-semibold mb-2">Mitigation Recommendations</h3>
            <p className="text-muted-foreground">
              Offers tailored security recommendations to help fix identified vulnerabilities and improve overall
              security.
            </p>
          </div>
        </div>

        <div className="mb-12">
          <h2 className="text-2xl font-bold mb-6">Start a Scan</h2>
          <div className="bg-card border rounded-lg p-6">
            <ScannerForm />
          </div>
        </div>

        <Features />

        <div className="text-center mt-12 text-sm text-muted-foreground">
          <p>
            This tool is for educational and security testing purposes only. Always obtain proper authorization before
            scanning any website.
          </p>
        </div>
      </div>
    </main>
  )
}
