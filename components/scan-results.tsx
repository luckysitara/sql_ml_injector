"use client"

import { useState } from "react"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { AlertCircle, AlertTriangle, CheckCircle } from "lucide-react"

interface Vulnerability {
  type: string
  parameter: string
  payload: string
  confidence: number
  details: string
  evidence: string
}

interface Mitigation {
  title: string
  description: string
  priority: "high" | "medium" | "low"
}

interface ScanSummary {
  totalTested: number
  vulnerableParameters: number
  scanDuration: number
}

interface ScanResultsProps {
  results: {
    vulnerabilities: Vulnerability[]
    mitigations: Mitigation[]
    summary: ScanSummary
  }
}

export function ScanResults({ results }: ScanResultsProps) {
  const [activeTab, setActiveTab] = useState("vulnerabilities")

  if (!results) {
    return null
  }

  const { vulnerabilities, mitigations, summary } = results

  // Determine overall security status
  let securityStatus = "secure"
  if (vulnerabilities.length > 0) {
    securityStatus = vulnerabilities.some((v) => v.confidence > 80) ? "critical" : "warning"
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <span>Scan Results</span>
            {securityStatus === "secure" && (
              <Badge className="bg-green-500">
                <CheckCircle className="mr-1 h-4 w-4" /> Secure
              </Badge>
            )}
            {securityStatus === "warning" && (
              <Badge className="bg-yellow-500">
                <AlertTriangle className="mr-1 h-4 w-4" /> Potential Issues
              </Badge>
            )}
            {securityStatus === "critical" && (
              <Badge className="bg-red-500">
                <AlertCircle className="mr-1 h-4 w-4" /> Vulnerabilities Detected
              </Badge>
            )}
          </CardTitle>
          <CardDescription>
            Scanned {summary.totalTested} parameters in {summary.scanDuration.toFixed(2)} seconds
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-3 gap-4 mb-4">
            <div className="bg-muted rounded-lg p-3 text-center">
              <div className="text-2xl font-bold">{summary.totalTested}</div>
              <div className="text-sm text-muted-foreground">Parameters Tested</div>
            </div>
            <div className="bg-muted rounded-lg p-3 text-center">
              <div className="text-2xl font-bold">{summary.vulnerableParameters}</div>
              <div className="text-sm text-muted-foreground">Vulnerable Parameters</div>
            </div>
            <div className="bg-muted rounded-lg p-3 text-center">
              <div className="text-2xl font-bold">{vulnerabilities.length}</div>
              <div className="text-sm text-muted-foreground">Vulnerabilities Found</div>
            </div>
          </div>

          <Tabs defaultValue="vulnerabilities" onValueChange={setActiveTab} value={activeTab}>
            <TabsList className="grid w-full grid-cols-2">
              <TabsTrigger value="vulnerabilities">Vulnerabilities</TabsTrigger>
              <TabsTrigger value="mitigations">Mitigations</TabsTrigger>
            </TabsList>
            <TabsContent value="vulnerabilities" className="space-y-4 mt-4">
              {vulnerabilities.length === 0 ? (
                <Alert className="bg-green-50 border-green-200">
                  <CheckCircle className="h-4 w-4 text-green-600" />
                  <AlertTitle>No vulnerabilities detected</AlertTitle>
                  <AlertDescription>
                    No SQL injection vulnerabilities were found during the scan. However, this doesn't guarantee that
                    the application is completely secure. Regular security testing is recommended.
                  </AlertDescription>
                </Alert>
              ) : (
                <Accordion type="single" collapsible className="w-full">
                  {vulnerabilities.map((vulnerability, index) => (
                    <AccordionItem key={index} value={`item-${index}`}>
                      <AccordionTrigger className="hover:no-underline">
                        <div className="flex items-center justify-between w-full pr-4">
                          <div className="flex items-center">
                            <Badge
                              className={
                                vulnerability.confidence > 80
                                  ? "bg-red-500 mr-2"
                                  : vulnerability.confidence > 60
                                    ? "bg-yellow-500 mr-2"
                                    : "bg-blue-500 mr-2"
                              }
                            >
                              {vulnerability.confidence > 80
                                ? "High"
                                : vulnerability.confidence > 60
                                  ? "Medium"
                                  : "Low"}
                            </Badge>
                            <span className="font-medium">{vulnerability.type}</span>
                          </div>
                          <span className="text-sm text-muted-foreground">Parameter: {vulnerability.parameter}</span>
                        </div>
                      </AccordionTrigger>
                      <AccordionContent className="space-y-2">
                        <div>
                          <span className="font-semibold">Details:</span> {vulnerability.details}
                        </div>
                        <div>
                          <span className="font-semibold">Payload:</span>{" "}
                          <code className="bg-muted px-1 py-0.5 rounded text-sm">{vulnerability.payload}</code>
                        </div>
                        <div>
                          <span className="font-semibold">Confidence:</span> {vulnerability.confidence}%
                        </div>
                        <div>
                          <span className="font-semibold">Evidence:</span>
                          <pre className="bg-muted p-2 rounded text-sm mt-1 overflow-x-auto">
                            {vulnerability.evidence}
                          </pre>
                        </div>
                      </AccordionContent>
                    </AccordionItem>
                  ))}
                </Accordion>
              )}
            </TabsContent>
            <TabsContent value="mitigations" className="space-y-4 mt-4">
              {mitigations.length === 0 ? (
                <Alert>
                  <AlertCircle className="h-4 w-4" />
                  <AlertTitle>No mitigations available</AlertTitle>
                  <AlertDescription>
                    No specific mitigations are available as no vulnerabilities were detected.
                  </AlertDescription>
                </Alert>
              ) : (
                <Accordion type="single" collapsible className="w-full">
                  {mitigations.map((mitigation, index) => (
                    <AccordionItem key={index} value={`item-${index}`}>
                      <AccordionTrigger className="hover:no-underline">
                        <div className="flex items-center justify-between w-full pr-4">
                          <div className="flex items-center">
                            <Badge
                              className={
                                mitigation.priority === "high"
                                  ? "bg-red-500 mr-2"
                                  : mitigation.priority === "medium"
                                    ? "bg-yellow-500 mr-2"
                                    : "bg-blue-500 mr-2"
                              }
                            >
                              {mitigation.priority.charAt(0).toUpperCase() + mitigation.priority.slice(1)}
                            </Badge>
                            <span className="font-medium">{mitigation.title}</span>
                          </div>
                        </div>
                      </AccordionTrigger>
                      <AccordionContent>
                        <div>{mitigation.description}</div>
                      </AccordionContent>
                    </AccordionItem>
                  ))}
                </Accordion>
              )}
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  )
}
