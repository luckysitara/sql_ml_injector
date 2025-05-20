"use client"

import { useState } from "react"
import { useForm, Controller } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import * as z from "zod"
import { Loader2, AlertCircle } from "lucide-react"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { ScanResults } from "@/components/scan-results"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Label } from "@/components/ui/label"

// Define the form schema
const formSchema = z.object({
  url: z.string().url({ message: "Please enter a valid URL" }).min(1, "URL is required"),
  parameters: z.string().optional().default(""),
  cookies: z.string().optional().default(""),
  headers: z.string().optional().default(""),
  deepScan: z.boolean().default(false),
})

// Define the form values type
type FormValues = z.infer<typeof formSchema>

export function ScannerForm() {
  const [isScanning, setIsScanning] = useState(false)
  const [scanResults, setScanResults] = useState<any>(null)
  const [error, setError] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState("parameters")

  // Initialize form with react-hook-form
  const {
    register,
    handleSubmit,
    control,
    formState: { errors },
  } = useForm<FormValues>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      url: "",
      parameters: "",
      cookies: "",
      headers: "",
      deepScan: false,
    },
  })

  // Handle form submission
  const onSubmit = async (values: FormValues) => {
    setIsScanning(true)
    setScanResults(null)
    setError(null)

    try {
      // Parse the string inputs into arrays
      const parameters = values.parameters ? values.parameters.split("\n").filter(Boolean) : []
      const cookies = values.cookies ? values.cookies.split("\n").filter(Boolean) : []
      const headers = values.headers ? values.headers.split("\n").filter(Boolean) : []

      console.log("Starting scan for URL:", values.url)

      const response = await fetch("/api/scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          url: values.url,
          parameters,
          cookies,
          headers,
          deepScan: values.deepScan,
        }),
      })

      // Check if the response is ok before trying to parse JSON
      if (!response.ok) {
        console.error("Scan API returned error status:", response.status)

        let errorMessage = `Server error: ${response.status} ${response.statusText}`

        try {
          const contentType = response.headers.get("content-type")
          if (contentType && contentType.includes("application/json")) {
            // If it's JSON, parse the error
            const errorData = await response.json()
            if (errorData.message || errorData.error) {
              errorMessage = errorData.message || errorData.error
            }
          }
        } catch (parseError) {
          console.error("Failed to parse error response:", parseError)
        }

        throw new Error(errorMessage)
      }

      // Now we know the response is ok, parse the JSON
      const data = await response.json()
      console.log("Scan completed successfully")
      setScanResults(data)
    } catch (err: any) {
      console.error("Scan error:", err)
      setError(err.message || "An unexpected error occurred during the scan")
    } finally {
      setIsScanning(false)
    }
  }

  return (
    <div className="space-y-8">
      <form onSubmit={handleSubmit(onSubmit)} className="space-y-8">
        <div className="space-y-2">
          <Label htmlFor="url">Target URL</Label>
          <Input id="url" placeholder="https://example.com/search?q=test" {...register("url")} />
          {errors.url && <p className="text-sm text-red-500">{errors.url.message}</p>}
          <p className="text-sm text-gray-500">
            Enter the URL of the application you want to scan for SQL injection vulnerabilities.
          </p>
        </div>

        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="parameters">Parameters</TabsTrigger>
            <TabsTrigger value="cookies">Cookies</TabsTrigger>
            <TabsTrigger value="headers">Headers</TabsTrigger>
          </TabsList>
          <TabsContent value="parameters">
            <div className="space-y-2">
              <Label htmlFor="parameters">Parameters to Test (Optional)</Label>
              <Textarea
                id="parameters"
                placeholder="param1
param2
param3"
                className="min-h-[120px]"
                {...register("parameters")}
              />
              <p className="text-sm text-gray-500">
                Enter each parameter name on a new line. If left empty, the scanner will automatically detect parameters
                from the URL.
              </p>
            </div>
          </TabsContent>
          <TabsContent value="cookies">
            <div className="space-y-2">
              <Label htmlFor="cookies">Cookies to Include (Optional)</Label>
              <Textarea
                id="cookies"
                placeholder="cookie1=value1
cookie2=value2"
                className="min-h-[120px]"
                {...register("cookies")}
              />
              <p className="text-sm text-gray-500">Enter each cookie on a new line in the format name=value.</p>
            </div>
          </TabsContent>
          <TabsContent value="headers">
            <div className="space-y-2">
              <Label htmlFor="headers">Custom Headers (Optional)</Label>
              <Textarea
                id="headers"
                placeholder="X-Custom-Header: value
Authorization: Bearer token"
                className="min-h-[120px]"
                {...register("headers")}
              />
              <p className="text-sm text-gray-500">Enter each header on a new line in the format name: value.</p>
            </div>
          </TabsContent>
        </Tabs>

        <div className="flex items-start space-x-3 space-y-0 rounded-md border p-4">
          <Controller
            name="deepScan"
            control={control}
            render={({ field }) => (
              <Checkbox id="deepScan" checked={field.value} onCheckedChange={(checked) => field.onChange(checked)} />
            )}
          />
          <div className="space-y-1 leading-none">
            <Label htmlFor="deepScan">Deep Scan</Label>
            <p className="text-sm text-gray-500">
              Enable deep scanning to test more payloads and perform more thorough analysis. This may take longer.
            </p>
          </div>
        </div>

        <Button type="submit" disabled={isScanning} className="w-full">
          {isScanning ? (
            <>
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              Scanning...
            </>
          ) : (
            "Start Scan"
          )}
        </Button>
      </form>

      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {scanResults && (
        <div className="mt-8">
          <ScanResults results={scanResults} />
        </div>
      )}
    </div>
  )
}
