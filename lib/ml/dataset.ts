import * as fs from "fs"
import * as path from "path"
import * as csv from "csv-parser"
import { createReadStream } from "fs"

// Define the structure of a training example
export interface SQLExample {
  query: string
  isSQLInjection: boolean
}

// Class to load and preprocess the SQL injection dataset
export class SQLInjectionDataset {
  private trainingData: SQLExample[] = []
  private validationData: SQLExample[] = []
  private testData: SQLExample[] = []

  // Load dataset from CSV files
  public async loadFromCSV(
    trainPath: string,
    validationPath?: string,
    testPath?: string,
    validationSplit = 0.2,
    testSplit = 0.1,
  ): Promise<void> {
    console.log("Loading dataset from CSV files...")

    // Load training data
    const allData: SQLExample[] = await this.readCSVFile(trainPath)

    // If validation and test paths are provided, load them separately
    if (validationPath && testPath) {
      this.trainingData = allData
      this.validationData = await this.readCSVFile(validationPath)
      this.testData = await this.readCSVFile(testPath)
    } else {
      // Otherwise, split the data
      this.shuffleArray(allData)

      const totalCount = allData.length
      const testCount = Math.floor(totalCount * testSplit)
      const validationCount = Math.floor(totalCount * validationSplit)
      const trainCount = totalCount - testCount - validationCount

      this.trainingData = allData.slice(0, trainCount)
      this.validationData = allData.slice(trainCount, trainCount + validationCount)
      this.testData = allData.slice(trainCount + validationCount)
    }

    console.log(
      `Dataset loaded: ${this.trainingData.length} training, ${this.validationData.length} validation, ${this.testData.length} test examples`,
    )
  }

  // Read a CSV file and return the data as an array of SQLExample objects
  private async readCSVFile(filePath: string): Promise<SQLExample[]> {
    return new Promise((resolve, reject) => {
      const results: SQLExample[] = []

      createReadStream(filePath)
        .pipe(csv())
        .on("data", (data) => {
          // Assuming CSV has 'query' and 'label' columns
          results.push({
            query: data.query,
            isSQLInjection: data.label === "1" || data.label === "True" || data.label === "true",
          })
        })
        .on("end", () => {
          resolve(results)
        })
        .on("error", (error) => {
          reject(error)
        })
    })
  }

  // Shuffle an array in-place using Fisher-Yates algorithm
  private shuffleArray(array: any[]): void {
    for (let i = array.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1))
      ;[array[i], array[j]] = [array[j], array[i]]
    }
  }

  // Generate a synthetic dataset if no real data is available
  public generateSyntheticDataset(size = 10000): void {
    console.log("Generating synthetic dataset...")

    const normalQueries = [
      "SELECT * FROM users WHERE username = 'john'",
      "SELECT id, name FROM products WHERE category = 'electronics'",
      "INSERT INTO orders (user_id, product_id, quantity) VALUES (1, 2, 3)",
      "UPDATE users SET last_login = NOW() WHERE id = 5",
      "DELETE FROM cart WHERE user_id = 7 AND expired = true",
      "SELECT COUNT(*) FROM visits WHERE date > '2023-01-01'",
      "SELECT AVG(price) FROM products GROUP BY category",
      "SELECT u.name, o.date FROM users u JOIN orders o ON u.id = o.user_id",
      "SELECT * FROM settings WHERE user_id = 42",
      "SELECT DISTINCT category FROM products ORDER BY category ASC",
    ]

    const sqlInjectionPatterns = [
      "' OR '1'='1",
      "' OR 1=1--",
      "'; DROP TABLE users; --",
      "' UNION SELECT username, password FROM users--",
      "' OR '1'='1' LIMIT 1; --",
      "admin'--",
      "1' OR SLEEP(5)--",
      "1'; WAITFOR DELAY '0:0:5'--",
      "' OR 1=1 UNION SELECT null, username, password FROM users--",
      "'; exec xp_cmdshell('net user');--",
      "' OR '1'='1'; INSERT INTO users VALUES ('hacker', 'password');--",
      "' AND (SELECT COUNT(*) FROM sysobjects) > 0--",
      "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
      "' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
      "' OR (SELECT COUNT(*) FROM users) > 0--",
    ]

    // Generate normal queries
    const normalCount = Math.floor(size * 0.6) // 60% normal queries
    const normalData: SQLExample[] = []

    for (let i = 0; i < normalCount; i++) {
      const baseQuery = normalQueries[Math.floor(Math.random() * normalQueries.length)]
      // Add some variation
      const query = this.addVariation(baseQuery)
      normalData.push({ query, isSQLInjection: false })
    }

    // Generate SQL injection queries
    const injectionCount = size - normalCount
    const injectionData: SQLExample[] = []

    for (let i = 0; i < injectionCount; i++) {
      const baseQuery = normalQueries[Math.floor(Math.random() * normalQueries.length)]
      const injectionPattern = sqlInjectionPatterns[Math.floor(Math.random() * sqlInjectionPatterns.length)]

      // Insert the injection pattern into the query
      const query = this.insertInjection(baseQuery, injectionPattern)
      injectionData.push({ query, isSQLInjection: true })
    }

    // Combine and shuffle the data
    const allData = [...normalData, ...injectionData]
    this.shuffleArray(allData)

    // Split into training, validation, and test sets
    const testCount = Math.floor(size * 0.1)
    const validationCount = Math.floor(size * 0.2)
    const trainCount = size - testCount - validationCount

    this.trainingData = allData.slice(0, trainCount)
    this.validationData = allData.slice(trainCount, trainCount + validationCount)
    this.testData = allData.slice(trainCount + validationCount)

    console.log(
      `Synthetic dataset generated: ${this.trainingData.length} training, ${this.validationData.length} validation, ${this.testData.length} test examples`,
    )
  }

  // Add random variation to a query
  private addVariation(query: string): string {
    // Add random whitespace
    if (Math.random() < 0.3) {
      query = query.replace(/\s+/g, " ").replace(/\s/g, (match) => {
        return Math.random() < 0.3 ? "  " : " "
      })
    }

    // Change case randomly
    if (Math.random() < 0.3) {
      const keywords = [
        "SELECT",
        "FROM",
        "WHERE",
        "AND",
        "OR",
        "INSERT",
        "UPDATE",
        "DELETE",
        "JOIN",
        "GROUP BY",
        "ORDER BY",
      ]
      for (const keyword of keywords) {
        if (query.toUpperCase().includes(keyword)) {
          const replacement = Math.random() < 0.5 ? keyword.toLowerCase() : keyword
          query = query.replace(new RegExp(keyword, "i"), replacement)
        }
      }
    }

    // Change parameter values
    if (Math.random() < 0.4) {
      query = query.replace(/'([^']*)'/g, (match, p1) => {
        if (Math.random() < 0.5) {
          return `'${p1}'`
        }
        // Generate a random string
        const chars = "abcdefghijklmnopqrstuvwxyz"
        let randomStr = ""
        const length = Math.floor(Math.random() * 10) + 1
        for (let i = 0; i < length; i++) {
          randomStr += chars.charAt(Math.floor(Math.random() * chars.length))
        }
        return `'${randomStr}'`
      })
    }

    return query
  }

  // Insert an SQL injection pattern into a query
  private insertInjection(query: string, injectionPattern: string): string {
    // Find positions where we can insert the injection
    const positions = []

    // After WHERE clause
    const wherePos = query.toUpperCase().indexOf("WHERE")
    if (wherePos !== -1) {
      const afterWhere = wherePos + "WHERE".length
      positions.push(afterWhere)
    }

    // Inside quotes
    const quoteMatches = [...query.matchAll(/'([^']*)'/g)]
    for (const match of quoteMatches) {
      if (match.index !== undefined) {
        positions.push(match.index + 1) // Position right after the opening quote
      }
    }

    // If no suitable positions found, just append to the end
    if (positions.length === 0) {
      return query + " " + injectionPattern
    }

    // Choose a random position to insert the injection
    const position = positions[Math.floor(Math.random() * positions.length)]

    return query.slice(0, position) + injectionPattern + query.slice(position)
  }

  // Get the training data
  public getTrainingData(): SQLExample[] {
    return this.trainingData
  }

  // Get the validation data
  public getValidationData(): SQLExample[] {
    return this.validationData
  }

  // Get the test data
  public getTestData(): SQLExample[] {
    return this.testData
  }

  // Save the dataset to CSV files
  public async saveToCSV(trainPath: string, validationPath: string, testPath: string): Promise<void> {
    await this.writeCSVFile(trainPath, this.trainingData)
    await this.writeCSVFile(validationPath, this.validationData)
    await this.writeCSVFile(testPath, this.testData)
    console.log("Dataset saved to CSV files")
  }

  // Write data to a CSV file
  private async writeCSVFile(filePath: string, data: SQLExample[]): Promise<void> {
    return new Promise((resolve, reject) => {
      // Create directory if it doesn't exist
      const dir = path.dirname(filePath)
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true })
      }

      // Write header
      const header = "query,label\n"
      fs.writeFileSync(filePath, header)

      // Write data
      for (const example of data) {
        const line = `"${example.query.replace(/"/g, '""')}",${example.isSQLInjection ? "1" : "0"}\n`
        fs.appendFileSync(filePath, line)
      }

      resolve()
    })
  }
}
