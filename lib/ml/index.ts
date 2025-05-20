import * as path from "path"
import * as fs from "fs"
import { Tokenizer } from "./tokenizer"
import { SQLPreprocessor } from "./preprocessor"
import { SQLInjectionModel } from "./model"

// Singleton instance of the model
let modelInstance: SQLInjectionModel | null = null

// Initialize the ML model
export async function initializeModel(): Promise<SQLInjectionModel> {
  if (modelInstance) {
    return modelInstance
  }

  console.log("Initializing SQL injection detection model...")

  const modelDir = path.join(process.cwd(), "models", "sql_injection")
  const tokenizerPath = path.join(modelDir, "tokenizer.json")
  const modelPath = path.join(modelDir, "model")

  // Check if model files exist
  if (!fs.existsSync(tokenizerPath) || !fs.existsSync(path.join(modelPath, "model.json"))) {
    throw new Error("Model files not found. Please train the model first.")
  }

  try {
    // Load tokenizer
    const tokenizer = await Tokenizer.load(tokenizerPath)

    // Create preprocessor
    const preprocessor = new SQLPreprocessor(tokenizer, {
      maxSequenceLength: 100,
      paddingStrategy: "pre",
      truncatingStrategy: "post",
    })

    // Create model
    const model = new SQLInjectionModel(preprocessor)

    // Load model weights
    await model.load(modelPath)

    modelInstance = model
    console.log("Model initialized successfully")

    return model
  } catch (error) {
    console.error("Error initializing model:", error)
    throw new Error("Failed to initialize model")
  }
}

// Predict if a query is a SQL injection
export async function predictSQLInjection(query: string): Promise<{
  isSQLInjection: boolean
  confidence: number
}> {
  const model = await initializeModel()
  return model.predict(query)
}
