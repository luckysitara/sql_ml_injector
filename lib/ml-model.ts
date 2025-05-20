import { TensorFlow } from "@tensorflow/tfjs-node"
import { Tokenizer } from "@tensorflow/tfjs-node-nlp"
import { loadModel } from "./model-loader"

// Maximum sequence length for input queries
const MAX_LEN = 100
// Maximum number of words in the vocabulary
const MAX_WORDS = 20000

// Tokenizer for processing SQL queries
let tokenizer: Tokenizer | null = null
// TensorFlow model for SQL injection detection
let model: TensorFlow.LayersModel | null = null

// Initialize the ML components
export async function initializeML() {
  if (model) return // Already initialized

  try {
    // Load the pre-trained model
    model = await loadModel()

    // Initialize and load the tokenizer
    tokenizer = new Tokenizer({
      numWords: MAX_WORDS,
      oov_token: "<OOV>",
    })

    // Load the vocabulary (in a real implementation, this would be loaded from a file)
    await loadTokenizerVocabulary()

    console.log("ML model and tokenizer initialized successfully")
  } catch (error) {
    console.error("Failed to initialize ML components:", error)
    throw new Error("ML initialization failed")
  }
}

// Load the tokenizer vocabulary
async function loadTokenizerVocabulary() {
  // In a real implementation, this would load from a saved vocabulary file
  // For this example, we'll use a simplified approach

  // Sample vocabulary from SQL injection payloads
  const vocabulary = new Map<string, number>()

  // Add common SQL injection terms to the vocabulary
  ;[
    "select",
    "union",
    "from",
    "where",
    "and",
    "or",
    "insert",
    "update",
    "delete",
    "drop",
    "table",
    "database",
    "exec",
    "execute",
    "sp_",
    "xp_",
    "declare",
    "cast",
    "convert",
    "varchar",
    "nvarchar",
    "char",
    "waitfor",
    "delay",
    "benchmark",
    "sleep",
    "pg_sleep",
    "version",
    "information_schema",
    "sysobjects",
    "sysusers",
    "systables",
    "all_tables",
    "all_tab_columns",
    "1=1",
    "1=2",
    "true",
    "false",
    "--",
    "/*",
    "*/",
    ";",
    "'",
    '"',
    "`",
    "admin",
    "password",
    "user",
    "username",
    "pass",
    "login",
    "concat",
    "substring",
    "ascii",
    "hex",
    "unhex",
    "base64",
    "encode",
    "decode",
    "load_file",
    "outfile",
    "dumpfile",
    "extractvalue",
    "updatexml",
  ].forEach((word, index) => {
    vocabulary.set(word, index + 1) // Reserve 0 for padding
  })

  // Set the vocabulary in the tokenizer
  if (tokenizer) {
    tokenizer.setWordIndex(vocabulary)
  }
}

// Process a query for prediction
function processQuery(query: string): number[][] {
  if (!tokenizer) {
    throw new Error("Tokenizer not initialized")
  }

  // Convert the query to a sequence of token IDs
  const sequence = tokenizer.textsToSequences([query])[0]

  // Pad the sequence to the required length
  const paddedSequence = padSequence(sequence, MAX_LEN)

  return [paddedSequence]
}

// Pad a sequence to the specified length
function padSequence(sequence: number[], maxLen: number): number[] {
  if (sequence.length > maxLen) {
    return sequence.slice(0, maxLen)
  }

  const padding = Array(maxLen - sequence.length).fill(0)
  return [...padding, ...sequence]
}

// Predict if a query is a SQL injection
export async function predictSQLInjection(query: string): Promise<{
  isSQLInjection: boolean
  confidence: number
}> {
  if (!model) {
    await initializeML()
  }

  try {
    // Process the query
    const processedQuery = processQuery(query)

    // Make prediction
    const prediction = (await model!.predict(TensorFlow.tensor2d(processedQuery))) as TensorFlow.Tensor

    // Get the confidence score
    const confidence = (await prediction.data())[0] * 100

    // Determine if it's a SQL injection based on confidence threshold
    const isSQLInjection = confidence > 50

    return {
      isSQLInjection,
      confidence,
    }
  } catch (error) {
    console.error("Prediction error:", error)
    throw new Error("Failed to predict SQL injection")
  }
}
