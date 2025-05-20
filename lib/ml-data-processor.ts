import * as tf from "@tensorflow/tfjs-node"
import { TfidfVectorizer } from "./tfidf-vectorizer"

// Maximum number of features for TF-IDF vectorization
const MAX_FEATURES = 5000

// TF-IDF vectorizer for processing SQL queries
let vectorizer: TfidfVectorizer | null = null

// Initialize the TF-IDF vectorizer
export async function initializeVectorizer() {
  if (vectorizer) return // Already initialized

  try {
    // Create a new TF-IDF vectorizer
    vectorizer = new TfidfVectorizer({
      maxFeatures: MAX_FEATURES,
    })

    // In a real implementation, we would fit the vectorizer on training data
    // For this example, we'll use a simplified approach with common SQL injection terms
    const commonTerms = [
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
    ]

    // Fit the vectorizer on common terms
    await vectorizer.fit(commonTerms)

    console.log("TF-IDF vectorizer initialized successfully")
  } catch (error) {
    console.error("Failed to initialize TF-IDF vectorizer:", error)
    throw new Error("TF-IDF vectorizer initialization failed")
  }
}

// Process a query for prediction
export async function processQuery(query: string): Promise<Float32Array> {
  if (!vectorizer) {
    await initializeVectorizer()
  }

  try {
    // Transform the query using the TF-IDF vectorizer
    const features = await vectorizer!.transform([query])

    return features[0]
  } catch (error) {
    console.error("Query processing error:", error)
    throw new Error("Failed to process query")
  }
}

// Convert processed features to a tensor for model input
export function featuresToTensor(features: Float32Array): tf.Tensor2D {
  return tf.tensor2d([Array.from(features)])
}
