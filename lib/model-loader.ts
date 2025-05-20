import * as tf from "@tensorflow/tfjs-node"
import * as fs from "fs"
import * as path from "path"

// Path to the model files
const MODEL_PATH = path.join(process.cwd(), "models", "sql_injection_model")

// Load the TensorFlow model
export async function loadModel(): Promise<tf.LayersModel> {
  try {
    // Check if model files exist
    if (!fs.existsSync(MODEL_PATH)) {
      // If model doesn't exist, create and train a new one
      return await createAndTrainModel()
    }

    // Load the model from files
    const model = await tf.loadLayersModel(`file://${MODEL_PATH}/model.json`)
    console.log("Model loaded successfully")
    return model
  } catch (error) {
    console.error("Error loading model:", error)
    // Fallback to creating a new model
    return await createAndTrainModel()
  }
}

// Create and train a new model
async function createAndTrainModel(): Promise<tf.LayersModel> {
  console.log("Creating and training a new model...")

  // Create a simple model for demonstration
  // In a real implementation, this would be a more complex model trained on a large dataset
  const model = tf.sequential()

  // Add model layers
  model.add(
    tf.layers.embedding({
      inputDim: 20000, // Vocabulary size
      outputDim: 100, // Embedding dimension
      inputLength: 100, // Maximum sequence length
    }),
  )

  model.add(tf.layers.spatialDropout1d({ rate: 0.3 }))

  model.add(
    tf.layers.bidirectional({
      layer: tf.layers.lstm({
        units: 256,
        returnSequences: true,
      }),
    }),
  )

  model.add(tf.layers.batchNormalization())
  model.add(tf.layers.dropout({ rate: 0.5 }))

  model.add(
    tf.layers.bidirectional({
      layer: tf.layers.lstm({
        units: 256,
        returnSequences: true,
      }),
    }),
  )

  model.add(tf.layers.batchNormalization())
  model.add(tf.layers.dropout({ rate: 0.5 }))

  model.add(
    tf.layers.bidirectional({
      layer: tf.layers.lstm({
        units: 256,
        returnSequences: false,
      }),
    }),
  )

  model.add(tf.layers.batchNormalization())
  model.add(tf.layers.dropout({ rate: 0.5 }))

  model.add(
    tf.layers.dense({
      units: 256,
      activation: "relu",
    }),
  )

  model.add(tf.layers.dropout({ rate: 0.5 }))

  model.add(
    tf.layers.dense({
      units: 1,
      activation: "sigmoid",
    }),
  )

  // Compile the model
  model.compile({
    optimizer: "adam",
    loss: "binaryCrossentropy",
    metrics: ["accuracy"],
  })

  // In a real implementation, we would train the model here
  // For this example, we'll just return the untrained model

  // Save the model
  try {
    if (!fs.existsSync(path.dirname(MODEL_PATH))) {
      fs.mkdirSync(path.dirname(MODEL_PATH), { recursive: true })
    }

    await model.save(`file://${MODEL_PATH}`)
    console.log("Model saved successfully")
  } catch (saveError) {
    console.error("Error saving model:", saveError)
  }

  return model
}
