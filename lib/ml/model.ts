import * as tf from "@tensorflow/tfjs-node"
import * as fs from "fs"
import type { SQLPreprocessor } from "./preprocessor"
import type { SQLExample } from "./dataset"

export interface ModelTrainingOptions {
  epochs?: number
  batchSize?: number
  validationSplit?: number
  learningRate?: number
  earlyStoppingPatience?: number
}

export class SQLInjectionModel {
  private model: tf.LayersModel | null = null
  private preprocessor: SQLPreprocessor

  constructor(preprocessor: SQLPreprocessor) {
    this.preprocessor = preprocessor
  }

  // Build the model architecture
  public buildModel(vocabSize: number, embeddingDim = 100): void {
    console.log("Building model...")

    const maxLen = this.preprocessor.getOptions().maxSequenceLength || 100

    // Create a sequential model
    this.model = tf.sequential()

    // Add embedding layer
    this.model.add(
      tf.layers.embedding({
        inputDim: vocabSize + 1, // +1 for padding token (0)
        outputDim: embeddingDim,
        inputLength: maxLen,
        maskZero: true,
      }),
    )

    // Add spatial dropout to prevent overfitting
    this.model.add(tf.layers.spatialDropout1d({ rate: 0.3 }))

    // Add bidirectional LSTM layers
    this.model.add(
      tf.layers.bidirectional({
        layer: tf.layers.lstm({
          units: 128,
          returnSequences: true,
        }),
      }),
    )

    this.model.add(tf.layers.batchNormalization())
    this.model.add(tf.layers.dropout({ rate: 0.5 }))

    this.model.add(
      tf.layers.bidirectional({
        layer: tf.layers.lstm({
          units: 64,
          returnSequences: false,
        }),
      }),
    )

    this.model.add(tf.layers.batchNormalization())
    this.model.add(tf.layers.dropout({ rate: 0.5 }))

    // Add dense layers
    this.model.add(
      tf.layers.dense({
        units: 64,
        activation: "relu",
      }),
    )

    this.model.add(tf.layers.dropout({ rate: 0.5 }))

    // Output layer
    this.model.add(
      tf.layers.dense({
        units: 1,
        activation: "sigmoid",
      }),
    )

    // Compile the model
    this.model.compile({
      optimizer: tf.train.adam({ learningRate: 0.001 }),
      loss: "binaryCrossentropy",
      metrics: ["accuracy"],
    })

    // Print model summary
    this.model.summary()
    console.log("Model built successfully")
  }

  // Train the model
  public async train(
    trainingData: SQLExample[],
    validationData: SQLExample[],
    options: ModelTrainingOptions = {},
  ): Promise<tf.History> {
    if (!this.model) {
      throw new Error("Model not built. Call buildModel() first.")
    }

    console.log("Training model...")

    // Set default options
    const epochs = options.epochs || 10
    const batchSize = options.batchSize || 32
    const validationSplit = options.validationSplit || 0.2

    // Preprocess training data
    const { xTensor: xTrain, yTensor: yTrain } = this.preprocessor.preprocess(trainingData)

    // Preprocess validation data if provided
    let xVal: tf.Tensor2D | undefined
    let yVal: tf.Tensor2D | undefined

    if (validationData.length > 0) {
      const { xTensor, yTensor } = this.preprocessor.preprocess(validationData)
      xVal = xTensor
      yVal = yTensor
    }

    // Configure callbacks
    const callbacks: tf.Callback[] = []

    // Add early stopping if patience is specified
    if (options.earlyStoppingPatience) {
      callbacks.push(
        tf.callbacks.earlyStopping({
          monitor: "val_loss",
          patience: options.earlyStoppingPatience,
          verbose: 1,
        }),
      )
    }

    // Train the model
    const history = await this.model.fit(xTrain, yTrain, {
      epochs,
      batchSize,
      validationSplit: xVal ? undefined : validationSplit,
      validationData: xVal && yVal ? [xVal, yVal] : undefined,
      callbacks,
      verbose: 1,
    })

    // Clean up tensors
    xTrain.dispose()
    yTrain.dispose()
    if (xVal) xVal.dispose()
    if (yVal) yVal.dispose()

    console.log("Model training completed")
    return history
  }

  // Evaluate the model
  public async evaluate(testData: SQLExample[]): Promise<{
    loss: number
    accuracy: number
    precision: number
    recall: number
    f1Score: number
  }> {
    if (!this.model) {
      throw new Error("Model not built or trained. Call buildModel() and train() first.")
    }

    console.log("Evaluating model...")

    // Preprocess test data
    const { xTensor: xTest, yTensor: yTest } = this.preprocessor.preprocess(testData)

    // Evaluate the model
    const result = (await this.model.evaluate(xTest, yTest)) as tf.Scalar[]
    const loss = result[0].dataSync()[0]
    const accuracy = result[1].dataSync()[0]

    // Make predictions for precision, recall, and F1 calculation
    const predictions = (await this.model.predict(xTest)) as tf.Tensor
    const predArray = await predictions.greater(tf.scalar(0.5)).dataSync()
    const trueArray = await yTest.dataSync()

    // Calculate precision, recall, and F1 score
    let truePositives = 0
    let falsePositives = 0
    let falseNegatives = 0

    for (let i = 0; i < predArray.length; i++) {
      if (predArray[i] === 1 && trueArray[i] === 1) {
        truePositives++
      } else if (predArray[i] === 1 && trueArray[i] === 0) {
        falsePositives++
      } else if (predArray[i] === 0 && trueArray[i] === 1) {
        falseNegatives++
      }
    }

    const precision = truePositives / (truePositives + falsePositives) || 0
    const recall = truePositives / (truePositives + falseNegatives) || 0
    const f1Score = (2 * (precision * recall)) / (precision + recall) || 0

    // Clean up tensors
    xTest.dispose()
    yTest.dispose()
    predictions.dispose()

    console.log(
      `Evaluation results: Loss: ${loss.toFixed(4)}, Accuracy: ${accuracy.toFixed(4)}, Precision: ${precision.toFixed(4)}, Recall: ${recall.toFixed(4)}, F1 Score: ${f1Score.toFixed(4)}`,
    )

    return { loss, accuracy, precision, recall, f1Score }
  }

  // Predict if a query is a SQL injection
  public async predict(query: string): Promise<{
    isSQLInjection: boolean
    confidence: number
  }> {
    if (!this.model) {
      throw new Error("Model not built or trained. Call buildModel() and train() first.")
    }

    // Preprocess the query
    const xTensor = this.preprocessor.preprocessQuery(query)

    // Make prediction
    const prediction = (await this.model.predict(xTensor)) as tf.Tensor
    const confidence = prediction.dataSync()[0]

    // Clean up tensors
    xTensor.dispose()
    prediction.dispose()

    return {
      isSQLInjection: confidence > 0.5,
      confidence: confidence * 100, // Convert to percentage
    }
  }

  // Save the model to disk
  public async save(modelDir: string): Promise<void> {
    if (!this.model) {
      throw new Error("Model not built or trained. Call buildModel() and train() first.")
    }

    // Create directory if it doesn't exist
    if (!fs.existsSync(modelDir)) {
      fs.mkdirSync(modelDir, { recursive: true })
    }

    // Save the model
    const modelPath = `file://${modelDir}`
    await this.model.save(modelPath)

    console.log(`Model saved to ${modelDir}`)
  }

  // Load the model from disk
  public async load(modelDir: string): Promise<void> {
    const modelPath = `file://${modelDir}`
    this.model = await tf.loadLayersModel(modelPath)

    // Compile the model
    this.model.compile({
      optimizer: tf.train.adam({ learningRate: 0.001 }),
      loss: "binaryCrossentropy",
      metrics: ["accuracy"],
    })

    console.log(`Model loaded from ${modelDir}`)
  }

  // Get the model
  public getModel(): tf.LayersModel | null {
    return this.model
  }

  // Get the preprocessor
  public getPreprocessor(): SQLPreprocessor {
    return this.preprocessor
  }
}
