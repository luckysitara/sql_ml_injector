import * as path from "path"
import * as fs from "fs"
import { SQLInjectionDataset } from "./dataset"
import { Tokenizer } from "./tokenizer"
import { SQLPreprocessor } from "./preprocessor"
import { SQLInjectionModel } from "./model"

// Main function to train the model
export async function trainModel(
  datasetPath?: string,
  outputDir: string = path.join(process.cwd(), "models", "sql_injection"),
): Promise<void> {
  console.log("Starting model training process...")

  // Create output directory if it doesn't exist
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true })
  }

  // Load or generate dataset
  const dataset = new SQLInjectionDataset()

  if (datasetPath && fs.existsSync(datasetPath)) {
    // Load dataset from CSV file
    await dataset.loadFromCSV(datasetPath)
  } else {
    // Generate synthetic dataset
    console.log("No dataset provided or file not found. Generating synthetic dataset...")
    dataset.generateSyntheticDataset(20000)

    // Save the synthetic dataset
    const datasetDir = path.join(outputDir, "dataset")
    await dataset.saveToCSV(
      path.join(datasetDir, "train.csv"),
      path.join(datasetDir, "validation.csv"),
      path.join(datasetDir, "test.csv"),
    )
  }

  // Get data splits
  const trainingData = dataset.getTrainingData()
  const validationData = dataset.getValidationData()
  const testData = dataset.getTestData()

  console.log(
    `Dataset loaded: ${trainingData.length} training, ${validationData.length} validation, ${testData.length} test examples`,
  )

  // Create and fit tokenizer
  const tokenizer = new Tokenizer({
    maxWords: 20000,
    oovToken: "<OOV>",
  })

  tokenizer.fit(trainingData.map((example) => example.query))

  // Save the tokenizer
  await tokenizer.save(path.join(outputDir, "tokenizer.json"))

  // Create preprocessor
  const preprocessor = new SQLPreprocessor(tokenizer, {
    maxSequenceLength: 100,
    paddingStrategy: "pre",
    truncatingStrategy: "post",
  })

  // Create and build model
  const model = new SQLInjectionModel(preprocessor)
  model.buildModel(tokenizer.getVocabularySize())

  // Train the model
  await model.train(trainingData, validationData, {
    epochs: 10,
    batchSize: 64,
    earlyStoppingPatience: 3,
  })

  // Evaluate the model
  const evaluationResults = await model.evaluate(testData)

  // Save evaluation results
  fs.writeFileSync(path.join(outputDir, "evaluation.json"), JSON.stringify(evaluationResults, null, 2))

  // Save the model
  await model.save(path.join(outputDir, "model"))

  console.log("Model training and evaluation completed successfully")
  console.log(`Model and artifacts saved to ${outputDir}`)
}

// If this file is run directly, train the model
if (require.main === module) {
  const datasetPath = process.argv[2]
  const outputDir = process.argv[3] || path.join(process.cwd(), "models", "sql_injection")

  trainModel(datasetPath, outputDir)
    .then(() => {
      console.log("Training script completed successfully")
      process.exit(0)
    })
    .catch((error) => {
      console.error("Error during training:", error)
      process.exit(1)
    })
}
