import * as tf from "@tensorflow/tfjs-node"
import type { Tokenizer } from "./tokenizer"
import type { SQLExample } from "./dataset"

export interface PreprocessorOptions {
  maxSequenceLength?: number
  paddingStrategy?: "pre" | "post"
  truncatingStrategy?: "pre" | "post"
}

export class SQLPreprocessor {
  private tokenizer: Tokenizer
  private options: PreprocessorOptions

  constructor(tokenizer: Tokenizer, options: PreprocessorOptions = {}) {
    this.tokenizer = tokenizer
    this.options = {
      maxSequenceLength: options.maxSequenceLength || 100,
      paddingStrategy: options.paddingStrategy || "pre",
      truncatingStrategy: options.truncatingStrategy || "post",
    }
  }

  // Preprocess a batch of examples
  public preprocess(examples: SQLExample[]): {
    xTensor: tf.Tensor2D
    yTensor: tf.Tensor2D
  } {
    // Extract queries and labels
    const queries = examples.map((example) => example.query)
    const labels = examples.map((example) => (example.isSQLInjection ? 1 : 0))

    // Convert queries to sequences
    const sequences = this.tokenizer.textsToSequences(queries)

    // Pad sequences
    const paddedSequences = this.padSequences(sequences)

    // Convert to tensors
    const xTensor = tf.tensor2d(paddedSequences)
    const yTensor = tf.tensor2d(labels.map((label) => [label]))

    return { xTensor, yTensor }
  }

  // Pad sequences to the same length
  private padSequences(sequences: number[][]): number[][] {
    return sequences.map((sequence) => {
      // Truncate if necessary
      let seq = [...sequence]
      if (seq.length > this.options.maxSequenceLength!) {
        if (this.options.truncatingStrategy === "pre") {
          seq = seq.slice(seq.length - this.options.maxSequenceLength!)
        } else {
          seq = seq.slice(0, this.options.maxSequenceLength!)
        }
      }

      // Pad if necessary
      if (seq.length < this.options.maxSequenceLength!) {
        const padding = Array(this.options.maxSequenceLength! - seq.length).fill(0)
        if (this.options.paddingStrategy === "pre") {
          seq = [...padding, ...seq]
        } else {
          seq = [...seq, ...padding]
        }
      }

      return seq
    })
  }

  // Preprocess a single query
  public preprocessQuery(query: string): tf.Tensor2D {
    const sequence = this.tokenizer.textsToSequences([query])[0]
    const paddedSequence = this.padSequences([sequence])[0]
    return tf.tensor2d([paddedSequence])
  }

  // Get the tokenizer
  public getTokenizer(): Tokenizer {
    return this.tokenizer
  }

  // Get the options
  public getOptions(): PreprocessorOptions {
    return { ...this.options }
  }
}
