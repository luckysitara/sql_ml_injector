import * as fs from "fs"
import * as path from "path"

export interface TokenizerOptions {
  maxWords?: number
  oovToken?: string
  charLevel?: boolean
}

export class Tokenizer {
  private wordIndex: Map<string, number> = new Map()
  private indexWord: Map<number, string> = new Map()
  private wordCounts: Map<string, number> = new Map()
  private options: TokenizerOptions
  private fitted = false

  constructor(options: TokenizerOptions = {}) {
    this.options = {
      maxWords: options.maxWords || 20000,
      oovToken: options.oovToken || "<OOV>",
      charLevel: options.charLevel || false,
    }

    // Add OOV token to the vocabulary
    if (this.options.oovToken) {
      this.wordIndex.set(this.options.oovToken, 1)
      this.indexWord.set(1, this.options.oovToken)
    }
  }

  // Tokenize text into words or characters
  private tokenize(text: string): string[] {
    if (this.options.charLevel) {
      // Character-level tokenization
      return text.split("")
    } else {
      // Word-level tokenization
      // SQL-specific tokenization that preserves important SQL syntax
      const sqlTokens = text
        .replace(/([(),;])/g, " $1 ") // Add spaces around punctuation
        .replace(/\s+/g, " ") // Normalize whitespace
        .trim()
        .toLowerCase()
        .split(" ")
        .filter((token) => token.length > 0)

      return sqlTokens
    }
  }

  // Fit the tokenizer on texts
  public fit(texts: string[]): void {
    console.log("Fitting tokenizer on texts...")

    // Count word frequencies
    for (const text of texts) {
      const tokens = this.tokenize(text)

      for (const token of tokens) {
        this.wordCounts.set(token, (this.wordCounts.get(token) || 0) + 1)
      }
    }

    // Sort words by frequency (descending)
    const sortedWords = Array.from(this.wordCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .map(([word, _]) => word)

    // Limit vocabulary size if maxWords is specified
    const vocabularySize = this.options.maxWords
      ? Math.min(this.options.maxWords, sortedWords.length)
      : sortedWords.length

    // Build word index (starting from index 2, as 0 is reserved for padding and 1 for OOV)
    let index = 2
    for (let i = 0; i < vocabularySize; i++) {
      const word = sortedWords[i]
      this.wordIndex.set(word, index)
      this.indexWord.set(index, word)
      index++
    }

    this.fitted = true
    console.log(`Tokenizer fitted with vocabulary size: ${this.wordIndex.size}`)
  }

  // Convert texts to sequences of token indices
  public textsToSequences(texts: string[]): number[][] {
    if (!this.fitted) {
      throw new Error("Tokenizer is not fitted. Call fit() first.")
    }

    const sequences: number[][] = []

    for (const text of texts) {
      const tokens = this.tokenize(text)
      const sequence: number[] = []

      for (const token of tokens) {
        if (this.wordIndex.has(token)) {
          sequence.push(this.wordIndex.get(token)!)
        } else if (this.options.oovToken) {
          // Use OOV token index
          sequence.push(this.wordIndex.get(this.options.oovToken)!)
        }
      }

      sequences.push(sequence)
    }

    return sequences
  }

  // Convert sequences back to texts
  public sequencesToTexts(sequences: number[][]): string[] {
    const texts: string[] = []

    for (const sequence of sequences) {
      const tokens: string[] = []

      for (const index of sequence) {
        if (index === 0) {
          // Skip padding
          continue
        } else if (this.indexWord.has(index)) {
          tokens.push(this.indexWord.get(index)!)
        }
      }

      texts.push(tokens.join(" "))
    }

    return texts
  }

  // Get the word index
  public getWordIndex(): Map<string, number> {
    return new Map(this.wordIndex)
  }

  // Set the word index (useful for loading a pre-trained tokenizer)
  public setWordIndex(wordIndex: Map<string, number>): void {
    this.wordIndex = new Map(wordIndex)

    // Rebuild index_word mapping
    this.indexWord.clear()
    for (const [word, index] of this.wordIndex.entries()) {
      this.indexWord.set(index, word)
    }

    this.fitted = true
  }

  // Get vocabulary size
  public getVocabularySize(): number {
    return this.wordIndex.size
  }

  // Save tokenizer to a JSON file
  public async save(filePath: string): Promise<void> {
    const dir = path.dirname(filePath)
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true })
    }

    const data = {
      wordIndex: Array.from(this.wordIndex.entries()),
      options: this.options,
    }

    fs.writeFileSync(filePath, JSON.stringify(data, null, 2))
    console.log(`Tokenizer saved to ${filePath}`)
  }

  // Load tokenizer from a JSON file
  public static async load(filePath: string): Promise<Tokenizer> {
    const data = JSON.parse(fs.readFileSync(filePath, "utf-8"))

    const tokenizer = new Tokenizer(data.options)
    tokenizer.setWordIndex(new Map(data.wordIndex))

    console.log(`Tokenizer loaded from ${filePath}`)
    return tokenizer
  }
}
