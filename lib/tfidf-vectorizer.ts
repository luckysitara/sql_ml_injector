// A simplified implementation of TF-IDF vectorization for text processing

interface TfidfVectorizerOptions {
  maxFeatures?: number
  minDocumentFrequency?: number
}

export class TfidfVectorizer {
  private vocabulary: Map<string, number>
  private documentFrequency: Map<string, number>
  private idfValues: Map<string, number>
  private totalDocuments: number
  private options: TfidfVectorizerOptions

  constructor(options: TfidfVectorizerOptions = {}) {
    this.vocabulary = new Map()
    this.documentFrequency = new Map()
    this.idfValues = new Map()
    this.totalDocuments = 0
    this.options = {
      maxFeatures: options.maxFeatures || 5000,
      minDocumentFrequency: options.minDocumentFrequency || 1,
    }
  }

  // Tokenize text into words
  private tokenize(text: string): string[] {
    // Simple tokenization by splitting on non-alphanumeric characters
    return text
      .toLowerCase()
      .replace(/[^a-z0-9\s]/g, " ")
      .split(/\s+/)
      .filter((token) => token.length > 0)
  }

  // Fit the vectorizer on a corpus of documents
  async fit(documents: string[]): Promise<void> {
    this.totalDocuments = documents.length

    // Count document frequency for each term
    const termCounts = new Map<string, number>()

    for (const doc of documents) {
      const tokens = this.tokenize(doc)
      const uniqueTokens = new Set(tokens)

      for (const token of uniqueTokens) {
        const count = this.documentFrequency.get(token) || 0
        this.documentFrequency.set(token, count + 1)
        termCounts.set(token, (termCounts.get(token) || 0) + 1)
      }
    }

    // Filter terms by document frequency and select top features
    const sortedTerms = Array.from(termCounts.entries())
      .filter(([term, _]) => (this.documentFrequency.get(term) || 0) >= (this.options.minDocumentFrequency || 1))
      .sort((a, b) => b[1] - a[1])
      .slice(0, this.options.maxFeatures)
      .map(([term, _]) => term)

    // Build vocabulary
    sortedTerms.forEach((term, index) => {
      this.vocabulary.set(term, index)
    })

    // Calculate IDF values
    for (const [term, index] of this.vocabulary.entries()) {
      const df = this.documentFrequency.get(term) || 0
      const idf = Math.log((this.totalDocuments + 1) / (df + 1)) + 1 // Smoothed IDF
      this.idfValues.set(term, idf)
    }
  }

  // Transform documents into TF-IDF feature vectors
  async transform(documents: string[]): Promise<Float32Array[]> {
    const result: Float32Array[] = []

    for (const doc of documents) {
      const tokens = this.tokenize(doc)
      const termFrequency = new Map<string, number>()

      // Count term frequency
      for (const token of tokens) {
        termFrequency.set(token, (termFrequency.get(token) || 0) + 1)
      }

      // Create feature vector
      const features = new Float32Array(this.vocabulary.size)

      for (const [term, index] of this.vocabulary.entries()) {
        const tf = termFrequency.get(term) || 0
        const idf = this.idfValues.get(term) || 0
        features[index] = tf * idf
      }

      result.push(features)
    }

    return result
  }

  // Get the vocabulary size
  getVocabularySize(): number {
    return this.vocabulary.size
  }

  // Get the vocabulary
  getVocabulary(): Map<string, number> {
    return new Map(this.vocabulary)
  }
}
