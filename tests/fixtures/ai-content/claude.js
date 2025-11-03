// Integration with Claude API from Anthropic
class DataProcessor {
  constructor() {
    this.data = [];
    this.model = 'claude-3';
  }

  process(input) {
    // Claude suggested this filtering approach
    return input.filter(item => item > 0);
  }
}