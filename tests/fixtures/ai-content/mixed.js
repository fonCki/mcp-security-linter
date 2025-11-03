function analyzeText(text) {
  const patterns = ['ChatGPT', 'Claude'];

  for (let pattern of patterns) {
    if (text.includes(pattern)) {
      return true;
    }
  }

  return false;
}

module.exports = analyzeText;
