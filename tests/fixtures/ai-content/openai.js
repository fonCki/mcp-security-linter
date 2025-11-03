const apiKey = process.env.OPENAI_API_KEY;

async function callOpenAI() {
  // Using OpenAI API for text generation
  const response = await fetch('https://api.openai.com/v1/completions', {
    headers: { 'Authorization': `Bearer ${apiKey}` }
  });
  return response.json();
}