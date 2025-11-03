function calculateSum(numbers) {
  let total = 0;
  for (let num of numbers) {
    total += num;
  }
  return total;
}

module.exports = calculateSum;