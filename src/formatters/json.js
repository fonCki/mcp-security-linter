function format(findings) {
  const output = {
    summary: {
      total: findings.length,
      errors: findings.filter(f => f.level === 'error').length,
      warnings: findings.filter(f => f.level === 'warning').length,
      info: findings.filter(f => f.level === 'info').length
    },
    findings: findings
  };

  return JSON.stringify(output, null, 2);
}

module.exports = { format };