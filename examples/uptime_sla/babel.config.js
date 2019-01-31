module.exports = function (api) {
  api.cache(false)

  const presets = [
    [
      '@babel/preset-env',
      {
        loose: true,
        modules: 'commonjs',
        targets: {
          node: 'current'
        },
        'useBuiltIns': 'entry'
      }
    ]
  ]

  const plugins = [
    [
      'module-resolver', {
        alias: {
          foo: '../../solidity-test-support'
        }
      }
    ],
    '@babel/plugin-proposal-export-namespace-from',
    '@babel/plugin-proposal-throw-expressions',
    '@babel/plugin-proposal-class-properties'
  ]

  return {
    presets,
    plugins
  }
}
