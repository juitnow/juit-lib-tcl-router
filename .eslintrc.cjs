'use strict'

module.exports = {
  root: true,
  extends: [
    'plugin:@plugjs/typescript',
  ],
  overrides: [ {
    files: [ 'test/**' ],
    rules: {
      'import/no-extraneous-dependencies': 'off',
    },
  } ],
}
